//! exFAT write side (planning doc §5, §7). Everything written is
//! FAT-chained (NoFatChain = 0) so allocation and growth are uniform.
//!
//! Ordering discipline (doc §7): allocate in the bitmap → write cluster
//! data → flush → publish/update the directory entry → flush. Data always
//! reaches disk before a directory entry references it, so a power cut
//! leaves at worst lost clusters (fsck-recoverable), never a directory
//! pointing at garbage. The exFAT power-loss harness exercises this.

use crate::boot::Geometry;
use crate::dir;
use crate::upcase::UpcaseTable;
use crate::{alloc, BitmapLoc, ExfatError, ExfatFs, ExfatResult, ReadAt, WriteAt};

const DIR_ATTR: u16 = 0x10;
const ARCHIVE_ATTR: u16 = 0x20;

/// Fixed valid timestamp (2024-01-01 00:00:00 local, no UTC offset). File
/// times are not part of tree-content equivalence, so a constant keeps
/// writes deterministic.
const FIXED_TS: u32 = ((2024 - 1980) << 25) | (1 << 21) | (1 << 16);

/// exFAT NameHash (spec §7.4.4) over the up-cased UTF-16 name.
fn name_hash(upcase: &UpcaseTable, name_utf16: &[u16]) -> u16 {
    let mut hash: u16 = 0;
    for &u in name_utf16 {
        let up = upcase.map(u);
        for byte in up.to_le_bytes() {
            hash = ((hash & 1) << 15)
                .wrapping_add(hash >> 1)
                .wrapping_add(byte as u16);
        }
    }
    hash
}

/// Entry-set checksum (spec §6.3.3): rotate-right u16 over all set bytes,
/// skipping bytes 2..4 of the first entry (the checksum field).
fn set_checksum(entries: &[[u8; 32]]) -> u16 {
    let mut cs: u16 = 0;
    for (idx, e) in entries.iter().enumerate() {
        for (i, &b) in e.iter().enumerate() {
            if idx == 0 && (i == 2 || i == 3) {
                continue;
            }
            cs = cs.rotate_right(1).wrapping_add(b as u16);
        }
    }
    cs
}

/// Physical slots of a directory: (disk_offset, cluster_index_in_chain).
struct DirSlots {
    chain: Vec<u32>,
    /// disk offset of every 32-byte slot, in chain order.
    offsets: Vec<u64>,
}

fn dir_slots<D: WriteAt>(disk: &mut D, geo: &Geometry, first: u32) -> ExfatResult<DirSlots> {
    let chain = crate::fat::read_chain(disk, geo, first, None)?;
    let per = (geo.cluster_bytes() / 32) as usize;
    let mut offsets = Vec::with_capacity(chain.len() * per);
    for &c in chain.iter() {
        let base = geo.cluster_offset(c)?;
        for s in 0..per {
            offsets.push(base + (s * 32) as u64);
        }
    }
    Ok(DirSlots { chain, offsets })
}

fn read_slot<D: ReadAt>(disk: &mut D, off: u64) -> ExfatResult<[u8; 32]> {
    let mut raw = [0u8; 32];
    disk.read_at(off, &mut raw)?;
    Ok(raw)
}

/// A located, in-use File entry set.
pub struct EntryLoc {
    pub offsets: Vec<u64>, // disk offset per entry in the set
    pub first_cluster: u32,
    pub data_len: u64,
    pub is_dir: bool,
    pub flags: u8,
}

fn utf16_name(name: &str) -> Vec<u16> {
    name.encode_utf16().collect()
}

/// Locate an in-use file/dir entry set by name (case-insensitive).
fn locate<D: WriteAt>(
    disk: &mut D,
    geo: &Geometry,
    upcase: &UpcaseTable,
    dir_first: u32,
    name: &str,
) -> ExfatResult<Option<EntryLoc>> {
    let slots = dir_slots(disk, geo, dir_first)?;
    let want: Vec<u16> = utf16_name(name).iter().map(|&u| upcase.map(u)).collect();
    let mut i = 0;
    while i < slots.offsets.len() {
        let raw = read_slot(disk, slots.offsets[i])?;
        if raw[0] == dir::ENTRY_END {
            break;
        }
        if raw[0] != dir::ENTRY_FILE {
            i += 1;
            continue;
        }
        let secondary = raw[1] as usize;
        if i + secondary >= slots.offsets.len() {
            break;
        }
        let set_offs: Vec<u64> = slots.offsets[i..=i + secondary].to_vec();
        let stream = read_slot(disk, set_offs[1])?;
        let attrs = u16::from_le_bytes([raw[4], raw[5]]);
        let name_len = stream[3] as usize;
        let flags = stream[1];
        let first = u32::from_le_bytes(stream[20..24].try_into().unwrap());
        let data_len = u64::from_le_bytes(stream[24..32].try_into().unwrap());

        let mut units = Vec::with_capacity(name_len);
        for &name_off in &set_offs[2..] {
            let ne = read_slot(disk, name_off)?;
            if ne[0] != dir::ENTRY_NAME {
                break;
            }
            for c in ne[2..32].chunks_exact(2) {
                if units.len() < name_len {
                    units.push(u16::from_le_bytes([c[0], c[1]]));
                }
            }
        }
        let have: Vec<u16> = units.iter().map(|&u| upcase.map(u)).collect();
        if have == want {
            return Ok(Some(EntryLoc {
                offsets: set_offs,
                first_cluster: first,
                data_len,
                is_dir: attrs & DIR_ATTR != 0,
                flags,
            }));
        }
        i += 1 + secondary;
    }
    Ok(None)
}

/// A directory we can write into: its first cluster, and — for a
/// subdirectory — where its own entry lives so growth can update its size.
/// Root has no entry (`entry` is None; its size is bounded by the FAT chain).
struct DirHandle {
    first_cluster: u32,
    entry: Option<EntryLoc>,
}

impl<D: WriteAt> ExfatFs<D> {
    fn bitmap(&self) -> ExfatResult<BitmapLoc> {
        self.bitmap
            .ok_or(ExfatError::Invalid("no allocation bitmap"))
    }

    fn resolve_dir(&mut self, path: &str) -> ExfatResult<DirHandle> {
        let mut handle = DirHandle {
            first_cluster: self.geo.root_first_cluster,
            entry: None,
        };
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let up = self.upcase_clone();
            let loc = locate(&mut self.disk, &self.geo, &up, handle.first_cluster, comp)?
                .ok_or(ExfatError::NotFound)?;
            if !loc.is_dir {
                return Err(ExfatError::Invalid("path component is not a directory"));
            }
            handle = DirHandle {
                first_cluster: loc.first_cluster,
                entry: Some(loc),
            };
        }
        Ok(handle)
    }

    fn resolve_parent<'a>(&mut self, path: &'a str) -> ExfatResult<(DirHandle, &'a str)> {
        let trimmed = path.trim_end_matches('/');
        let (parent, leaf) = match trimmed.rsplit_once('/') {
            Some((p, l)) => (p, l),
            None => ("", trimmed),
        };
        if leaf.is_empty() {
            return Err(ExfatError::Invalid("empty file name"));
        }
        Ok((self.resolve_dir(parent)?, leaf))
    }

    // UpcaseTable isn't Clone-cheap-worry: it's a small Vec; clone to dodge
    // the borrow checker across &mut self.disk uses. Called rarely.
    fn upcase_clone(&self) -> UpcaseTable {
        self.upcase.snapshot()
    }

    /// Zero a freshly allocated directory cluster (all end-of-directory).
    fn zero_cluster(&mut self, cluster: u32) -> ExfatResult<()> {
        let zero = vec![0u8; self.geo.cluster_bytes() as usize];
        let off = self.geo.cluster_offset(cluster)?;
        self.disk.write_at(off, &zero)?;
        Ok(())
    }

    /// Find `k` consecutive usable slots within a single cluster of `dir`,
    /// growing the directory by a cluster if none exist. Returns their disk
    /// offsets. Growth updates a subdirectory's own size entry.
    fn find_or_make_slot_run(&mut self, dir: &DirHandle, k: usize) -> ExfatResult<Vec<u64>> {
        let slots = dir_slots(&mut self.disk, &self.geo, dir.first_cluster)?;
        let per = (self.geo.cluster_bytes() / 32) as usize;
        // Scan each cluster for a run of k usable slots.
        for ci in 0..slots.chain.len() {
            let start = ci * per;
            let mut run_start: Option<usize> = None;
            for s in start..start + per {
                let raw = read_slot(&mut self.disk, slots.offsets[s])?;
                let usable = raw[0] == dir::ENTRY_END || raw[0] & 0x80 == 0;
                if usable {
                    let rs = *run_start.get_or_insert(s);
                    if s - rs + 1 >= k {
                        return Ok(slots.offsets[rs..rs + k].to_vec());
                    }
                } else {
                    run_start = None;
                }
            }
        }
        // No room: grow by one cluster (k always fits in a fresh cluster).
        let bm = self.bitmap()?;
        let tail = *slots.chain.last().unwrap();
        let added = alloc::extend_chain(&mut self.disk, &self.geo, &bm, tail, 1)?;
        let new_cluster = added[0];
        self.zero_cluster(new_cluster)?;
        self.disk.flush()?;
        // Subdirectory grew: update its DataLength in its parent.
        if let Some(entry) = &dir.entry {
            let new_len = entry.data_len + self.geo.cluster_bytes();
            self.rewrite_stream(entry, entry.first_cluster, new_len, new_len, entry.flags)?;
            self.disk.flush()?;
        }
        let base = self.geo.cluster_offset(new_cluster)?;
        Ok((0..k).map(|s| base + (s * 32) as u64).collect())
    }

    /// Rewrite a set's Stream entry (cluster/size/flags) and its File
    /// entry's checksum in place.
    fn rewrite_stream(
        &mut self,
        entry: &EntryLoc,
        first_cluster: u32,
        data_len: u64,
        valid_len: u64,
        flags: u8,
    ) -> ExfatResult<()> {
        let mut file = read_slot(&mut self.disk, entry.offsets[0])?;
        let mut stream = read_slot(&mut self.disk, entry.offsets[1])?;
        stream[1] = flags;
        stream[8..16].copy_from_slice(&valid_len.to_le_bytes());
        stream[20..24].copy_from_slice(&first_cluster.to_le_bytes());
        stream[24..32].copy_from_slice(&data_len.to_le_bytes());

        // Rebuild the full set to recompute the checksum.
        let mut set = vec![file, stream];
        for off in &entry.offsets[2..] {
            set.push(read_slot(&mut self.disk, *off)?);
        }
        let cs = set_checksum(&set);
        file[2..4].copy_from_slice(&cs.to_le_bytes());

        self.disk.write_at(entry.offsets[0], &file)?;
        self.disk.write_at(entry.offsets[1], &stream)?;
        Ok(())
    }

    /// Write a File entry set for `leaf` into `parent`, pointing at existing
    /// clusters (`first_cluster`/`data_len`). Does no allocation itself.
    fn place_entry_set(
        &mut self,
        parent: &DirHandle,
        leaf: &str,
        is_dir: bool,
        first_cluster: u32,
        data_len: u64,
        flags: u8,
    ) -> ExfatResult<()> {
        let up = self.upcase_clone();
        let name_u16 = utf16_name(leaf);
        if name_u16.is_empty() || name_u16.len() > 255 {
            return Err(ExfatError::Invalid("bad name length"));
        }
        let name_entries = name_u16.len().div_ceil(15);
        let secondary = 1 + name_entries;
        let total = 1 + secondary;
        let offs = self.find_or_make_slot_run(parent, total)?;

        let mut file = [0u8; 32];
        file[0] = dir::ENTRY_FILE;
        file[1] = secondary as u8;
        let attrs = if is_dir { DIR_ATTR } else { ARCHIVE_ATTR };
        file[4..6].copy_from_slice(&attrs.to_le_bytes());
        file[8..12].copy_from_slice(&FIXED_TS.to_le_bytes());
        file[12..16].copy_from_slice(&FIXED_TS.to_le_bytes());
        file[16..20].copy_from_slice(&FIXED_TS.to_le_bytes());

        let mut stream = [0u8; 32];
        stream[0] = dir::ENTRY_STREAM;
        stream[1] = flags;
        stream[3] = name_u16.len() as u8;
        let nh = name_hash(&up, &name_u16);
        stream[4..6].copy_from_slice(&nh.to_le_bytes());
        stream[8..16].copy_from_slice(&data_len.to_le_bytes()); // valid = data
        stream[20..24].copy_from_slice(&first_cluster.to_le_bytes());
        stream[24..32].copy_from_slice(&data_len.to_le_bytes());

        let mut entries = vec![file, stream];
        for chunk in name_u16.chunks(15) {
            let mut ne = [0u8; 32];
            ne[0] = dir::ENTRY_NAME;
            for (k, &u) in chunk.iter().enumerate() {
                ne[2 + k * 2..4 + k * 2].copy_from_slice(&u.to_le_bytes());
            }
            entries.push(ne);
        }
        let cs = set_checksum(&entries);
        entries[0][2..4].copy_from_slice(&cs.to_le_bytes());

        for (e, off) in entries.iter().zip(&offs) {
            self.disk.write_at(*off, e)?;
        }
        self.disk.flush()?;
        Ok(())
    }

    /// Create an entry set (file or directory) named `leaf` in `parent`.
    /// For a directory, allocates and zeroes one initial cluster.
    fn create_entry(&mut self, parent: &DirHandle, leaf: &str, is_dir: bool) -> ExfatResult<()> {
        let up = self.upcase_clone();
        if locate(&mut self.disk, &self.geo, &up, parent.first_cluster, leaf)?.is_some() {
            return Err(ExfatError::Invalid("already exists"));
        }
        // A directory needs an initial cluster (ordering: data before entry).
        // Flags: bit0 AllocationPossible; bit1 NoFatChain stays 0.
        let (first_cluster, data_len, flags) = if is_dir {
            let bm = self.bitmap()?;
            let chain = alloc::alloc_chain(&mut self.disk, &self.geo, &bm, 1)?;
            self.zero_cluster(chain[0])?;
            self.disk.flush()?;
            (chain[0], self.geo.cluster_bytes(), 0x01)
        } else {
            (0u32, 0u64, 0x00)
        };
        self.place_entry_set(parent, leaf, is_dir, first_cluster, data_len, flags)
    }

    /// Move `from` to `to`. Re-points a fresh entry set at the same
    /// clusters, then clears the old entry (clusters are not freed).
    pub fn rename(&mut self, from: &str, to: &str) -> ExfatResult<()> {
        let (from_parent, from_leaf) = self.resolve_parent(from)?;
        let up = self.upcase_clone();
        let src = locate(
            &mut self.disk,
            &self.geo,
            &up,
            from_parent.first_cluster,
            from_leaf,
        )?
        .ok_or(ExfatError::NotFound)?;
        let (to_parent, to_leaf) = self.resolve_parent(to)?;
        if locate(
            &mut self.disk,
            &self.geo,
            &up,
            to_parent.first_cluster,
            to_leaf,
        )?
        .is_some()
        {
            return Err(ExfatError::Invalid("destination exists"));
        }
        self.place_entry_set(
            &to_parent,
            to_leaf,
            src.is_dir,
            src.first_cluster,
            src.data_len,
            src.flags,
        )?;
        // Clear the old entry's in-use bits (keep the clusters).
        for off in &src.offsets {
            let mut raw = read_slot(&mut self.disk, *off)?;
            raw[0] &= 0x7F;
            self.disk.write_at(*off, &raw)?;
        }
        self.disk.flush()?;
        Ok(())
    }

    /// Public: create an empty file at `path`.
    pub fn create_file(&mut self, path: &str) -> ExfatResult<()> {
        let (parent, leaf) = self.resolve_parent(path)?;
        self.create_entry(&parent, leaf, false)
    }

    /// Public: create a directory at `path`.
    pub fn make_dir(&mut self, path: &str) -> ExfatResult<()> {
        let (parent, leaf) = self.resolve_parent(path)?;
        self.create_entry(&parent, leaf, true)
    }

    /// Public: write `buf` at `offset` in the file at `path`, extending and
    /// zero-filling as needed.
    pub fn write_file(&mut self, path: &str, offset: u64, buf: &[u8]) -> ExfatResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let (parent, leaf) = self.resolve_parent(path)?;
        let up = self.upcase_clone();
        let entry = locate(&mut self.disk, &self.geo, &up, parent.first_cluster, leaf)?
            .ok_or(ExfatError::NotFound)?;
        if entry.is_dir {
            return Err(ExfatError::Invalid("write to a directory"));
        }
        let cluster_bytes = self.geo.cluster_bytes();
        let new_size = (offset + buf.len() as u64).max(entry.data_len);
        let old_clusters = entry.data_len.div_ceil(cluster_bytes);
        let new_clusters = new_size.div_ceil(cluster_bytes);
        let bm = self.bitmap()?;

        // Grow the chain if needed (data-before-metadata ordering).
        let mut first = entry.first_cluster;
        let mut chain = if entry.data_len == 0 {
            Vec::new()
        } else {
            crate::fat::read_chain(&mut self.disk, &self.geo, first, Some(old_clusters))?
        };
        if new_clusters > old_clusters {
            let need = (new_clusters - old_clusters) as u32;
            let added = if chain.is_empty() {
                let c = alloc::alloc_chain(&mut self.disk, &self.geo, &bm, need)?;
                first = c[0];
                c
            } else {
                alloc::extend_chain(&mut self.disk, &self.geo, &bm, *chain.last().unwrap(), need)?
            };
            chain.extend_from_slice(&added);
        }

        // Zero-fill any gap between the old end and the write offset.
        if offset > entry.data_len {
            self.zero_range(&chain, entry.data_len, offset - entry.data_len)?;
        }
        // Write the payload.
        self.write_range(&chain, offset, buf)?;
        self.disk.flush()?;

        // Publish the new size/first-cluster.
        self.rewrite_stream(&entry, first, new_size, new_size, 0x01)?;
        self.disk.flush()?;
        Ok(buf.len())
    }

    fn write_range(&mut self, chain: &[u32], offset: u64, buf: &[u8]) -> ExfatResult<()> {
        let cb = self.geo.cluster_bytes();
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let ci = (pos / cb) as usize;
            let within = pos % cb;
            let n = ((cb - within) as usize).min(buf.len() - done);
            let cluster = *chain
                .get(ci)
                .ok_or(ExfatError::Invalid("write past chain"))?;
            let off = self.geo.cluster_offset(cluster)? + within;
            self.disk.write_at(off, &buf[done..done + n])?;
            done += n;
        }
        Ok(())
    }

    fn zero_range(&mut self, chain: &[u32], offset: u64, len: u64) -> ExfatResult<()> {
        let zero = vec![0u8; self.geo.cluster_bytes() as usize];
        let mut done = 0u64;
        while done < len {
            let pos = offset + done;
            let cb = self.geo.cluster_bytes();
            let within = pos % cb;
            let n = (cb - within).min(len - done);
            let ci = (pos / cb) as usize;
            let cluster = *chain
                .get(ci)
                .ok_or(ExfatError::Invalid("zero past chain"))?;
            let off = self.geo.cluster_offset(cluster)? + within;
            self.disk.write_at(off, &zero[..n as usize])?;
            done += n;
        }
        Ok(())
    }

    /// Truncate a file to `len` (grow with zeros or shrink, freeing clusters).
    pub fn truncate_file(&mut self, path: &str, len: u64) -> ExfatResult<()> {
        let (parent, leaf) = self.resolve_parent(path)?;
        let up = self.upcase_clone();
        let entry = locate(&mut self.disk, &self.geo, &up, parent.first_cluster, leaf)?
            .ok_or(ExfatError::NotFound)?;
        if entry.is_dir {
            return Err(ExfatError::Invalid("truncate a directory"));
        }
        let cb = self.geo.cluster_bytes();
        if len > entry.data_len {
            // Extend via a zero-fill write of the final byte region.
            if len > 0 {
                let pad = len - entry.data_len;
                let filler = vec![0u8; pad.min(cb) as usize];
                // write_file handles allocation + gap zeroing.
                self.write_file(path, len - filler.len() as u64, &filler)?;
            }
            return Ok(());
        }
        // Shrink: keep the clusters we still need, free the rest.
        let keep = len.div_ceil(cb);
        let old = entry.data_len.div_ceil(cb);
        let bm = self.bitmap()?;
        if old > 0 {
            let chain =
                crate::fat::read_chain(&mut self.disk, &self.geo, entry.first_cluster, Some(old))?;
            if keep == 0 {
                alloc::free_chain(
                    &mut self.disk,
                    &self.geo,
                    &bm,
                    entry.first_cluster,
                    Some(old),
                )?;
                self.rewrite_stream(&entry, 0, 0, 0, 0x00)?;
            } else {
                // New tail ends the chain; free the suffix.
                alloc::set_fat(
                    &mut self.disk,
                    &self.geo,
                    chain[keep as usize - 1],
                    crate::fat::END_OF_CHAIN,
                )?;
                for &c in &chain[keep as usize..] {
                    // free suffix cluster by cluster
                    alloc::free_chain(&mut self.disk, &self.geo, &bm, c, Some(1))?;
                }
                self.rewrite_stream(&entry, entry.first_cluster, len, len, 0x01)?;
            }
            self.disk.flush()?;
        }
        Ok(())
    }

    /// Remove a file or empty directory at `path`.
    pub fn remove(&mut self, path: &str) -> ExfatResult<()> {
        let (parent, leaf) = self.resolve_parent(path)?;
        let up = self.upcase_clone();
        let entry = locate(&mut self.disk, &self.geo, &up, parent.first_cluster, leaf)?
            .ok_or(ExfatError::NotFound)?;
        if entry.is_dir {
            // Refuse non-empty directories.
            let kids = dir::read_directory(
                &mut self.disk,
                &self.geo,
                entry.first_cluster,
                false,
                u64::MAX,
            )?;
            if !kids.is_empty() {
                return Err(ExfatError::Invalid("directory not empty"));
            }
        }
        // Clear in-use bit on every entry in the set.
        for off in &entry.offsets {
            let mut raw = read_slot(&mut self.disk, *off)?;
            raw[0] &= 0x7F;
            self.disk.write_at(*off, &raw)?;
        }
        self.disk.flush()?;
        // Free the data clusters.
        if entry.first_cluster >= 2 {
            let bm = self.bitmap()?;
            alloc::free_chain(&mut self.disk, &self.geo, &bm, entry.first_cluster, None)?;
            self.disk.flush()?;
        }
        Ok(())
    }
}
