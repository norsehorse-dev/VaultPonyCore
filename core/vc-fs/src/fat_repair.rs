//! Repair for a FAT32 top folder damaged by releases up to 2.0.0.
//!
//! Those releases did not zero a new cluster of the FAT32 root directory
//! (third_party/fatfs/VAULTPONY.md, 6). Inside a container the uncleared
//! cluster is noise, so a top folder that grew past its first cluster
//! listed junk files and folders among the real ones.
//!
//! This runs on the decrypted block device before the filesystem mounts,
//! and only writes two things, both inside the root directory's own
//! clusters:
//!
//! 1. zeros over everything after the first end-of-directory mark, an area
//!    no reader looks at but which would surface as more junk the next time
//!    an entry is added;
//! 2. the deleted mark (0xE5) on each junk entry before it.
//!
//! No entry moves and no cluster is freed. An entry is junk only when it
//! breaks a rule no FAT writer breaks (see [`is_junk`]); anything else is
//! left alone. Each write stands alone, so a cut at any point leaves a valid
//! directory with less junk, and the next mount finishes the job.
//!
//! When a repair was made, the whole tree is then walked once to find files
//! whose cluster chains no longer hold: deleting a junk entry under an old
//! release could free clusters a real file was using. Those are reported,
//! never changed.

use std::collections::{HashMap, HashSet};
use vc_io::BlockDevice;
use vc_types::{VcError, VcResult};

const ENTRY: usize = 32;
const DELETED: u8 = 0xE5;
const ATTR_VOLUME: u8 = 0x08;
const ATTR_DIR: u8 = 0x10;
const ATTR_LFN: u8 = 0x0F;
const FAT_BAD: u32 = 0x0FFF_FFF7;
const FAT_END: u32 = 0x0FFF_FFF8;
const FAT_BLOCK: u64 = 4096;
/// The most damaged paths a report names; the total is counted regardless.
const MAX_REPORTED: usize = 50;
const MAX_DEPTH: usize = 64;
/// A directory larger than this is not read (nor repaired).
const MAX_DIR_BYTES: u64 = 256 << 20;

/// What a repair did and found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepairReport {
    /// Junk directory entries removed from the top folder.
    pub junk_entries: u64,
    /// Paths of files and folders whose cluster chain is broken, at most
    /// [`MAX_REPORTED`] of them. A folder's path ends in `/`.
    pub damaged: Vec<String>,
    /// How many were found in all.
    pub damaged_total: u64,
}

struct Geometry {
    cluster_bytes: u64,
    fat_offset: u64,
    data_offset: u64,
    max_cluster: u32,
    root_cluster: u32,
}

fn le16(b: &[u8], at: usize) -> u32 {
    u16::from_le_bytes([b[at], b[at + 1]]) as u32
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// The FAT32 layout from the boot sector, or None for anything else.
fn geometry(dev: &mut dyn BlockDevice) -> VcResult<Option<Geometry>> {
    if dev.len()? < 512 {
        return Ok(None);
    }
    let mut b = [0u8; 512];
    dev.read_at(0, &mut b)?;
    if b[510] != 0x55 || b[511] != 0xAA {
        return Ok(None);
    }
    let sector = le16(&b, 11) as u64;
    let per_cluster = b[13] as u64;
    let reserved = le16(&b, 14) as u64;
    let fats = b[16] as u64;
    let root_entries = le16(&b, 17);
    let total16 = le16(&b, 19) as u64;
    let fat_size16 = le16(&b, 22);
    let total32 = le32(&b, 32) as u64;
    let fat_size32 = le32(&b, 36) as u64;
    let ext_flags = le16(&b, 40);
    let root_cluster = le32(&b, 44);
    if !(512..=4096).contains(&sector) || !sector.is_power_of_two() {
        return Ok(None);
    }
    if per_cluster == 0 || !per_cluster.is_power_of_two() || fats == 0 {
        return Ok(None);
    }
    // FAT12/16 keep the root in a fixed area, which never grows.
    if root_entries != 0 || fat_size16 != 0 || fat_size32 == 0 {
        return Ok(None);
    }
    let total = if total16 != 0 { total16 } else { total32 };
    let first_data = reserved + fats * fat_size32;
    if total <= first_data {
        return Ok(None);
    }
    let clusters = (total - first_data) / per_cluster;
    if !(65_525..=0x0FFF_FFF5).contains(&clusters) {
        return Ok(None);
    }
    // Mirroring off: only the FAT named in the flags is current.
    let active = if ext_flags & 0x80 != 0 {
        (ext_flags & 0x0F) as u64
    } else {
        0
    };
    if active >= fats {
        return Ok(None);
    }
    let max_cluster = clusters as u32 + 1;
    if root_cluster < 2 || root_cluster > max_cluster {
        return Ok(None);
    }
    if total * sector > dev.len()? {
        return Ok(None);
    }
    Ok(Some(Geometry {
        cluster_bytes: per_cluster * sector,
        fat_offset: (reserved + active * fat_size32) * sector,
        data_offset: first_data * sector,
        max_cluster,
        root_cluster,
    }))
}

struct Volume<'a> {
    dev: &'a mut dyn BlockDevice,
    geo: Geometry,
    fat_cache: HashMap<u64, Vec<u8>>,
}

impl Volume<'_> {
    fn fat(&mut self, cluster: u32) -> VcResult<u32> {
        let at = cluster as u64 * 4;
        let block = at / FAT_BLOCK;
        if !self.fat_cache.contains_key(&block) {
            let mut buf = vec![0u8; FAT_BLOCK as usize];
            let start = self.geo.fat_offset + block * FAT_BLOCK;
            // The FAT may end inside the last block.
            let end = (self.geo.max_cluster as u64 + 1) * 4;
            let n = FAT_BLOCK.min(end - block * FAT_BLOCK) as usize;
            self.dev.read_at(start, &mut buf[..n])?;
            self.fat_cache.insert(block, buf);
        }
        let buf = &self.fat_cache[&block];
        Ok(le32(buf, (at % FAT_BLOCK) as usize) & 0x0FFF_FFFF)
    }

    fn cluster_offset(&self, cluster: u32) -> u64 {
        self.geo.data_offset + (cluster as u64 - 2) * self.geo.cluster_bytes
    }

    /// Follow a chain from `first`. Returns how many clusters it has and
    /// whether it is sound: every cluster inside the volume and in use, an
    /// end mark at the end, no loop, and (with `seen`) no cluster that
    /// another chain already holds. `collect` receives the clusters.
    fn chain(
        &mut self,
        first: u32,
        mut seen: Option<&mut Vec<u8>>,
        mut collect: Option<&mut Vec<u32>>,
    ) -> VcResult<(u64, bool)> {
        let mut count = 0u64;
        let mut sound = true;
        let mut cluster = first;
        loop {
            if cluster < 2 || cluster > self.geo.max_cluster {
                return Ok((count, false));
            }
            let next = self.fat(cluster)?;
            if next == 0 || next == FAT_BAD {
                return Ok((count, false));
            }
            if let Some(bits) = seen.as_deref_mut() {
                let (byte, bit) = ((cluster / 8) as usize, 1u8 << (cluster % 8));
                if bits[byte] & bit != 0 {
                    // Shared with another chain, or a loop.
                    return Ok((count, false));
                }
                bits[byte] |= bit;
            }
            count += 1;
            if let Some(out) = collect.as_deref_mut() {
                out.push(cluster);
            }
            if count > self.geo.max_cluster as u64 {
                sound = false;
            }
            if next >= FAT_END || !sound {
                return Ok((count, sound));
            }
            cluster = next;
        }
    }

    fn read_clusters(&mut self, chain: &[u32]) -> VcResult<Vec<u8>> {
        let cb = self.geo.cluster_bytes as usize;
        let mut out = vec![0u8; chain.len() * cb];
        for (i, &c) in chain.iter().enumerate() {
            let at = self.cluster_offset(c);
            self.dev.read_at(at, &mut out[i * cb..(i + 1) * cb])?;
        }
        Ok(out)
    }
}

struct Item {
    name: String,
    is_dir: bool,
    first: u32,
    size: u32,
}

struct Parsed {
    items: Vec<Item>,
    /// Indexes of junk entries (short entries that break a hard rule, and
    /// long-name records that belong to no real entry).
    junk: Vec<usize>,
    /// Index of the first end-of-directory mark, or the entry count.
    end: usize,
}

fn first_cluster(e: &[u8]) -> u32 {
    (le16(e, 20) << 16) | le16(e, 26)
}

/// True when a short entry breaks a rule every FAT writer keeps, so it can
/// only be noise:
/// - a reserved attribute bit is set;
/// - it is a volume label that is also a folder, or has clusters or a size;
/// - its first cluster is outside the volume;
/// - it has a size but no cluster, or is a folder with a size or no cluster;
/// - its 8.3 name starts with a space, or holds a control character or one
///   FAT forbids in a short name.
fn is_junk(e: &[u8], max_cluster: u32) -> bool {
    let attr = e[11];
    if attr & 0xC0 != 0 {
        return true;
    }
    let first = first_cluster(e);
    let size = le32(e, 28);
    if attr & ATTR_VOLUME != 0 {
        return attr & ATTR_DIR != 0 || first != 0 || size != 0;
    }
    if first == 1 || first > max_cluster {
        return true;
    }
    let is_dir = attr & ATTR_DIR != 0;
    if is_dir && (size != 0 || first == 0) {
        return true;
    }
    if !is_dir && size != 0 && first == 0 {
        return true;
    }
    let name = &e[0..11];
    if name[0] == b' ' {
        return true;
    }
    for (i, &b) in name.iter().enumerate() {
        // 0x05 in the first byte stands for a real 0xE5.
        if b < 0x20 && !(i == 0 && b == 0x05) {
            return true;
        }
        if matches!(
            b,
            b'"' | b'*'
                | b'+'
                | b','
                | b'.'
                | b'/'
                | b':'
                | b';'
                | b'<'
                | b'='
                | b'>'
                | b'?'
                | b'['
                | b'\\'
                | b']'
                | b'|'
                | 0x7F
        ) {
            return true;
        }
    }
    false
}

fn lfn_checksum(short: &[u8]) -> u8 {
    short[..11].iter().fold(0u8, |sum, &b| {
        (sum >> 1).wrapping_add((sum & 1) << 7).wrapping_add(b)
    })
}

/// The long name a run of records gives the short entry `short`, or None
/// when the run is not a well-formed set for it.
fn long_name(run: &[&[u8]], short: &[u8]) -> Option<String> {
    let first = run.first()?;
    let count = (first[0] & 0x3F) as usize;
    if first[0] & 0x40 == 0 || count == 0 || count != run.len() {
        return None;
    }
    let sum = lfn_checksum(short);
    let mut units: Vec<u16> = Vec::with_capacity(count * 13);
    for (k, rec) in run.iter().enumerate() {
        let order = rec[0];
        if (order & 0x3F) as usize != count - k || (k > 0 && order & 0x40 != 0) {
            return None;
        }
        if rec[11] != ATTR_LFN || rec[12] != 0 || rec[13] != sum || le16(rec, 26) != 0 {
            return None;
        }
    }
    // Records are stored last part first.
    for rec in run.iter().rev() {
        for at in [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30] {
            units.push(u16::from_le_bytes([rec[at], rec[at + 1]]));
        }
    }
    let len = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    if len == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&units[..len]))
}

fn short_name(e: &[u8]) -> String {
    let piece = |bytes: &[u8], lower: bool| -> String {
        let end = bytes.iter().rposition(|&b| b != b' ').map_or(0, |p| p + 1);
        bytes[..end]
            .iter()
            .map(|&b| match b {
                b if b.is_ascii() && lower => b.to_ascii_lowercase() as char,
                b if b.is_ascii() => b as char,
                _ => '\u{FFFD}',
            })
            .collect()
    };
    let mut base_bytes = [0u8; 8];
    base_bytes.copy_from_slice(&e[0..8]);
    if base_bytes[0] == 0x05 {
        base_bytes[0] = 0xE5;
    }
    let base = piece(&base_bytes, e[12] & 0x08 != 0);
    let ext = piece(&e[8..11], e[12] & 0x10 != 0);
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

/// Read a directory's entries up to its end mark, sorting them into real
/// items and junk. A long-name record that belongs to no real entry counts
/// as junk; every reader ignores such a record anyway.
fn parse(bytes: &[u8], max_cluster: u32) -> Parsed {
    let count = bytes.len() / ENTRY;
    let mut items = Vec::new();
    let mut junk = Vec::new();
    let mut run: Vec<usize> = Vec::new();
    let mut end = count;
    for i in 0..count {
        let e = &bytes[i * ENTRY..(i + 1) * ENTRY];
        if e[0] == 0x00 {
            end = i;
            break;
        }
        if e[0] == DELETED {
            junk.append(&mut run);
            continue;
        }
        if e[11] & 0x3F == ATTR_LFN {
            if e[11] & 0xC0 != 0 {
                junk.append(&mut run);
                junk.push(i);
            } else {
                run.push(i);
            }
            continue;
        }
        if is_junk(e, max_cluster) {
            junk.append(&mut run);
            junk.push(i);
            continue;
        }
        let records: Vec<&[u8]> = run
            .iter()
            .map(|&r| &bytes[r * ENTRY..(r + 1) * ENTRY])
            .collect();
        let long = long_name(&records, e);
        if long.is_none() {
            junk.append(&mut run);
        }
        run.clear();
        if e[11] & ATTR_VOLUME != 0 {
            continue;
        }
        items.push(Item {
            name: long.unwrap_or_else(|| short_name(e)),
            is_dir: e[11] & ATTR_DIR != 0,
            first: first_cluster(e),
            size: le32(e, 28),
        });
    }
    junk.append(&mut run);
    junk.sort_unstable();
    Parsed { items, junk, end }
}

/// True when a folder's first cluster opens with its own `.` entry, which is
/// how every subfolder starts.
fn starts_with_dot(bytes: &[u8], own_cluster: u32) -> bool {
    bytes.len() >= ENTRY
        && &bytes[0..11] == b".          "
        && bytes[11] & ATTR_DIR != 0
        && first_cluster(&bytes[..ENTRY]) == own_cluster
}

struct Walk {
    seen: Vec<u8>,
    dirs: HashSet<u32>,
    damaged: Vec<String>,
    total: u64,
}

impl Walk {
    fn note(&mut self, path: String) {
        self.total += 1;
        if self.damaged.len() < MAX_REPORTED {
            self.damaged.push(path);
        }
    }
}

fn walk(
    vol: &mut Volume<'_>,
    bytes: &[u8],
    path: &str,
    depth: usize,
    w: &mut Walk,
) -> VcResult<()> {
    let parsed = parse(bytes, vol.geo.max_cluster);
    for item in parsed.items {
        let here = format!("{path}/{}", item.name);
        if !item.is_dir {
            if item.size == 0 && item.first == 0 {
                continue;
            }
            let need = (item.size as u64).div_ceil(vol.geo.cluster_bytes);
            let (count, sound) = vol.chain(item.first, Some(&mut w.seen), None)?;
            if !sound || count < need {
                w.note(here);
            }
            continue;
        }
        if item.name == "." || item.name == ".." {
            continue;
        }
        if depth >= MAX_DEPTH || !w.dirs.insert(item.first) {
            continue;
        }
        let mut chain = Vec::new();
        let (count, sound) = vol.chain(item.first, Some(&mut w.seen), Some(&mut chain))?;
        if count * vol.geo.cluster_bytes > MAX_DIR_BYTES {
            w.note(format!("{here}/"));
            continue;
        }
        let sub = vol.read_clusters(&chain)?;
        if !sound || !starts_with_dot(&sub, item.first) {
            w.note(format!("{here}/"));
            continue;
        }
        walk(vol, &sub, &here, depth + 1, w)?;
    }
    Ok(())
}

fn write_clusters(
    vol: &mut Volume<'_>,
    chain: &[u32],
    bytes: &[u8],
    which: impl Iterator<Item = usize>,
) -> VcResult<()> {
    let cb = vol.geo.cluster_bytes as usize;
    let mut last = usize::MAX;
    for k in which {
        if k == last {
            continue;
        }
        last = k;
        let at = vol.cluster_offset(chain[k]);
        vol.dev.write_at(at, &bytes[k * cb..(k + 1) * cb])?;
    }
    vol.dev.flush()
}

fn try_repair(dev: &mut dyn BlockDevice) -> VcResult<Option<RepairReport>> {
    let Some(geo) = geometry(dev)? else {
        return Ok(None);
    };
    let mut vol = Volume {
        dev,
        geo,
        fat_cache: HashMap::new(),
    };
    let mut seen = vec![0u8; vol.geo.max_cluster as usize / 8 + 1];
    let mut chain = Vec::new();
    let root = vol.geo.root_cluster;
    let (count, sound) = vol.chain(root, Some(&mut seen), Some(&mut chain))?;
    // The damage needs a root that grew past its first cluster. A root whose
    // own chain is broken is not something to write into.
    if !sound || count < 2 || count * vol.geo.cluster_bytes > MAX_DIR_BYTES {
        return Ok(None);
    }
    let mut bytes = vol.read_clusters(&chain)?;
    let parsed = parse(&bytes, vol.geo.max_cluster);
    let tail = parsed.end * ENTRY;
    let tail_dirty = bytes[tail..].iter().any(|&b| b != 0);
    if parsed.junk.is_empty() && !tail_dirty {
        return Ok(None);
    }
    let cb = vol.geo.cluster_bytes as usize;
    // First the area past the end mark, which nothing reads...
    if tail_dirty {
        bytes[tail..].fill(0);
        write_clusters(&mut vol, &chain, &bytes, tail / cb..chain.len())?;
    }
    // ...then the junk in front of it, one deleted mark each.
    if !parsed.junk.is_empty() {
        for &i in &parsed.junk {
            bytes[i * ENTRY] = DELETED;
        }
        write_clusters(
            &mut vol,
            &chain,
            &bytes,
            parsed.junk.iter().map(|&i| i * ENTRY / cb),
        )?;
    }
    let mut w = Walk {
        seen,
        dirs: HashSet::new(),
        damaged: Vec::new(),
        total: 0,
    };
    w.dirs.insert(root);
    walk(&mut vol, &bytes, "", 0, &mut w)?;
    Ok(Some(RepairReport {
        junk_entries: parsed.junk.len() as u64,
        damaged: w.damaged,
        damaged_total: w.total,
    }))
}

/// Repair the top folder of the FAT32 volume on `dev` if it carries the old
/// damage. None when there was nothing to do, the volume is not FAT32, or
/// the device could not be written (a read-only vault is left as it is).
/// Never fails the mount.
pub fn repair_root(dev: &mut dyn BlockDevice) -> Option<RepairReport> {
    match try_repair(dev) {
        Ok(report) => report,
        Err(e) => {
            let kind = match e {
                VcError::Io(_) => "device error",
                _ => "error",
            };
            log::warn!("FAT32 top folder repair skipped: {kind}");
            None
        }
    }
}
