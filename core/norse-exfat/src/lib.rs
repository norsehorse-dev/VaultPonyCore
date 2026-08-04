//! norse-exfat — our exFAT implementation (planning doc §7).
//!
//! Read side (P2): boot region with VBR checksum, FAT chain walking,
//! up-case table (decompressed), directory entry sets with secondary
//! entries and set checksums, NoFatChain contiguous files, and
//! ValidDataLength semantics.
//!
//! Write side (P5, `write.rs`/`alloc.rs`): allocation bitmap + FAT-chained
//! allocation (everything we write is NoFatChain = 0 for uniformity),
//! entry-set creation with checksums and NameHash, directory growth,
//! file write/truncate, rename, and delete, all under the alloc→data→
//! flush→entry→flush ordering discipline. Verified against the exfat-fuse
//! reference driver by a 10k-op differential fuzz (vc-fs) and a
//! write-prefix reader-safety harness (`tests/powerloss.rs`).
//!
//! Crate evaluation (doc §7 said evaluate before owning; verdict recorded
//! here as promised): as of Aug 2026 the crates.io field — `exfat` 0.1,
//! `exfat-fs` 0.1, `exfat-slim`/`embedded-exfat` (embedded, own I/O
//! models), `lamexfat`/`fat-core` (read-only, forensic/no_std focus) — is
//! uniformly pre-1.0, none with a maintained write story, none matching
//! our BlockDevice model. Since P5 write must be ours regardless and read
//! structures are its foundation, we own the read side too.
//!
//! This crate is deliberately standalone: no dependency on the rest of the
//! workspace beyond `log`. The `ReadAt` trait below is its entire I/O
//! surface; `vc-fs` adapts it to the decrypted block device.

pub mod alloc;
pub mod boot;
pub mod dir;
pub mod fat;
pub mod format;
pub mod upcase;
pub mod write;

use std::io;

/// The crate's I/O surface: positioned reads over the volume image.
pub trait ReadAt {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
    fn len(&mut self) -> io::Result<u64>;
    fn is_empty(&mut self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }
}

/// Positioned writes, for the write side (P5). `flush` is a real durability
/// barrier — the ordering discipline in `write.rs` depends on it.
pub trait WriteAt: ReadAt {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}

#[derive(Debug)]
pub enum ExfatError {
    /// Not an exFAT volume, or a structurally invalid one. The string names
    /// what failed — surfaced to users only through vc-fs's error mapping.
    Invalid(&'static str),
    /// Path lookup failed.
    NotFound,
    Io(io::Error),
}

impl std::fmt::Display for ExfatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExfatError::Invalid(what) => write!(f, "invalid exFAT volume: {what}"),
            ExfatError::NotFound => write!(f, "not found"),
            ExfatError::Io(e) => write!(f, "I/O: {e}"),
        }
    }
}

impl std::error::Error for ExfatError {}

impl From<io::Error> for ExfatError {
    fn from(e: io::Error) -> Self {
        ExfatError::Io(e)
    }
}

pub type ExfatResult<T> = Result<T, ExfatError>;

/// A directory entry as the read API reports it.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    /// DataLength — the allocated logical size.
    pub size: u64,
    /// ValidDataLength — bytes actually written; the tail up to `size`
    /// reads as zeros (exFAT's pre-allocation feature).
    pub valid_size: u64,
    pub first_cluster: u32,
    /// GeneralSecondaryFlags bit 1: contiguous, no FAT chain.
    pub no_fat_chain: bool,
    /// Last-modified as Unix millis (UTC if the volume recorded an offset,
    /// else as-stored).
    pub mtime_ms: Option<i64>,
}

/// Location of the allocation bitmap (from its root system entry).
#[derive(Debug, Clone, Copy)]
pub(crate) struct BitmapLoc {
    pub first_cluster: u32,
    pub length_bytes: u64,
}

pub struct ExfatFs<D: ReadAt> {
    disk: D,
    pub(crate) geo: boot::Geometry,
    upcase: upcase::UpcaseTable,
    pub(crate) bitmap: Option<BitmapLoc>,
}

impl<D: ReadAt> ExfatFs<D> {
    pub fn open(mut disk: D) -> ExfatResult<Self> {
        let geo = boot::read_boot_region(&mut disk)?;
        // Locate the up-case table from the root directory's system entries.
        let mut fs = Self {
            disk,
            geo,
            upcase: upcase::UpcaseTable::identity(),
            bitmap: None,
        };
        if let Some((first_cluster, data_len)) = fs.find_upcase_entry()? {
            fs.upcase = upcase::UpcaseTable::load(&mut fs.disk, &fs.geo, first_cluster, data_len)?;
        }
        fs.bitmap = fs.find_bitmap_entry()?;
        Ok(fs)
    }

    fn find_bitmap_entry(&mut self) -> ExfatResult<Option<BitmapLoc>> {
        let root = self.geo.root_first_cluster;
        let mut found = None;
        dir::walk_raw_entries(&mut self.disk, &self.geo, root, false, u64::MAX, |raw| {
            // First allocation bitmap only (bit 0 of flags clear = bitmap #1).
            if raw[0] == dir::ENTRY_BITMAP && raw[1] & 0x01 == 0 {
                let first = u32::from_le_bytes(raw[20..24].try_into().unwrap());
                let len = u64::from_le_bytes(raw[24..32].try_into().unwrap());
                found = Some(BitmapLoc {
                    first_cluster: first,
                    length_bytes: len,
                });
                return Ok(false);
            }
            Ok(true)
        })?;
        Ok(found)
    }

    fn find_upcase_entry(&mut self) -> ExfatResult<Option<(u32, u64)>> {
        let root = self.geo.root_first_cluster;
        let mut found = None;
        dir::walk_raw_entries(&mut self.disk, &self.geo, root, false, u64::MAX, |raw| {
            if raw[0] == dir::ENTRY_UPCASE {
                let first = u32::from_le_bytes(raw[20..24].try_into().unwrap());
                let len = u64::from_le_bytes(raw[24..32].try_into().unwrap());
                found = Some((first, len));
                return Ok(false);
            }
            Ok(true)
        })?;
        Ok(found)
    }

    /// List a directory given its stream facts (root: `root_dir()`).
    pub fn list_dir(
        &mut self,
        first_cluster: u32,
        no_fat_chain: bool,
        data_len: u64,
    ) -> ExfatResult<Vec<Entry>> {
        dir::read_directory(
            &mut self.disk,
            &self.geo,
            first_cluster,
            no_fat_chain,
            data_len,
        )
    }

    /// The root directory's stream facts.
    pub fn root_dir(&self) -> (u32, bool, u64) {
        (self.geo.root_first_cluster, false, u64::MAX)
    }

    /// Resolve a `/`-separated path (case-insensitive per the volume's
    /// up-case table) to its entry. Empty or "/" resolves to None (root).
    pub fn lookup(&mut self, path: &str) -> ExfatResult<Option<Entry>> {
        let mut cur: Option<Entry> = None;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let (fc, nfc, len) = match &cur {
                None => self.root_dir(),
                Some(e) if e.is_dir => (e.first_cluster, e.no_fat_chain, e.size),
                Some(_) => return Err(ExfatError::NotFound),
            };
            let entries = self.list_dir(fc, nfc, len)?;
            let want: Vec<u16> = comp.encode_utf16().map(|u| self.upcase.map(u)).collect();
            cur = Some(
                entries
                    .into_iter()
                    .find(|e| {
                        let have: Vec<u16> =
                            e.name.encode_utf16().map(|u| self.upcase.map(u)).collect();
                        have == want
                    })
                    .ok_or(ExfatError::NotFound)?,
            );
        }
        Ok(cur)
    }

    /// Read from a file described by `entry` at `offset`; returns bytes
    /// read (short only at end of file). The region between ValidDataLength
    /// and DataLength reads as zeros.
    pub fn read_file(&mut self, entry: &Entry, offset: u64, buf: &mut [u8]) -> ExfatResult<usize> {
        if entry.is_dir {
            return Err(ExfatError::Invalid("read_file on a directory"));
        }
        if offset >= entry.size {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(entry.size - offset) as usize;
        let cluster_bytes = self.geo.cluster_bytes();
        let mut done = 0usize;

        // Resolve the chain once per call; NoFatChain files are arithmetic.
        let chain: Option<Vec<u32>> = if entry.no_fat_chain {
            None
        } else {
            Some(fat::read_chain(
                &mut self.disk,
                &self.geo,
                entry.first_cluster,
                Some(entry.size.div_ceil(cluster_bytes)),
            )?)
        };

        while done < want {
            let pos = offset + done as u64;
            let cluster_idx = pos / cluster_bytes;
            let within = pos % cluster_bytes;
            let n = ((cluster_bytes - within) as usize).min(want - done);

            if pos >= entry.valid_size {
                // Pre-allocated tail: zeros by definition.
                buf[done..done + n].fill(0);
                done += n;
                continue;
            }
            let n_valid = n.min((entry.valid_size - pos) as usize);

            let cluster = match &chain {
                None => entry.first_cluster + cluster_idx as u32,
                Some(c) => *c
                    .get(cluster_idx as usize)
                    .ok_or(ExfatError::Invalid("cluster chain shorter than file"))?,
            };
            let disk_off = self.geo.cluster_offset(cluster)? + within;
            self.disk
                .read_at(disk_off, &mut buf[done..done + n_valid])?;
            if n_valid < n {
                buf[done + n_valid..done + n].fill(0);
            }
            done += n;
        }
        Ok(done)
    }
}
