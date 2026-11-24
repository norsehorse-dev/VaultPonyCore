//! VFS trait and filesystem adapters (planning doc §5, §7).
//!
//! Adapters: `fatfs` (FAT12/16/32 RW), `norse-exfat` (ours; read first,
//! write as its own release), `ntfs` crate (RO). Every adapter's results are
//! parity-tested against a desktop loop-mount of the same fixture (§7).

pub mod detect;
pub mod exfat;
pub mod ext4;
pub mod fat;
pub mod fat_repair;
pub mod io;
pub mod ntfs_ro;

use vc_types::{VcError, VcResult};

/// Kinds of filesystem we can identify inside a container, supported or not.
/// Unsupported ones are *named* to the user, never a generic failure (§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    Fat,
    Exfat,
    Ntfs,
    Ext4,
    Unknown,
}

/// Directory entry metadata, minimal on purpose — grow as the shells need.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// Modification time as Unix millis, if the FS records one.
    pub mtime_ms: Option<i64>,
}

/// Size and free space of a mounted filesystem, in bytes of file data the
/// volume can hold (cluster heap only; boot sectors, FATs, and the exFAT
/// bitmap are not counted as either).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsSpace {
    pub total_bytes: u64,
    pub free_bytes: u64,
    /// Allocation unit. A file occupies whole clusters, so pre-flight checks
    /// round each file up to this.
    pub cluster_bytes: u64,
}

impl FsSpace {
    /// Bytes `len` bytes of file content actually take on disk.
    pub fn on_disk(&self, len: u64) -> u64 {
        if self.cluster_bytes == 0 {
            return len;
        }
        len.div_ceil(self.cluster_bytes) * self.cluster_bytes
    }
}

/// FAT's per-file ceiling: the directory entry's size field is 32 bits.
pub const FAT_MAX_FILE_BYTES: u64 = u32::MAX as u64;

/// The VFS every shell talks to (§5): list/stat/open/read/write/rename/
/// mkdir/unlink/truncate/flush. Paths are `/`-separated, relative to the
/// volume root, and always UTF-8 (adapters handle FS-native encodings).
pub trait Vfs: Send {
    fn kind(&self) -> FsKind;
    /// Whether this adapter supports writes (NTFS: no; exFAT: not until P5).
    fn writable(&self) -> bool;

    fn list(&mut self, path: &str) -> VcResult<Vec<DirEntry>>;
    fn stat(&mut self, path: &str) -> VcResult<DirEntry>;

    /// Random-access read; returns bytes read (short only at EOF).
    fn read_at(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> VcResult<usize>;

    fn write_at(&mut self, path: &str, offset: u64, buf: &[u8]) -> VcResult<usize>;
    fn create(&mut self, path: &str) -> VcResult<()>;
    fn mkdir(&mut self, path: &str) -> VcResult<()>;
    fn rename(&mut self, from: &str, to: &str) -> VcResult<()>;
    fn unlink(&mut self, path: &str) -> VcResult<()>;
    fn truncate(&mut self, path: &str, len: u64) -> VcResult<()>;
    fn flush(&mut self) -> VcResult<()>;

    /// About to be dropped because another process changed the volume: drop
    /// without writing any cached metadata back (FAT: FSInfo, dirty flag).
    fn release_without_writing(&mut self) {}

    /// What the mount-time repair of an old FAT32 top folder did, handed
    /// over once (see [`fat_repair`]). None when nothing was repaired.
    fn take_repair_report(&mut self) -> Option<fat_repair::RepairReport> {
        None
    }

    /// Put the file at `src` in place of `dst`, replacing `dst` if it exists.
    /// A case-only change of the same name is a rename, for folders too.
    /// Used to land a fully written temporary file over the original, so a
    /// writer killed mid-copy leaves the original intact. FAT and exFAT have
    /// no atomic rename-over, so the default removes `dst` and then renames:
    /// a kill between the two leaves `src` complete and `dst` missing, which
    /// the caller's recovery (rename the leftover temp file in) repairs.
    /// Both paths must be in the same directory or the caller must accept a
    /// move. Flushes before returning.
    fn replace(&mut self, src: &str, dst: &str) -> VcResult<()> {
        let src_entry = self.stat(src)?;
        // The same entry (FAT and exFAT names ignore case): never delete it,
        // that would delete the source. A case-only change is a rename.
        let (sp, sn) = split_parent(src);
        let (dp, dn) = split_parent(dst);
        if sp == dp && sn.to_lowercase() == dn.to_lowercase() {
            if sn != dn {
                // fatfs treats a case-only rename as a no-op, so go through
                // a temporary name.
                let parent = if sp == "/" {
                    String::new()
                } else {
                    src[..src.len() - sn.len() - 1].to_string()
                };
                let tmp = format!("{parent}/.vaultpony-case-{}.tmp", std::process::id());
                self.rename(src, &tmp)?;
                self.rename(&tmp, dst)?;
            }
            return self.flush();
        }
        if src_entry.is_dir {
            return Err(VcError::Filesystem("replace: source is a directory".into()));
        }
        match self.stat(dst) {
            Ok(d) if d.is_dir => {
                return Err(VcError::Filesystem(
                    "replace: destination is a directory".into(),
                ))
            }
            Ok(_) => {
                self.unlink(dst)?;
                self.flush()?;
            }
            Err(_) => {}
        }
        self.rename(src, dst)?;
        self.flush()
    }

    /// Total and free space. Adapters that can't say (NTFS, read-only)
    /// keep the default refusal and the shells hide the figure.
    fn space(&mut self) -> VcResult<FsSpace> {
        Err(VcError::Filesystem(
            "free space is not available for this filesystem".into(),
        ))
    }

    /// Largest single file the filesystem can hold, if it has a limit
    /// below anything a container could reach (FAT: 4 GiB - 1).
    fn max_file_bytes(&self) -> Option<u64> {
        None
    }
}

/// "/a/b" -> ("/a", "b"), with the parent normalized ("" and "/" are root).
fn split_parent(path: &str) -> (String, &str) {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(i) => {
            let parent = trimmed[..i].trim_end_matches('/');
            (
                if parent.is_empty() {
                    "/".to_string()
                } else {
                    parent.to_lowercase()
                },
                &trimmed[i + 1..],
            )
        }
        None => ("/".to_string(), trimmed),
    }
}

/// Format a fresh FAT filesystem across a decrypted device (new-container
/// creation, doc §7). Re-exported from the FAT adapter.
pub fn format_fat(dev: Box<dyn vc_io::BlockDevice>) -> VcResult<()> {
    fat::format(dev)
}

/// Format a fresh exFAT filesystem across a decrypted device — the large-file
/// alternative to FAT (no 4 GiB per-file limit). `serial` is a random volume
/// id supplied by the caller.
pub fn format_exfat(dev: Box<dyn vc_io::BlockDevice>, serial: u32) -> VcResult<()> {
    exfat::format(dev, serial)
}

/// Open the right adapter for the decrypted volume, or a *named* refusal
/// (doc §4: naming what the container holds beats a generic failure).
pub fn open_volume(mut dev: Box<dyn vc_io::BlockDevice>) -> VcResult<Box<dyn Vfs>> {
    let mut boot = [0u8; 4096];
    dev.read_at(0, &mut boot)?;
    match detect::sniff(&boot) {
        FsKind::Fat => {
            let repair = fat_repair::repair_root(dev.as_mut());
            let mut vfs = fat::FatVfs::open(io::DeviceIo::new(dev)?)?;
            vfs.set_repair_report(repair);
            Ok(Box::new(vfs))
        }
        FsKind::Exfat => Ok(Box::new(exfat::ExfatVfs::open(dev)?)),
        FsKind::Ntfs => Ok(Box::new(ntfs_ro::NtfsVfs::open(dev)?)),
        FsKind::Ext4 => Ok(Box::new(ext4::Ext4Vfs::open(dev)?)),
        FsKind::Unknown => Err(VcError::UnknownFilesystem),
    }
}
