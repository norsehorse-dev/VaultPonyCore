//! VFS trait and filesystem adapters (planning doc §5, §7).
//!
//! Adapters: `fatfs` (FAT12/16/32 RW), `norse-exfat` (ours; read first,
//! write as its own release), `ntfs` crate (RO). Every adapter's results are
//! parity-tested against a desktop loop-mount of the same fixture (§7).

pub mod detect;
pub mod exfat;
pub mod fat;
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
/// (doc §4: "this container holds ext4" beats a generic failure).
pub fn open_volume(mut dev: Box<dyn vc_io::BlockDevice>) -> VcResult<Box<dyn Vfs>> {
    let mut boot = [0u8; 4096];
    dev.read_at(0, &mut boot)?;
    match detect::sniff(&boot) {
        FsKind::Fat => Ok(Box::new(fat::FatVfs::open(io::DeviceIo::new(dev)?)?)),
        FsKind::Exfat => Ok(Box::new(exfat::ExfatVfs::open(dev)?)),
        FsKind::Ntfs => Ok(Box::new(ntfs_ro::NtfsVfs::open(dev)?)),
        FsKind::Ext4 => Err(VcError::UnsupportedFilesystem("ext4".into())),
        FsKind::Unknown => Err(VcError::UnknownFilesystem),
    }
}
