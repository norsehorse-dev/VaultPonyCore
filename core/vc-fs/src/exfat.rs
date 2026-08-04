//! exFAT adapter over norse-exfat (doc §7). Read (P2) and write (P5) —
//! create/write/mkdir/rename/unlink/truncate — behind the Vfs trait.

use crate::{DirEntry, FsKind, Vfs};
use norse_exfat::{Entry, ExfatFs};
use vc_types::{VcError, VcResult};

/// norse-exfat's I/O surface over our block device.
struct DeviceReadAt(Box<dyn vc_io::BlockDevice>);

impl norse_exfat::ReadAt for DeviceReadAt {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.0.read_at(offset, buf).map_err(|e| match e {
            VcError::Io(io) => io,
            other => std::io::Error::other(other.to_string()),
        })
    }

    fn len(&mut self) -> std::io::Result<u64> {
        self.0
            .len()
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

impl norse_exfat::WriteAt for DeviceReadAt {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> std::io::Result<()> {
        self.0.write_at(offset, buf).map_err(|e| match e {
            VcError::Io(io) => io,
            other => std::io::Error::other(other.to_string()),
        })
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .flush()
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

pub struct ExfatVfs {
    fs: ExfatFs<DeviceReadAt>,
}

impl ExfatVfs {
    pub fn open(dev: Box<dyn vc_io::BlockDevice>) -> VcResult<Self> {
        let fs = ExfatFs::open(DeviceReadAt(dev)).map_err(fs_err)?;
        Ok(Self { fs })
    }

    fn resolve(&mut self, path: &str) -> VcResult<Option<Entry>> {
        self.fs.lookup(path).map_err(fs_err)
    }
}

/// Lay a fresh, empty exFAT filesystem across the whole decrypted device.
/// `serial` is the volume id (a random value from the caller). New-container
/// creation only — the device must already be sized (doc §7).
pub fn format(dev: Box<dyn vc_io::BlockDevice>, serial: u32) -> VcResult<()> {
    let mut d = DeviceReadAt(dev);
    let total = norse_exfat::ReadAt::len(&mut d).map_err(VcError::Io)?;
    norse_exfat::format::format(&mut d, total, serial).map_err(fs_err)?;
    norse_exfat::WriteAt::flush(&mut d).map_err(VcError::Io)?;
    Ok(())
}

fn fs_err(e: norse_exfat::ExfatError) -> VcError {
    match e {
        norse_exfat::ExfatError::NotFound => VcError::Filesystem("not found".into()),
        other => VcError::Filesystem(other.to_string()),
    }
}

fn entry_of(e: &Entry) -> DirEntry {
    DirEntry {
        name: e.name.clone(),
        is_dir: e.is_dir,
        size: e.size,
        mtime_ms: e.mtime_ms,
    }
}

impl Vfs for ExfatVfs {
    fn kind(&self) -> FsKind {
        FsKind::Exfat
    }

    fn writable(&self) -> bool {
        true // P5: read + write; whether writes reach disk is the session's call.
    }

    fn list(&mut self, path: &str) -> VcResult<Vec<DirEntry>> {
        let dir = match self.resolve(path)? {
            None => self.fs.root_dir(),
            Some(e) if e.is_dir => (e.first_cluster, e.no_fat_chain, e.size),
            Some(_) => return Err(VcError::Filesystem("not a directory".into())),
        };
        let entries = self.fs.list_dir(dir.0, dir.1, dir.2).map_err(fs_err)?;
        Ok(entries.iter().map(entry_of).collect())
    }

    fn stat(&mut self, path: &str) -> VcResult<DirEntry> {
        match self.resolve(path)? {
            None => Ok(DirEntry {
                name: "/".into(),
                is_dir: true,
                size: 0,
                mtime_ms: None,
            }),
            Some(e) => Ok(entry_of(&e)),
        }
    }

    fn read_at(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> VcResult<usize> {
        let entry = self
            .resolve(path)?
            .ok_or_else(|| VcError::Filesystem("cannot read the root directory".into()))?;
        self.fs.read_file(&entry, offset, buf).map_err(fs_err)
    }

    fn write_at(&mut self, path: &str, offset: u64, buf: &[u8]) -> VcResult<usize> {
        self.fs.write_file(path, offset, buf).map_err(fs_err)
    }

    fn create(&mut self, path: &str) -> VcResult<()> {
        self.fs.create_file(path).map_err(fs_err)
    }

    fn mkdir(&mut self, path: &str) -> VcResult<()> {
        self.fs.make_dir(path).map_err(fs_err)
    }

    fn rename(&mut self, from: &str, to: &str) -> VcResult<()> {
        self.fs.rename(from, to).map_err(fs_err)
    }

    fn unlink(&mut self, path: &str) -> VcResult<()> {
        self.fs.remove(path).map_err(fs_err)
    }

    fn truncate(&mut self, path: &str, len: u64) -> VcResult<()> {
        self.fs.truncate_file(path, len).map_err(fs_err)
    }

    fn flush(&mut self) -> VcResult<()> {
        Ok(())
    }
}
