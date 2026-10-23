//! Read-only wrappers for volumes opened in TrueCrypt mode (plan 6.2).
//!
//! Two layers, so neither the filesystem adapter nor anything below it can
//! change a TrueCrypt container: the device refuses every write (the FAT
//! adapter would otherwise write FSInfo or its dirty bit on its own), and the
//! filesystem reports itself read-only so the shells hide write actions the
//! way they already do for NTFS.

use vc_fs::{DirEntry, FsKind, FsSpace, Vfs};
use vc_io::BlockDevice;
use vc_types::{VcError, VcResult};

pub(crate) struct ReadOnlyDevice(pub Box<dyn BlockDevice>);

impl BlockDevice for ReadOnlyDevice {
    fn len(&mut self) -> VcResult<u64> {
        self.0.len()
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> VcResult<()> {
        self.0.read_at(offset, buf)
    }
    fn write_at(&mut self, _offset: u64, _buf: &[u8]) -> VcResult<()> {
        Err(VcError::TrueCryptReadOnly)
    }
    fn flush(&mut self) -> VcResult<()> {
        Ok(())
    }
}

pub(crate) struct ReadOnlyVfs(pub Box<dyn Vfs>);

impl Vfs for ReadOnlyVfs {
    fn kind(&self) -> FsKind {
        self.0.kind()
    }
    fn writable(&self) -> bool {
        false
    }
    fn list(&mut self, path: &str) -> VcResult<Vec<DirEntry>> {
        self.0.list(path)
    }
    fn stat(&mut self, path: &str) -> VcResult<DirEntry> {
        self.0.stat(path)
    }
    fn read_at(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> VcResult<usize> {
        self.0.read_at(path, offset, buf)
    }
    fn write_at(&mut self, _: &str, _: u64, _: &[u8]) -> VcResult<usize> {
        Err(VcError::TrueCryptReadOnly)
    }
    fn create(&mut self, _: &str) -> VcResult<()> {
        Err(VcError::TrueCryptReadOnly)
    }
    fn mkdir(&mut self, _: &str) -> VcResult<()> {
        Err(VcError::TrueCryptReadOnly)
    }
    fn rename(&mut self, _: &str, _: &str) -> VcResult<()> {
        Err(VcError::TrueCryptReadOnly)
    }
    fn unlink(&mut self, _: &str) -> VcResult<()> {
        Err(VcError::TrueCryptReadOnly)
    }
    fn truncate(&mut self, _: &str, _: u64) -> VcResult<()> {
        Err(VcError::TrueCryptReadOnly)
    }
    fn flush(&mut self) -> VcResult<()> {
        Ok(())
    }
    fn release_without_writing(&mut self) {
        self.0.release_without_writing()
    }
    fn replace(&mut self, _: &str, _: &str) -> VcResult<()> {
        Err(VcError::TrueCryptReadOnly)
    }
    fn space(&mut self) -> VcResult<FsSpace> {
        self.0.space()
    }
    fn max_file_bytes(&self) -> Option<u64> {
        self.0.max_file_bytes()
    }
}

impl Drop for ReadOnlyVfs {
    fn drop(&mut self) {
        // Nothing to write back, and the device would refuse it anyway.
        self.0.release_without_writing();
    }
}
