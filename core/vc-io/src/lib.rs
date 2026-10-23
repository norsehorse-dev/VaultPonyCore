//! Block-device abstraction (planning doc §5).
//!
//! Two impls: `FileDevice` over `std::fs` (desktop, CLI, tests) and
//! `RawFdDevice` over a dup'd fd handed across FFI from SAF /
//! security-scoped URLs (mobile) — the core never touches platform storage
//! APIs. Read-ahead cache and write-ordering hooks land with the FS layer.

use std::fs::File;
use vc_types::VcResult;

/// Random-access block I/O over a container file.
///
/// Offsets are byte offsets from the start of the container. Implementations
/// must support arbitrary-offset reads — random access is what makes
/// streaming (video seek) work on mobile (doc §6).
pub trait BlockDevice: Send {
    /// Total size in bytes (needed for backup-header offsets).
    fn len(&mut self) -> VcResult<u64>;

    fn is_empty(&mut self) -> VcResult<bool> {
        Ok(self.len()? == 0)
    }

    /// Read exactly `buf.len()` bytes at `offset`.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> VcResult<()>;

    /// Write exactly `buf.len()` bytes at `offset`.
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> VcResult<()>;

    /// Durably flush all prior writes. The exFAT write-ordering discipline
    /// (doc §7) is built on this being a real barrier.
    fn flush(&mut self) -> VcResult<()>;
}

/// `std::fs::File`-backed device (desktop / CLI / test harness).
pub struct FileDevice {
    file: File,
}

impl FileDevice {
    pub fn open_read(path: &std::path::Path) -> VcResult<Self> {
        Ok(Self {
            file: File::open(path)?,
        })
    }

    pub fn open_rw(path: &std::path::Path) -> VcResult<Self> {
        Ok(Self {
            file: File::options().read(true).write(true).open(path)?,
        })
    }
}

impl BlockDevice for FileDevice {
    fn len(&mut self) -> VcResult<u64> {
        Ok(self.file.metadata()?.len())
    }

    // Positional I/O (pread/pwrite): the file offset is never used, so a
    // dup'd or passed fd shared with another process (the iOS File Provider
    // extension, rc3) can't move this device's reads and writes.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> VcResult<()> {
        pos::read_exact_at(&self.file, buf, offset)?;
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> VcResult<()> {
        pos::write_all_at(&self.file, buf, offset)?;
        Ok(())
    }

    fn flush(&mut self) -> VcResult<()> {
        self.file.sync_data()?;
        Ok(())
    }
}

#[cfg(unix)]
mod pos {
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    pub fn read_exact_at(f: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        f.read_exact_at(buf, offset)
    }

    pub fn write_all_at(f: &File, buf: &[u8], offset: u64) -> std::io::Result<()> {
        f.write_all_at(buf, offset)
    }
}

#[cfg(windows)]
mod pos {
    use std::fs::File;
    use std::io::{Error, ErrorKind};
    use std::os::windows::fs::FileExt;

    // seek_read/seek_write move the handle's offset but take an explicit
    // one each call, so concurrent users of the handle can't misplace them.
    pub fn read_exact_at(f: &File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
        while !buf.is_empty() {
            match f.seek_read(buf, offset) {
                Ok(0) => return Err(Error::new(ErrorKind::UnexpectedEof, "short read")),
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn write_all_at(f: &File, mut buf: &[u8], mut offset: u64) -> std::io::Result<()> {
        while !buf.is_empty() {
            match f.seek_write(buf, offset) {
                Ok(0) => return Err(Error::new(ErrorKind::WriteZero, "short write")),
                Ok(n) => {
                    buf = &buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Raw-fd device for mobile: constructed from a dup'd file descriptor passed
/// across the FFI boundary. The fd is owned by this device and closed on
/// drop.
///
/// Contract with the shell: the fd handed across FFI must be *dup'd* (e.g.
/// `ParcelFileDescriptor.detachFd()` on Android after a dup, or a dup of a
/// security-scoped handle on iOS) — this device takes ownership and closes
/// it on drop. Internally it is a `FileDevice` over `File::from(OwnedFd)`;
/// the platform storage API never crosses into the core (doc §5).
#[cfg(unix)]
pub struct RawFdDevice;

#[cfg(unix)]
impl RawFdDevice {
    /// Take ownership of `fd` and wrap it as a block device.
    ///
    /// # Safety
    /// `fd` must be an open, seekable file descriptor that the caller owns
    /// and will not use or close afterwards.
    pub unsafe fn from_raw_fd(fd: std::os::fd::RawFd) -> FileDevice {
        use std::os::fd::{FromRawFd, OwnedFd};
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        FileDevice {
            file: File::from(owned),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    #[test]
    fn reads_and_writes_ignore_the_shared_file_offset() {
        let path = std::env::temp_dir().join(format!("vcio-pos-{}", std::process::id()));
        std::fs::write(&path, vec![0u8; 8192]).unwrap();
        let mut a = FileDevice::open_rw(&path).unwrap();
        // A second handle on the same open file description, like a dup'd fd
        // handed to another process.
        let mut other = a.file.try_clone().unwrap();
        a.write_at(4096, b"vault").unwrap();
        other.seek(SeekFrom::Start(100)).unwrap();
        other.write_all(b"xx").unwrap();
        let mut buf = [0u8; 5];
        a.read_at(4096, &mut buf).unwrap();
        assert_eq!(&buf, b"vault");
        a.write_at(200, b"yy").unwrap();
        // The other handle's offset was not moved by this device.
        assert_eq!(other.stream_position().unwrap(), 102);
        std::fs::remove_file(&path).ok();
    }
}
