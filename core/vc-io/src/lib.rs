//! Block-device abstraction (planning doc §5).
//!
//! Two impls: `FileDevice` over `std::fs` (desktop, CLI, tests) and
//! `RawFdDevice` over a dup'd fd handed across FFI from SAF /
//! security-scoped URLs (mobile) — the core never touches platform storage
//! APIs. Read-ahead cache and write-ordering hooks land with the FS layer.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
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

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> VcResult<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)?;
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> VcResult<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(buf)?;
        Ok(())
    }

    fn flush(&mut self) -> VcResult<()> {
        self.file.sync_data()?;
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
