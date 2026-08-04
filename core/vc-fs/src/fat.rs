//! FAT12/16/32 adapter over the `fatfs` crate (doc §7: "wrap, test, done").
//! Read side for P0; write ops land with P4 behind the same trait.

use crate::io::DeviceIo;
use crate::{DirEntry, FsKind, Vfs};
use std::io::{Read, Seek, SeekFrom, Write};
use vc_types::{VcError, VcResult};

pub struct FatVfs {
    fs: fatfs::FileSystem<DeviceIo>,
}

// SAFETY: `fatfs::FileSystem` fails auto-Send only because `FsOptions`
// stores `&'static dyn OemCpConverter` and `&'static dyn TimeProvider`
// without Sync bounds. We construct with `FsOptions::new()`, whose defaults
// are the crate's stateless unit structs (`LossyOemCpConverter`,
// `DefaultTimeProvider`) — immutable statics with no interior mutability,
// safe to reference from any thread. Every other field is owned. Revisit if
// FsOptions ever carries custom providers here, or on any fatfs upgrade
// (unsafe is a code-review event — THREAT_MODEL.md).
unsafe impl Send for FatVfs {}

impl FatVfs {
    pub fn open(dev: DeviceIo) -> VcResult<Self> {
        let fs = fatfs::FileSystem::new(dev, fatfs::FsOptions::new())
            .map_err(|e| VcError::Filesystem(format!("FAT mount: {e}")))?;
        Ok(Self { fs })
    }
}

/// Lay a fresh FAT filesystem across the whole (decrypted) device — used when
/// creating a new container (doc §7). fatfs auto-selects FAT12/16/32 from the
/// volume size, the same way VeraCrypt sizes small volumes.
pub fn format(dev: Box<dyn vc_io::BlockDevice>) -> VcResult<()> {
    let mut io = DeviceIo::new(dev)?;
    fatfs::format_volume(&mut io, fatfs::FormatVolumeOptions::new())
        .map_err(|e| VcError::Filesystem(format!("FAT format: {e}")))?;
    io.flush().map_err(VcError::Io)?;
    Ok(())
}

fn fs_err(e: std::io::Error) -> VcError {
    VcError::Filesystem(e.to_string())
}

/// fatfs paths are `/`-separated already; strip the leading slash our VFS
/// convention uses and reject empties early.
fn fat_path(path: &str) -> &str {
    path.trim_start_matches('/')
}

/// fatfs `DateTime` → Unix millis (days-from-civil, Howard Hinnant's
/// algorithm — no chrono dependency for one conversion).
fn to_unix_ms(dt: fatfs::DateTime) -> i64 {
    let (y, m, d) = (
        dt.date.year as i64,
        dt.date.month as i64,
        dt.date.day as i64,
    );
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs =
        days * 86400 + dt.time.hour as i64 * 3600 + dt.time.min as i64 * 60 + dt.time.sec as i64;
    secs * 1000 + dt.time.millis as i64
}

fn entry_of(e: &fatfs::DirEntry<'_, DeviceIo>) -> DirEntry {
    DirEntry {
        name: e.file_name(),
        is_dir: e.is_dir(),
        size: e.len(),
        mtime_ms: Some(to_unix_ms(e.modified())),
    }
}

impl Vfs for FatVfs {
    fn kind(&self) -> FsKind {
        FsKind::Fat
    }

    fn writable(&self) -> bool {
        // The adapter supports writes (P4); whether they reach the disk is
        // decided by how the session opened the container file.
        true
    }

    fn list(&mut self, path: &str) -> VcResult<Vec<DirEntry>> {
        let root = self.fs.root_dir();
        let dir = if fat_path(path).is_empty() {
            root
        } else {
            root.open_dir(fat_path(path)).map_err(fs_err)?
        };
        let mut out = Vec::new();
        for e in dir.iter() {
            let e = e.map_err(fs_err)?;
            let name = e.file_name();
            if name == "." || name == ".." {
                continue;
            }
            out.push(entry_of(&e));
        }
        Ok(out)
    }

    fn stat(&mut self, path: &str) -> VcResult<DirEntry> {
        let p = fat_path(path);
        if p.is_empty() {
            return Ok(DirEntry {
                name: "/".into(),
                is_dir: true,
                size: 0,
                mtime_ms: None,
            });
        }
        // fatfs has no direct stat; list the parent and find the leaf.
        let (parent, leaf) = match p.rsplit_once('/') {
            Some((a, b)) => (a, b),
            None => ("", p),
        };
        let entries = self.list(parent)?;
        entries
            .into_iter()
            .find(|e| e.name.eq_ignore_ascii_case(leaf))
            .ok_or_else(|| VcError::Filesystem(format!("not found: {leaf}")))
    }

    fn read_at(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> VcResult<usize> {
        let mut f = self
            .fs
            .root_dir()
            .open_file(fat_path(path))
            .map_err(fs_err)?;
        f.seek(SeekFrom::Start(offset)).map_err(fs_err)?;
        let mut total = 0;
        while total < buf.len() {
            let n = f.read(&mut buf[total..]).map_err(fs_err)?;
            if n == 0 {
                break;
            }
            total += n;
        }
        Ok(total)
    }

    fn write_at(&mut self, path: &str, offset: u64, buf: &[u8]) -> VcResult<usize> {
        let mut f = self
            .fs
            .root_dir()
            .open_file(fat_path(path))
            .map_err(fs_err)?;
        // Writing past EOF zero-fills the gap (fatfs does not extend on a
        // bare seek-past-end).
        let size = f.seek(SeekFrom::End(0)).map_err(fs_err)?;
        if offset > size {
            let mut remaining = offset - size;
            let zeros = [0u8; 4096];
            while remaining > 0 {
                let n = remaining.min(4096) as usize;
                f.write_all(&zeros[..n]).map_err(fs_err)?;
                remaining -= n as u64;
            }
        } else {
            f.seek(SeekFrom::Start(offset)).map_err(fs_err)?;
        }
        f.write_all(buf).map_err(fs_err)?;
        f.flush().map_err(fs_err)?;
        Ok(buf.len())
    }

    fn create(&mut self, path: &str) -> VcResult<()> {
        self.fs
            .root_dir()
            .create_file(fat_path(path))
            .map_err(fs_err)?;
        Ok(())
    }

    fn mkdir(&mut self, path: &str) -> VcResult<()> {
        self.fs
            .root_dir()
            .create_dir(fat_path(path))
            .map_err(fs_err)?;
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &str) -> VcResult<()> {
        let root = self.fs.root_dir();
        root.rename(fat_path(from), &root, fat_path(to))
            .map_err(fs_err)
    }

    fn unlink(&mut self, path: &str) -> VcResult<()> {
        self.fs.root_dir().remove(fat_path(path)).map_err(fs_err)
    }

    fn truncate(&mut self, path: &str, len: u64) -> VcResult<()> {
        let mut f = self
            .fs
            .root_dir()
            .open_file(fat_path(path))
            .map_err(fs_err)?;
        f.seek(SeekFrom::Start(len)).map_err(fs_err)?;
        f.truncate().map_err(fs_err)?;
        f.flush().map_err(fs_err)
    }

    fn flush(&mut self) -> VcResult<()> {
        // fatfs flushes FSInfo and the dirty flag on unmount/Drop; per-file
        // data is flushed at each op above. Nothing additional to do here
        // until we hold long-lived open files (P7 streaming writes).
        Ok(())
    }
}
