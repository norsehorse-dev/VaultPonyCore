//! NTFS read-only adapter over the `ntfs` crate (doc §7: plenty of
//! Windows-created containers exist; write is out indefinitely).

use crate::io::DeviceIo;
use crate::{DirEntry, FsKind, Vfs};
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::{NtfsFileName, NtfsFileNamespace};
use ntfs::{Ntfs, NtfsFile, NtfsReadSeek};
use vc_types::{VcError, VcResult};

pub struct NtfsVfs {
    fs: Ntfs,
    io: DeviceIo,
}

fn fs_err<E: std::fmt::Display>(e: E) -> VcError {
    VcError::Filesystem(e.to_string())
}

/// NT time (100 ns ticks since 1601-01-01) → Unix millis.
fn nt_to_unix_ms(nt: u64) -> i64 {
    (nt / 10_000) as i64 - 11_644_473_600_000
}

/// Authoritative file size: the unnamed $DATA attribute's value length.
/// The $FILE_NAME copy in the index is allowed to be stale (NTFS updates
/// it lazily) — never trust it for sizes.
fn data_len(io: &mut DeviceIo, file: &NtfsFile<'_>) -> VcResult<u64> {
    let item = file
        .data(io, "")
        .ok_or_else(|| VcError::Filesystem("no data attribute".into()))?
        .map_err(fs_err)?;
    let attribute = item.to_attribute().map_err(fs_err)?;
    Ok(attribute.value(io).map_err(fs_err)?.len())
}

/// Walk `path` components from the root via the file-name index
/// (case-insensitive per the volume's up-case table). Free function so the
/// returned file borrows only `fs`, leaving `io` free for further calls.
fn resolve<'n>(fs: &'n Ntfs, io: &mut DeviceIo, path: &str) -> VcResult<NtfsFile<'n>> {
    let mut file = fs.root_directory(io).map_err(fs_err)?;
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        let index = file.directory_index(io).map_err(fs_err)?;
        let mut finder = index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, fs, io, comp)
            .ok_or_else(|| VcError::Filesystem(format!("not found: {comp}")))?
            .map_err(fs_err)?;
        let file_ref = entry.file_reference();
        file = file_ref.to_file(fs, io).map_err(fs_err)?;
    }
    Ok(file)
}

impl NtfsVfs {
    pub fn open(dev: Box<dyn vc_io::BlockDevice>) -> VcResult<Self> {
        let mut io = DeviceIo::new(dev)?;
        let mut fs = Ntfs::new(&mut io).map_err(fs_err)?;
        // $UpCase drives case-insensitive index lookups.
        fs.read_upcase_table(&mut io).map_err(fs_err)?;
        Ok(Self { fs, io })
    }

    fn entry_of(name: &NtfsFileName) -> DirEntry {
        DirEntry {
            name: name.name().to_string_lossy(),
            is_dir: name.is_directory(),
            size: name.data_size(),
            mtime_ms: Some(nt_to_unix_ms(name.modification_time().nt_timestamp())),
        }
    }
}

impl Vfs for NtfsVfs {
    fn kind(&self) -> FsKind {
        FsKind::Ntfs
    }

    fn writable(&self) -> bool {
        false // Out indefinitely (doc §2).
    }

    fn list(&mut self, path: &str) -> VcResult<Vec<DirEntry>> {
        let (fs, io) = (&self.fs, &mut self.io);
        let file = resolve(fs, io, path)?;
        let index = file.directory_index(io).map_err(fs_err)?;
        let mut iter = index.entries();
        let mut out = Vec::new();
        while let Some(entry) = iter.next(io) {
            let entry = entry.map_err(fs_err)?;
            let name: NtfsFileName = entry.key().expect("file name index").map_err(fs_err)?;
            // Skip 8.3 duplicates and system files ($MFT and friends live
            // in the root; never surface them — doc §11, no noise).
            if name.namespace() == NtfsFileNamespace::Dos {
                continue;
            }
            let display = name.name().to_string_lossy();
            if display.starts_with('$') || display == "." {
                continue;
            }
            let mut e = Self::entry_of(&name);
            if !e.is_dir {
                // Index sizes can be stale; ask the MFT record.
                let file = entry.file_reference().to_file(fs, io).map_err(fs_err)?;
                e.size = data_len(io, &file)?;
            }
            out.push(e);
        }
        Ok(out)
    }

    fn stat(&mut self, path: &str) -> VcResult<DirEntry> {
        if path.split('/').all(|c| c.is_empty()) {
            return Ok(DirEntry {
                name: "/".into(),
                is_dir: true,
                size: 0,
                mtime_ms: None,
            });
        }
        let (fs, io) = (&self.fs, &mut self.io);
        let file = resolve(fs, io, path)?;
        let mut found = file.name(io, Some(NtfsFileNamespace::Win32), None);
        if found.is_none() {
            found = file.name(io, Some(NtfsFileNamespace::Win32AndDos), None);
        }
        if found.is_none() {
            found = file.name(io, Some(NtfsFileNamespace::Posix), None);
        }
        let name = found
            .ok_or_else(|| VcError::Filesystem("unnamed file".into()))?
            .map_err(fs_err)?;
        let mut e = Self::entry_of(&name);
        if !e.is_dir {
            e.size = data_len(io, &file)?;
        }
        Ok(e)
    }

    fn read_at(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> VcResult<usize> {
        let (fs, io) = (&self.fs, &mut self.io);
        let file = resolve(fs, io, path)?;
        let item = file
            .data(io, "")
            .ok_or_else(|| VcError::Filesystem("no data attribute".into()))?
            .map_err(fs_err)?;
        let attribute = item.to_attribute().map_err(fs_err)?;
        let mut value = attribute.value(io).map_err(fs_err)?;
        value
            .seek(io, std::io::SeekFrom::Start(offset))
            .map_err(fs_err)?;
        let mut total = 0;
        while total < buf.len() {
            let n = value.read(io, &mut buf[total..]).map_err(fs_err)?;
            if n == 0 {
                break;
            }
            total += n;
        }
        Ok(total)
    }

    fn write_at(&mut self, _path: &str, _offset: u64, _buf: &[u8]) -> VcResult<usize> {
        Err(VcError::Filesystem("NTFS is read-only".into()))
    }

    fn create(&mut self, _path: &str) -> VcResult<()> {
        Err(VcError::Filesystem("NTFS is read-only".into()))
    }

    fn mkdir(&mut self, _path: &str) -> VcResult<()> {
        Err(VcError::Filesystem("NTFS is read-only".into()))
    }

    fn rename(&mut self, _from: &str, _to: &str) -> VcResult<()> {
        Err(VcError::Filesystem("NTFS is read-only".into()))
    }

    fn unlink(&mut self, _path: &str) -> VcResult<()> {
        Err(VcError::Filesystem("NTFS is read-only".into()))
    }

    fn truncate(&mut self, _path: &str, _len: u64) -> VcResult<()> {
        Err(VcError::Filesystem("NTFS is read-only".into()))
    }

    fn flush(&mut self) -> VcResult<()> {
        Ok(())
    }
}
