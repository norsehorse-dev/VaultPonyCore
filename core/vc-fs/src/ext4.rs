//! ext4 read-only adapter over the `ext4-view` crate (2.0.0, plan 6.3).
//!
//! Linux users often format VeraCrypt volumes as ext4. `ext4-view` is
//! read-only by design (no write path to audit), replays the journal in
//! memory instead of writing it, and also reads ext2/ext3. Read-write ext4 is
//! a 2.1 item with its own plan.
//!
//! - Symlinks, FIFOs, sockets and device nodes are listed as plain entries
//!   of size 0; reading one is refused. Nothing ever follows a symlink, so
//!   no path resolves anywhere a listing didn't show.
//! - Owners and permission bits are not shown.
//! - ext4 names are bytes. A name that isn't UTF-8 is listed with U+FFFD
//!   replacement characters, and a path containing one is matched back to
//!   the raw name by listing its parent, so the file stays readable.

use crate::{DirEntry, FsKind, FsSpace, Vfs};
use ext4_view::{Ext4, Ext4Error, Ext4Read, File, Metadata, PathBuf};
use vc_io::BlockDevice;
use vc_types::{VcError, VcResult};

const READ_ONLY: &str = "ext4 is read-only in this version";

struct Reader(Box<dyn BlockDevice>);

impl Ext4Read for Reader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.0
            .read_at(start_byte, dst)
            .map_err(|e| Box::new(std::io::Error::other(e.to_string())) as _)
    }
}

pub struct Ext4Vfs {
    fs: Ext4,
    space: FsSpace,
    /// The file the last read went to, so streaming a video doesn't resolve
    /// its path again for every chunk.
    open: Option<(String, File)>,
}

// SAFETY: `Ext4` (and `File`, which holds a clone of it) is `!Send` only
// because it shares its state through `Rc`/`RefCell`. Every clone of that
// `Rc` lives inside this struct: `fs`, the cached `File`, and the iterators
// and entries a method creates and drops before returning. Nothing borrowed
// from or cloned out of `fs` is ever returned (callers get our own
// `DirEntry`/`FsSpace` values), so moving the struct moves every reference
// count with it, and `&mut self` on every `Vfs` method (plus the session
// mutex above it) means one thread at a time. The reader inside is our
// `Reader`, which only holds a `Send` block device.
unsafe impl Send for Ext4Vfs {}

fn fs_err(e: Ext4Error) -> VcError {
    match e {
        Ext4Error::NotFound => VcError::Filesystem("not found".into()),
        Ext4Error::Encrypted => {
            VcError::Filesystem("this file uses ext4 encryption, which VaultPony can't read".into())
        }
        Ext4Error::Incompatible(i) => VcError::Ext4Unsupported(i.to_string()),
        Ext4Error::Corrupt(c) => VcError::Filesystem(format!("ext4 is damaged: {c}")),
        other => VcError::Filesystem(other.to_string()),
    }
}

fn mtime_ms(m: &Metadata) -> Option<i64> {
    let t = m.modified();
    t.seconds()
        .checked_mul(1000)
        .and_then(|ms| ms.checked_add(i64::from(t.nanoseconds() / 1_000_000)))
}

fn entry(name: String, m: &Metadata) -> DirEntry {
    let is_dir = m.is_dir();
    let regular = m.file_type().is_regular_file();
    DirEntry {
        name,
        is_dir,
        size: if regular { m.len() } else { 0 },
        mtime_ms: mtime_ms(m),
    }
}

/// Size and free space from the superblock. ext4-view doesn't expose these;
/// the fields are fixed by the on-disk format (Documentation/filesystems/
/// ext4/super.rst). The free count is what the kernel last wrote, which is
/// current for any volume that was unmounted cleanly.
fn read_space(dev: &mut dyn BlockDevice) -> VcResult<FsSpace> {
    let mut sb = [0u8; 1024];
    dev.read_at(1024, &mut sb)?;
    let u32_at = |o: usize| u64::from(u32::from_le_bytes(sb[o..o + 4].try_into().unwrap()));
    let log = u32_at(0x18);
    if log > 6 {
        return Err(VcError::Filesystem(
            "ext4 superblock: bad block size".into(),
        ));
    }
    let block = 1024u64 << log;
    let incompat = u32_at(0x60);
    let wide = incompat & 0x80 != 0; // INCOMPAT_64BIT
    let blocks = u32_at(0x04) | if wide { u32_at(0x150) << 32 } else { 0 };
    let free = u32_at(0x0C) | if wide { u32_at(0x158) << 32 } else { 0 };
    Ok(FsSpace {
        total_bytes: blocks.saturating_mul(block),
        free_bytes: free.min(blocks).saturating_mul(block),
        cluster_bytes: block,
    })
}

impl Ext4Vfs {
    pub fn open(mut dev: Box<dyn BlockDevice>) -> VcResult<Self> {
        let space = read_space(dev.as_mut())?;
        let fs = Ext4::load(Box::new(Reader(dev))).map_err(fs_err)?;
        Ok(Self {
            fs,
            space,
            open: None,
        })
    }

    /// Our `/`-separated UTF-8 path as raw ext4 name components. Components
    /// holding U+FFFD are matched against their parent's raw names.
    fn raw_path(&self, path: &str) -> VcResult<Vec<Vec<u8>>> {
        let mut comps: Vec<Vec<u8>> = Vec::new();
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            if comp == "." || comp == ".." {
                return Err(VcError::Filesystem("invalid path".into()));
            }
            if !comp.contains('\u{FFFD}') {
                comps.push(comp.as_bytes().to_vec());
                continue;
            }
            let mut found = None;
            for e in self.fs.read_dir(&to_path(&comps)).map_err(fs_err)? {
                let e = e.map_err(fs_err)?;
                let name = e.file_name();
                if String::from_utf8_lossy(name.as_ref()) == comp {
                    found = Some(name.as_ref().to_vec());
                    break;
                }
            }
            comps.push(found.ok_or_else(|| VcError::Filesystem("not found".into()))?);
        }
        Ok(comps)
    }

    /// Metadata without following a final symlink, refusing any path whose
    /// earlier components aren't real folders (listings never show a symlink
    /// as a folder, so only a made-up path gets here).
    fn lstat(&self, comps: &[Vec<u8>]) -> VcResult<Metadata> {
        for i in 1..comps.len() {
            let m = self
                .fs
                .symlink_metadata(&to_path(&comps[..i]))
                .map_err(fs_err)?;
            if !m.is_dir() {
                return Err(VcError::Filesystem("not a folder".into()));
            }
        }
        self.fs.symlink_metadata(&to_path(comps)).map_err(fs_err)
    }
}

fn to_path(comps: &[Vec<u8>]) -> PathBuf {
    let mut p = PathBuf::new("/");
    for c in comps {
        p.push(c);
    }
    p
}

impl Vfs for Ext4Vfs {
    fn kind(&self) -> FsKind {
        FsKind::Ext4
    }

    fn writable(&self) -> bool {
        false
    }

    fn list(&mut self, path: &str) -> VcResult<Vec<DirEntry>> {
        let raw = self.raw_path(path)?;
        if !self.lstat(&raw)?.is_dir() {
            return Err(VcError::Filesystem("not a folder".into()));
        }
        let mut out = Vec::new();
        for e in self.fs.read_dir(&to_path(&raw)).map_err(fs_err)? {
            let e = e.map_err(fs_err)?;
            let name = e.file_name();
            let bytes = name.as_ref();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name = String::from_utf8_lossy(bytes).into_owned();
            // DirEntry::metadata does not follow symlinks.
            let m = e.metadata().map_err(fs_err)?;
            out.push(entry(name, &m));
        }
        Ok(out)
    }

    fn stat(&mut self, path: &str) -> VcResult<DirEntry> {
        let raw = self.raw_path(path)?;
        let m = self.lstat(&raw)?;
        let name = path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string();
        Ok(entry(name, &m))
    }

    fn read_at(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> VcResult<usize> {
        let cached = matches!(&self.open, Some((p, _)) if p == path);
        if !cached {
            self.open = None;
            let raw = self.raw_path(path)?;
            let m = self.lstat(&raw)?;
            if m.is_dir() {
                return Err(VcError::Filesystem("is a folder".into()));
            }
            if !m.file_type().is_regular_file() {
                return Err(VcError::Filesystem(
                    "not a regular file (link or special file)".into(),
                ));
            }
            // The final component is known not to be a symlink, so open's
            // symlink following has nothing to follow.
            let file = self.fs.open(&to_path(&raw)).map_err(fs_err)?;
            self.open = Some((path.to_string(), file));
        }
        let (_, file) = self.open.as_mut().unwrap();
        let len = file.metadata().len();
        if offset >= len || buf.is_empty() {
            return Ok(0);
        }
        file.seek_to(offset).map_err(fs_err)?;
        let want = buf
            .len()
            .min(usize::try_from(len - offset).unwrap_or(usize::MAX));
        let mut done = 0;
        while done < want {
            let n = file.read_bytes(&mut buf[done..want]).map_err(fs_err)?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }

    fn write_at(&mut self, _: &str, _: u64, _: &[u8]) -> VcResult<usize> {
        Err(VcError::Filesystem(READ_ONLY.into()))
    }
    fn create(&mut self, _: &str) -> VcResult<()> {
        Err(VcError::Filesystem(READ_ONLY.into()))
    }
    fn mkdir(&mut self, _: &str) -> VcResult<()> {
        Err(VcError::Filesystem(READ_ONLY.into()))
    }
    fn rename(&mut self, _: &str, _: &str) -> VcResult<()> {
        Err(VcError::Filesystem(READ_ONLY.into()))
    }
    fn unlink(&mut self, _: &str) -> VcResult<()> {
        Err(VcError::Filesystem(READ_ONLY.into()))
    }
    fn truncate(&mut self, _: &str, _: u64) -> VcResult<()> {
        Err(VcError::Filesystem(READ_ONLY.into()))
    }
    fn flush(&mut self) -> VcResult<()> {
        Ok(())
    }
    fn replace(&mut self, _: &str, _: &str) -> VcResult<()> {
        Err(VcError::Filesystem(READ_ONLY.into()))
    }

    fn space(&mut self) -> VcResult<FsSpace> {
        Ok(self.space)
    }
}
