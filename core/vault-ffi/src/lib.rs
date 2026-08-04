//! UniFFI boundary — generates the Kotlin and Swift bindings (doc §5).
//!
//! Surface (P3): unlock a container from a dup'd file descriptor, browse,
//! read file content in chunks, lock. The fd contract keeps every platform
//! storage API (SAF, security-scoped URLs) on the shell side; the core
//! sees only a file descriptor it owns.
//!
//! Secret handling at this boundary (doc §5, §11): the passphrase arrives
//! as foreign-allocated memory, is wrapped in `Zeroizing` immediately, and
//! the Rust copy is wiped when unlock returns. Auditing the *generated*
//! glue for lingering foreign-side copies is a standing pre-release task
//! (tracked in THREAT_MODEL.md review gates). No error message crossing
//! this boundary carries names, paths, or key material.

use std::sync::Mutex;
use vc_types::VcError;
use zeroize::{Zeroize, Zeroizing};

uniffi::setup_scaffolding!();

/// Core version string for about screens; also the walking-skeleton probe.
#[uniffi::export]
pub fn core_version() -> String {
    vault_core::core_version()
}

/// Encryption schemes a new container can use, in menu order (single ciphers
/// first, then cascades) — exactly the names `create_container` /
/// `create_hidden_container` accept for `scheme`. Lets the shells populate a
/// picker straight from the core so the two never drift.
#[uniffi::export]
pub fn encryption_schemes() -> Vec<String> {
    vc_types::registry::ENCRYPTION_SCHEMES
        .iter()
        .filter(|s| vc_crypto::SchemeXts::supported(s))
        .map(|s| s.name.to_string())
        .collect()
}

/// Hashes (PRFs) a new container can use, in menu order — the names
/// `create_container` / `create_hidden_container` accept for `prf`.
#[uniffi::export]
pub fn hashes() -> Vec<String> {
    vc_types::registry::PRFS
        .iter()
        .map(|p| p.name.to_string())
        .collect()
}

/// Filesystems a new container can be formatted with — the values
/// `create_container` / `create_hidden_container` accept for `filesystem`.
/// FAT is universal; exFAT lifts the 4 GiB per-file limit.
#[uniffi::export]
pub fn filesystems() -> Vec<String> {
    vec!["FAT".to_string(), "exFAT".to_string()]
}

fn parse_fs(name: &str) -> FfiResult<vault_core::ContainerFs> {
    match name {
        "FAT" => Ok(vault_core::ContainerFs::Fat),
        "exFAT" => Ok(vault_core::ContainerFs::Exfat),
        _ => Err(VaultError::Internal),
    }
}

/// Create a brand-new container over `fd` (a freshly-created, writable SAF
/// document the caller hands over) and format an empty FAT filesystem inside,
/// so it opens as a usable volume. `scheme`/`prf` are registry names
/// (e.g. "AES", "SHA-512").
#[uniffi::export]
pub fn create_container(
    fd: i32,
    size: u64,
    passphrase: String,
    pim: u32,
    keyfiles: Vec<Vec<u8>>,
    scheme: String,
    prf: String,
    filesystem: String,
) -> FfiResult<()> {
    let passphrase = Zeroizing::new(passphrase);

    // Adopt the fd up front so every early-error path still closes it. The
    // caller handed ownership across the FFI and expects us to close it; if we
    // returned before adopting (e.g. an unknown scheme string), the fd leaked.
    use std::os::fd::{FromRawFd, IntoRawFd};
    let file = unsafe { std::fs::File::from_raw_fd(fd) };

    let fs = parse_fs(&filesystem)?;
    let scheme = vc_types::registry::ENCRYPTION_SCHEMES
        .iter()
        .find(|s| s.name == scheme)
        .ok_or(VaultError::Internal)?;
    let prf = vc_types::registry::PRFS
        .iter()
        .find(|p| p.name == prf)
        .ok_or(VaultError::Internal)?;

    // A SAF-created document starts empty; size it so create_volume's writes
    // land at real offsets. Best-effort: create_volume's tail writes extend the
    // file anyway if the provider rejects ftruncate.
    let _ = file.set_len(size);

    // SAFETY: same fd-ownership contract as unlock_fd / RawFdDevice. into_raw_fd
    // releases the fd without closing it; RawFdDevice owns and closes it next.
    let dev = unsafe { vc_io::RawFdDevice::from_raw_fd(file.into_raw_fd()) };
    let params = vault_core::CreateParams {
        scheme,
        prf,
        pim,
        passphrase: passphrase.as_bytes(),
        keyfiles: &keyfiles,
        size,
        sector_size: 512,
    };
    vault_core::create_container(Box::new(dev), &params, fs)?;
    Ok(())
}

/// Create a container that hides a second volume inside the first (doc §9).
/// `outer_*` is the decoy volume; `hidden_*` is the concealed one. The outer
/// header records no trace of the hidden volume, so the outer password alone
/// is fully deniable. `hidden_size` is the hidden volume's data-area size in
/// bytes; it is carved from the tail of the outer volume and must leave the
/// outer with a usable margin (the core validates and errors otherwise).
///
/// `scheme`/`prf` (registry names) apply to both volumes. `fd` is a single
/// freshly-created, writable SAF document the caller hands over; the core
/// dup's it internally for the three passes (write both headers, format outer,
/// format hidden) and closes every handle before returning.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn create_hidden_container(
    fd: i32,
    size: u64,
    outer_passphrase: String,
    hidden_passphrase: String,
    pim: u32,
    hidden_size: u64,
    scheme: String,
    prf: String,
    filesystem: String,
) -> FfiResult<()> {
    use std::os::fd::{FromRawFd, IntoRawFd};

    let outer_passphrase = Zeroizing::new(outer_passphrase);
    let hidden_passphrase = Zeroizing::new(hidden_passphrase);
    let fs = parse_fs(&filesystem)?;
    let scheme = vc_types::registry::ENCRYPTION_SCHEMES
        .iter()
        .find(|s| s.name == scheme)
        .ok_or(VaultError::Internal)?;
    let prf = vc_types::registry::PRFS
        .iter()
        .find(|p| p.name == prf)
        .ok_or(VaultError::Internal)?;

    // Own the handed-over fd as a File. Size it up front so header/backup
    // writes at the tail land at real offsets; the File is the single owner
    // and closes the fd when this function returns.
    let base = unsafe { std::fs::File::from_raw_fd(fd) };
    let _ = base.set_len(size);

    // Each pass gets its own dup'd fd via try_clone → RawFdDevice, so the
    // three passes never share a file position and each closes its own dup.
    let make = || -> vc_types::VcResult<Box<dyn vc_io::BlockDevice>> {
        let cloned = base
            .try_clone()
            .map_err(|e| VcError::Io(std::io::Error::new(e.kind(), "dup fd")))?;
        let raw = cloned.into_raw_fd();
        Ok(Box::new(unsafe { vc_io::RawFdDevice::from_raw_fd(raw) }))
    };

    let outer = vault_core::CreateParams {
        scheme,
        prf,
        pim,
        passphrase: outer_passphrase.as_bytes(),
        keyfiles: &[],
        size,
        sector_size: 512,
    };
    let hidden = vault_core::CreateParams {
        scheme,
        prf,
        pim,
        passphrase: hidden_passphrase.as_bytes(),
        keyfiles: &[],
        size,
        sector_size: 512,
    };
    vault_core::create_container_with_hidden(make, &outer, &hidden, hidden_size, fs)?;
    Ok(())
}

/// Export the container's 128 KiB header backup over a read-only `fd`, for the
/// caller to save to a file (doc §6). The bytes are ciphertext — no secret
/// beyond the container's own — but the backup keeps accepting the *current*
/// password forever, so the caller must warn the user to guard it.
#[uniffi::export]
pub fn export_header_backup(fd: i32) -> FfiResult<Vec<u8>> {
    let mut dev = unsafe { vc_io::RawFdDevice::from_raw_fd(fd) };
    Ok(vault_core::export_header_backup(&mut dev)?)
}

/// Restore the primary header from a `backup` file's bytes over a writable
/// `fd`. Verifies the backup unlocks with the password (+ keyfiles) before
/// writing; on a wrong password nothing is written.
#[uniffi::export]
pub fn restore_header_from_file(
    fd: i32,
    backup: Vec<u8>,
    passphrase: String,
    pim: u32,
    keyfiles: Vec<Vec<u8>>,
) -> FfiResult<()> {
    let passphrase = Zeroizing::new(passphrase);
    let mut keyfiles = keyfiles;
    let secret = vc_crypto::apply_keyfiles(passphrase.as_bytes(), &keyfiles);
    for kf in &mut keyfiles {
        kf.zeroize();
    }
    let mut dev = unsafe { vc_io::RawFdDevice::from_raw_fd(fd) };
    vault_core::restore_header_from_file(&mut dev, &backup, &secret, pim)?;
    Ok(())
}

/// Restore the primary header from the container's own embedded backup over a
/// writable `fd` — no external file needed. Verifies before writing.
#[uniffi::export]
pub fn restore_header_from_embedded(
    fd: i32,
    passphrase: String,
    pim: u32,
    keyfiles: Vec<Vec<u8>>,
) -> FfiResult<()> {
    let passphrase = Zeroizing::new(passphrase);
    let mut keyfiles = keyfiles;
    let secret = vc_crypto::apply_keyfiles(passphrase.as_bytes(), &keyfiles);
    for kf in &mut keyfiles {
        kf.zeroize();
    }
    let mut dev = unsafe { vc_io::RawFdDevice::from_raw_fd(fd) };
    vault_core::restore_header_from_embedded(&mut dev, &secret, pim)?;
    Ok(())
}

/// Change a container's password/PIM over a writable `fd` (doc §6). The data
/// is untouched — only the header is re-encrypted under the new password. The
/// old password (+ keyfiles) selects the volume and is verified before any
/// write; a wrong old password changes nothing. Keyfiles are folded into each
/// password exactly as at unlock time.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn change_password(
    fd: i32,
    old_passphrase: String,
    old_pim: u32,
    old_keyfiles: Vec<Vec<u8>>,
    new_passphrase: String,
    new_pim: u32,
    new_keyfiles: Vec<Vec<u8>>,
) -> FfiResult<()> {
    let old_passphrase = Zeroizing::new(old_passphrase);
    let new_passphrase = Zeroizing::new(new_passphrase);
    let mut old_keyfiles = old_keyfiles;
    let mut new_keyfiles = new_keyfiles;
    let old_secret = vc_crypto::apply_keyfiles(old_passphrase.as_bytes(), &old_keyfiles);
    let new_secret = vc_crypto::apply_keyfiles(new_passphrase.as_bytes(), &new_keyfiles);
    for kf in old_keyfiles.iter_mut().chain(new_keyfiles.iter_mut()) {
        kf.zeroize();
    }
    let mut dev = unsafe { vc_io::RawFdDevice::from_raw_fd(fd) };
    vault_core::change_password(&mut dev, &old_secret, old_pim, &new_secret, new_pim)?;
    Ok(())
}

/// User-explainable unlock/browse failures. Deliberately coarser than the
/// core's error type: shells branch on these, they don't diagnose.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VaultError {
    #[error("wrong password/PIM, or not a VeraCrypt container")]
    NotFoundOrWrongPassword,
    #[error("container requires a newer format version than supported")]
    VersionTooNew,
    #[error("system-encryption volumes are not supported")]
    SystemVolume,
    #[error("write blocked to protect the hidden volume; the volume is now read-only")]
    HiddenVolumeProtected,
    #[error("volume header is damaged; the embedded backup header may help")]
    HeaderDamaged,
    #[error("filesystem not supported yet: {name}")]
    UnsupportedFilesystem { name: String },
    // Field is `detail`, not `message`: UniFFI generates each error variant as
    // a Kotlin class extending Exception, and a `message` field collides with
    // Throwable.message (conflicting-declaration / override errors).
    #[error("filesystem error: {detail}")]
    Filesystem { detail: String },
    #[error("I/O error: {detail}")]
    Io { detail: String },
    #[error("internal error")]
    Internal,
}

impl From<VcError> for VaultError {
    fn from(e: VcError) -> Self {
        match e {
            VcError::NotFoundOrWrongPassword => VaultError::NotFoundOrWrongPassword,
            VcError::VersionTooNew { .. } => VaultError::VersionTooNew,
            VcError::SystemVolume => VaultError::SystemVolume,
            VcError::HiddenVolumeProtected => VaultError::HiddenVolumeProtected,
            VcError::HeaderDamaged => VaultError::HeaderDamaged,
            VcError::UnsupportedFilesystem(name) => VaultError::UnsupportedFilesystem { name },
            VcError::UnknownFilesystem => VaultError::UnsupportedFilesystem {
                name: "unrecognized".into(),
            },
            VcError::Filesystem(detail) => VaultError::Filesystem { detail },
            VcError::Io(io) => VaultError::Io {
                // io::Error display strings don't carry paths for our
                // pread/pwrite usage; still, keep it to the kind.
                detail: io.kind().to_string(),
            },
            VcError::Internal(_) => VaultError::Internal,
        }
    }
}

type FfiResult<T> = Result<T, VaultError>;

#[derive(uniffi::Record)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime_ms: Option<i64>,
}

#[derive(uniffi::Record)]
pub struct VolumeFacts {
    pub scheme: String,
    pub prf: String,
    pub filesystem: String,
    pub writable: bool,
}

/// Unlock progress: candidate `step` of `total`, currently trying `prf`.
/// Fired from the unlock thread; implementations must be fast and must not
/// call back into the session.
#[uniffi::export(with_foreign)]
pub trait UnlockProgressListener: Send + Sync {
    fn on_progress(&self, step: u32, total: u32, prf: String);
}

/// One unlocked container. Thread-safe; operations serialize on an
/// internal lock. After `lock()` every call fails with `Internal`.
#[derive(uniffi::Object)]
pub struct VaultSession {
    inner: Mutex<Option<vault_core::Session>>,
}

fn with_session<T>(
    slot: &Mutex<Option<vault_core::Session>>,
    f: impl FnOnce(&mut vault_core::Session) -> FfiResult<T>,
) -> FfiResult<T> {
    let mut guard = slot.lock().map_err(|_| VaultError::Internal)?;
    match guard.as_mut() {
        Some(s) => f(s),
        None => Err(VaultError::Internal), // used after lock()
    }
}

#[uniffi::export]
impl VaultSession {
    /// Unlock a container from a file descriptor the caller has dup'd and
    /// hands over completely (Android: `ParcelFileDescriptor.detachFd()`).
    /// The session owns and closes it.
    #[uniffi::constructor]
    pub fn unlock_fd(
        fd: i32,
        passphrase: String,
        pim: u32,
        keyfiles: Vec<Vec<u8>>,
        listener: Option<std::sync::Arc<dyn UnlockProgressListener>>,
    ) -> FfiResult<std::sync::Arc<Self>> {
        let passphrase = Zeroizing::new(passphrase);
        // Fold any keyfiles into the passphrase exactly as the CLI does; an
        // empty list is the identity. The derived secret is `Zeroizing`, and
        // we wipe the raw keyfile bytes as soon as they've been mixed in.
        let mut keyfiles = keyfiles;
        let secret = vc_crypto::apply_keyfiles(passphrase.as_bytes(), &keyfiles);
        for kf in &mut keyfiles {
            kf.zeroize();
        }
        // SAFETY: ownership contract documented above and on RawFdDevice.
        let dev = unsafe { vc_io::RawFdDevice::from_raw_fd(fd) };
        let mut progress = |step: usize, total: usize, prf: &str| {
            if let Some(l) = &listener {
                l.on_progress(step as u32, total as u32, prf.to_string());
            }
        };
        let session =
            vault_core::Session::unlock_device(Box::new(dev), &secret, pim, &mut progress)?;
        Ok(std::sync::Arc::new(Self {
            inner: Mutex::new(Some(session)),
        }))
    }

    /// Open the OUTER volume of a hidden container read-write, write-protecting
    /// the hidden region (doc §9). Both passwords are required: the outer one
    /// unlocks the outer volume, the hidden one is used only to learn which
    /// bytes to shield. Any outer write that would land in the hidden region is
    /// refused and latches the whole volume read-only
    /// (`VaultError::HiddenVolumeProtected`). Use this instead of `unlock_fd`
    /// when adding files to a decoy/outer volume that has a hidden volume you
    /// must not clobber.
    ///
    /// `fd` must be opened read-write. Fails with `NotFoundOrWrongPassword` if
    /// either password is wrong or there is no hidden volume — the same error
    /// either way, so it reveals nothing a plain unlock wouldn't (doc §11).
    #[uniffi::constructor]
    pub fn unlock_outer_protected_fd(
        fd: i32,
        outer_passphrase: String,
        hidden_passphrase: String,
        pim: u32,
        listener: Option<std::sync::Arc<dyn UnlockProgressListener>>,
    ) -> FfiResult<std::sync::Arc<Self>> {
        let outer_passphrase = Zeroizing::new(outer_passphrase);
        let hidden_passphrase = Zeroizing::new(hidden_passphrase);
        // SAFETY: ownership contract documented on RawFdDevice.
        let dev = unsafe { vc_io::RawFdDevice::from_raw_fd(fd) };
        let mut progress = |step: usize, total: usize, prf: &str| {
            if let Some(l) = &listener {
                l.on_progress(step as u32, total as u32, prf.to_string());
            }
        };
        let session = vault_core::Session::unlock_outer_protected_device(
            Box::new(dev),
            outer_passphrase.as_bytes(),
            hidden_passphrase.as_bytes(),
            pim,
            &mut progress,
        )?;
        Ok(std::sync::Arc::new(Self {
            inner: Mutex::new(Some(session)),
        }))
    }

    pub fn facts(&self) -> FfiResult<VolumeFacts> {
        with_session(&self.inner, |s| {
            let (scheme, prf) = (s.scheme().to_string(), s.prf().to_string());
            let vfs = s.vfs();
            Ok(VolumeFacts {
                scheme,
                prf,
                filesystem: format!("{:?}", vfs.kind()),
                writable: vfs.writable(),
            })
        })
    }

    pub fn list(&self, path: String) -> FfiResult<Vec<DirEntry>> {
        with_session(&self.inner, |s| {
            Ok(s.vfs()
                .list(&path)?
                .into_iter()
                .map(|e| DirEntry {
                    name: e.name,
                    is_dir: e.is_dir,
                    size: e.size,
                    mtime_ms: e.mtime_ms,
                })
                .collect())
        })
    }

    pub fn stat(&self, path: String) -> FfiResult<DirEntry> {
        with_session(&self.inner, |s| {
            let e = s.vfs().stat(&path)?;
            Ok(DirEntry {
                name: e.name,
                is_dir: e.is_dir,
                size: e.size,
                mtime_ms: e.mtime_ms,
            })
        })
    }

    /// Read up to `len` bytes at `offset`. Short only at end of file. This
    /// is the random-access primitive proxy file descriptors are built on
    /// (doc §8 — streaming without extraction).
    pub fn read_at(&self, path: String, offset: u64, len: u32) -> FfiResult<Vec<u8>> {
        // 8 MiB per call keeps a misbehaving caller from ballooning the
        // process; proxy fds read in much smaller chunks.
        let len = len.min(8 << 20) as usize;
        with_session(&self.inner, |s| {
            let mut buf = vec![0u8; len];
            let n = s.vfs().read_at(&path, offset, &mut buf)?;
            buf.truncate(n);
            Ok(buf)
        })
    }

    // -- Write surface (doc §7). Every mutation goes through the same locked
    // session; the caller flushes when a logical operation is complete so the
    // encrypted backing store is consistent. On a read-only filesystem (NTFS)
    // or a read-only backing fd these return an error rather than corrupting.

    /// Write `data` at `offset`, returning bytes written.
    pub fn write_at(&self, path: String, offset: u64, data: Vec<u8>) -> FfiResult<u32> {
        with_session(&self.inner, |s| Ok(s.vfs().write_at(&path, offset, &data)? as u32))
    }

    /// Create an empty regular file (errors if it already exists).
    pub fn create(&self, path: String) -> FfiResult<()> {
        with_session(&self.inner, |s| {
            s.vfs().create(&path)?;
            Ok(())
        })
    }

    /// Create a directory.
    pub fn mkdir(&self, path: String) -> FfiResult<()> {
        with_session(&self.inner, |s| {
            s.vfs().mkdir(&path)?;
            Ok(())
        })
    }

    /// Rename/move within the volume.
    pub fn rename(&self, from: String, to: String) -> FfiResult<()> {
        with_session(&self.inner, |s| {
            s.vfs().rename(&from, &to)?;
            Ok(())
        })
    }

    /// Remove a file or an empty directory.
    pub fn remove(&self, path: String) -> FfiResult<()> {
        with_session(&self.inner, |s| {
            s.vfs().unlink(&path)?;
            Ok(())
        })
    }

    /// Truncate (or extend) a file to `len` bytes.
    pub fn truncate(&self, path: String, len: u64) -> FfiResult<()> {
        with_session(&self.inner, |s| {
            s.vfs().truncate(&path, len)?;
            Ok(())
        })
    }

    /// Flush pending writes through every layer to the backing store. Call
    /// this once a logical operation (e.g. an import) is complete.
    pub fn flush(&self) -> FfiResult<()> {
        with_session(&self.inner, |s| {
            s.vfs().flush()?;
            Ok(())
        })
    }

    /// Zeroize keys through every layer and drop the filesystem. Idempotent.
    pub fn lock(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(s) = guard.take() {
                s.lock();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;

    fn fixture_fd() -> Option<i32> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/aes-sha_512-fat-512-pim0-plain.vc");
        let f = std::fs::File::open(path).ok()?;
        Some(f.into_raw_fd())
    }

    #[test]
    fn unlock_browse_read_lock_through_the_ffi_types() {
        let Some(fd) = fixture_fd() else {
            eprintln!("SKIP: fixture corpus not present");
            return;
        };
        let s = VaultSession::unlock_fd(fd, "vaultpony-fixture".into(), 0, Vec::new(), None).unwrap();
        let facts = s.facts().unwrap();
        assert_eq!(facts.scheme, "AES");
        assert_eq!(facts.filesystem, "Fat");

        let names: Vec<String> = s
            .list("/".into())
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"readme.txt".to_string()));

        let data = s.read_at("/readme.txt".into(), 0, 1024).unwrap();
        assert_eq!(data, b"VaultPony fixture tree v1\n");
        // Offset reads work (the proxy-fd primitive).
        let tail = s.read_at("/readme.txt".into(), 10, 1024).unwrap();
        assert_eq!(tail, b"fixture tree v1\n");

        s.lock();
        s.lock(); // idempotent
        assert!(matches!(s.list("/".into()), Err(VaultError::Internal)));
    }

    #[test]
    fn create_hidden_then_unlock_both_through_the_ffi() {
        // Exercises the fd-dup factory: create over one fd, then open the
        // outer and hidden volumes each by their own password.
        let tmp = std::env::temp_dir().join("vaultpony-ffi-hidden.vc");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .unwrap();
        let fd = f.into_raw_fd();
        create_hidden_container(
            fd,
            8 << 20,
            "outer-ffi".into(),
            "hidden-ffi".into(),
            0,
            2 << 20,
            "AES".into(),
            "SHA-512".into(),
            "exFAT".into(),
        )
        .unwrap();

        for pw in ["outer-ffi", "hidden-ffi"] {
            let dfd = std::fs::File::open(&tmp).unwrap().into_raw_fd();
            let s = VaultSession::unlock_fd(dfd, pw.into(), 0, Vec::new(), None).unwrap();
            // Fresh FAT root lists without error.
            s.list("/".into()).unwrap();
            s.lock();
        }
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn outer_protected_unlock_through_the_ffi() {
        // Create a hidden container, then open the OUTER volume with both
        // passwords through the protected fd path and browse it.
        let tmp = std::env::temp_dir().join("vaultpony-ffi-protected.vc");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .unwrap();
        create_hidden_container(
            f.into_raw_fd(),
            8 << 20,
            "outer-prot".into(),
            "hidden-prot".into(),
            0,
            2 << 20,
            "AES".into(),
            "SHA-512".into(),
            "FAT".into(),
        )
        .unwrap();

        let dfd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&tmp)
            .unwrap()
            .into_raw_fd();
        let s = VaultSession::unlock_outer_protected_fd(
            dfd,
            "outer-prot".into(),
            "hidden-prot".into(),
            0,
            None,
        )
        .unwrap();
        // Outer volume opens and lists (its fresh FAT root).
        s.list("/".into()).unwrap();
        // The mount is writable (protection guards writes into the hidden
        // region; ordinary outer writes still go through).
        assert!(s.facts().unwrap().writable);
        s.lock();

        // Wrong hidden password → same coarse error as any failed unlock.
        let dfd2 = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&tmp)
            .unwrap()
            .into_raw_fd();
        match VaultSession::unlock_outer_protected_fd(
            dfd2,
            "outer-prot".into(),
            "wrong-hidden".into(),
            0,
            None,
        ) {
            Err(VaultError::NotFoundOrWrongPassword) => {}
            Err(other) => panic!("expected NotFoundOrWrongPassword, got {other:?}"),
            Ok(_) => panic!("wrong hidden password should not unlock"),
        }
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn header_backup_and_restore_through_the_ffi() {
        use std::io::{Seek, SeekFrom, Write};
        let tmp = std::env::temp_dir().join("vaultpony-ffi-recover.vc");
        let size: u64 = 8 << 20;
        let corrupt = |off: u64, n: usize| {
            let mut f = std::fs::OpenOptions::new().write(true).open(&tmp).unwrap();
            f.seek(SeekFrom::Start(off)).unwrap();
            f.write_all(&vec![0xFFu8; n]).unwrap();
            f.flush().unwrap();
        };
        let open = |write: bool| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(write)
                .open(&tmp)
                .unwrap()
                .into_raw_fd()
        };

        // Fresh container.
        {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .unwrap();
            f.set_len(size).unwrap();
            create_container(
                f.into_raw_fd(),
                size,
                "recover-me".into(),
                0,
                Vec::new(),
                "AES".into(),
                "SHA-512".into(),
                "FAT".into(),
            )
            .unwrap();
        }

        // Export the 128 KiB header backup.
        let backup = export_header_backup(open(false)).unwrap();
        assert_eq!(backup.len(), 131072);

        // Embedded restore: wreck the primary header, restore from the
        // container's own tail backup, then wreck BOTH tail backups — unlock
        // must still work, proving the primary was actually rewritten.
        corrupt(0, 65536);
        restore_header_from_embedded(open(true), "recover-me".into(), 0, Vec::new()).unwrap();
        corrupt(size - 131072, 131072);
        VaultSession::unlock_fd(open(false), "recover-me".into(), 0, Vec::new(), None)
            .unwrap()
            .lock();

        // File restore: now every on-disk header slot is garbage; only the
        // exported file can bring it back.
        corrupt(0, 131072);
        assert!(VaultSession::unlock_fd(open(false), "recover-me".into(), 0, Vec::new(), None).is_err());
        restore_header_from_file(open(true), backup, "recover-me".into(), 0, Vec::new()).unwrap();
        VaultSession::unlock_fd(open(false), "recover-me".into(), 0, Vec::new(), None)
            .unwrap()
            .lock();

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn change_password_rekeys_but_keeps_data() {
        let tmp = std::env::temp_dir().join("vaultpony-ffi-chpw.vc");
        let size: u64 = 8 << 20;
        let open = |write: bool| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(write)
                .open(&tmp)
                .unwrap()
                .into_raw_fd()
        };
        // Fresh container, then write a file so we can prove data survives.
        {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .unwrap();
            f.set_len(size).unwrap();
            create_container(
                f.into_raw_fd(),
                size,
                "old-pass".into(),
                0,
                Vec::new(),
                "AES".into(),
                "SHA-512".into(),
                "FAT".into(),
            )
            .unwrap();
        }
        {
            let s = VaultSession::unlock_fd(open(true), "old-pass".into(), 0, Vec::new(), None).unwrap();
            s.create("/keep.txt".into()).unwrap();
            s.write_at("/keep.txt".into(), 0, b"survive".to_vec()).unwrap();
            s.flush().unwrap();
            s.lock();
        }

        change_password(
            open(true),
            "old-pass".into(),
            0,
            Vec::new(),
            "new-pass".into(),
            0,
            Vec::new(),
        )
        .unwrap();

        // Old password no longer works.
        assert!(VaultSession::unlock_fd(open(false), "old-pass".into(), 0, Vec::new(), None).is_err());
        // New password works and the file is intact — master keys unchanged.
        let s = VaultSession::unlock_fd(open(true), "new-pass".into(), 0, Vec::new(), None).unwrap();
        let data = s.read_at("/keep.txt".into(), 0, 64).unwrap();
        assert_eq!(&data, b"survive");
        s.lock();

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn wrong_password_maps_to_the_right_ffi_error() {
        let Some(fd) = fixture_fd() else {
            eprintln!("SKIP: fixture corpus not present");
            return;
        };
        match VaultSession::unlock_fd(fd, "nope".into(), 0, Vec::new(), None) {
            Err(VaultError::NotFoundOrWrongPassword) => {}
            Err(other) => panic!("wrong error: {other}"),
            Ok(_) => panic!("wrong password unlocked"),
        }
    }
}
