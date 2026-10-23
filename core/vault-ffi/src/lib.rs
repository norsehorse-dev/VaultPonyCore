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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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

/// The name VeraCrypt shows for a scheme ("AES-Twofish-Serpent" for
/// "AES(Twofish(Serpent))"). Shells show this everywhere a user sees a
/// scheme; the registry name stays what `create_container` takes and what
/// `VolumeFacts.scheme` reports. Unknown names come back unchanged.
#[uniffi::export]
pub fn scheme_display_name(name: String) -> String {
    vc_types::registry::scheme_by_name(&name)
        .map(|s| s.display_name())
        .unwrap_or(name)
}

/// The unlock "Hash" menu (2.0.0, issues #5 and #6): Auto, then each hash
/// in VeraCrypt's PRF order. `label` is the hash's name for the menu.
#[derive(uniffi::Record)]
pub struct HashChoice {
    pub filter: KdfFilter,
    pub label: String,
}

#[uniffi::export]
pub fn hash_choices() -> Vec<HashChoice> {
    let mut out = vec![HashChoice {
        filter: KdfFilter::Auto,
        label: "Auto".to_string(),
    }];
    out.extend(
        vc_types::KdfFilter::SINGLE
            .iter()
            .map(|(f, name)| HashChoice {
                filter: (*f).into(),
                label: name.to_string(),
            }),
    );
    out
}

/// The single-hash filter for a PRF name (as `VolumeFacts.prf` reports it),
/// or None. For remembering a hash the user picked.
#[uniffi::export]
pub fn kdf_filter_for_prf(prf: String) -> Option<KdfFilter> {
    vc_types::KdfFilter::for_prf(&prf).map(Into::into)
}

/// Whether an unlock under `filter` may run Argon2id, so the shell should
/// check free memory first (`argon2_memory_mib`).
#[uniffi::export]
pub fn kdf_filter_may_use_argon2(filter: KdfFilter) -> bool {
    vc_types::KdfFilter::from(filter).may_use_argon2()
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

/// Which key derivations an unlock may try. `Auto` matches VeraCrypt
/// (everything); a single hash matches VeraCrypt's PKCS-5 PRF choice;
/// `Pbkdf2Only` (every PBKDF2 hash) is kept for remembered Face ID and
/// biometric unlocks from before 2.0.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum KdfFilter {
    Auto,
    Pbkdf2Only,
    Argon2idOnly,
    Sha512,
    Sha256,
    Blake2s256,
    Whirlpool,
    Streebog,
}

impl From<vc_types::KdfFilter> for KdfFilter {
    fn from(f: vc_types::KdfFilter) -> Self {
        match f {
            vc_types::KdfFilter::Auto => KdfFilter::Auto,
            vc_types::KdfFilter::Pbkdf2Only => KdfFilter::Pbkdf2Only,
            vc_types::KdfFilter::Argon2idOnly => KdfFilter::Argon2idOnly,
            vc_types::KdfFilter::Sha512 => KdfFilter::Sha512,
            vc_types::KdfFilter::Sha256 => KdfFilter::Sha256,
            vc_types::KdfFilter::Blake2s256 => KdfFilter::Blake2s256,
            vc_types::KdfFilter::Whirlpool => KdfFilter::Whirlpool,
            vc_types::KdfFilter::Streebog => KdfFilter::Streebog,
        }
    }
}

impl From<KdfFilter> for vc_types::KdfFilter {
    fn from(f: KdfFilter) -> Self {
        match f {
            KdfFilter::Auto => vc_types::KdfFilter::Auto,
            KdfFilter::Pbkdf2Only => vc_types::KdfFilter::Pbkdf2Only,
            KdfFilter::Argon2idOnly => vc_types::KdfFilter::Argon2idOnly,
            KdfFilter::Sha512 => vc_types::KdfFilter::Sha512,
            KdfFilter::Sha256 => vc_types::KdfFilter::Sha256,
            KdfFilter::Blake2s256 => vc_types::KdfFilter::Blake2s256,
            KdfFilter::Whirlpool => vc_types::KdfFilter::Whirlpool,
            KdfFilter::Streebog => vc_types::KdfFilter::Streebog,
        }
    }
}

/// Memory one Argon2id derivation needs at `pim` (0 = default), in MiB, so
/// a shell can check free memory before starting an unlock that may run it.
#[uniffi::export]
pub fn argon2_memory_mib(pim: u32) -> u32 {
    vc_types::registry::argon2_cost(pim).memory_mib()
}

/// A cancel handle for one unlock-style call. Create it, pass it in, and
/// call `cancel()` from any thread; the call returns `Cancelled` before its
/// next key derivation. Nothing is written by a cancelled call.
#[derive(uniffi::Object, Default)]
pub struct UnlockCancel {
    flag: AtomicBool,
}

#[uniffi::export]
impl UnlockCancel {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

fn secret<'a>(
    passphrase: &'a [u8],
    pim: u32,
    kdf: KdfFilter,
    cancel: &'a Option<Arc<UnlockCancel>>,
) -> vault_core::UnlockSecret<'a> {
    vault_core::UnlockSecret {
        passphrase,
        pim,
        kdf: kdf.into(),
        cancel: cancel.as_deref().map(|c| &c.flag),
    }
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
    kdf: KdfFilter,
    cancel: Option<Arc<UnlockCancel>>,
) -> FfiResult<()> {
    let passphrase = Zeroizing::new(passphrase);
    let mut keyfiles = keyfiles;
    vc_crypto::check_keyfiles(&keyfiles)?;
    let effective = vc_crypto::apply_keyfiles(passphrase.as_bytes(), &keyfiles);
    for kf in &mut keyfiles {
        kf.zeroize();
    }
    let mut dev = unsafe { vc_io::RawFdDevice::from_raw_fd(fd) };
    vault_core::restore_header_from_file_with(
        &mut dev,
        &backup,
        &secret(&effective, pim, kdf, &cancel),
    )?;
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
    kdf: KdfFilter,
    cancel: Option<Arc<UnlockCancel>>,
) -> FfiResult<()> {
    let passphrase = Zeroizing::new(passphrase);
    let mut keyfiles = keyfiles;
    vc_crypto::check_keyfiles(&keyfiles)?;
    let effective = vc_crypto::apply_keyfiles(passphrase.as_bytes(), &keyfiles);
    for kf in &mut keyfiles {
        kf.zeroize();
    }
    let mut dev = unsafe { vc_io::RawFdDevice::from_raw_fd(fd) };
    vault_core::restore_header_from_embedded_with(
        &mut dev,
        &secret(&effective, pim, kdf, &cancel),
    )?;
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
    new_prf: Option<String>,
    kdf: KdfFilter,
    cancel: Option<Arc<UnlockCancel>>,
) -> FfiResult<()> {
    let old_passphrase = Zeroizing::new(old_passphrase);
    let new_passphrase = Zeroizing::new(new_passphrase);
    let mut old_keyfiles = old_keyfiles;
    let mut new_keyfiles = new_keyfiles;
    vc_crypto::check_keyfiles(&old_keyfiles)?;
    vc_crypto::check_keyfiles(&new_keyfiles)?;
    let old_secret = vc_crypto::apply_keyfiles(old_passphrase.as_bytes(), &old_keyfiles);
    let new_secret = vc_crypto::apply_keyfiles(new_passphrase.as_bytes(), &new_keyfiles);
    for kf in old_keyfiles.iter_mut().chain(new_keyfiles.iter_mut()) {
        kf.zeroize();
    }
    // Adopt the fd before any early return so it is always closed.
    let mut dev = unsafe { vc_io::RawFdDevice::from_raw_fd(fd) };
    let new_prf = match new_prf {
        None => None,
        Some(name) => Some(
            vc_types::registry::PRFS
                .iter()
                .find(|p| p.name == name)
                .ok_or(VaultError::Internal)?,
        ),
    };
    vault_core::change_password_to(
        &mut dev,
        &secret(&old_secret, old_pim, kdf, &cancel),
        &vault_core::UnlockSecret::new(&new_secret, new_pim),
        new_prf,
        new_passphrase.as_bytes(),
    )?;
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
    /// Argon2id needed more memory than the device could spare. Not a wrong
    /// password: the shell should say so and can offer a PBKDF2-only retry.
    #[error("not enough free memory for Argon2id ({needed_mib} MiB needed)")]
    KdfOutOfMemory { needed_mib: u32 },
    /// The caller's `UnlockCancel` fired. Nothing was written.
    #[error("cancelled")]
    Cancelled,
    /// A custom PIM below `default_pim` needs a password of at least
    /// `min_len` characters (VeraCrypt's rule: `default_pim` is 485 for
    /// PBKDF2 hashes and 12 for Argon2id).
    #[error("a PIM below {default_pim} needs a password of at least {min_len} characters")]
    PasswordTooShortForPim { min_len: u32, default_pim: u32 },
    /// A keyfile has no bytes; VeraCrypt refuses those too.
    #[error("a keyfile is empty")]
    EmptyKeyfile,
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
            VcError::KdfOutOfMemory { needed_mib } => VaultError::KdfOutOfMemory { needed_mib },
            VcError::Cancelled => VaultError::Cancelled,
            VcError::EmptyKeyfile => VaultError::EmptyKeyfile,
            VcError::PasswordTooShortForPim {
                min_len,
                default_pim,
            } => VaultError::PasswordTooShortForPim {
                min_len: min_len as u32,
                default_pim,
            },
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
    /// The hidden volume is what's open (the user typed its password).
    pub hidden: bool,
    /// Outer volume with hidden-volume write protection (both passwords).
    pub outer_protected: bool,
    /// Per-file size limit of the filesystem, if it has one (FAT: 4 GiB - 1).
    pub max_file_bytes: Option<u64>,
}

/// Total and free space of an unlocked volume. Separate from `VolumeFacts`
/// because the first call on a session counts free clusters, and the shells
/// refresh it after writes.
#[derive(uniffi::Record, Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeSpace {
    pub total_bytes: u64,
    pub free_bytes: u64,
    /// Allocation unit; every file takes a whole number of these.
    pub cluster_bytes: u64,
}

/// Let sessions unlocked from now on export a key handoff for the iOS File
/// Provider extension ([`VaultSession::export_handoff`]). Off by default; the
/// iOS app turns it on at launch. Android and desktop never call this, so
/// their sessions keep master keys only inside the XTS engine.
#[uniffi::export]
pub fn enable_files_handoff(on: bool) {
    vault_core::enable_handoff(on);
}

/// Largest single `read_at` in normal processes (8 MiB) and under the
/// low-memory profile (1 MiB).
const READ_CAP: u32 = 8 << 20;
const READ_CAP_LOW_MEMORY: u32 = 1 << 20;
static READ_CAP_NOW: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(READ_CAP);

/// Low-memory profile for processes with a tight memory limit (the iOS File
/// Provider extension, about 20 MB): caps `read_at` at 1 MiB and the exFAT
/// allocation-bitmap copy at 1 MiB (larger bitmaps are read from disk).
/// Process-wide; call before unlocking or importing.
#[uniffi::export]
pub fn set_low_memory_profile(on: bool) {
    if on {
        READ_CAP_NOW.store(READ_CAP_LOW_MEMORY, Ordering::Relaxed);
        norse_exfat::alloc::set_max_cached_bitmap_bytes(1 << 20);
    } else {
        READ_CAP_NOW.store(READ_CAP, Ordering::Relaxed);
        norse_exfat::alloc::set_max_cached_bitmap_bytes(
            norse_exfat::alloc::DEFAULT_MAX_CACHED_BITMAP_BYTES,
        );
    }
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
        kdf: KdfFilter,
        cancel: Option<Arc<UnlockCancel>>,
        listener: Option<std::sync::Arc<dyn UnlockProgressListener>>,
    ) -> FfiResult<std::sync::Arc<Self>> {
        let passphrase = Zeroizing::new(passphrase);
        // Fold any keyfiles into the passphrase exactly as the CLI does; an
        // empty list is the identity. The derived secret is `Zeroizing`, and
        // we wipe the raw keyfile bytes as soon as they've been mixed in.
        let mut keyfiles = keyfiles;
        vc_crypto::check_keyfiles(&keyfiles)?;
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
        let session = vault_core::Session::unlock_device_with(
            Box::new(dev),
            &self::secret(&secret, pim, kdf, &cancel),
            &mut progress,
        )?;
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
        kdf: KdfFilter,
        cancel: Option<Arc<UnlockCancel>>,
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
        let session = vault_core::Session::unlock_outer_protected_device_with(
            Box::new(dev),
            &secret(outer_passphrase.as_bytes(), pim, kdf, &cancel),
            hidden_passphrase.as_bytes(),
            &mut progress,
        )?;
        Ok(std::sync::Arc::new(Self {
            inner: Mutex::new(Some(session)),
        }))
    }

    /// Open a volume another process unlocked, from its
    /// [`export_handoff`](Self::export_handoff) blob and this process's own
    /// dup'd fd to the same container (owned and closed by the session, like
    /// `unlock_fd`). No KDF runs. `NotFoundOrWrongPassword` if the fd is not
    /// the container the blob came from. The blob is wiped before returning.
    #[uniffi::constructor]
    pub fn import_handoff_fd(fd: i32, blob: Vec<u8>) -> FfiResult<std::sync::Arc<Self>> {
        let blob = Zeroizing::new(blob);
        // SAFETY: ownership contract documented on RawFdDevice.
        let dev = unsafe { vc_io::RawFdDevice::from_raw_fd(fd) };
        let session = vault_core::Session::import_handoff(Box::new(dev), &blob)?;
        Ok(std::sync::Arc::new(Self {
            inner: Mutex::new(Some(session)),
        }))
    }

    /// Keys, scheme, geometry and a container fingerprint for
    /// [`import_handoff_fd`](Self::import_handoff_fd) in another process.
    /// Holds master keys: keep it in memory, pass it straight over XPC, and
    /// drop it. Fails with `Internal` unless `enable_files_handoff(true)` was
    /// called before this session was unlocked.
    pub fn export_handoff(&self) -> FfiResult<Vec<u8>> {
        with_session(&self.inner, |s| {
            let mut blob = s.export_handoff()?;
            // UniFFI copies this into a RustBuffer and frees both without
            // wiping them; THREAT_MODEL.md (key handoff) accounts for it.
            Ok(std::mem::take(&mut *blob))
        })
    }

    /// Drop the filesystem and mount it again over the same keys, discarding
    /// cached allocation state. Call before touching the volume when another
    /// process (the app or its File Provider extension) wrote to it since this
    /// session last flushed.
    pub fn remount(&self) -> FfiResult<()> {
        with_session(&self.inner, |s| {
            s.remount()?;
            Ok(())
        })
    }

    /// Put the file at `src` in place of `dst` (replacing it if present), then
    /// flush. Not atomic on FAT or exFAT: a kill in between leaves `src`
    /// complete and `dst` missing; rename `src` in to recover.
    pub fn replace(&self, src: String, dst: String) -> FfiResult<()> {
        with_session(&self.inner, |s| {
            s.replace(&src, &dst)?;
            Ok(())
        })
    }

    pub fn facts(&self) -> FfiResult<VolumeFacts> {
        with_session(&self.inner, |s| {
            let (scheme, prf) = (s.scheme().to_string(), s.prf().to_string());
            let (hidden, outer_protected) = (s.is_hidden(), s.is_outer_protected());
            let max_file_bytes = s.max_file_bytes();
            let vfs = s.vfs();
            Ok(VolumeFacts {
                scheme,
                prf,
                filesystem: format!("{:?}", vfs.kind()),
                writable: vfs.writable(),
                hidden,
                outer_protected,
                max_file_bytes,
            })
        })
    }

    /// Total and free space. Fails for filesystems that can't report it
    /// (NTFS, read-only); the shells then hide the figure.
    pub fn space(&self) -> FfiResult<VolumeSpace> {
        with_session(&self.inner, |s| {
            let sp = s.space()?;
            Ok(VolumeSpace {
                total_bytes: sp.total_bytes,
                free_bytes: sp.free_bytes,
                cluster_bytes: sp.cluster_bytes,
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
        // 8 MiB per call (1 MiB under the low-memory profile) keeps a
        // misbehaving caller from ballooning the process; proxy fds read in
        // much smaller chunks.
        let len = len.min(READ_CAP_NOW.load(Ordering::Relaxed)) as usize;
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
        with_session(&self.inner, |s| {
            Ok(s.vfs().write_at(&path, offset, &data)? as u32)
        })
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
        let s = VaultSession::unlock_fd(
            fd,
            "vaultpony-fixture".into(),
            0,
            Vec::new(),
            KdfFilter::Auto,
            None,
            None,
        )
        .unwrap();
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
            let s =
                VaultSession::unlock_fd(dfd, pw.into(), 0, Vec::new(), KdfFilter::Auto, None, None)
                    .unwrap();
            // Fresh FAT root lists without error.
            s.list("/".into()).unwrap();
            // The facts say which volume opened; only the hidden password
            // marks a session hidden.
            let facts = s.facts().unwrap();
            assert_eq!(facts.hidden, pw == "hidden-ffi");
            assert!(!facts.outer_protected);
            assert_eq!(facts.max_file_bytes, None, "exFAT has no 4 GiB cap");
            let space = s.space().unwrap();
            assert!(space.total_bytes > 0 && space.free_bytes <= space.total_bytes);
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
            KdfFilter::Auto,
            None,
            None,
        )
        .unwrap();
        // Outer volume opens and lists (its fresh FAT root).
        s.list("/".into()).unwrap();
        // The mount is writable (protection guards writes into the hidden
        // region; ordinary outer writes still go through).
        let facts = s.facts().unwrap();
        assert!(facts.writable);
        assert!(facts.outer_protected);
        assert!(!facts.hidden);
        assert_eq!(facts.max_file_bytes, Some(u32::MAX as u64));
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
            KdfFilter::Auto,
            None,
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
        restore_header_from_embedded(
            open(true),
            "recover-me".into(),
            0,
            Vec::new(),
            KdfFilter::Auto,
            None,
        )
        .unwrap();
        corrupt(size - 131072, 131072);
        VaultSession::unlock_fd(
            open(false),
            "recover-me".into(),
            0,
            Vec::new(),
            KdfFilter::Auto,
            None,
            None,
        )
        .unwrap()
        .lock();

        // File restore: now every on-disk header slot is garbage; only the
        // exported file can bring it back.
        corrupt(0, 131072);
        assert!(VaultSession::unlock_fd(
            open(false),
            "recover-me".into(),
            0,
            Vec::new(),
            KdfFilter::Auto,
            None,
            None
        )
        .is_err());
        restore_header_from_file(
            open(true),
            backup,
            "recover-me".into(),
            0,
            Vec::new(),
            KdfFilter::Auto,
            None,
        )
        .unwrap();
        VaultSession::unlock_fd(
            open(false),
            "recover-me".into(),
            0,
            Vec::new(),
            KdfFilter::Auto,
            None,
            None,
        )
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
            let s = VaultSession::unlock_fd(
                open(true),
                "old-pass".into(),
                0,
                Vec::new(),
                KdfFilter::Auto,
                None,
                None,
            )
            .unwrap();
            s.create("/keep.txt".into()).unwrap();
            s.write_at("/keep.txt".into(), 0, b"survive".to_vec())
                .unwrap();
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
            None,
            KdfFilter::Auto,
            None,
        )
        .unwrap();

        // Old password no longer works.
        assert!(VaultSession::unlock_fd(
            open(false),
            "old-pass".into(),
            0,
            Vec::new(),
            KdfFilter::Auto,
            None,
            None
        )
        .is_err());
        // New password works and the file is intact — master keys unchanged.
        let s = VaultSession::unlock_fd(
            open(true),
            "new-pass".into(),
            0,
            Vec::new(),
            KdfFilter::Auto,
            None,
            None,
        )
        .unwrap();
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
        match VaultSession::unlock_fd(
            fd,
            "nope".into(),
            0,
            Vec::new(),
            KdfFilter::Auto,
            None,
            None,
        ) {
            Err(VaultError::NotFoundOrWrongPassword) => {}
            Err(other) => panic!("wrong error: {other}"),
            Ok(_) => panic!("wrong password unlocked"),
        }
    }

    /// Free space drops by exactly the clusters a write takes, survives a
    /// lock and re-unlock (FAT recounts, exFAT reloads its bitmap), and comes
    /// back when the file is removed. Both filesystems VaultPony creates.
    #[test]
    fn space_tracks_writes_and_survives_reopen() {
        for fs in ["FAT", "exFAT"] {
            let tmp = std::env::temp_dir().join(format!("vaultpony-ffi-space-{fs}.vc"));
            let f = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .unwrap();
            create_container(
                f.into_raw_fd(),
                8 << 20,
                "space-pw".into(),
                0,
                Vec::new(),
                "AES".into(),
                "SHA-512".into(),
                fs.into(),
            )
            .unwrap();
            let open = || {
                let fd = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&tmp)
                    .unwrap()
                    .into_raw_fd();
                VaultSession::unlock_fd(
                    fd,
                    "space-pw".into(),
                    0,
                    Vec::new(),
                    KdfFilter::Auto,
                    None,
                    None,
                )
                .unwrap()
            };

            let s = open();
            let before = s.space().unwrap();
            assert!(before.cluster_bytes > 0, "{fs}");
            assert!(
                before.free_bytes > 0 && before.free_bytes <= before.total_bytes,
                "{fs}"
            );

            let len: u64 = 300 * 1024 + 17;
            s.create("/blob.bin".into()).unwrap();
            s.write_at("/blob.bin".into(), 0, vec![0xA5; len as usize])
                .unwrap();
            s.flush().unwrap();
            let after = s.space().unwrap();
            let on_disk = len.div_ceil(before.cluster_bytes) * before.cluster_bytes;
            assert_eq!(before.free_bytes - after.free_bytes, on_disk, "{fs}: write");
            s.lock();

            let s = open();
            assert_eq!(s.space().unwrap(), after, "{fs}: reopen");
            s.remove("/blob.bin".into()).unwrap();
            s.flush().unwrap();
            assert_eq!(
                s.space().unwrap().free_bytes,
                before.free_bytes,
                "{fs}: remove"
            );
            s.lock();

            let s = open();
            assert_eq!(
                s.space().unwrap().free_bytes,
                before.free_bytes,
                "{fs}: reopen after remove"
            );
            s.lock();
            let _ = std::fs::remove_file(&tmp);
        }
    }

    #[test]
    fn handoff_through_the_ffi_types() {
        enable_files_handoff(true);
        let tmp =
            std::env::temp_dir().join(format!("vaultpony-ffi-handoff-{}.vc", std::process::id()));
        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .unwrap();
        let pw = "ffi-handoff-password-000001";
        create_container(
            f.into_raw_fd(),
            8 << 20,
            pw.into(),
            1,
            Vec::new(),
            "AES".into(),
            "SHA-512".into(),
            "exFAT".into(),
        )
        .unwrap();
        let fd = || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&tmp)
                .unwrap()
                .into_raw_fd()
        };
        let app = VaultSession::unlock_fd(
            fd(),
            pw.into(),
            1,
            Vec::new(),
            KdfFilter::Pbkdf2Only,
            None,
            None,
        )
        .unwrap();
        app.create("/a.txt".into()).unwrap();
        app.write_at("/a.txt".into(), 0, b"from the app".to_vec())
            .unwrap();
        app.flush().unwrap();

        // (The low-memory profile is process-wide, so it is exercised in
        // vault-core's own low_memory test binary, not here.)
        let ext = VaultSession::import_handoff_fd(fd(), app.export_handoff().unwrap()).unwrap();
        assert_eq!(
            ext.read_at("/a.txt".into(), 0, 64).unwrap(),
            b"from the app"
        );
        ext.create("/.b.part".into()).unwrap();
        ext.write_at("/.b.part".into(), 0, b"from Files".to_vec())
            .unwrap();
        ext.flush().unwrap();
        ext.replace("/.b.part".into(), "/b.txt".into()).unwrap();
        ext.lock();

        app.remount().unwrap();
        assert_eq!(app.read_at("/b.txt".into(), 0, 64).unwrap(), b"from Files");
        assert_eq!(app.list("/".into()).unwrap().len(), 2);

        // A blob is refused on any other file.
        let other =
            std::env::temp_dir().join(format!("vaultpony-ffi-handoff-b-{}.vc", std::process::id()));
        std::fs::copy(&tmp, &other).unwrap();
        let mut bytes = std::fs::read(&other).unwrap();
        bytes[0] ^= 1; // the salt of the primary header
        std::fs::write(&other, bytes).unwrap();
        let other_fd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&other)
            .unwrap()
            .into_raw_fd();
        assert!(matches!(
            VaultSession::import_handoff_fd(other_fd, app.export_handoff().unwrap()),
            Err(VaultError::NotFoundOrWrongPassword)
        ));
        app.lock();
        std::fs::remove_file(&tmp).ok();
        std::fs::remove_file(&other).ok();
    }
}
