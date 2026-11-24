//! Unlocked-volume sessions (doc §5).
//!
//! A `Session` is one unlocked container: the decrypted device wrapped in
//! its filesystem adapter. Master keys live inside the XTS engine (plus one
//! zeroizing copy when the process enabled the File Provider handoff); the
//! parsed header (and its key material) is zeroized before `unlock`
//! returns. The mount table, auto-lock timers, and the remembered-parameters
//! cache arrive with the shells (P3+) — this is the core they will call.

use crate::handoff::{handoff_enabled, KeyRecord};
use crate::readonly::{ReadOnlyDevice, ReadOnlyVfs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use vc_format::{
    find_header, find_header_at, position_offset, DecryptedDevice, FoundHeader, ProtectedDevice,
    UnlockProgress, UnlockSecret,
};
use vc_fs::Vfs;
use vc_io::{BlockDevice, FileDevice};
use vc_types::{consts, HeaderPosition, VcError, VcResult};
use zeroize::Zeroizing;

/// Which filesystem a new container is formatted with. FAT is the universal
/// default; exFAT lifts the 4 GiB per-file limit for large-file vaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerFs {
    Fat,
    Exfat,
}

/// Create a brand-new, ready-to-use container: write the VeraCrypt volume,
/// then lay a fresh filesystem in the decrypted data area so it opens as an
/// empty volume rather than "unknown filesystem" (doc §7). `dev` must already
/// be `params.size` bytes.
pub fn create_container(
    mut dev: Box<dyn vc_io::BlockDevice>,
    params: &vc_format::CreateParams<'_>,
    fs: ContainerFs,
) -> VcResult<()> {
    vc_format::create_volume(dev.as_mut(), params)?;
    format_data(dev, params, fs)
}

/// A random 32-bit id for a fresh exFAT volume. Non-secret, and encrypted on
/// disk anyway (it lives inside the volume), but drawn from the OS CSPRNG.
fn random_serial() -> VcResult<u32> {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|e| VcError::Internal(format!("rng: {e}")))?;
    Ok(u32::from_le_bytes(b))
}

/// Re-derive the master keys through the header for `params`, open the
/// decrypted data area, and lay a fresh filesystem in it.
fn format_data(
    mut dev: Box<dyn vc_io::BlockDevice>,
    params: &vc_format::CreateParams<'_>,
    fs: ContainerFs,
) -> VcResult<()> {
    let secret = vc_crypto::apply_keyfiles(params.passphrase, params.keyfiles);
    // We just wrote this header, so search only its PRF: found on the first
    // derivation instead of after the whole sweep.
    let kdf = vc_types::KdfFilter::for_prf(params.prf.name).unwrap_or(match params.prf.kdf {
        vc_types::Kdf::Pbkdf2 => vc_types::KdfFilter::Pbkdf2Only,
        vc_types::Kdf::Argon2id => vc_types::KdfFilter::Argon2idOnly,
    });
    let found = find_header(
        dev.as_mut(),
        &UnlockSecret {
            kdf,
            ..UnlockSecret::new(secret.as_slice(), params.pim)
        },
        &mut |_, _, _| {},
    )?;
    let xts = vc_crypto::SchemeXts::new(
        found.scheme,
        &found.header.master_keys[..found.scheme.key_bytes()],
    )?;
    let geometry = found.header.geometry;
    let decrypted = DecryptedDevice::new(dev, xts, &geometry);
    match fs {
        ContainerFs::Fat => vc_fs::format_fat(Box::new(decrypted)),
        ContainerFs::Exfat => vc_fs::format_exfat(Box::new(decrypted), random_serial()?),
    }
}

/// Create a container with a hidden volume inside it. `make_dev` returns a
/// fresh handle to the same backing store on each call (a re-open or a dup'd
/// fd) — three are used: one to write both headers, one to format the outer
/// FAT, one to format the hidden FAT. The outer is formatted first (its empty
/// filesystem spans the whole area); the hidden then formats the tail it
/// occupies, which the outer sees as free space (doc §9). `outer`/`hidden`
/// carry each volume's own secret; both share the container `size`.
pub fn create_container_with_hidden(
    mut make_dev: impl FnMut() -> VcResult<Box<dyn vc_io::BlockDevice>>,
    outer: &vc_format::CreateParams<'_>,
    hidden: &vc_format::CreateParams<'_>,
    hidden_data_size: u64,
    fs: ContainerFs,
) -> VcResult<()> {
    {
        let mut dev = make_dev()?;
        vc_format::create_volume(dev.as_mut(), outer)?;
        vc_format::create_hidden(dev.as_mut(), hidden, hidden_data_size)?;
    }
    format_data(make_dev()?, outer, fs)?;
    format_data(make_dev()?, hidden, fs)?;
    Ok(())
}

/// Opaque handle the shells hold; maps to an entry in the mount table (P3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

/// One unlocked container.
pub struct Session {
    vfs: Box<dyn Vfs>,
    /// The decrypted (and, for outer-protected sessions, shielded) device the
    /// filesystem sits on. Shared with `vfs` so [`Session::remount`] can drop
    /// the filesystem and open a fresh one over the same keys.
    device: SharedDevice,
    record: KeyRecord,
    /// Hidden-volume protection latch, outer-protected sessions only.
    latch: Option<Arc<AtomicBool>>,
    scheme: &'static str,
    prf: &'static str,
    /// The header that opened this session sits in a hidden-volume slot.
    hidden: bool,
    /// Outer volume opened with hidden-volume write protection.
    outer_protected: bool,
    /// Opened in TrueCrypt mode: the device and filesystem refuse writes.
    truecrypt: bool,
}

/// A block device several owners can hold: the session and its filesystem.
#[derive(Clone)]
struct SharedDevice(Arc<Mutex<Box<dyn BlockDevice>>>);

impl SharedDevice {
    fn new(dev: Box<dyn BlockDevice>) -> Self {
        Self(Arc::new(Mutex::new(dev)))
    }

    fn with<T>(&self, f: impl FnOnce(&mut dyn BlockDevice) -> VcResult<T>) -> VcResult<T> {
        let mut guard = self
            .0
            .lock()
            .map_err(|_| VcError::Internal("device lock poisoned".into()))?;
        f(guard.as_mut())
    }
}

impl BlockDevice for SharedDevice {
    fn len(&mut self) -> VcResult<u64> {
        self.with(|d| d.len())
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> VcResult<()> {
        self.with(|d| d.read_at(offset, buf))
    }
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> VcResult<()> {
        self.with(|d| d.write_at(offset, buf))
    }
    fn flush(&mut self) -> VcResult<()> {
        self.with(|d| d.flush())
    }
}

/// Stand-in filesystem while a remount is between dropping the old one and
/// opening the new one (and if reopening fails): every call errors.
struct Unmounted;

impl Vfs for Unmounted {
    fn kind(&self) -> vc_fs::FsKind {
        vc_fs::FsKind::Unknown
    }
    fn writable(&self) -> bool {
        false
    }
    fn list(&mut self, _: &str) -> VcResult<Vec<vc_fs::DirEntry>> {
        Err(unmounted())
    }
    fn stat(&mut self, _: &str) -> VcResult<vc_fs::DirEntry> {
        Err(unmounted())
    }
    fn read_at(&mut self, _: &str, _: u64, _: &mut [u8]) -> VcResult<usize> {
        Err(unmounted())
    }
    fn write_at(&mut self, _: &str, _: u64, _: &[u8]) -> VcResult<usize> {
        Err(unmounted())
    }
    fn create(&mut self, _: &str) -> VcResult<()> {
        Err(unmounted())
    }
    fn mkdir(&mut self, _: &str) -> VcResult<()> {
        Err(unmounted())
    }
    fn rename(&mut self, _: &str, _: &str) -> VcResult<()> {
        Err(unmounted())
    }
    fn unlink(&mut self, _: &str) -> VcResult<()> {
        Err(unmounted())
    }
    fn truncate(&mut self, _: &str, _: u64) -> VcResult<()> {
        Err(unmounted())
    }
    fn flush(&mut self) -> VcResult<()> {
        Ok(())
    }
}

fn unmounted() -> VcError {
    VcError::Internal("filesystem not mounted".into())
}

/// The decrypted device a session sits on: TrueCrypt volumes get the
/// write-refusing wrapper underneath everything else.
fn session_device(dev: Box<dyn BlockDevice>, truecrypt: bool) -> SharedDevice {
    if truecrypt {
        SharedDevice::new(Box::new(ReadOnlyDevice(dev)))
    } else {
        SharedDevice::new(dev)
    }
}

/// Mount the filesystem over a session's device, read-only for TrueCrypt.
fn mount(device: &SharedDevice, truecrypt: bool) -> VcResult<Box<dyn Vfs>> {
    let vfs = vc_fs::open_volume(Box::new(device.clone()))?;
    Ok(if truecrypt {
        Box::new(ReadOnlyVfs(vfs))
    } else {
        vfs
    })
}

/// Capture how a header opened, before the header (and its keys) is dropped.
fn key_record(
    dev: &mut dyn BlockDevice,
    found: &FoundHeader,
    protected: Option<(u64, u64)>,
) -> VcResult<KeyRecord> {
    let container_len = dev.len()?;
    let header_offset = position_offset(found.header.position, container_len)
        .ok_or_else(|| VcError::Internal("header position outside container".into()))?;
    let mut salt = [0u8; consts::SALT_LEN];
    dev.read_at(header_offset, &mut salt)?;
    let keys = if handoff_enabled() {
        Zeroizing::new(found.header.master_keys[..found.scheme.key_bytes()].to_vec())
    } else {
        Zeroizing::new(Vec::new())
    };
    Ok(KeyRecord {
        keys,
        scheme: found.scheme,
        prf: found.prf,
        geometry: found.header.geometry,
        header_offset,
        salt,
        container_len,
        hidden: found.header.position.is_hidden(),
        protected,
        truecrypt: found.truecrypt,
    })
}

impl Session {
    /// Unlock flow (doc §6): full ordered candidate search, then FS
    /// detection and adapter construction (doc §7).
    pub fn unlock(
        path: &Path,
        passphrase: &[u8],
        pim: u32,
        progress: &mut UnlockProgress<'_>,
    ) -> VcResult<Self> {
        Self::unlock_with(path, passphrase, pim, false, progress)
    }

    /// Unlock with an explicit read/write mode. Writable sessions open the
    /// container file read-write; whether the *filesystem* accepts writes
    /// is still the adapter's call (`Vfs::writable`).
    pub fn unlock_with(
        path: &Path,
        passphrase: &[u8],
        pim: u32,
        writable: bool,
        progress: &mut UnlockProgress<'_>,
    ) -> VcResult<Self> {
        let dev = if writable {
            FileDevice::open_rw(path)?
        } else {
            FileDevice::open_read(path)?
        };
        Self::unlock_device(Box::new(dev), passphrase, pim, progress)
    }

    /// Unlock over an already-open block device. This is the mobile entry
    /// point: shells hand a dup'd fd across FFI (`vc_io::RawFdDevice`) and
    /// the core never touches platform storage APIs (doc §5).
    pub fn unlock_device(
        dev: Box<dyn vc_io::BlockDevice>,
        passphrase: &[u8],
        pim: u32,
        progress: &mut UnlockProgress<'_>,
    ) -> VcResult<Self> {
        Self::unlock_device_with(dev, &UnlockSecret::new(passphrase, pim), progress)
    }

    /// [`unlock_device`](Self::unlock_device) with the full secret: a KDF
    /// filter to narrow the search and a cancel flag the shell can raise
    /// from its UI thread.
    pub fn unlock_device_with(
        mut dev: Box<dyn vc_io::BlockDevice>,
        secret: &UnlockSecret<'_>,
        progress: &mut UnlockProgress<'_>,
    ) -> VcResult<Self> {
        let found = find_header(dev.as_mut(), secret, progress)?;
        let record = key_record(dev.as_mut(), &found, None)?;
        let xts = vc_crypto::SchemeXts::new(
            found.scheme,
            &found.header.master_keys[..found.scheme.key_bytes()],
        )?;
        // `found.header` (incl. master keys) is zeroized on drop here; from
        // this point key material lives inside the XTS engine, plus the
        // record's copy when handoff is enabled (THREAT_MODEL.md).
        let geometry = found.header.geometry;
        let hidden = found.header.position.is_hidden();
        let truecrypt = found.truecrypt;
        let device = session_device(
            Box::new(DecryptedDevice::new(dev, xts, &geometry)),
            truecrypt,
        );
        let vfs = mount(&device, truecrypt)?;
        Ok(Self {
            vfs,
            device,
            record,
            latch: None,
            scheme: found.scheme.name,
            prf: found.prf.name,
            hidden,
            outer_protected: false,
            truecrypt,
        })
    }

    /// Open a volume in a second process from a [`Session::export_handoff`]
    /// blob and that process's own fd to the same container. No KDF runs.
    /// Fails with `NotFoundOrWrongPassword` if `dev` is not the container the
    /// blob came from (length and header salt are checked).
    pub fn import_handoff(mut dev: Box<dyn BlockDevice>, blob: &[u8]) -> VcResult<Self> {
        let (mut record, tripped) = KeyRecord::decode(blob)?;
        record.check_container(dev.as_mut())?;
        let xts = vc_crypto::SchemeXts::new(record.scheme, &record.keys)?;
        if !handoff_enabled() {
            record.keys = Zeroizing::new(Vec::new());
        }
        let decrypted = DecryptedDevice::new(dev, xts, &record.geometry);
        let truecrypt = record.truecrypt;
        let (device, latch) = match record.protected {
            Some((start, len)) => {
                let latch = Arc::new(AtomicBool::new(tripped));
                let protected =
                    ProtectedDevice::with_latch(Box::new(decrypted), start, len, latch.clone());
                (SharedDevice::new(Box::new(protected)), Some(latch))
            }
            None => (session_device(Box::new(decrypted), truecrypt), None),
        };
        let vfs = mount(&device, truecrypt)?;
        Ok(Self {
            vfs,
            device,
            scheme: record.scheme.name,
            prf: record.prf.name,
            hidden: record.hidden,
            outer_protected: latch.is_some(),
            latch,
            record,
            truecrypt,
        })
    }

    /// Everything another process needs to open this volume without the
    /// password: scheme, master keys, geometry, container fingerprint. Never
    /// the password, PIM or keyfiles. Only for sessions unlocked after
    /// [`crate::enable_handoff`]. The caller must keep the blob in memory and
    /// wipe it after use.
    pub fn export_handoff(&self) -> VcResult<Zeroizing<Vec<u8>>> {
        let tripped = self
            .latch
            .as_ref()
            .is_some_and(|l| l.load(Ordering::Relaxed));
        self.record.encode(tripped)
    }

    /// Drop the filesystem and mount it again over the same decrypted device.
    /// For when another process wrote to the volume since this session last
    /// looked: every cached allocation state (FAT FSInfo, the exFAT bitmap
    /// copy, the free-space count) is thrown away. Flush before another
    /// process writes, so nothing stale is pending when this runs.
    pub fn remount(&mut self) -> VcResult<()> {
        let mut old = std::mem::replace(&mut self.vfs, Box::new(Unmounted));
        // Its cached metadata predates the other process's writes.
        old.release_without_writing();
        drop(old);
        self.vfs = mount(&self.device, self.truecrypt)?;
        Ok(())
    }

    /// Replace `dst` with `src` (see [`Vfs::replace`]).
    pub fn replace(&mut self, src: &str, dst: &str) -> VcResult<()> {
        self.vfs.replace(src, dst)
    }

    /// Open the OUTER volume read-write with hidden-volume protection
    /// (doc §9). Both passwords are required: `outer_passphrase` unlocks the
    /// outer volume for writing, `hidden_passphrase` unlocks the hidden
    /// header only to learn the region to protect. Any outer write that
    /// would land in that region is refused and latches the whole volume
    /// read-only (`VcError::HiddenVolumeProtected`).
    ///
    /// Fails with `NotFoundOrWrongPassword` if either password is wrong or
    /// the container has no hidden volume — the error is the same whether
    /// there is no hidden volume or the hidden password is wrong, so this
    /// path reveals nothing a plain unlock wouldn't (doc §11).
    pub fn unlock_outer_protected(
        path: &Path,
        outer_passphrase: &[u8],
        hidden_passphrase: &[u8],
        pim: u32,
        progress: &mut UnlockProgress<'_>,
    ) -> VcResult<Self> {
        let dev = FileDevice::open_rw(path)?;
        Self::unlock_outer_protected_device(
            Box::new(dev),
            outer_passphrase,
            hidden_passphrase,
            pim,
            progress,
        )
    }

    /// Hidden-protected outer unlock over an already-open, writable block
    /// device — the mobile entry point (shells hand a dup'd rw fd across FFI,
    /// exactly like `unlock_device`). Same contract and error behaviour as
    /// [`unlock_outer_protected`].
    pub fn unlock_outer_protected_device(
        dev: Box<dyn vc_io::BlockDevice>,
        outer_passphrase: &[u8],
        hidden_passphrase: &[u8],
        pim: u32,
        progress: &mut UnlockProgress<'_>,
    ) -> VcResult<Self> {
        Self::unlock_outer_protected_device_with(
            dev,
            &UnlockSecret::new(outer_passphrase, pim),
            hidden_passphrase,
            progress,
        )
    }

    /// [`unlock_outer_protected_device`](Self::unlock_outer_protected_device)
    /// with the full outer secret. The hidden lookup reuses its PIM, KDF
    /// filter and cancel flag with `hidden_passphrase`. The filter applies to
    /// both lookups, so a user who narrows it must pick one that covers both
    /// volumes (VeraCrypt lets outer and hidden use different KDFs).
    pub fn unlock_outer_protected_device_with(
        mut dev: Box<dyn vc_io::BlockDevice>,
        outer_secret: &UnlockSecret<'_>,
        hidden_passphrase: &[u8],
        progress: &mut UnlockProgress<'_>,
    ) -> VcResult<Self> {
        // Protection exists to let the outer volume be written; TrueCrypt
        // volumes never are.
        if outer_secret.truecrypt {
            return Err(VcError::TrueCryptReadOnly);
        }
        // Outer must resolve to a non-hidden slot.
        let outer = find_header_at(
            dev.as_mut(),
            outer_secret,
            &[HeaderPosition::Primary, HeaderPosition::BackupPrimary],
            progress,
        )?;

        // Hidden header, for the protected region only. We keep no hidden
        // keys — just its geometry.
        let hidden = find_header_at(
            dev.as_mut(),
            &UnlockSecret {
                passphrase: hidden_passphrase,
                legacy_passphrase: None,
                ..*outer_secret
            },
            &[HeaderPosition::Hidden, HeaderPosition::BackupHidden],
            &mut |_, _, _| {},
        )?;

        // Translate the hidden data area into the outer volume's coordinate
        // space (0 = outer data-area start).
        let outer_geo = outer.header.geometry;
        let hidden_geo = hidden.header.geometry;
        let protected_start = hidden_geo
            .encrypted_area_start
            .checked_sub(outer_geo.encrypted_area_start)
            .ok_or_else(|| VcError::Internal("hidden region precedes outer data".into()))?;
        if protected_start + hidden_geo.encrypted_area_size > outer_geo.encrypted_area_size {
            return Err(VcError::Internal(
                "hidden region exceeds outer data area".into(),
            ));
        }

        let record = key_record(
            dev.as_mut(),
            &outer,
            Some((protected_start, hidden_geo.encrypted_area_size)),
        )?;
        let xts = vc_crypto::SchemeXts::new(
            outer.scheme,
            &outer.header.master_keys[..outer.scheme.key_bytes()],
        )?;
        let decrypted = DecryptedDevice::new(dev, xts, &outer_geo);
        let latch = Arc::new(AtomicBool::new(false));
        let protected = ProtectedDevice::with_latch(
            Box::new(decrypted),
            protected_start,
            hidden_geo.encrypted_area_size,
            latch.clone(),
        );
        let device = SharedDevice::new(Box::new(protected));
        let vfs = vc_fs::open_volume(Box::new(device.clone()))?;
        Ok(Self {
            vfs,
            device,
            record,
            latch: Some(latch),
            scheme: outer.scheme.name,
            prf: outer.prf.name,
            hidden: false,
            outer_protected: true,
            truecrypt: false,
        })
    }

    pub fn vfs(&mut self) -> &mut dyn Vfs {
        self.vfs.as_mut()
    }

    pub fn scheme(&self) -> &'static str {
        self.scheme
    }

    pub fn prf(&self) -> &'static str {
        self.prf
    }

    /// Whether this session is the hidden volume. Only ever true when the
    /// user typed the hidden password, so the shells may label it; a plain
    /// outer unlock reports false and shows nothing (doc §9).
    pub fn is_hidden(&self) -> bool {
        self.hidden
    }

    /// Whether this volume was opened in TrueCrypt mode (and so is
    /// read-only).
    pub fn is_truecrypt(&self) -> bool {
        self.truecrypt
    }

    /// Whether this is the outer volume with hidden-volume protection on
    /// (both passwords given).
    pub fn is_outer_protected(&self) -> bool {
        self.outer_protected
    }

    /// Total and free space of the open filesystem.
    pub fn space(&mut self) -> VcResult<vc_fs::FsSpace> {
        self.vfs.space()
    }

    /// What the mount-time repair of an old FAT32 top folder did
    /// (`vc_fs::fat_repair`), handed over once. None when nothing was
    /// repaired.
    pub fn take_repair_report(&mut self) -> Option<vc_fs::fat_repair::RepairReport> {
        self.vfs.take_repair_report()
    }

    /// The filesystem's per-file size limit, if any (FAT: 4 GiB - 1).
    pub fn max_file_bytes(&self) -> Option<u64> {
        self.vfs.max_file_bytes()
    }

    /// Drop the VFS and the XTS engine. There is only one lock path; the
    /// auto-lock timers and screen-off policy (P3) call exactly this.
    pub fn lock(self) {
        drop(self);
    }
}
