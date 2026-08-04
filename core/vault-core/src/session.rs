//! Unlocked-volume sessions (doc §5).
//!
//! A `Session` is one unlocked container: the decrypted device wrapped in
//! its filesystem adapter. Master keys live inside the XTS engine only; the
//! parsed header (and its key material) is zeroized before `unlock`
//! returns. The mount table, auto-lock timers, and the remembered-parameters
//! cache arrive with the shells (P3+) — this is the core they will call.

use std::path::Path;
use vc_format::{
    find_header, find_header_at, DecryptedDevice, ProtectedDevice, UnlockProgress, UnlockSecret,
};
use vc_fs::Vfs;
use vc_io::FileDevice;
use vc_types::{HeaderPosition, VcError, VcResult};

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
    let found = find_header(
        dev.as_mut(),
        &UnlockSecret {
            passphrase: secret.as_slice(),
            pim: params.pim,
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
    scheme: &'static str,
    prf: &'static str,
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
        mut dev: Box<dyn vc_io::BlockDevice>,
        passphrase: &[u8],
        pim: u32,
        progress: &mut UnlockProgress<'_>,
    ) -> VcResult<Self> {
        let found = find_header(dev.as_mut(), &UnlockSecret { passphrase, pim }, progress)?;
        let xts = vc_crypto::SchemeXts::new(
            found.scheme,
            &found.header.master_keys[..found.scheme.key_bytes()],
        )?;
        // `found.header` (incl. master keys) is zeroized on drop here; from
        // this point the only key material lives inside the XTS engine.
        let geometry = found.header.geometry;
        let decrypted = DecryptedDevice::new(dev, xts, &geometry);
        let vfs = vc_fs::open_volume(Box::new(decrypted))?;
        Ok(Self {
            vfs,
            scheme: found.scheme.name,
            prf: found.prf.name,
        })
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
        mut dev: Box<dyn vc_io::BlockDevice>,
        outer_passphrase: &[u8],
        hidden_passphrase: &[u8],
        pim: u32,
        progress: &mut UnlockProgress<'_>,
    ) -> VcResult<Self> {
        // Outer must resolve to a non-hidden slot.
        let outer = find_header_at(
            dev.as_mut(),
            &UnlockSecret {
                passphrase: outer_passphrase,
                pim,
            },
            &[HeaderPosition::Primary, HeaderPosition::BackupPrimary],
            progress,
        )?;

        // Hidden header, for the protected region only. We keep no hidden
        // keys — just its geometry.
        let hidden = find_header_at(
            dev.as_mut(),
            &UnlockSecret {
                passphrase: hidden_passphrase,
                pim,
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

        let xts = vc_crypto::SchemeXts::new(
            outer.scheme,
            &outer.header.master_keys[..outer.scheme.key_bytes()],
        )?;
        let decrypted = DecryptedDevice::new(dev, xts, &outer_geo);
        let protected = ProtectedDevice::new(
            Box::new(decrypted),
            protected_start,
            hidden_geo.encrypted_area_size,
        );
        let vfs = vc_fs::open_volume(Box::new(protected))?;
        Ok(Self {
            vfs,
            scheme: outer.scheme.name,
            prf: outer.prf.name,
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

    /// Drop the VFS and the XTS engine. There is only one lock path; the
    /// auto-lock timers and screen-off policy (P3) call exactly this.
    pub fn lock(self) {
        drop(self);
    }
}
