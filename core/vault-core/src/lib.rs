//! Session layer: unlock flow, mount table, auto-lock timers, and the path
//! API the shells (Android/iOS/desktop/CLI) consume (planning doc §5).
//!
//! Owns every secret lifecycle: passphrases and keys live exactly as long
//! as a session needs them and are zeroized on lock (doc §11).

pub mod probe;
pub mod session;

pub use probe::{probe, HeaderSource, VolumeInfo};
pub use session::{
    create_container, create_container_with_hidden, ContainerFs, Session, SessionId,
};
pub use vc_format::CreateParams;

use vc_types::VcResult;

/// Export the container's leading header group (primary + hidden slots,
/// 128 KiB of ciphertext) for offline safekeeping (doc §6). Carries no secret
/// the container doesn't already hold — but it keeps accepting the *current*
/// password even after a password change, so it must be guarded like the
/// container itself.
pub fn export_header_backup(dev: &mut dyn vc_io::BlockDevice) -> VcResult<Vec<u8>> {
    vc_format::repair::export_headers(dev)
}

/// Restore the primary header from a previously exported backup file. The
/// backup must unlock with `passphrase`/`pim` before a byte is written
/// (verify-then-write); `passphrase` is the effective secret (keyfiles already
/// folded in by the caller).
pub fn restore_header_from_file(
    dev: &mut dyn vc_io::BlockDevice,
    backup: &[u8],
    passphrase: &[u8],
    pim: u32,
) -> VcResult<()> {
    vc_format::repair::restore_from_file(
        dev,
        backup,
        &vc_format::UnlockSecret { passphrase, pim },
    )
    .map(|_| ())
}

/// Restore the primary header from the container's own embedded backup
/// (the trailing copy), verifying it unlocks first. Recovers a container whose
/// primary header was damaged, with no external file needed.
pub fn restore_header_from_embedded(
    dev: &mut dyn vc_io::BlockDevice,
    passphrase: &[u8],
    pim: u32,
) -> VcResult<()> {
    vc_format::repair::restore_primary_from_embedded(
        dev,
        &vc_format::UnlockSecret { passphrase, pim },
    )
    .map(|_| ())
}

/// Change a volume's password/PIM in place (doc §6). The data is untouched —
/// only the header key protecting the master keys is re-derived. `old`/`new`
/// are effective secrets (keyfiles folded in by the caller); the `old` secret
/// selects which volume (outer or hidden) is re-keyed. Verify-then-write.
pub fn change_password(
    dev: &mut dyn vc_io::BlockDevice,
    old_passphrase: &[u8],
    old_pim: u32,
    new_passphrase: &[u8],
    new_pim: u32,
) -> VcResult<()> {
    vc_format::repair::change_password(
        dev,
        &vc_format::UnlockSecret {
            passphrase: old_passphrase,
            pim: old_pim,
        },
        &vc_format::UnlockSecret {
            passphrase: new_passphrase,
            pim: new_pim,
        },
    )
}

/// Core version string, threaded through to every shell's about screen and
/// used by the FFI walking skeleton to prove the toolchain end to end.
pub fn core_version() -> String {
    format!("vault-core {}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_populated() {
        assert!(super::core_version().starts_with("vault-core "));
    }
}
