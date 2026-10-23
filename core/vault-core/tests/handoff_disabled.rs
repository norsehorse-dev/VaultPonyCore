//! Handoff is opt-in per process: without `enable_handoff(true)` a session
//! keeps no copy of its master keys and refuses to export. Its own test
//! binary, because the switch is process-wide.

use vault_core::{ContainerFs, Session};
use vc_format::{CreateParams, UnlockSecret};
use vc_io::FileDevice;
use vc_types::KdfFilter;

const PW: &[u8] = b"handoff-disabled-password-01";

#[test]
fn export_needs_handoff_enabled_at_unlock() {
    let path =
        std::env::temp_dir().join(format!("vaultpony-handoff-off-{}.vc", std::process::id()));
    let f = std::fs::File::create(&path).unwrap();
    f.set_len(4 << 20).unwrap();
    drop(f);
    let params = CreateParams {
        scheme: &vc_types::registry::ENCRYPTION_SCHEMES[0],
        prf: &vc_types::registry::PRFS[0],
        pim: 1,
        passphrase: PW,
        keyfiles: &[],
        size: 4 << 20,
        sector_size: 512,
    };
    vault_core::create_container(
        Box::new(FileDevice::open_rw(&path).unwrap()),
        &params,
        ContainerFs::Fat,
    )
    .unwrap();
    let unlock = || {
        Session::unlock_device_with(
            Box::new(FileDevice::open_rw(&path).unwrap()),
            &UnlockSecret {
                kdf: KdfFilter::Pbkdf2Only,
                ..UnlockSecret::new(PW, 1)
            },
            &mut |_, _, _| {},
        )
        .unwrap()
    };

    let off = unlock();
    assert!(off.export_handoff().is_err());

    // Turning it on later doesn't reach back into an existing session.
    vault_core::enable_handoff(true);
    assert!(off.export_handoff().is_err());
    let on = unlock();
    let blob = on.export_handoff().unwrap();

    // An importing process without handoff on keeps no key copy either: it
    // can use the volume but can't re-export.
    vault_core::enable_handoff(false);
    let mut imported =
        Session::import_handoff(Box::new(FileDevice::open_rw(&path).unwrap()), &blob).unwrap();
    assert!(imported.vfs().list("/").is_ok());
    assert!(imported.export_handoff().is_err());
    std::fs::remove_file(&path).ok();
}
