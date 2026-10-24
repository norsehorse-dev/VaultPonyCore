//! Vaults VaultPony 1.x made with keyfiles and a passphrase over 64 bytes
//! still open. 1.x always mixed keyfiles into a 64-byte pool; 2.0 uses
//! VeraCrypt's 128-byte pool for long passphrases, so unlock falls back to
//! the 1.x mix after the VeraCrypt one finds nothing, and changing the
//! password rewrites the header with the VeraCrypt mix.
//!
//! A 1.x vault is made here by creating a container whose passphrase is
//! the 1.x mixed secret with no keyfiles: `apply_keyfiles` is the identity
//! then, so the header is encrypted exactly as 1.x encrypted it.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use vault_core::{ContainerFs, CreateParams, Session, UnlockSecret};
use vc_crypto::{apply_keyfiles, apply_keyfiles_legacy};
use vc_format::find_header;
use vc_io::FileDevice;
use vc_types::{KdfFilter, VcError};

const SIZE: u64 = 8 << 20;
const PW: &[u8] = b"a passphrase that is well over sixty-four bytes long, as 1.x allowed it";

fn keyfiles() -> Vec<Vec<u8>> {
    vec![(0..200u32).map(|i| (i * 7 + 3) as u8).collect()]
}

fn scheme() -> &'static vc_types::EncryptionScheme {
    vc_types::registry::ENCRYPTION_SCHEMES
        .iter()
        .find(|s| s.name == "AES")
        .unwrap()
}

fn sha512() -> &'static vc_types::Prf {
    vc_types::registry::PRFS
        .iter()
        .find(|p| p.name == "SHA-512")
        .unwrap()
}

fn temp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vaultpony-keyfile-legacy-{name}-{}.vc",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    std::fs::File::create(&p).unwrap().set_len(SIZE).unwrap();
    p
}

fn params(passphrase: &[u8]) -> CreateParams<'_> {
    CreateParams {
        scheme: scheme(),
        prf: sha512(),
        pim: 0,
        passphrase,
        keyfiles: &[],
        size: SIZE,
        sector_size: 512,
    }
}

/// SHA-512 only, so a wrong-password sweep stays fast.
fn secret<'a>(passphrase: &'a [u8], legacy: Option<&'a [u8]>) -> UnlockSecret<'a> {
    UnlockSecret {
        kdf: KdfFilter::for_prf("SHA-512").unwrap(),
        legacy_passphrase: legacy,
        ..UnlockSecret::new(passphrase, 0)
    }
}

/// A container encrypted the way 1.x did for `PW` + `keyfiles()`.
fn legacy_vault(name: &str) -> PathBuf {
    assert!(PW.len() > 64);
    let legacy = apply_keyfiles_legacy(PW, &keyfiles()).unwrap();
    let path = temp(name);
    vault_core::create_container(
        Box::new(FileDevice::open_rw(&path).unwrap()),
        &params(&legacy),
        ContainerFs::Fat,
    )
    .unwrap();
    path
}

#[test]
fn a_1x_vault_opens_only_through_the_fallback() {
    let path = legacy_vault("open");
    let kf = keyfiles();
    let modern = apply_keyfiles(PW, &kf);
    let legacy = apply_keyfiles_legacy(PW, &kf).unwrap();

    // The VeraCrypt mix alone does not open it (this is the 2.0 regression).
    let mut dev = FileDevice::open_read(&path).unwrap();
    let r = find_header(&mut dev, &secret(&modern, None), &mut |_, _, _| {});
    assert!(matches!(r, Err(VcError::NotFoundOrWrongPassword)));

    // With the fallback it opens, and says which mix matched. Progress
    // covers both sweeps from the first report, so it never runs backwards.
    let mut seen: Vec<(usize, usize)> = Vec::new();
    let found = find_header(&mut dev, &secret(&modern, Some(&legacy)), &mut |i, n, _| {
        seen.push((i, n))
    })
    .unwrap();
    assert!(found.legacy_keyfile_mix);
    assert!(!found.header.position.is_hidden());
    let total = seen[0].1;
    assert!(seen.iter().all(|&(_, n)| n == total));
    assert!(seen.windows(2).all(|w| w[1].0 > w[0].0));
    assert!(seen.last().unwrap().0 < total);

    // The full session path opens it too.
    let mut session = Session::unlock_device_with(
        Box::new(FileDevice::open_read(&path).unwrap()),
        &secret(&modern, Some(&legacy)),
        &mut |_, _, _| {},
    )
    .unwrap();
    assert!(session.space().is_ok());
    session.lock();

    // A vault made with the VeraCrypt mix never reports the fallback.
    let path2 = temp("modern");
    vault_core::create_container(
        Box::new(FileDevice::open_rw(&path2).unwrap()),
        &CreateParams {
            keyfiles: &kf,
            ..params(PW)
        },
        ContainerFs::Fat,
    )
    .unwrap();
    let mut dev2 = FileDevice::open_read(&path2).unwrap();
    let found = find_header(
        &mut dev2,
        &secret(&modern, Some(&legacy)),
        &mut |_, _, _| {},
    )
    .unwrap();
    assert!(!found.legacy_keyfile_mix);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&path2);
}

#[test]
fn a_wrong_password_still_fails_after_both_sweeps() {
    let path = legacy_vault("wrong");
    let kf = keyfiles();
    let other = b"another passphrase that is also well over sixty-four bytes in length";
    let modern = apply_keyfiles(other, &kf);
    let legacy = apply_keyfiles_legacy(other, &kf).unwrap();
    let mut dev = FileDevice::open_read(&path).unwrap();
    let mut seen: Vec<(usize, usize)> = Vec::new();
    let r = find_header(&mut dev, &secret(&modern, Some(&legacy)), &mut |i, n, _| {
        seen.push((i, n))
    });
    assert!(matches!(r, Err(VcError::NotFoundOrWrongPassword)));
    let total = seen[0].1;
    assert_eq!(seen.len(), total, "both sweeps report every step once");
    assert!(seen
        .iter()
        .enumerate()
        .all(|(k, &(i, n))| i == k && n == total));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_cancel_is_not_followed_by_the_fallback() {
    let path = legacy_vault("cancel");
    let kf = keyfiles();
    let modern = apply_keyfiles(PW, &kf);
    let legacy = apply_keyfiles_legacy(PW, &kf).unwrap();
    let cancel = AtomicBool::new(true);
    let mut dev = FileDevice::open_read(&path).unwrap();
    let r = find_header(
        &mut dev,
        &UnlockSecret {
            cancel: Some(&cancel),
            ..secret(&modern, Some(&legacy))
        },
        &mut |_, _, _| {},
    );
    assert!(matches!(r, Err(VcError::Cancelled)));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn changing_the_password_moves_a_1x_vault_to_the_veracrypt_mix() {
    let path = legacy_vault("change");
    let kf = keyfiles();
    let modern = apply_keyfiles(PW, &kf);
    let legacy = apply_keyfiles_legacy(PW, &kf).unwrap();
    let mut dev = FileDevice::open_rw(&path).unwrap();
    // Same password and keyfiles: only the mix changes.
    vault_core::change_password_to(
        &mut dev,
        &secret(&modern, Some(&legacy)),
        &UnlockSecret::new(&modern, 0),
        None,
        PW,
    )
    .unwrap();
    let found = find_header(&mut dev, &secret(&modern, None), &mut |_, _, _| {}).unwrap();
    assert!(!found.legacy_keyfile_mix);
    let r = find_header(&mut dev, &secret(&legacy, None), &mut |_, _, _| {});
    assert!(matches!(r, Err(VcError::NotFoundOrWrongPassword)));
    // The data is untouched: the session still mounts it.
    let mut session = Session::unlock_device_with(
        Box::new(FileDevice::open_read(&path).unwrap()),
        &secret(&modern, None),
        &mut |_, _, _| {},
    )
    .unwrap();
    assert!(session.space().is_ok());
    session.lock();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_1x_hidden_volume_opens_through_the_fallback() {
    let kf = keyfiles();
    let modern = apply_keyfiles(PW, &kf);
    let legacy = apply_keyfiles_legacy(PW, &kf).unwrap();
    let path = temp("hidden");
    vault_core::create_container_with_hidden(
        || Ok(Box::new(FileDevice::open_rw(&path)?) as Box<dyn vc_io::BlockDevice>),
        &params(b"outer decoy password"),
        &params(&legacy),
        2 << 20,
        ContainerFs::Fat,
    )
    .unwrap();
    let session = Session::unlock_device_with(
        Box::new(FileDevice::open_read(&path).unwrap()),
        &secret(&modern, Some(&legacy)),
        &mut |_, _, _| {},
    )
    .unwrap();
    assert!(session.is_hidden());
    session.lock();
    let _ = std::fs::remove_file(&path);
}
