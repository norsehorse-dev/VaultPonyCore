//! Argon2id on the write side (VaultPony 1.1.0, P2): creating Argon2id
//! containers, VeraCrypt's low-PIM password rule (Argon2id and PBKDF2),
//! moving a header between KDFs on a password change, and header restore
//! on Argon2id volumes.
//!
//! Needs no fixture corpus: every container is made in a temp file.
//! VeraCrypt-side interop for these lives in argon2id_interop.rs.

use std::path::{Path, PathBuf};
use vault_core::{ContainerFs, CreateParams, KdfFilter, Session, UnlockSecret};
use vc_io::FileDevice;
use vc_types::{Prf, VcError};

const SIZE: u64 = 8 << 20;
const LONG_PW: &[u8] = b"a-long-argon2id-password";
const SHORT_PW: &[u8] = b"short-pw";

fn prf(name: &str) -> &'static Prf {
    vc_types::registry::PRFS
        .iter()
        .find(|p| p.name == name)
        .unwrap()
}

fn scheme(name: &str) -> &'static vc_types::EncryptionScheme {
    vc_types::registry::ENCRYPTION_SCHEMES
        .iter()
        .find(|s| s.name == name)
        .unwrap()
}

fn temp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("vaultpony-a2w-{}-{name}.vc", std::process::id()));
    std::fs::write(&p, vec![0u8; SIZE as usize]).unwrap();
    p
}

fn params<'a>(prf_name: &str, pim: u32, pw: &'a [u8], keyfiles: &'a [Vec<u8>]) -> CreateParams<'a> {
    CreateParams {
        scheme: scheme("AES"),
        prf: prf(prf_name),
        pim,
        passphrase: pw,
        keyfiles,
        size: SIZE,
        sector_size: 512,
    }
}

fn create(path: &Path, p: &CreateParams<'_>) -> Result<(), VcError> {
    vault_core::create_container(
        Box::new(FileDevice::open_rw(path).unwrap()),
        p,
        ContainerFs::Fat,
    )
}

fn open(path: &Path, pw: &[u8], pim: u32, kdf: KdfFilter, rw: bool) -> Result<Session, VcError> {
    let dev = if rw {
        FileDevice::open_rw(path).unwrap()
    } else {
        FileDevice::open_read(path).unwrap()
    };
    Session::unlock_device_with(
        Box::new(dev),
        &UnlockSecret {
            kdf,
            ..UnlockSecret::new(pw, pim)
        },
        &mut |_, _, _| {},
    )
}

fn put(s: &mut Session, name: &str, data: &[u8]) {
    let vfs = s.vfs();
    vfs.create(name).unwrap();
    vfs.write_at(name, 0, data).unwrap();
    vfs.flush().unwrap();
}

fn get(s: &mut Session, name: &str) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let n = s.vfs().read_at(name, 0, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

#[test]
fn created_argon2id_container_opens_and_holds_data() {
    let path = temp("create");
    create(&path, &params("Argon2id", 1, LONG_PW, &[])).unwrap();
    let mut s = open(&path, LONG_PW, 1, KdfFilter::Argon2idOnly, true).unwrap();
    assert_eq!(s.prf(), "Argon2id");
    put(&mut s, "hello.txt", b"argon2id write side");
    drop(s);
    let mut s = open(&path, LONG_PW, 1, KdfFilter::Auto, false).unwrap();
    assert_eq!(get(&mut s, "hello.txt"), b"argon2id write side");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_applies_the_low_pim_password_rule() {
    let path = temp("rule");
    // PIM below Argon2id's default with a short password: refused before
    // anything is written.
    let before = std::fs::read(&path).unwrap();
    match create(&path, &params("Argon2id", 1, SHORT_PW, &[])) {
        Err(VcError::PasswordTooShortForPim {
            min_len: 20,
            default_pim: 12,
        }) => {}
        other => panic!("expected PasswordTooShortForPim, got {other:?}"),
    }
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");

    // PBKDF2 gets the same rule below its default PIM (485).
    match create(&path, &params("SHA-512", 1, SHORT_PW, &[])) {
        Err(VcError::PasswordTooShortForPim {
            min_len: 20,
            default_pim: 485,
        }) => {}
        other => panic!("expected PasswordTooShortForPim, got {other:?}"),
    }
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");

    // The exemptions upstream makes: default PIM, PIM at the default, a
    // keyfile-only (empty) password, and a long password.
    create(&path, &params("Argon2id", 0, SHORT_PW, &[])).unwrap();
    create(&path, &params("Argon2id", 12, SHORT_PW, &[])).unwrap();
    let key = vec![(0..64u8).collect::<Vec<u8>>()];
    create(&path, &params("Argon2id", 1, b"", &key)).unwrap();
    create(&path, &params("SHA-512", 485, SHORT_PW, &[])).unwrap();
    create(&path, &params("SHA-512", 1, LONG_PW, &[])).unwrap();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn password_change_moves_the_header_between_kdfs() {
    let path = temp("rekey");
    create(&path, &params("SHA-512", 0, b"old-pass", &[])).unwrap();
    let mut s = open(&path, b"old-pass", 0, KdfFilter::Pbkdf2Only, true).unwrap();
    put(&mut s, "keep.txt", b"data survives both rekeys");
    drop(s);

    // SHA-512 -> Argon2id at a low PIM with a long password.
    {
        let mut dev = FileDevice::open_rw(&path).unwrap();
        vault_core::change_password_to(
            &mut dev,
            &UnlockSecret::new(b"old-pass", 0),
            &UnlockSecret::new(LONG_PW, 1),
            Some(prf("Argon2id")),
            LONG_PW,
        )
        .unwrap();
    }
    assert!(matches!(
        open(&path, b"old-pass", 0, KdfFilter::Auto, false),
        Err(VcError::NotFoundOrWrongPassword)
    ));
    assert!(matches!(
        open(&path, LONG_PW, 1, KdfFilter::Pbkdf2Only, false),
        Err(VcError::NotFoundOrWrongPassword)
    ));
    let mut s = open(&path, LONG_PW, 1, KdfFilter::Argon2idOnly, false).unwrap();
    assert_eq!((s.scheme(), s.prf()), ("AES", "Argon2id"));
    assert_eq!(get(&mut s, "keep.txt"), b"data survives both rekeys");
    drop(s);

    // Argon2id -> Whirlpool, default PIM for the new KDF.
    {
        let mut dev = FileDevice::open_rw(&path).unwrap();
        vault_core::change_password_to(
            &mut dev,
            &UnlockSecret {
                kdf: KdfFilter::Argon2idOnly,
                ..UnlockSecret::new(LONG_PW, 1)
            },
            &UnlockSecret::new(b"back-again", 0),
            Some(prf("Whirlpool")),
            b"back-again",
        )
        .unwrap();
    }
    let mut s = open(&path, b"back-again", 0, KdfFilter::Pbkdf2Only, false).unwrap();
    assert_eq!(s.prf(), "Whirlpool");
    assert_eq!(get(&mut s, "keep.txt"), b"data survives both rekeys");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn password_change_rule_uses_the_target_kdf_and_writes_nothing_on_refusal() {
    let path = temp("rekey-rule");
    create(&path, &params("SHA-512", 0, b"old-pass", &[])).unwrap();
    let before = std::fs::read(&path).unwrap();

    // Moving to Argon2id at PIM 1 with a short password is refused.
    let mut dev = FileDevice::open_rw(&path).unwrap();
    let r = vault_core::change_password_to(
        &mut dev,
        &UnlockSecret::new(b"old-pass", 0),
        &UnlockSecret::new(SHORT_PW, 1),
        Some(prf("Argon2id")),
        SHORT_PW,
    );
    assert!(
        matches!(r, Err(VcError::PasswordTooShortForPim { .. })),
        "{r:?}"
    );
    drop(dev);
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");

    // Keeping SHA-512 (None): the rule uses the kept KDF's default, 485.
    let mut dev = FileDevice::open_rw(&path).unwrap();
    let r = vault_core::change_password_to(
        &mut dev,
        &UnlockSecret::new(b"old-pass", 0),
        &UnlockSecret::new(SHORT_PW, 1),
        None,
        SHORT_PW,
    );
    assert!(
        matches!(
            r,
            Err(VcError::PasswordTooShortForPim {
                default_pim: 485,
                ..
            })
        ),
        "{r:?}"
    );
    drop(dev);
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");

    // At or above that default a short password is fine.
    let mut dev = FileDevice::open_rw(&path).unwrap();
    vault_core::change_password_to(
        &mut dev,
        &UnlockSecret::new(b"old-pass", 0),
        &UnlockSecret::new(SHORT_PW, 500),
        None,
        SHORT_PW,
    )
    .unwrap();
    drop(dev);
    assert_eq!(
        open(&path, SHORT_PW, 500, KdfFilter::Pbkdf2Only, false)
            .unwrap()
            .prf(),
        "SHA-512"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn argon2id_headers_restore_from_embedded_and_from_file() {
    use std::io::{Seek, SeekFrom, Write};
    let path = temp("restore");
    create(&path, &params("Argon2id", 1, LONG_PW, &[])).unwrap();
    let backup = {
        let mut dev = FileDevice::open_read(&path).unwrap();
        vault_core::export_header_backup(&mut dev).unwrap()
    };
    let wipe_front = || {
        let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&vec![0xAAu8; 512]).unwrap();
    };
    let secret = UnlockSecret {
        kdf: KdfFilter::Argon2idOnly,
        ..UnlockSecret::new(LONG_PW, 1)
    };

    wipe_front();
    {
        let mut dev = FileDevice::open_rw(&path).unwrap();
        vault_core::restore_header_from_embedded_with(&mut dev, &secret).unwrap();
    }
    assert_eq!(
        open(&path, LONG_PW, 1, KdfFilter::Argon2idOnly, false)
            .unwrap()
            .prf(),
        "Argon2id"
    );

    wipe_front();
    {
        let mut dev = FileDevice::open_rw(&path).unwrap();
        vault_core::restore_header_from_file_with(&mut dev, &backup, &secret).unwrap();
    }
    assert_eq!(
        open(&path, LONG_PW, 1, KdfFilter::Argon2idOnly, false)
            .unwrap()
            .prf(),
        "Argon2id"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn hidden_volume_can_use_a_different_kdf_from_its_outer() {
    let path = temp("hidden");
    let outer = params("SHA-512", 0, b"outer-pass", &[]);
    let hidden = params("Argon2id", 1, LONG_PW, &[]);
    vault_core::create_container_with_hidden(
        || Ok(Box::new(FileDevice::open_rw(&path)?) as Box<dyn vc_io::BlockDevice>),
        &outer,
        &hidden,
        2 << 20,
        ContainerFs::Fat,
    )
    .unwrap();
    assert_eq!(
        open(&path, b"outer-pass", 0, KdfFilter::Auto, false)
            .unwrap()
            .prf(),
        "SHA-512"
    );
    let mut h = open(&path, LONG_PW, 1, KdfFilter::Auto, true).unwrap();
    assert_eq!(h.prf(), "Argon2id");
    put(&mut h, "hidden.txt", b"in the hidden volume");
    drop(h);
    let mut h = open(&path, LONG_PW, 1, KdfFilter::Argon2idOnly, false).unwrap();
    assert_eq!(get(&mut h, "hidden.txt"), b"in the hidden volume");
    let _ = std::fs::remove_file(&path);
}
