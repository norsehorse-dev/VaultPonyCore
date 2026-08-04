//! Header damage and recovery, end to end (doc §6): a container with a
//! destroyed primary header still unlocks via the embedded backup; restore
//! rebuilds the primary; a wrong password writes nothing; the external
//! backup file recovers a container whose entire leading header group is
//! gone.

use std::path::PathBuf;
use vc_format::repair::{export_headers, restore_from_file, restore_primary_from_embedded};
use vc_format::{find_header, find_header_at, UnlockSecret};
use vc_io::FileDevice;
use vc_types::{HeaderPosition, VcError};

const PASSWORD: &[u8] = b"vaultpony-fixture";
const FIXTURE: &str = "aes-sha_512-fat-512-pim0-plain.vc";

fn secret() -> UnlockSecret<'static> {
    UnlockSecret {
        passphrase: PASSWORD,
        pim: 0,
    }
}

fn fixture_copy(tag: &str) -> Option<PathBuf> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(FIXTURE);
    if !src.exists() {
        return None;
    }
    let dst =
        std::env::temp_dir().join(format!("vaultpony-repair-{tag}-{}.vc", std::process::id()));
    std::fs::copy(&src, &dst).unwrap();
    Some(dst)
}

fn zero_range(path: &PathBuf, start: u64, len: usize) {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.seek(SeekFrom::Start(start)).unwrap();
    f.write_all(&vec![0u8; len]).unwrap();
}

#[test]
fn destroyed_primary_unlocks_via_backup_and_restores() {
    let Some(container) = fixture_copy("embedded") else {
        eprintln!("SKIP: fixture corpus not present");
        return;
    };
    // Destroy the primary header (first 64 KiB region).
    zero_range(&container, 0, 65_536);

    // Unlock still works — recovery order finds the embedded backup.
    let mut dev = FileDevice::open_read(&container).unwrap();
    let found = find_header(&mut dev, &secret(), &mut |_, _, _| {}).unwrap();
    assert_eq!(found.header.position, HeaderPosition::BackupPrimary);
    drop(dev);

    // Wrong password: verify-then-write means nothing is written.
    let before = std::fs::read(&container).unwrap();
    let mut dev = FileDevice::open_rw(&container).unwrap();
    let err = restore_primary_from_embedded(
        &mut dev,
        &UnlockSecret {
            passphrase: b"nope",
            pim: 0,
        },
    )
    .unwrap_err();
    assert!(matches!(err, VcError::NotFoundOrWrongPassword));
    drop(dev);
    assert_eq!(
        before,
        std::fs::read(&container).unwrap(),
        "wrote on failure"
    );

    // Right password: restore, then the PRIMARY position unlocks and the
    // volume's files are readable again.
    let mut dev = FileDevice::open_rw(&container).unwrap();
    restore_primary_from_embedded(&mut dev, &secret()).unwrap();
    drop(dev);

    let mut dev = FileDevice::open_read(&container).unwrap();
    let found = find_header_at(
        &mut dev,
        &secret(),
        &[HeaderPosition::Primary],
        &mut |_, _, _| {},
    )
    .unwrap();
    assert_eq!(found.header.position, HeaderPosition::Primary);
    drop(dev);

    let mut s = vault_core::Session::unlock(&container, PASSWORD, 0, &mut |_, _, _| {}).unwrap();
    let mut buf = [0u8; 32];
    let n = s.vfs().read_at("/readme.txt", 0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"VaultPony fixture tree v1\n");
    s.lock();

    let _ = std::fs::remove_file(&container);
}

#[test]
fn external_backup_recovers_a_fully_headerless_front() {
    let Some(container) = fixture_copy("external") else {
        eprintln!("SKIP: fixture corpus not present");
        return;
    };
    // Export while healthy.
    let mut dev = FileDevice::open_read(&container).unwrap();
    let backup = export_headers(&mut dev).unwrap();
    assert_eq!(backup.len(), 131_072);
    drop(dev);

    // Destroy the entire leading header group (primary + hidden slot).
    zero_range(&container, 0, 131_072);

    // Restore from the exported file; volume reads again.
    let mut dev = FileDevice::open_rw(&container).unwrap();
    restore_from_file(&mut dev, &backup, &secret()).unwrap();
    drop(dev);

    let mut s = vault_core::Session::unlock(&container, PASSWORD, 0, &mut |_, _, _| {}).unwrap();
    let names: Vec<String> = s
        .vfs()
        .list("/")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(names.contains(&"readme.txt".to_string()));
    s.lock();

    // A garbage backup file is rejected before writing.
    let mut dev = FileDevice::open_rw(&container).unwrap();
    let err = restore_from_file(&mut dev, &vec![0u8; 131_072], &secret()).unwrap_err();
    assert!(matches!(err, VcError::NotFoundOrWrongPassword));

    let _ = std::fs::remove_file(&container);
}
