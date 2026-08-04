//! The P0 gate, live: unlock the real fixture created by desktop VeraCrypt
//! (doc §13 — fixtures are the specification). Skips politely when the
//! fixture corpus isn't present (it is not committed to git; see
//! tools/gen-fixtures/README.md to build it).

use std::path::PathBuf;
use vc_types::VcError;

const FIXTURE: &str = "aes-sha_512-fat-512-pim0-plain.vc";
const PASSWORD: &[u8] = b"vaultpony-fixture";

fn fixture_path() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(FIXTURE);
    p.exists().then_some(p)
}

#[test]
fn unlocks_the_sha512_aes_fat_fixture() {
    let Some(path) = fixture_path() else {
        eprintln!("SKIP: fixture corpus not present ({FIXTURE})");
        return;
    };
    let mut steps = 0usize;
    let info = vault_core::probe(&path, PASSWORD, 0, &mut |_, _, _| steps += 1).unwrap();

    assert_eq!(info.scheme, "AES");
    assert_eq!(info.prf, "SHA-512");
    assert_eq!(info.header_version, 5);
    assert_eq!(info.geometry.sector_size, 512);
    assert_eq!(info.geometry.volume_size, 16 * 1024 * 1024 - 262_144);
    assert_eq!(info.geometry.encrypted_area_start, 131_072);
    assert_eq!(
        info.geometry.encrypted_area_size,
        16 * 1024 * 1024 - 262_144
    );
    assert_eq!(info.geometry.hidden_volume_size, 0);
    assert_eq!(info.filesystem, vc_fs::FsKind::Fat);
    // SHA-512 is the first PRF tried: the default combo must unlock on the
    // first candidate (doc §6 ordering).
    assert_eq!(steps, 1);
}

#[test]
fn wrong_password_is_indistinguishable_from_no_container() {
    let Some(path) = fixture_path() else {
        eprintln!("SKIP: fixture corpus not present ({FIXTURE})");
        return;
    };
    let err = vault_core::probe(&path, b"not-the-password", 0, &mut |_, _, _| {}).unwrap_err();
    assert!(matches!(err, VcError::NotFoundOrWrongPassword));
}
