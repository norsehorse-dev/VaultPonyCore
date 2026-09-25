//! The Argon2id gate (VaultPony 1.1.0): VeraCrypt 1.26.29 volumes that mix
//! KDFs and use keyfiles unlock and read, the KDF filter narrows the search
//! without changing what it finds, and a cancel stops it.
//!
//! Plain Argon2id fixtures (every scheme, PIM 0/1/32) are covered by
//! matrix_gate.rs. The fixtures here carry their own secrets, so they are
//! marked with a `kind` in the manifest and skipped by the generic gates.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use vault_core::{KdfFilter, Session, UnlockSecret};
use vc_io::FileDevice;
use vc_types::VcError;

const MIXED: &str = "aes_sha_512-outer-serpent_argon2id-hidden";
const KEYFILE: &str = "aes-argon2id-fat-512-pim1-keyfile";
const PLAIN_ARGON: &str = "aes-argon2id-fat-512-pim1-plain";
const PLAIN_SHA: &str = "aes-sha_512-fat-512-pim0-plain";

fn fixtures_dir() -> PathBuf {
    std::env::var_os("VAULTPONY_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures"))
}

/// The manifest entry for `id`, or None (test skips) when the corpus or that
/// fixture is absent. The corpus is regenerable, not committed.
fn entry(id: &str) -> Option<serde_json::Value> {
    let dir = fixtures_dir();
    let m = dir.join("manifest.json");
    if !m.exists() || !dir.join(format!("{id}.vc")).exists() {
        eprintln!("SKIP: fixture {id} not present");
        return None;
    }
    let m: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(m).unwrap()).unwrap();
    let e = m["fixtures"][id].clone();
    (e["status"] == "ok").then_some(e).or_else(|| {
        eprintln!("SKIP: fixture {id} not in manifest");
        None
    })
}

fn open(id: &str) -> Box<dyn vc_io::BlockDevice> {
    Box::new(FileDevice::open_read(&fixtures_dir().join(format!("{id}.vc"))).unwrap())
}

fn unlock(id: &str, secret: &UnlockSecret<'_>) -> Result<Session, VcError> {
    Session::unlock_device_with(open(id), secret, &mut |_, _, _| {})
}

fn sha256_of(s: &mut Session, rel: &str) -> String {
    use sha2::{Digest, Sha256};
    let vfs = s.vfs();
    let mut hasher = Sha256::new();
    let mut off = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = vfs.read_at(rel, off, &mut buf).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        off += n as u64;
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn assert_tree(s: &mut Session, tree: &serde_json::Value, id: &str) {
    for (rel, want) in tree.as_object().unwrap() {
        assert_eq!(sha256_of(s, rel), want.as_str().unwrap(), "{id}/{rel}");
    }
}

fn with_filter<'a>(passphrase: &'a [u8], pim: u32, kdf: KdfFilter) -> UnlockSecret<'a> {
    UnlockSecret {
        kdf,
        ..UnlockSecret::new(passphrase, pim)
    }
}

#[test]
fn mixed_kdf_hidden_volume_opens_both_ways() {
    let Some(e) = entry(MIXED) else { return };
    let p = &e["params"];
    let outer_pw = p["outer_password"].as_str().unwrap().as_bytes();
    let hidden_pw = p["hidden_password"].as_str().unwrap().as_bytes();

    let mut hidden = unlock(MIXED, &UnlockSecret::new(hidden_pw, 0)).unwrap();
    assert_eq!((hidden.scheme(), hidden.prf()), ("Serpent", "Argon2id"));
    assert_tree(&mut hidden, &e["hidden_tree"], MIXED);

    let mut outer = unlock(MIXED, &UnlockSecret::new(outer_pw, 0)).unwrap();
    assert_eq!((outer.scheme(), outer.prf()), ("AES", "SHA-512"));
    assert_tree(&mut outer, &e["outer_tree"], MIXED);
    assert!(
        outer.vfs().stat("secret.txt").is_err(),
        "outer must not see the hidden tree"
    );
}

#[test]
fn filter_narrows_the_search_per_volume() {
    let Some(e) = entry(MIXED) else { return };
    let p = &e["params"];
    let outer_pw = p["outer_password"].as_str().unwrap().as_bytes();
    let hidden_pw = p["hidden_password"].as_str().unwrap().as_bytes();

    let hidden = unlock(MIXED, &with_filter(hidden_pw, 0, KdfFilter::Argon2idOnly)).unwrap();
    assert_eq!(hidden.prf(), "Argon2id");
    assert!(matches!(
        unlock(MIXED, &with_filter(hidden_pw, 0, KdfFilter::Pbkdf2Only)),
        Err(VcError::NotFoundOrWrongPassword)
    ));

    let outer = unlock(MIXED, &with_filter(outer_pw, 0, KdfFilter::Pbkdf2Only)).unwrap();
    assert_eq!(outer.prf(), "SHA-512");
    assert!(matches!(
        unlock(MIXED, &with_filter(outer_pw, 0, KdfFilter::Argon2idOnly)),
        Err(VcError::NotFoundOrWrongPassword)
    ));
}

#[test]
fn outer_protected_open_works_across_kdfs() {
    let Some(e) = entry(MIXED) else { return };
    let p = &e["params"];
    let outer_pw = p["outer_password"].as_str().unwrap().as_bytes();
    let hidden_pw = p["hidden_password"].as_str().unwrap().as_bytes();

    // Work on a copy: the protected open is read-write.
    let tmp = std::env::temp_dir().join("vaultpony-argon2id-mixed-protect.vc");
    std::fs::copy(fixtures_dir().join(format!("{MIXED}.vc")), &tmp).unwrap();
    let dev = Box::new(FileDevice::open_rw(&tmp).unwrap());
    let mut s = Session::unlock_outer_protected_device_with(
        dev,
        &UnlockSecret::new(outer_pw, 0),
        hidden_pw,
        &mut |_, _, _| {},
    )
    .unwrap();
    assert_eq!(s.prf(), "SHA-512");
    assert!(s.vfs().writable());
    drop(s);
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn keyfile_is_mixed_in_before_argon2id() {
    let Some(e) = entry(KEYFILE) else { return };
    let p = &e["params"];
    let pw = p["password"].as_str().unwrap().as_bytes();
    let pim = p["pim"].as_u64().unwrap() as u32;
    let key = std::fs::read(fixtures_dir().join(p["keyfile"].as_str().unwrap())).unwrap();

    let effective = vc_crypto::apply_keyfiles(pw, &[key]);
    let mut s = unlock(
        KEYFILE,
        &with_filter(&effective, pim, KdfFilter::Argon2idOnly),
    )
    .unwrap();
    assert_eq!(s.prf(), "Argon2id");
    assert_tree(&mut s, &e["tree"], KEYFILE);

    assert!(matches!(
        unlock(KEYFILE, &with_filter(pw, pim, KdfFilter::Argon2idOnly)),
        Err(VcError::NotFoundOrWrongPassword)
    ));
}

#[test]
fn argon2id_only_skips_every_pbkdf2_derivation() {
    let Some(e) = entry(PLAIN_ARGON) else { return };
    let pw = e["params"]["password"].as_str().unwrap().as_bytes();
    let mut seen = Vec::new();
    let s = Session::unlock_device_with(
        open(PLAIN_ARGON),
        &with_filter(pw, 1, KdfFilter::Argon2idOnly),
        &mut |_, total, prf| seen.push((total, prf.to_string())),
    )
    .unwrap();
    assert_eq!(s.prf(), "Argon2id");
    // Found at the primary slot on the first derivation; the total counts
    // only the Argon2id candidates (one per header slot).
    assert_eq!(seen, vec![(4, "Argon2id".to_string())]);
}

#[test]
fn pbkdf2_only_wrong_password_never_touches_argon2id() {
    let Some(_) = entry(PLAIN_SHA) else { return };
    let mut prfs = Vec::new();
    let r = Session::unlock_device_with(
        open(PLAIN_SHA),
        &with_filter(b"definitely-wrong", 0, KdfFilter::Pbkdf2Only),
        &mut |_, _, prf| prfs.push(prf.to_string()),
    );
    assert!(matches!(r, Err(VcError::NotFoundOrWrongPassword)));
    assert_eq!(prfs.len(), 5 * 4, "five PBKDF2 PRFs x four header slots");
    assert!(prfs.iter().all(|p| p != "Argon2id"));
}

#[test]
fn a_raised_cancel_stops_before_any_derivation() {
    let Some(_) = entry(PLAIN_SHA) else { return };
    let flag = AtomicBool::new(true);
    let mut steps = 0;
    let r = Session::unlock_device_with(
        open(PLAIN_SHA),
        &UnlockSecret {
            cancel: Some(&flag),
            ..UnlockSecret::new(b"vaultpony-fixture", 0)
        },
        &mut |_, _, _| steps += 1,
    );
    assert!(matches!(r, Err(VcError::Cancelled)));
    assert_eq!(steps, 0);
}

#[test]
fn cancel_mid_search_wins_over_wrong_password() {
    let Some(_) = entry(PLAIN_ARGON) else { return };
    let flag = AtomicBool::new(false);
    let mut steps = 0;
    // Raise the flag from the progress callback once the Argon2id sweep has
    // started, as a UI thread would. The search must stop at the next slot
    // instead of finishing the sweep and reporting a wrong password.
    let r = Session::unlock_device_with(
        open(PLAIN_ARGON),
        &UnlockSecret {
            cancel: Some(&flag),
            ..with_filter(b"wrong-password-wrong-password", 1, KdfFilter::Argon2idOnly)
        },
        &mut |_, _, _| {
            steps += 1;
            flag.store(true, Ordering::Relaxed);
        },
    );
    assert!(matches!(r, Err(VcError::Cancelled)));
    assert_eq!(steps, 1, "stopped after the first Argon2id slot");
}
