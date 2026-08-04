//! The P8 gate (doc §12/§14): hidden volumes unlock and read, and the
//! deniability posture holds — the outer password never reveals the hidden
//! volume, a wrong password is indistinguishable from a container with no
//! hidden volume, and nothing about a hidden match is observable beyond the
//! decrypted bytes themselves.

use std::path::PathBuf;
use vc_types::VcError;

const FIXTURE: &str = "aes-sha_512-fat-hidden.vc";

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn manifest() -> Option<serde_json::Value> {
    let p = fixtures_dir().join("manifest.json");
    p.exists()
        .then(|| serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
}

#[test]
fn hidden_password_reads_the_hidden_tree() {
    let container = fixtures_dir().join(FIXTURE);
    let Some(m) = manifest() else {
        eprintln!("SKIP: fixtures not present");
        return;
    };
    let entry = &m["fixtures"]["aes-sha_512-fat-hidden"];
    if !container.exists() || entry["status"] != "ok" {
        eprintln!("SKIP: hidden fixture not present");
        return;
    }
    let hidden_pw = entry["params"]["hidden_password"].as_str().unwrap();
    let tree = entry["hidden_tree"].as_object().unwrap();

    let mut s = vault_core::Session::unlock(&container, hidden_pw.as_bytes(), 0, &mut |_, _, _| {})
        .unwrap();
    let vfs = s.vfs();

    // Every file in the hidden tree reads back byte-identical.
    use sha2::{Digest, Sha256};
    for (rel, want) in tree {
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
        let got: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            &got,
            want.as_str().unwrap(),
            "hidden/{rel}: content mismatch"
        );
    }
    assert!(vfs
        .list("/")
        .unwrap()
        .iter()
        .any(|e| e.name == "readme.txt"));
    s.lock();
}

#[test]
fn outer_password_opens_a_different_volume_and_never_the_hidden_tree() {
    let container = fixtures_dir().join(FIXTURE);
    let Some(m) = manifest() else {
        eprintln!("SKIP: fixtures not present");
        return;
    };
    let entry = &m["fixtures"]["aes-sha_512-fat-hidden"];
    if !container.exists() || entry["status"] != "ok" {
        eprintln!("SKIP: hidden fixture not present");
        return;
    }
    let outer_pw = entry["params"]["outer_password"].as_str().unwrap();
    let hidden_pw = entry["params"]["hidden_password"].as_str().unwrap();

    // The outer volume's data area starts at the standard offset; the
    // hidden volume's starts deep in the host. Different geometry proves
    // the password — not a flag — selected the volume.
    use vc_format::{find_header, UnlockSecret};
    use vc_io::FileDevice;
    let mut dev = FileDevice::open_read(&container).unwrap();
    let outer = find_header(
        &mut dev,
        &UnlockSecret {
            passphrase: outer_pw.as_bytes(),
            pim: 0,
        },
        &mut |_, _, _| {},
    )
    .unwrap();
    let mut dev = FileDevice::open_read(&container).unwrap();
    let hidden = find_header(
        &mut dev,
        &UnlockSecret {
            passphrase: hidden_pw.as_bytes(),
            pim: 0,
        },
        &mut |_, _, _| {},
    )
    .unwrap();

    assert!(
        !outer.header.position.is_hidden(),
        "outer opened a hidden slot"
    );
    assert!(
        hidden.header.position.is_hidden(),
        "hidden opened a non-hidden slot"
    );
    assert_ne!(
        outer.header.geometry.encrypted_area_start, hidden.header.geometry.encrypted_area_start,
        "outer and hidden must be distinct regions"
    );
    assert_eq!(outer.header.geometry.encrypted_area_start, 131_072);
}

#[test]
fn wrong_password_is_indistinguishable_from_no_hidden_volume() {
    let container = fixtures_dir().join(FIXTURE);
    if !container.exists() {
        eprintln!("SKIP: hidden fixture not present");
        return;
    }
    // The same error a normal container gives — no "hidden volume present"
    // signal, ever (doc §11).
    let err = vault_core::probe(&container, b"definitely-wrong", 0, &mut |_, _, _| {}).unwrap_err();
    assert!(matches!(err, VcError::NotFoundOrWrongPassword));
}
