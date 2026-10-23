//! TrueCrypt mode gate (2.0.0 rc5, plan 6.2): TrueCrypt 6.x/7.x volumes open
//! in TrueCrypt mode and only there, read-only, with every file intact.
//!
//! Two corpora, both regenerable and not committed:
//! - `fixtures/synth-tc/`: AES containers written by
//!   tools/gen-fixtures/synth_truecrypt.py (OpenSSL PBKDF2 and AES-XTS, no
//!   code shared with the core).
//! - `fixtures/rc5/`: containers made by TrueCrypt 7.1a itself
//!   (create_rc5_fixtures.py), every PRF, ciphers and cascades. The release
//!   gate.
//!
//! Each test skips when its corpus is absent.

use std::path::PathBuf;
use vault_core::{Session, UnlockSecret};
use vc_io::FileDevice;
use vc_types::VcError;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn manifest(dir: &str, file: &str) -> Option<serde_json::Value> {
    let p = root().join(dir).join(file);
    if !p.exists() {
        eprintln!("SKIP: {dir}/{file} not present");
        return None;
    }
    Some(serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
}

fn dev(dir: &str, name: &str) -> Box<dyn vc_io::BlockDevice> {
    Box::new(FileDevice::open_read(&root().join(dir).join(name)).unwrap())
}

fn tc(pw: &[u8]) -> UnlockSecret<'_> {
    UnlockSecret {
        truecrypt: true,
        ..UnlockSecret::new(pw, 0)
    }
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

fn assert_read_only(s: &mut Session, id: &str) {
    assert!(s.is_truecrypt(), "{id}");
    let vfs = s.vfs();
    assert!(!vfs.writable(), "{id}");
    for r in [
        vfs.create("new.txt"),
        vfs.mkdir("newdir"),
        vfs.unlink("readme.txt"),
        vfs.rename("readme.txt", "x.txt"),
        vfs.truncate("readme.txt", 0),
    ] {
        assert!(matches!(r, Err(VcError::TrueCryptReadOnly)), "{id}: {r:?}");
    }
    assert!(matches!(
        vfs.write_at("readme.txt", 0, b"x"),
        Err(VcError::TrueCryptReadOnly)
    ));
}

#[test]
fn synthetic_truecrypt_volumes_open_read_only() {
    let Some(m) = manifest("synth-tc", "manifest-synth.json") else {
        return;
    };
    for (id, e) in m.as_object().unwrap() {
        if e["header_version"].as_u64().unwrap() < 4 {
            continue;
        }
        let file = format!("{id}.tc");
        let pw = e["password"].as_str().unwrap().as_bytes();
        let before = std::fs::read(root().join("synth-tc").join(&file)).unwrap();

        let mut steps = 0usize;
        let mut s =
            Session::unlock_device_with(dev("synth-tc", &file), &tc(pw), &mut |_, _, _| steps += 1)
                .unwrap_or_else(|err| panic!("{id}: {err:?}"));
        let want_prf = match e["prf"].as_str().unwrap() {
            "ripemd160" => "RIPEMD-160",
            "sha512" => "SHA-512",
            other => panic!("{other}"),
        };
        assert_eq!((s.scheme(), s.prf()), ("AES", want_prf), "{id}");
        assert!(!s.is_hidden());
        assert_tree(&mut s, &e["tree"], id);
        assert_read_only(&mut s, id);
        s.remount().unwrap();
        assert!(!s.vfs().writable(), "{id} after remount");
        drop(s);

        // Opened through a writable fd, nothing still reaches the file.
        let rw = Box::new(FileDevice::open_rw(&root().join("synth-tc").join(&file)).unwrap());
        let mut s = Session::unlock_device_with(rw, &tc(pw), &mut |_, _, _| {}).unwrap();
        assert_read_only(&mut s, id);
        drop(s);
        assert_eq!(
            std::fs::read(root().join("synth-tc").join(&file)).unwrap(),
            before,
            "{id} changed on disk"
        );

        // VeraCrypt mode never finds a TrueCrypt header (PIM 1 only to keep
        // the test quick; the magic decides, not the iteration count).
        let r = Session::unlock_device_with(
            dev("synth-tc", &file),
            &UnlockSecret {
                kdf: vault_core::KdfFilter::Sha512,
                ..UnlockSecret::new(pw, 1)
            },
            &mut |_, _, _| {},
        );
        assert!(matches!(r, Err(VcError::NotFoundOrWrongPassword)), "{id}");

        if let Some(hpw) = e["hidden_password"].as_str() {
            let mut h = Session::unlock_device_with(
                dev("synth-tc", &file),
                &tc(hpw.as_bytes()),
                &mut |_, _, _| {},
            )
            .unwrap();
            assert!(h.is_hidden());
            assert_tree(&mut h, &e["hidden_tree"], id);
            assert_read_only(&mut h, id);
        }
    }
}

#[test]
fn wrong_password_walks_every_truecrypt_derivation() {
    let Some(_) = manifest("synth-tc", "manifest-synth.json") else {
        return;
    };
    let mut steps = 0usize;
    let r = Session::unlock_device_with(
        dev("synth-tc", "synth-tc-aes-ripemd160.tc"),
        &tc(b"not-the-password"),
        &mut |_, _, _| steps += 1,
    );
    assert!(matches!(r, Err(VcError::NotFoundOrWrongPassword)));
    // Three PRFs at four header positions, the same for every container.
    assert_eq!(steps, 12);
}

#[test]
fn truecrypt_before_6_is_named() {
    let Some(_) = manifest("synth-tc", "manifest-synth.json") else {
        return;
    };
    let r = Session::unlock_device_with(
        dev("synth-tc", "synth-tc5-aes-sha512.tc"),
        &tc(b"vaultpony-fixture"),
        &mut |_, _, _| {},
    );
    assert!(
        matches!(
            r,
            Err(VcError::TrueCryptVersionUnsupported { version: 0x0500 })
        ),
        "{:?}",
        r.err()
    );
}

#[test]
fn header_writes_are_refused_in_truecrypt_mode() {
    let Some(_) = manifest("synth-tc", "manifest-synth.json") else {
        return;
    };
    let mut d = dev("synth-tc", "synth-tc-aes-ripemd160.tc");
    let r = vault_core::change_password_with(
        d.as_mut(),
        &tc(b"vaultpony-fixture"),
        &UnlockSecret::new(b"new-password-new-password", 0),
    );
    assert!(matches!(r, Err(VcError::TrueCryptReadOnly)));
    let r = Session::unlock_outer_protected_device_with(
        dev("synth-tc", "synth-tc-aes-ripemd160-hidden.tc"),
        &tc(b"vaultpony-fixture"),
        b"vaultpony-fixture-hidden",
        &mut |_, _, _| {},
    );
    assert!(matches!(r, Err(VcError::TrueCryptReadOnly)));
}

/// TrueCrypt 7.1a's own containers: the release gate.
#[test]
fn truecrypt_7_1a_fixtures_open_with_every_prf_and_cascade() {
    let Some(m) = manifest("rc5", "manifest-rc5.json") else {
        return;
    };
    let Some(all) = m["truecrypt"].as_object() else {
        eprintln!("SKIP: no TrueCrypt entries in manifest-rc5.json");
        return;
    };
    for (id, e) in all {
        let p = &e["params"];
        let file = format!("{id}.tc");
        let pw = p["password"].as_str().unwrap();
        let keyfiles: Vec<Vec<u8>> = if p["keyfile"].as_bool() == Some(true) {
            vec![std::fs::read(root().join("rc5").join(format!("{id}.key"))).unwrap()]
        } else {
            vec![]
        };
        let secret = vc_crypto::apply_keyfiles(pw.as_bytes(), &keyfiles);
        let mut s = Session::unlock_device_with(dev("rc5", &file), &tc(&secret), &mut |_, _, _| {})
            .unwrap_or_else(|err| panic!("{id}: {err:?}"));
        let scheme = vc_types::registry::scheme_by_name(s.scheme()).unwrap();
        assert_eq!(
            scheme.display_name(),
            p["encryption"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(s.prf(), p["hash"].as_str().unwrap(), "{id}");
        assert_tree(&mut s, &e["tree"], id);
        assert_read_only(&mut s, id);
        if let Some(hpw) = e["hidden_password"].as_str() {
            let mut h = Session::unlock_device_with(
                dev("rc5", &file),
                &tc(hpw.as_bytes()),
                &mut |_, _, _| {},
            )
            .unwrap_or_else(|err| panic!("{id} hidden: {err:?}"));
            assert!(h.is_hidden(), "{id}");
            assert_tree(&mut h, &e["hidden_tree"], id);
        }
        if !keyfiles.is_empty() {
            let r = Session::unlock_device_with(
                dev("rc5", &file),
                &tc(pw.as_bytes()),
                &mut |_, _, _| {},
            );
            assert!(
                matches!(r, Err(VcError::NotFoundOrWrongPassword)),
                "{id} without keyfile"
            );
        }
    }
}

/// The iOS File Provider handoff carries TrueCrypt mode across, so the
/// extension's copy of the session is read-only too.
#[test]
fn handoff_keeps_truecrypt_read_only() {
    let Some(m) = manifest("synth-tc", "manifest-synth.json") else {
        return;
    };
    let id = "synth-tc-aes-ripemd160";
    vault_core::enable_handoff(true);
    let s = Session::unlock_device_with(
        dev("synth-tc", &format!("{id}.tc")),
        &tc(b"vaultpony-fixture"),
        &mut |_, _, _| {},
    )
    .unwrap();
    let blob = s.export_handoff().unwrap();
    drop(s);
    let rw =
        Box::new(FileDevice::open_rw(&root().join("synth-tc").join(format!("{id}.tc"))).unwrap());
    let mut imported = Session::import_handoff(rw, &blob).unwrap();
    assert_eq!(imported.prf(), "RIPEMD-160");
    assert_read_only(&mut imported, id);
    assert_tree(&mut imported, &m[id]["tree"], id);
}
