//! VeraCrypt 1.26.29 opens what VaultPony writes with Argon2id: new
//! containers (cascade, default PIM, keyfile, hidden volume with a
//! different KDF from its outer) and headers moved between KDFs by a
//! password change. VeraCrypt reports the volume type and KDF it found,
//! and both are checked.
//!
//! Ignored by default: needs the VeraCrypt 1.26.29+ console with FUSE.
//! Run with `cargo test --release -p vault-core --test argon2id_interop --
//! --ignored --test-threads 1`. The binary is `veracrypt` on PATH, or the
//! `VERACRYPT` environment variable (on macOS:
//! `/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt`, with macFUSE).
//! Run explicitly without a usable VeraCrypt, these tests fail rather than
//! skip, so a green run always means VeraCrypt really opened the volumes.

use std::path::{Path, PathBuf};
use std::process::Command;
use vault_core::{ContainerFs, CreateParams, UnlockSecret};
use vc_io::FileDevice;

const SIZE: u64 = 16 << 20;

fn veracrypt() -> String {
    std::env::var("VERACRYPT").unwrap_or_else(|_| "veracrypt".into())
}

/// Panics unless a VeraCrypt console that knows Argon2id is available.
fn require_vc_with_argon2() {
    assert!(
        have_vc_with_argon2(),
        "VeraCrypt 1.26.29+ console not found at `{}`; set VERACRYPT to its path",
        veracrypt()
    );
}

fn have_vc_with_argon2() -> bool {
    Command::new(veracrypt())
        .args(["--text", "--version"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|v| v.trim().strip_prefix("VeraCrypt ").map(str::to_string))
        .and_then(|v| {
            let parts: Vec<u32> = v.split('.').filter_map(|p| p.parse().ok()).collect();
            (parts.len() == 3).then(|| (parts[0], parts[1], parts[2]) >= (1, 26, 29))
        })
        .unwrap_or(false)
}

fn prf(name: &str) -> &'static vc_types::Prf {
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
    let p = std::env::temp_dir().join(format!("vaultpony-a2i-{}-{name}.vc", std::process::id()));
    std::fs::write(&p, vec![0u8; SIZE as usize]).unwrap();
    p
}

fn params<'a>(
    s: &str,
    p: &str,
    pim: u32,
    pw: &'a [u8],
    keyfiles: &'a [Vec<u8>],
) -> CreateParams<'a> {
    CreateParams {
        scheme: scheme(s),
        prf: prf(p),
        pim,
        passphrase: pw,
        keyfiles,
        size: SIZE,
        sector_size: 512,
    }
}

/// Mount with VeraCrypt (FUSE, no filesystem), read back what it reports,
/// dismount. Returns (type, kdf) such as ("Hidden", "Argon2"), or None if
/// VeraCrypt could not open the volume.
fn vc_properties(
    path: &Path,
    pw: &str,
    pim: u32,
    keyfile: Option<&Path>,
) -> Option<(String, String)> {
    let mut args: Vec<String> = [
        "--text",
        "--non-interactive",
        "--password",
        pw,
        "--pim",
        &pim.to_string(),
        "--filesystem",
        "none",
        "--mount-options",
        "nokernelcrypto",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Some(k) = keyfile {
        args.push("--keyfiles".into());
        args.push(k.to_string_lossy().into());
    }
    args.push("--mount".into());
    args.push(path.to_string_lossy().into());
    let mounted = Command::new(veracrypt())
        .args(&args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !mounted {
        return None;
    }
    let out = Command::new(veracrypt())
        .args(["--text", "--volume-properties"])
        .arg(path)
        .output()
        .unwrap();
    let _ = Command::new(veracrypt())
        .args(["--text", "--dismount"])
        .arg(path)
        .status();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
            .unwrap_or_default()
    };
    Some((field("Type:"), field("KDF:")))
}

fn create(path: &Path, p: &CreateParams<'_>) {
    vault_core::create_container(
        Box::new(FileDevice::open_rw(path).unwrap()),
        p,
        ContainerFs::Fat,
    )
    .unwrap();
}

fn normal(kdf: &str) -> Option<(String, String)> {
    Some(("Normal".to_string(), kdf.to_string()))
}

#[test]
#[ignore = "needs the VeraCrypt 1.26.29+ console; run explicitly"]
fn veracrypt_opens_our_argon2id_containers() {
    require_vc_with_argon2();
    let long = "a-long-argon2id-password";

    for (s, pim) in [("Serpent(Twofish(AES))", 1), ("AES", 0), ("Camellia", 32)] {
        let path = temp(&format!("{}-{pim}", s.replace(['(', ')'], "_")));
        create(&path, &params(s, "Argon2id", pim, long.as_bytes(), &[]));
        assert_eq!(
            vc_properties(&path, long, pim, None),
            normal("Argon2"),
            "{s} PIM {pim}"
        );
        eprintln!("VeraCrypt opened our {s} / Argon2id / PIM {pim}");
        let _ = std::fs::remove_file(&path);
    }

    // Keyfile + short password at the default PIM.
    let kf = std::env::temp_dir().join(format!("vaultpony-a2i-{}.key", std::process::id()));
    let key: Vec<u8> = (0..2048u32).map(|i| (i * 7 + 3) as u8).collect();
    std::fs::write(&kf, &key).unwrap();
    let path = temp("keyfile");
    create(&path, &params("AES", "Argon2id", 0, b"kpw", &[key]));
    assert_eq!(vc_properties(&path, "kpw", 0, Some(&kf)), normal("Argon2"));
    assert_eq!(
        vc_properties(&path, "kpw", 0, None),
        None,
        "keyfile must be required"
    );
    eprintln!("VeraCrypt opened our Argon2id keyfile container");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&kf);
}

#[test]
#[ignore = "needs the VeraCrypt 1.26.29+ console; run explicitly"]
fn veracrypt_opens_our_mixed_kdf_hidden_volume() {
    require_vc_with_argon2();
    let path = temp("hidden");
    let outer = params("AES", "SHA-512", 0, b"outer-pass", &[]);
    let hidden = params("Twofish", "Argon2id", 0, b"hidden-pass", &[]);
    vault_core::create_container_with_hidden(
        || Ok(Box::new(FileDevice::open_rw(&path)?) as Box<dyn vc_io::BlockDevice>),
        &outer,
        &hidden,
        4 << 20,
        ContainerFs::Fat,
    )
    .unwrap();
    assert_eq!(
        vc_properties(&path, "outer-pass", 0, None),
        normal("HMAC-SHA-512")
    );
    assert_eq!(
        vc_properties(&path, "hidden-pass", 0, None),
        Some(("Hidden".to_string(), "Argon2".to_string()))
    );
    eprintln!("VeraCrypt opened our SHA-512 outer and Argon2id hidden volume");
    let _ = std::fs::remove_file(&path);
}

#[test]
#[ignore = "needs the VeraCrypt 1.26.29+ console; run explicitly"]
fn veracrypt_follows_our_kdf_changes() {
    require_vc_with_argon2();
    let path = temp("rekey");
    create(
        &path,
        &params("AES(Twofish)", "SHA-512", 0, b"first-pass", &[]),
    );
    assert_eq!(
        vc_properties(&path, "first-pass", 0, None),
        normal("HMAC-SHA-512")
    );

    let rekey = |old: &[u8], old_pim, new: &[u8], new_pim, to: &str| {
        let mut dev = FileDevice::open_rw(&path).unwrap();
        vault_core::change_password_to(
            &mut dev,
            &UnlockSecret::new(old, old_pim),
            &UnlockSecret::new(new, new_pim),
            Some(prf(to)),
            new,
        )
        .unwrap();
    };

    rekey(b"first-pass", 0, b"second-password-argon2", 2, "Argon2id");
    assert_eq!(vc_properties(&path, "first-pass", 0, None), None);
    assert_eq!(
        vc_properties(&path, "second-password-argon2", 2, None),
        normal("Argon2")
    );
    eprintln!("VeraCrypt followed SHA-512 -> Argon2id");

    rekey(b"second-password-argon2", 2, b"third-pass", 0, "Streebog");
    assert_eq!(
        vc_properties(&path, "third-pass", 0, None),
        normal("HMAC-Streebog")
    );
    eprintln!("VeraCrypt followed Argon2id -> Streebog");
    let _ = std::fs::remove_file(&path);
}
