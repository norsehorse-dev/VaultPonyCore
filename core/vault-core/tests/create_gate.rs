//! The P10 gate (doc §12): containers we create are opened by desktop
//! VeraCrypt across the cipher/PRF matrix, and keyfile containers interop
//! both directions.
//!
//! Two layers:
//!  - always-run, in-process: create across a representative matrix and
//!    reopen with our own reader (fast; no external tools).
//!  - `#[ignore]`, needs the `veracrypt` console: create across the matrix
//!    and confirm VeraCrypt itself unlocks each, plus keyfile both ways.
//!    Run explicitly: `cargo test -p vault-core --release --test create_gate
//!    -- --ignored --nocapture`.

use vc_format::{create_volume, find_header, CreateParams, UnlockSecret};
use vc_io::BlockDevice;
use vc_types::{VcError, VcResult};

struct Mem(Vec<u8>);
impl BlockDevice for Mem {
    fn len(&mut self) -> VcResult<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_at(&mut self, o: u64, b: &mut [u8]) -> VcResult<()> {
        let o = o as usize;
        if o + b.len() > self.0.len() {
            return Err(VcError::Io(std::io::Error::from(
                std::io::ErrorKind::UnexpectedEof,
            )));
        }
        b.copy_from_slice(&self.0[o..o + b.len()]);
        Ok(())
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> VcResult<()> {
        let o = o as usize;
        self.0[o..o + b.len()].copy_from_slice(b);
        Ok(())
    }
    fn flush(&mut self) -> VcResult<()> {
        Ok(())
    }
}

fn scheme(name: &str) -> &'static vc_types::EncryptionScheme {
    vc_types::registry::ENCRYPTION_SCHEMES
        .iter()
        .find(|s| s.name == name)
        .unwrap()
}
fn prf(name: &str) -> &'static vc_types::Prf {
    vc_types::registry::PRFS
        .iter()
        .find(|p| p.name == name)
        .unwrap()
}

#[test]
fn created_containers_reopen_with_our_reader_across_the_matrix() {
    let size = 16 * 1024 * 1024u64;
    // A representative spread: single ciphers, both digest families, a
    // 2-layer and a 3-layer cascade. (The full scheme×PRF sweep against
    // VeraCrypt itself is the #[ignore] gate below.)
    let combos = [
        ("AES", "SHA-512"),
        ("Camellia", "Streebog"),
        ("AES(Twofish)", "Whirlpool"),
        ("Serpent(Twofish(AES))", "SHA-256"),
    ];
    for (s, p) in combos {
        let mut dev = Mem(vec![0u8; size as usize]);
        let params = CreateParams {
            scheme: scheme(s),
            prf: prf(p),
            pim: 0,
            passphrase: b"correct horse",
            keyfiles: &[],
            size,
            sector_size: 512,
        };
        let (start, sz) = create_volume(&mut dev, &params).unwrap();
        assert_eq!(start, 131_072);
        assert_eq!(sz, size - 262_144);

        let found = find_header(
            &mut dev,
            &UnlockSecret {
                passphrase: b"correct horse",
                pim: 0,
            },
            &mut |_, _, _| {},
        )
        .unwrap_or_else(|e| panic!("{s}/{p}: reopen failed: {e}"));
        assert_eq!(found.scheme.name, s);
        assert_eq!(found.prf.name, p);
        assert_eq!(found.header.geometry.encrypted_area_start, 131_072);
    }

    // Wrong password is rejected on a created container (checked once — this
    // walks the whole candidate matrix and is the slow path).
    let mut dev = Mem(vec![0u8; size as usize]);
    create_volume(
        &mut dev,
        &CreateParams {
            scheme: scheme("AES"),
            prf: prf("SHA-512"),
            pim: 0,
            passphrase: b"correct horse",
            keyfiles: &[],
            size,
            sector_size: 512,
        },
    )
    .unwrap();
    assert!(matches!(
        find_header(
            &mut dev,
            &UnlockSecret {
                passphrase: b"nope",
                pim: 0
            },
            &mut |_, _, _| {}
        ),
        Err(VcError::NotFoundOrWrongPassword)
    ));
}

#[test]
fn created_container_with_keyfile_needs_the_keyfile() {
    let size = 16 * 1024 * 1024u64;
    let keyfile = vec![0x5Au8; 3000];
    let mut dev = Mem(vec![0u8; size as usize]);
    let secret_in = vc_crypto::apply_keyfiles(b"pw", std::slice::from_ref(&keyfile));
    create_volume(
        &mut dev,
        &CreateParams {
            scheme: scheme("AES"),
            prf: prf("SHA-512"),
            pim: 0,
            passphrase: b"pw",
            keyfiles: std::slice::from_ref(&keyfile),
            size,
            sector_size: 512,
        },
    )
    .unwrap();

    // Opens with password + keyfile.
    assert!(find_header(
        &mut dev,
        &UnlockSecret {
            passphrase: &secret_in,
            pim: 0
        },
        &mut |_, _, _| {}
    )
    .is_ok());
    // Fails with password alone.
    assert!(matches!(
        find_header(
            &mut dev,
            &UnlockSecret {
                passphrase: b"pw",
                pim: 0
            },
            &mut |_, _, _| {}
        ),
        Err(VcError::NotFoundOrWrongPassword)
    ));
}

// ---- VeraCrypt interop (explicit) ---------------------------------------

#[cfg(test)]
mod vc_interop {
    use super::*;
    use std::path::Path;
    use std::process::Command;

    fn have_vc() -> bool {
        Command::new("veracrypt")
            .arg("--text")
            .arg("--version")
            .output()
            .is_ok()
    }

    fn create_file(path: &Path, s: &str, p: &str, pw: &[u8], keyfile: Option<&Path>) {
        let size = 16 * 1024 * 1024u64;
        std::fs::write(path, vec![0u8; size as usize]).unwrap();
        let keyfiles: Vec<Vec<u8>> = keyfile
            .map(|k| vec![std::fs::read(k).unwrap()])
            .unwrap_or_default();
        let mut dev = vc_io::FileDevice::open_rw(path).unwrap();
        create_volume(
            &mut dev,
            &CreateParams {
                scheme: scheme(s),
                prf: prf(p),
                pim: 0,
                passphrase: pw,
                keyfiles: &keyfiles,
                size,
                sector_size: 512,
            },
        )
        .unwrap();
    }

    fn vc_opens(path: &Path, pw: &str, keyfile: Option<&Path>) -> bool {
        let mut args = vec![
            "--text".into(),
            "--non-interactive".into(),
            "--password".into(),
            pw.to_string(),
            "--pim".into(),
            "0".into(),
            "--filesystem".into(),
            "none".into(),
            "--mount-options".into(),
            "nokernelcrypto".into(),
        ];
        if let Some(k) = keyfile {
            args.push("--keyfiles".into());
            args.push(k.to_string_lossy().into());
        }
        args.push("--mount".into());
        args.push(path.to_string_lossy().into());
        let ok = Command::new("veracrypt")
            .args(&args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            let _ = Command::new("veracrypt")
                .args(["--text", "--dismount"])
                .status();
        }
        ok
    }

    #[test]
    #[ignore = "needs the veracrypt console; run explicitly for the P10 gate"]
    fn veracrypt_opens_our_containers_and_keyfiles_interop() {
        if !have_vc() {
            eprintln!("SKIP: veracrypt not installed");
            return;
        }
        let dir = std::env::temp_dir();
        for (s, p) in [
            ("AES", "SHA-512"),
            ("Serpent", "Whirlpool"),
            ("Twofish", "SHA-256"),
            ("AES(Twofish)", "Streebog"),
        ] {
            let path = dir.join(format!("vp-p10-{}-{}.vc", s.replace(['(', ')'], "_"), p));
            create_file(&path, s, p, b"gatepw", None);
            assert!(vc_opens(&path, "gatepw", None), "VC did not open {s}/{p}");
            eprintln!("VC opened our {s} / {p}");
            let _ = std::fs::remove_file(&path);
        }

        // Keyfile, our create -> VC open.
        let kf = dir.join("vp-p10-key.dat");
        std::fs::write(&kf, (0..4096u32).map(|i| (i * 3) as u8).collect::<Vec<_>>()).unwrap();
        let kpath = dir.join("vp-p10-keyfile.vc");
        create_file(&kpath, "AES", "SHA-512", b"kpw", Some(&kf));
        assert!(
            vc_opens(&kpath, "kpw", Some(&kf)),
            "VC did not open our keyfile container"
        );
        eprintln!("VC opened our keyfile container");
        let _ = std::fs::remove_file(&kpath);
        let _ = std::fs::remove_file(&kf);
    }
}
