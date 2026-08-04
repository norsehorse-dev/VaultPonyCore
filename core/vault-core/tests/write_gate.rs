//! The P4 write gate (doc §12): a full write workload through the stack —
//! create/write/mkdir/rename/truncate/delete — then three verdicts:
//!
//! 1. Round-trip: a fresh unlock reads back exactly what was written.
//! 2. Dot-entry hygiene: directories we create carry bare `.`/`..` entries
//!    (regression test for the vendored fatfs patch).
//! 3. fsck-equivalence: the decrypted image passes `fsck.fat -n` with no
//!    complaints (skipped politely when fsck.fat is not installed).

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use vc_format::{find_header, DecryptedDevice, UnlockSecret};
use vc_io::{BlockDevice, FileDevice};

const PASSWORD: &[u8] = b"vaultpony-fixture";
const FIXTURE: &str = "aes-sha_512-fat-512-pim0-plain.vc";

fn fixture_copy() -> Option<PathBuf> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(FIXTURE);
    if !src.exists() {
        return None;
    }
    let dst = std::env::temp_dir().join(format!("vaultpony-write-gate-{}.vc", std::process::id()));
    std::fs::copy(&src, &dst).unwrap();
    Some(dst)
}

fn sha(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Decrypt the container's data area to a plain image file using the
/// format layer directly (no VeraCrypt dependency in the test).
fn decrypt_to_image(container: &Path, out: &Path) {
    let mut dev = FileDevice::open_read(container).unwrap();
    let found = find_header(
        &mut dev,
        &UnlockSecret {
            passphrase: PASSWORD,
            pim: 0,
        },
        &mut |_, _, _| {},
    )
    .unwrap();
    let geometry = found.header.geometry;
    let xts = vc_crypto::SchemeXts::new(
        found.scheme,
        &found.header.master_keys[..found.scheme.key_bytes()],
    )
    .unwrap();
    let mut decrypted = DecryptedDevice::new(Box::new(dev), xts, &geometry);
    let len = decrypted.len().unwrap();
    let mut img = vec![0u8; len as usize];
    decrypted.read_at(0, &mut img).unwrap();
    std::fs::write(out, img).unwrap();
}

#[test]
fn p4_write_gate() {
    let Some(container) = fixture_copy() else {
        eprintln!("SKIP: fixture corpus not present");
        return;
    };

    // -- Write workload ----------------------------------------------------
    let payload: Vec<u8> = (0..2_000_000u32).map(|i| (i * 31 % 251) as u8).collect();
    let payload_hash = sha(&payload);
    {
        let mut s =
            vault_core::Session::unlock_with(&container, PASSWORD, 0, true, &mut |_, _, _| {})
                .unwrap();
        let vfs = s.vfs();
        assert!(vfs.writable());

        vfs.mkdir("/newdir").unwrap();
        vfs.mkdir("/newdir/sub").unwrap();
        vfs.create("/newdir/sub/payload.bin").unwrap();
        vfs.write_at("/newdir/sub/payload.bin", 0, &payload)
            .unwrap();

        vfs.create("/scratch.txt").unwrap();
        vfs.write_at("/scratch.txt", 0, b"first draft").unwrap();
        vfs.truncate("/scratch.txt", 5).unwrap();
        vfs.rename("/scratch.txt", "/newdir/kept.txt").unwrap();

        vfs.create("/doomed.bin").unwrap();
        vfs.write_at("/doomed.bin", 0, &[0xDDu8; 4096]).unwrap();
        vfs.unlink("/doomed.bin").unwrap();

        // Overwrite an existing fixture file in place.
        vfs.write_at("/readme.txt", 0, b"REWRITTEN!").unwrap();
        vfs.truncate("/readme.txt", 10).unwrap();

        vfs.flush().unwrap();
        s.lock();
    }

    // -- Verdict 1: fresh unlock reads back the new reality ---------------
    {
        let mut s =
            vault_core::Session::unlock(&container, PASSWORD, 0, &mut |_, _, _| {}).unwrap();
        let vfs = s.vfs();

        let mut buf = vec![0u8; payload.len() + 10];
        let n = vfs.read_at("/newdir/sub/payload.bin", 0, &mut buf).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(sha(&buf[..n]), payload_hash, "payload mismatch");

        let mut small = [0u8; 32];
        let n = vfs.read_at("/newdir/kept.txt", 0, &mut small).unwrap();
        assert_eq!(&small[..n], b"first");

        let n = vfs.read_at("/readme.txt", 0, &mut small).unwrap();
        assert_eq!(&small[..n], b"REWRITTEN!");

        let root: Vec<String> = vfs.list("/").unwrap().into_iter().map(|e| e.name).collect();
        assert!(!root.contains(&"doomed.bin".to_string()), "unlink failed");
        assert!(
            !root.contains(&"scratch.txt".to_string()),
            "rename left source"
        );
        // Original fixture tree still intact.
        let n = vfs
            .read_at("/deep/a/b/c/d/e/f/leaf.txt", 0, &mut small)
            .unwrap();
        assert_eq!(&small[..n], b"nested\n");
        s.lock();
    }

    // -- Verdicts 2 + 3: raw image checks ----------------------------------
    let img_path = container.with_extension("img");
    decrypt_to_image(&container, &img_path);

    // Dot-entry hygiene: no LFN (attr 0x0F) entry may precede a `.` entry.
    let img = std::fs::read(&img_path).unwrap();
    let mut dot_lfn = 0;
    for w in img.windows(64) {
        let (a, b) = (&w[..32], &w[32..]);
        if a[11] == 0x0F && b[11] == 0x10 && (b.starts_with(b".          ")) {
            dot_lfn += 1;
        }
    }
    assert_eq!(dot_lfn, 0, "found LFN records attached to `.` entries");

    if Command::new("fsck.fat").arg("--help").output().is_ok() {
        let out = Command::new("fsck.fat")
            .args(["-n", img_path.to_str().unwrap()])
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "fsck.fat found problems:\n{text}");
    } else {
        eprintln!("NOTE: fsck.fat not installed; structural verdict skipped");
    }

    let _ = std::fs::remove_file(&container);
    let _ = std::fs::remove_file(&img_path);
}
