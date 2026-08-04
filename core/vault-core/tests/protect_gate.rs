//! The P9 gate (doc §12): hidden-volume write protection, verified against
//! the behavior desktop VeraCrypt documents — with protection on, a write
//! that would land in the hidden region is refused and the outer volume
//! goes read-only, and the hidden volume survives byte-identical; with
//! protection off, the same write corrupts the hidden volume (proving the
//! protection is both necessary and effective).

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use vault_core::Session;

const FIXTURE: &str = "aes-sha_512-fat-protect.vc";
const OUTER_PW: &[u8] = b"outer-pw";
const HIDDEN_PW: &[u8] = b"hidden-pw";

fn fixture_copy(tag: &str) -> Option<PathBuf> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(FIXTURE);
    if !src.exists() {
        return None;
    }
    let dst = std::env::temp_dir().join(format!("vp-protect-{tag}-{}.vc", std::process::id()));
    std::fs::copy(&src, &dst).unwrap();
    Some(dst)
}

/// Read the hidden volume's whole tree into path -> sha256. Returns Err if
/// the volume can't be opened or a file can't be read (i.e. it's damaged).
fn snapshot_hidden(container: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut s = Session::unlock(container, HIDDEN_PW, 0, &mut |_, _, _| {})
        .map_err(|e| format!("unlock: {e}"))?;
    let mut out = BTreeMap::new();
    collect(s.vfs(), "/", &mut out).map_err(|e| format!("walk: {e}"))?;
    s.lock();
    Ok(out)
}

fn collect(
    vfs: &mut dyn vc_fs::Vfs,
    dir: &str,
    out: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    for e in vfs.list(dir).map_err(|e| e.to_string())? {
        let path = if dir == "/" {
            format!("/{}", e.name)
        } else {
            format!("{dir}/{}", e.name)
        };
        if e.is_dir {
            collect(vfs, &path, out)?;
        } else {
            let mut hasher = Sha256::new();
            let mut off = 0u64;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = vfs
                    .read_at(&path, off, &mut buf)
                    .map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                off += n as u64;
            }
            out.insert(
                path,
                hasher
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            );
        }
    }
    Ok(())
}

/// Append 256 KiB chunks to /decoy.bin through `vfs` until a write fails.
/// Returns the error string of the first failed write, or None if the whole
/// budget was written without a failure.
fn fill_until_blocked(vfs: &mut dyn vc_fs::Vfs) -> Option<String> {
    vfs.create("/decoy.bin").ok()?;
    let chunk = vec![0xEEu8; 256 * 1024];
    let mut offset = 0u64;
    for _ in 0..80 {
        // ~20 MiB budget
        if let Err(e) = vfs.write_at("/decoy.bin", offset, &chunk) {
            return Some(e.to_string());
        }
        offset += chunk.len() as u64;
    }
    None
}

#[test]
fn protection_on_blocks_the_write_and_the_hidden_volume_survives() {
    let Some(container) = fixture_copy("on") else {
        eprintln!("SKIP: protection fixture not present");
        return;
    };
    let before = snapshot_hidden(&container).expect("hidden readable before");
    assert!(before.keys().any(|k| k.ends_with("readme.txt")));

    // Mount the OUTER volume with protection and overrun it into the hidden
    // region. The write must be refused.
    let mut s =
        Session::unlock_outer_protected(&container, OUTER_PW, HIDDEN_PW, 0, &mut |_, _, _| {})
            .expect("protected unlock");
    let blocked = fill_until_blocked(s.vfs());
    assert!(
        blocked
            .as_deref()
            .is_some_and(|e| e.contains("read-only") || e.contains("hidden")),
        "expected a protection block, got {blocked:?}"
    );
    // Read-only latched: even a tiny write now fails.
    assert!(s.vfs().write_at("/decoy.bin", 0, b"x").is_err());
    s.lock();

    // The hidden volume is untouched.
    let after = snapshot_hidden(&container).expect("hidden readable after");
    assert_eq!(before, after, "hidden volume changed despite protection");

    let _ = std::fs::remove_file(&container);
}

#[test]
fn protection_off_corrupts_the_hidden_volume() {
    // The contrast case (desktop VC's documented warning): writing to an
    // unprotected outer volume destroys the hidden one.
    let Some(container) = fixture_copy("off") else {
        eprintln!("SKIP: protection fixture not present");
        return;
    };
    let before = snapshot_hidden(&container).expect("hidden readable before");

    // Plain writable outer mount — no protection.
    let mut s = Session::unlock_with(&container, OUTER_PW, 0, true, &mut |_, _, _| {})
        .expect("outer unlock");
    let blocked = fill_until_blocked(s.vfs());
    // The fill may stop when the FAT is genuinely full, but it must never be
    // stopped by hidden-volume protection — that's the whole distinction.
    if let Some(e) = &blocked {
        assert!(
            !e.contains("read-only") && !e.contains("hidden"),
            "unprotected mount unexpectedly protected the hidden volume: {e}"
        );
    }
    s.lock();

    // The hidden volume is now damaged: either unreadable, or its contents
    // no longer match. (Its header at 64 KiB survives — only the data area,
    // which the outer FS just wrote over, is destroyed.)
    let damaged = match snapshot_hidden(&container) {
        Err(_) => true,
        Ok(after) => after != before,
    };
    assert!(
        damaged,
        "hidden volume unexpectedly intact without protection"
    );

    let _ = std::fs::remove_file(&container);
}
