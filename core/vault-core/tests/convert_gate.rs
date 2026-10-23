//! "Convert to VeraCrypt" gate (2.0.0 rc5, plan 6.2): `copy_tree` copies a
//! read-only volume into a new container exactly, cleans up names FAT can't
//! hold the way bulk import does, skips links, refuses files too large for
//! the destination, and stops cleanly on cancel or when a vault is locked.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use vault_core::{ContainerFs, CreateParams, Session, UnlockSecret};
use vc_format::{find_header, DecryptedDevice};
use vc_io::{BlockDevice, FileDevice};
use vc_types::VcError;

const PW: &[u8] = b"convert-gate-password-01";
const MIB: u64 = 1 << 20;

fn sha(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vaultpony-convert-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn secret() -> UnlockSecret<'static> {
    UnlockSecret {
        kdf: vault_core::KdfFilter::Sha512,
        ..UnlockSecret::new(PW, 1)
    }
}

fn new_container(path: &Path, size: u64, fs: ContainerFs) {
    std::fs::File::create(path).unwrap().set_len(size).unwrap();
    let params = CreateParams {
        scheme: vc_types::registry::scheme_by_name("AES").unwrap(),
        prf: vc_types::registry::PRFS
            .iter()
            .find(|p| p.name == "SHA-512")
            .unwrap(),
        pim: 1,
        passphrase: PW,
        keyfiles: &[],
        size,
        sector_size: 512,
    };
    vault_core::create_container(Box::new(FileDevice::open_rw(path).unwrap()), &params, fs)
        .unwrap();
}

fn open(path: &Path) -> Session {
    Session::unlock_device_with(
        Box::new(FileDevice::open_rw(path).unwrap()),
        &secret(),
        &mut |_, _, _| {},
    )
    .unwrap()
}

/// A container whose volume is the ext4 image `mke2fs -d` makes of `tree`.
fn ext4_source(dir: &Path, tree: &Path, size: u64) -> PathBuf {
    let img = dir.join("fs.img");
    let out = Command::new("mke2fs")
        .args(["-q", "-F", "-t", "ext4", "-d"])
        .arg(tree)
        .arg(&img)
        .arg(format!("{}k", size / 1024))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let image = std::fs::read(&img).unwrap();
    let path = dir.join("source.vc");
    new_container(&path, image.len() as u64 + 256 * 1024, ContainerFs::Fat);
    let mut dev: Box<dyn BlockDevice> = Box::new(FileDevice::open_rw(&path).unwrap());
    let found = find_header(dev.as_mut(), &secret(), &mut |_, _, _| {}).unwrap();
    let xts = vc_crypto::SchemeXts::new(
        found.scheme,
        &found.header.master_keys[..found.scheme.key_bytes()],
    )
    .unwrap();
    let mut data = DecryptedDevice::new(dev, xts, &found.header.geometry);
    data.write_at(0, &image).unwrap();
    data.flush().unwrap();
    path
}

fn read_all(s: &mut Session, rel: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = s.vfs().read_at(rel, out.len() as u64, &mut buf).unwrap();
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

fn tree_of(s: &mut Session) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![String::new()];
    while let Some(dir) = stack.pop() {
        for e in s
            .vfs()
            .list(if dir.is_empty() { "/" } else { &dir })
            .unwrap()
        {
            let p = if dir.is_empty() {
                e.name.clone()
            } else {
                format!("{dir}/{}", e.name)
            };
            if e.is_dir {
                out.insert(format!("{p}/"), String::new());
                stack.push(p);
            } else {
                let data = read_all(s, &p);
                out.insert(p, sha(&data));
            }
        }
    }
    out
}

#[test]
fn truecrypt_volume_converts_exactly() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synth-tc");
    let src_path = root.join("synth-tc-aes-ripemd160.tc");
    if !src_path.exists() {
        eprintln!("SKIP: fixtures/synth-tc not present");
        return;
    }
    let mut src = Session::unlock_device_with(
        Box::new(FileDevice::open_read(&src_path).unwrap()),
        &UnlockSecret {
            truecrypt: true,
            ..UnlockSecret::new(b"vaultpony-fixture", 0)
        },
        &mut |_, _, _| {},
    )
    .unwrap();
    let dir = tmp("tc");
    let dst_path = dir.join("converted.vc");
    new_container(&dst_path, 16 * MIB, ContainerFs::Fat);
    let mut dst = open(&dst_path);

    let plan = vault_core::plan_copy(&mut src, &mut dst).unwrap();
    assert!(plan.too_big.is_empty() && plan.skipped.is_empty());
    let summary = vault_core::summarize_tree(&mut src).unwrap();
    assert_eq!((summary.files, summary.folders, summary.bytes), (plan.files, plan.folders, plan.bytes));
    assert_eq!(summary.largest_file, 2 * MIB);
    let mut last = vault_core::CopyProgress::default();
    let report = vault_core::copy_tree(&mut src, &mut dst, None, &mut |p| last = *p).unwrap();
    assert_eq!((report.files, report.folders), (plan.files, plan.folders));
    assert_eq!(report.bytes, plan.bytes);
    assert_eq!(report.renamed, 0);
    assert_eq!((last.files_done, last.bytes_done), (plan.files, plan.bytes));

    let want = tree_of(&mut src);
    drop(dst);
    let mut reopened = open(&dst_path);
    assert_eq!(tree_of(&mut reopened), want);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn names_links_and_large_files_follow_the_import_rules() {
    if Command::new("mke2fs").arg("-V").output().is_err() {
        eprintln!("SKIP: mke2fs not installed");
        return;
    }
    let dir = tmp("names");
    let tree = dir.join("tree");
    std::fs::create_dir_all(tree.join("Docs")).unwrap();
    std::fs::create_dir_all(tree.join("docs")).unwrap();
    std::fs::write(tree.join("a:b?.txt"), b"colon").unwrap();
    std::fs::write(tree.join("Photo.jpg"), b"one").unwrap();
    std::fs::write(tree.join("photo.jpg"), b"two").unwrap();
    std::fs::write(tree.join("Docs/in-upper.txt"), b"upper").unwrap();
    std::fs::write(tree.join("docs/in-lower.txt"), b"lower").unwrap();
    std::fs::write(
        tree.join(std::ffi::OsStr::from_bytes(b"latin1-\xe9.txt")),
        b"bytes",
    )
    .unwrap();
    std::os::unix::fs::symlink("Photo.jpg", tree.join("link")).unwrap();
    let src_path = ext4_source(&dir, &tree, 16 * MIB);
    let mut src = open(&src_path);

    let dst_path = dir.join("dst.vc");
    new_container(&dst_path, 16 * MIB, ContainerFs::Fat);
    let mut dst = open(&dst_path);
    let plan = vault_core::plan_copy(&mut src, &mut dst).unwrap();
    assert_eq!(plan.skipped, vec!["/link".to_string()]);
    let report = vault_core::copy_tree(&mut src, &mut dst, None, &mut |_| {}).unwrap();
    assert_eq!(report.skipped, 1);
    // "a:b?.txt" cleaned, one of Photo/photo and one of Docs/docs numbered.
    assert_eq!(report.renamed, 3);
    let got = tree_of(&mut dst);
    assert_eq!(got["a_b_.txt"], sha(b"colon"));
    assert_eq!(got["latin1-\u{FFFD}.txt"], sha(b"bytes"));
    let photos: Vec<_> = got
        .iter()
        .filter(|(k, _)| k.to_lowercase().starts_with("photo"))
        .collect();
    assert_eq!(photos.len(), 2, "{got:?}");
    assert!(
        got.contains_key("Docs/") && got.contains_key("docs (1)/"),
        "{got:?}"
    );
    assert!(!got.contains_key("link"));

    // A file over FAT's 4 GiB limit: refused before anything is written,
    // fine into exFAT. Sparse, so the image stays small.
    let big_tree = dir.join("big");
    std::fs::create_dir_all(&big_tree).unwrap();
    std::fs::File::create(big_tree.join("huge.bin"))
        .unwrap()
        .set_len(4 * 1024 * MIB + 1)
        .unwrap();
    let big_src_dir = dir.join("bigsrc");
    std::fs::create_dir_all(&big_src_dir).unwrap();
    let big_src = ext4_source(&big_src_dir, &big_tree, 16 * MIB);
    let mut big = open(&big_src);
    let fat_path = dir.join("fat.vc");
    new_container(&fat_path, 16 * MIB, ContainerFs::Fat);
    let mut fat = open(&fat_path);
    let plan = vault_core::plan_copy(&mut big, &mut fat).unwrap();
    assert_eq!(plan.too_big, vec!["/huge.bin".to_string()]);
    let r = vault_core::copy_tree(&mut big, &mut fat, None, &mut |_| {});
    assert!(matches!(r, Err(VcError::Filesystem(_))));
    assert!(fat.vfs().list("/").unwrap().is_empty(), "nothing written");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cancel_and_lock_stop_the_copy_without_a_partial_file() {
    if Command::new("mke2fs").arg("-V").output().is_err() {
        eprintln!("SKIP: mke2fs not installed");
        return;
    }
    let dir = tmp("cancel");
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let blob: Vec<u8> = (0..6 * MIB as usize).map(|i| (i % 253) as u8).collect();
    std::fs::write(tree.join("a-first.bin"), &blob).unwrap();
    std::fs::write(tree.join("b-second.bin"), &blob).unwrap();
    let src_path = ext4_source(&dir, &tree, 32 * MIB);

    // Cancel during the second file.
    let mut src = open(&src_path);
    let dst_path = dir.join("dst.vc");
    new_container(&dst_path, 32 * MIB, ContainerFs::Fat);
    let mut dst = open(&dst_path);
    let flag = AtomicBool::new(false);
    let r = vault_core::copy_tree(&mut src, &mut dst, Some(&flag), &mut |p| {
        if p.files_done == 1 && p.bytes_done > 6 * MIB + MIB {
            flag.store(true, Ordering::Relaxed);
        }
    });
    assert!(matches!(r, Err(VcError::Cancelled)));
    let files: Vec<_> = dst
        .vfs()
        .list("/")
        .unwrap()
        .into_iter()
        .filter(|e| !e.is_dir)
        .map(|e| e.name)
        .collect();
    assert_eq!(files, vec!["a-first.bin".to_string()]);
    drop(dst);
    drop(src);

    // Locking the destination (the shells set the slot to None) ends it too.
    let src = Mutex::new(Some(open(&src_path)));
    let dst2_path = dir.join("dst2.vc");
    new_container(&dst2_path, 32 * MIB, ContainerFs::Fat);
    let dst = Mutex::new(Some(open(&dst2_path)));
    let mut locked = false;
    let r = vault_core::copy_tree(&src, &dst, None, &mut |p| {
        if !locked && p.bytes_done > MIB {
            locked = true;
            // The copy holds no lock between calls, so this doesn't block.
            dst.lock().unwrap().take();
        }
    });
    assert!(matches!(r, Err(VcError::Cancelled)), "{r:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
