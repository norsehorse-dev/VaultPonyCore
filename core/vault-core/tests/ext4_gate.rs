//! Read-only ext4 gate (2.0.0 rc5, plan 6.3), in-process: build ext4, ext3
//! and ext2 images with `mke2fs -d` from a known tree, place each inside a
//! container we create, and read everything back through a session. Skips
//! when `mke2fs` isn't installed. The VeraCrypt-made ext4 containers in
//! `fixtures/rc5` (create_rc5_fixtures.py) are the release gate and are
//! checked at the end when present.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use vault_core::{ContainerFs, CreateParams, Session, UnlockSecret};
use vc_format::{find_header, DecryptedDevice};
use vc_io::{BlockDevice, FileDevice};
use vc_types::VcError;

const PW: &[u8] = b"ext4-gate-password-0001";
const MIB: u64 = 1 << 20;

fn sha(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vaultpony-ext4-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The tree every image is built from; returns path -> sha256 for regular
/// files (paths as the session lists them).
fn make_tree(root: &Path) -> BTreeMap<String, String> {
    let mut want = BTreeMap::new();
    let mut put = |rel: &str, data: &[u8]| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, data).unwrap();
        want.insert(rel.to_string(), sha(data));
    };
    put("readme.txt", b"VaultPony ext4 tree\n");
    put("empty.bin", b"");
    let big: Vec<u8> = (0..3 * MIB as usize).map(|i| (i * 7 % 251) as u8).collect();
    put("big/three-mib.bin", &big);
    put("deep/a/b/c/d/e/f/leaf.txt", b"nested\n");
    put(
        "unicode/\u{e5}\u{e9}\u{ee} \u{f8}\u{fc}\u{2013}\u{98a8}\u{6c34}.txt",
        b"unicode name\n",
    );
    put(&format!("long/{}.dat", "x".repeat(200)), b"long name\n");
    for i in 0..600 {
        put(
            &format!("many/file-{i:04}.txt"),
            format!("{i}\n").as_bytes(),
        );
    }
    for i in 0..10 {
        put(&format!("tiny/t{i}.txt"), format!("tiny {i}\n").as_bytes());
    }
    let sparse = root.join("sparse.bin");
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::File::create(&sparse).unwrap();
        f.set_len(6 * MIB).unwrap();
        f.seek(SeekFrom::Start(3 * MIB)).unwrap();
        f.write_all(b"middle").unwrap();
    }
    want.insert("sparse.bin".into(), sha(&std::fs::read(&sparse).unwrap()));
    std::fs::create_dir_all(root.join("links")).unwrap();
    std::os::unix::fs::symlink("../readme.txt", root.join("links/to-readme")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.join("links/escape")).unwrap();
    std::os::unix::fs::symlink("../deep", root.join("links/to-deep")).unwrap();
    let raw = std::ffi::OsStr::from_bytes(b"latin1-\xe9.txt");
    std::fs::create_dir_all(root.join("names")).unwrap();
    std::fs::write(root.join("names").join(raw), b"not utf-8\n").unwrap();
    want.insert("names/latin1-\u{FFFD}.txt".into(), sha(b"not utf-8\n"));
    let fifo = root.join("fifo");
    let ok = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "mkfifo");
    want
}

fn have_mke2fs() -> bool {
    Command::new("mke2fs").arg("-V").output().is_ok()
}

/// A container holding the ext4 image built from `tree` with `args`.
fn container(name: &str, tree: &Path, args: &[&str], size: u64) -> PathBuf {
    let dir = tmp(name);
    let img = dir.join("fs.img");
    let out = Command::new("mke2fs")
        .args(["-q", "-F"])
        .args(args)
        .arg("-d")
        .arg(tree)
        .arg(&img)
        .arg(format!("{}k", size / 1024))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let image = std::fs::read(&img).unwrap();

    let path = dir.join("vault.vc");
    let total = image.len() as u64 + 256 * 1024;
    std::fs::File::create(&path)
        .unwrap()
        .set_len(total)
        .unwrap();
    let params = CreateParams {
        scheme: vc_types::registry::scheme_by_name("AES").unwrap(),
        prf: vc_types::registry::PRFS
            .iter()
            .find(|p| p.name == "SHA-512")
            .unwrap(),
        pim: 1,
        passphrase: PW,
        keyfiles: &[],
        size: total,
        sector_size: 512,
    };
    vault_core::create_container(
        Box::new(FileDevice::open_rw(&path).unwrap()),
        &params,
        ContainerFs::Fat,
    )
    .unwrap();
    let mut dev: Box<dyn BlockDevice> = Box::new(FileDevice::open_rw(&path).unwrap());
    let found = find_header(
        dev.as_mut(),
        &UnlockSecret {
            kdf: vault_core::KdfFilter::Sha512,
            ..UnlockSecret::new(PW, 1)
        },
        &mut |_, _, _| {},
    )
    .unwrap();
    let xts = vc_crypto::SchemeXts::new(
        found.scheme,
        &found.header.master_keys[..found.scheme.key_bytes()],
    )
    .unwrap();
    let mut data = DecryptedDevice::new(dev, xts, &found.header.geometry);
    assert_eq!(data.len().unwrap(), image.len() as u64);
    data.write_at(0, &image).unwrap();
    data.flush().unwrap();
    path
}

fn read_all(s: &mut Session, rel: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 100_000];
    loop {
        let n = s
            .vfs()
            .read_at(rel, out.len() as u64, &mut buf)
            .unwrap_or_else(|e| panic!("{rel} at {}: {e:?}", out.len()));
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

fn check(name: &str, path: &Path, want: &BTreeMap<String, String>, size: u64) {
    let before = std::fs::read(path).unwrap();
    let mut s = Session::unlock_device_with(
        Box::new(FileDevice::open_rw(path).unwrap()),
        &UnlockSecret {
            kdf: vault_core::KdfFilter::Sha512,
            ..UnlockSecret::new(PW, 1)
        },
        &mut |_, _, _| {},
    )
    .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    assert_eq!(s.vfs().kind(), vc_fs::FsKind::Ext4, "{name}");
    assert!(!s.vfs().writable(), "{name}");

    for (rel, digest) in want {
        assert_eq!(&sha(&read_all(&mut s, rel)), digest, "{name}/{rel}");
        let st = s.vfs().stat(rel).unwrap();
        assert!(!st.is_dir, "{name}/{rel}");
    }
    // Reads at an offset, the way a video player seeks.
    let mut buf = [0u8; 6];
    assert_eq!(s.vfs().read_at("sparse.bin", 3 * MIB, &mut buf).unwrap(), 6);
    assert_eq!(&buf, b"middle");
    assert_eq!(s.vfs().read_at("sparse.bin", 6 * MIB, &mut buf).unwrap(), 0);

    let root: BTreeMap<_, _> = s
        .vfs()
        .list("/")
        .unwrap()
        .into_iter()
        .map(|e| (e.name.clone(), e))
        .collect();
    for d in ["big", "deep", "links", "many", "names", "unicode"] {
        assert!(root[d].is_dir, "{name}: {d}");
    }
    assert!(!root["fifo"].is_dir && root["fifo"].size == 0, "{name}");
    assert!(root["readme.txt"].mtime_ms.is_some());
    assert_eq!(s.vfs().list("many").unwrap().len(), 600, "{name}");

    let links: BTreeMap<_, _> = s
        .vfs()
        .list("links")
        .unwrap()
        .into_iter()
        .map(|e| (e.name.clone(), e))
        .collect();
    assert_eq!(links.len(), 3);
    for (n, e) in &links {
        assert!(!e.is_dir && e.size == 0, "{name}: {n}");
        assert!(
            s.vfs().read_at(&format!("links/{n}"), 0, &mut buf).is_err(),
            "{name}: read {n}"
        );
    }
    // Nothing resolves through a symlink, even a made-up path.
    assert!(s.vfs().list("links/to-deep").is_err());
    assert!(s
        .vfs()
        .read_at("links/to-deep/a/b/c/d/e/f/leaf.txt", 0, &mut buf)
        .is_err());
    assert!(s.vfs().read_at("fifo", 0, &mut buf).is_err());
    assert!(s.vfs().read_at("../readme.txt", 0, &mut buf).is_err());

    let names = s.vfs().list("names").unwrap();
    assert_eq!(names[0].name, "latin1-\u{FFFD}.txt");

    let sp = s.space().unwrap();
    assert_eq!(sp.total_bytes, size, "{name}");
    assert!(
        sp.free_bytes > 0 && sp.free_bytes < sp.total_bytes,
        "{name}"
    );

    for r in [
        s.vfs().create("new.txt"),
        s.vfs().mkdir("d"),
        s.vfs().unlink("readme.txt"),
        s.vfs().rename("readme.txt", "r.txt"),
    ] {
        assert!(r.is_err(), "{name}");
    }
    assert!(s.vfs().write_at("readme.txt", 0, b"x").is_err());
    s.remount().unwrap();
    assert_eq!(sha(&read_all(&mut s, "readme.txt")), want["readme.txt"]);
    drop(s);
    assert!(
        std::fs::read(path).unwrap() == before,
        "{name}: container changed"
    );
}

#[test]
fn ext_family_images_read_back_exactly() {
    if !have_mke2fs() {
        eprintln!("SKIP: mke2fs not installed");
        return;
    }
    let tree_dir = tmp("tree");
    let want = make_tree(&tree_dir);
    let size = 32 * MIB;
    let cases: &[(&str, &[&str])] = &[
        ("ext4-default", &["-t", "ext4"]),
        ("ext4-1k", &["-t", "ext4", "-b", "1024"]),
        ("ext4-no-journal", &["-t", "ext4", "-O", "^has_journal"]),
        ("ext4-32bit", &["-t", "ext4", "-O", "^64bit,^metadata_csum"]),
        ("ext3", &["-t", "ext3"]),
        ("ext2", &["-t", "ext2"]),
    ];
    for (name, args) in cases {
        let path = container(name, &tree_dir, args, size);
        check(name, &path, &want, size);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
    let _ = std::fs::remove_dir_all(&tree_dir);
}

#[test]
fn unsupported_ext4_features_are_named() {
    if !have_mke2fs() {
        eprintln!("SKIP: mke2fs not installed");
        return;
    }
    let tree_dir = tmp("tree-unsupported");
    std::fs::write(tree_dir.join("a.txt"), b"a").unwrap();
    // inline_data (small files stored in the inode) is off by default in
    // mkfs.ext4 and ext4-view 1.0 doesn't read it: the unlock must say so
    // by name rather than fail generically.
    let path = container(
        "inline",
        &tree_dir,
        &["-t", "ext4", "-O", "inline_data"],
        16 * MIB,
    );
    let r = Session::unlock_device_with(
        Box::new(FileDevice::open_read(&path).unwrap()),
        &UnlockSecret {
            kdf: vault_core::KdfFilter::Sha512,
            ..UnlockSecret::new(PW, 1)
        },
        &mut |_, _, _| {},
    );
    match r {
        Err(VcError::Ext4Unsupported(detail)) => {
            assert!(detail.contains("DATA_IN_INODE"), "{detail}")
        }
        Ok(_) => panic!("inline_data opened; update this test and the plan"),
        Err(e) => panic!("{e:?}"),
    }
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
    let _ = std::fs::remove_dir_all(&tree_dir);
}

/// VeraCrypt's own ext4 containers (release gate; skips without them).
#[test]
fn veracrypt_ext4_fixtures_read_back() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rc5");
    let m = dir.join("manifest-rc5.json");
    if !m.exists() {
        eprintln!("SKIP: fixtures/rc5 not present");
        return;
    }
    let m: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(m).unwrap()).unwrap();
    let Some(all) = m["ext4"].as_object() else {
        return;
    };
    for (id, e) in all {
        let path = dir.join(format!("{id}.vc"));
        let open = |pw: &str| {
            Session::unlock_device_with(
                Box::new(FileDevice::open_read(&path).unwrap()),
                &UnlockSecret::new(pw.as_bytes(), 0),
                &mut |_, _, _| {},
            )
            .unwrap_or_else(|err| panic!("{id}: {err:?}"))
        };
        let mut sessions = vec![(open(e["params"]["password"].as_str().unwrap()), &e["tree"])];
        if let Some(hpw) = e["hidden_password"].as_str() {
            sessions.push((open(hpw), &e["hidden_tree"]));
        }
        for (mut s, tree) in sessions {
            for (rel, want) in tree.as_object().unwrap() {
                let want = want.as_str().unwrap();
                let rel = match rel.strip_prefix("hex:") {
                    Some(h) => {
                        let bytes: Vec<u8> = (0..h.len())
                            .step_by(2)
                            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                            .collect();
                        String::from_utf8_lossy(&bytes).into_owned()
                    }
                    None => rel.clone(),
                };
                if want.starts_with("symlink:") || want == "fifo" {
                    let st = s.vfs().stat(&rel).unwrap();
                    assert!(!st.is_dir && st.size == 0, "{id}/{rel}");
                    assert!(
                        s.vfs().read_at(&rel, 0, &mut [0u8; 4]).is_err(),
                        "{id}/{rel}"
                    );
                    continue;
                }
                assert_eq!(sha(&read_all(&mut s, &rel)), want, "{id}/{rel}");
            }
        }
    }
}

struct Mem(Vec<u8>);
impl BlockDevice for Mem {
    fn len(&mut self) -> vc_types::VcResult<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_at(&mut self, o: u64, b: &mut [u8]) -> vc_types::VcResult<()> {
        let o = o as usize;
        match self.0.get(o..o + b.len()) {
            Some(s) => {
                b.copy_from_slice(s);
                Ok(())
            }
            None => Err(VcError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))),
        }
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> vc_types::VcResult<()> {
        Err(VcError::Internal("read-only".into()))
    }
    fn flush(&mut self) -> vc_types::VcResult<()> {
        Ok(())
    }
}

/// Mutation rounds; raise with VAULTPONY_EXT4_ROUNDS for a longer search.
fn rounds() -> usize {
    std::env::var("VAULTPONY_EXT4_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(600)
}

/// A damaged or hostile ext4 volume must give errors, never a panic (the
/// release build aborts on panic). Mutates metadata blocks of a small image
/// and walks everything each time.
#[test]
fn damaged_ext4_metadata_never_panics() {
    if !have_mke2fs() {
        eprintln!("SKIP: mke2fs not installed");
        return;
    }
    let dir = tmp("fuzz");
    let tree = dir.join("tree");
    std::fs::create_dir_all(tree.join("d/e")).unwrap();
    for i in 0..40 {
        std::fs::write(tree.join(format!("d/f{i}.txt")), vec![b'x'; i * 100]).unwrap();
    }
    std::fs::write(tree.join("d/e/big.bin"), vec![7u8; 300_000]).unwrap();
    std::os::unix::fs::symlink("d/f1.txt", tree.join("l")).unwrap();
    let img = dir.join("fs.img");
    let ok = Command::new("mke2fs")
        .args(["-q", "-F", "-t", "ext4", "-b", "1024", "-d"])
        .arg(&tree)
        .arg(&img)
        .arg("2048k")
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let base = std::fs::read(&img).unwrap();
    // Metadata lives in the first blocks: superblock, group descriptors,
    // bitmaps, inode table, directory and extent blocks.
    let hot = 200 * 1024;
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for round in 0..rounds() {
        let mut data = base.clone();
        for _ in 0..1 + round % 8 {
            let at = (rnd() as usize) % hot;
            data[at] ^= 1 << (rnd() % 8);
        }
        let r = std::panic::catch_unwind(|| {
            let Ok(mut fs) = vc_fs::ext4::Ext4Vfs::open(Box::new(Mem(data))) else {
                return;
            };
            use vc_fs::Vfs;
            let mut stack = vec!["/".to_string()];
            let mut buf = vec![0u8; 4096];
            let mut steps = 0;
            while let Some(d) = stack.pop() {
                steps += 1;
                if steps > 200 {
                    break;
                }
                let Ok(list) = fs.list(&d) else { continue };
                for e in list.into_iter().take(100) {
                    let p = format!("{}/{}", d.trim_end_matches('/'), e.name);
                    if e.is_dir {
                        stack.push(p);
                    } else {
                        let _ = fs.stat(&p);
                        let _ = fs.read_at(&p, 0, &mut buf);
                        let _ = fs.read_at(&p, e.size.saturating_sub(10), &mut buf);
                    }
                }
            }
            let _ = fs.space();
        });
        assert!(r.is_ok(), "round {round} panicked");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
