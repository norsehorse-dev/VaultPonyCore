//! The P5 gate (doc §12): 10k randomized filesystem ops applied by our
//! exFAT writer, diffed against the exfat-3g reference driver's view, zero
//! divergence. Our writer writes; the reference reads; a shadow model says
//! what the tree must contain.
//!
//! Needs root + mkfs.exfat + exfat-fuse + losetup (Linux CI / dev box);
//! skips politely otherwise. Run explicitly:
//!   cargo test -p vc-fs --release --test exfat_fuzz -- --nocapture --ignored

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;
use vc_fs::Vfs;
use vc_io::BlockDevice;
use vc_types::VcResult;

const OPS: usize = 10_000;
const CHECK_EVERY: usize = 1_000;
const IMG_BYTES: u64 = 64 << 20;

/// File-backed block device that fsyncs on flush (so the loop device sees
/// our writes when the reference driver mounts).
struct FileDev(std::fs::File);
impl BlockDevice for FileDev {
    fn len(&mut self) -> VcResult<u64> {
        Ok(self.0.metadata().map_err(vc_types::VcError::Io)?.len())
    }
    fn read_at(&mut self, o: u64, b: &mut [u8]) -> VcResult<()> {
        self.0
            .seek(SeekFrom::Start(o))
            .map_err(vc_types::VcError::Io)?;
        self.0.read_exact(b).map_err(vc_types::VcError::Io)
    }
    fn write_at(&mut self, o: u64, b: &[u8]) -> VcResult<()> {
        self.0
            .seek(SeekFrom::Start(o))
            .map_err(vc_types::VcError::Io)?;
        self.0.write_all(b).map_err(vc_types::VcError::Io)
    }
    fn flush(&mut self) -> VcResult<()> {
        self.0.sync_data().map_err(vc_types::VcError::Io)
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn tools_present() -> bool {
    for t in ["mkfs.exfat", "losetup", "mount.exfat-fuse"] {
        if Command::new(t).arg("--help").output().is_err()
            && Command::new(t).arg("--version").output().is_err()
        {
            return false;
        }
    }
    // Need root for losetup/mount.
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn reference_tree(img: &Path) -> BTreeMap<String, Option<String>> {
    // Returns path -> Some(sha256) for files, None for dirs.
    let loop_dev = String::from_utf8(
        Command::new("losetup")
            .args(["-f", "--show", img.to_str().unwrap()])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    let mnt = img.with_extension("refmnt");
    std::fs::create_dir_all(&mnt).unwrap();
    let out = BTreeMap::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(Command::new("mount.exfat-fuse")
            .args(["-o", "ro", &loop_dev, mnt.to_str().unwrap()])
            .status()
            .unwrap()
            .success());
        let mut t = out;
        walk_ref(&mnt, &mnt, &mut t);
        let _ = Command::new("fusermount3")
            .args(["-u", mnt.to_str().unwrap()])
            .status();
        t
    }));
    let _ = Command::new("losetup").args(["-d", &loop_dev]).status();
    let _ = std::fs::remove_dir(&mnt);
    result.unwrap_or_else(|_| panic!("reference mount/walk failed"))
}

fn walk_ref(root: &Path, dir: &Path, out: &mut BTreeMap<String, Option<String>>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let path = e.path();
        let rel = format!("/{}", path.strip_prefix(root).unwrap().to_string_lossy());
        if e.file_type().unwrap().is_dir() {
            out.insert(rel, None);
            walk_ref(root, &path, out);
        } else {
            let data = std::fs::read(&path).unwrap();
            out.insert(rel, Some(hash(&data)));
        }
    }
}

fn hash(d: &[u8]) -> String {
    Sha256::digest(d)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn shadow_tree(
    files: &BTreeMap<String, Vec<u8>>,
    dirs: &std::collections::BTreeSet<String>,
) -> BTreeMap<String, Option<String>> {
    let mut t = BTreeMap::new();
    for d in dirs {
        t.insert(d.clone(), None);
    }
    for (p, c) in files {
        t.insert(p.clone(), Some(hash(c)));
    }
    t
}

fn open_vfs(img: &Path) -> Box<dyn Vfs> {
    let dev = FileDev(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(img)
            .unwrap(),
    );
    vc_fs::exfat::ExfatVfs::open(Box::new(dev))
        .map(|v| Box::new(v) as Box<dyn Vfs>)
        .unwrap()
}

#[test]
#[ignore = "needs root + exfat tools; run explicitly for the P5 gate"]
fn exfat_write_matches_reference_over_10k_ops() {
    if !tools_present() {
        eprintln!("SKIP: exfat tools or root not available");
        return;
    }
    let img = std::env::temp_dir().join(format!("vp-exfuzz-{}.img", std::process::id()));
    std::fs::write(&img, vec![0u8; IMG_BYTES as usize]).unwrap();
    assert!(Command::new("mkfs.exfat")
        .args(["-c", "32k", img.to_str().unwrap()])
        .output()
        .unwrap()
        .status
        .success());

    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut vfs = open_vfs(&img);
    // A small pool of directories (root + a few subdirs).
    let dir_pool = ["", "/da", "/db", "/dc"];

    let mut applied = 0usize;
    for step in 0..OPS {
        let d = dir_pool[rng.below(dir_pool.len())];
        let fname = format!("{}/f{}.bin", d, rng.below(40));
        let op = rng.below(100);
        let r: VcResult<()> = (|| {
            if op < 8 {
                // mkdir one of the pool dirs (idempotent-ish; ignore exists)
                let nd = dir_pool[1 + rng.below(dir_pool.len() - 1)];
                if !dirs.contains(nd) {
                    vfs.mkdir(nd)?;
                    dirs.insert(nd.to_string());
                }
            } else if op < 60 {
                // create+write or overwrite a file
                let len = rng.below(20_000);
                let byte = rng.next() as u8;
                let content = vec![byte; len];
                if !files.contains_key(&fname) {
                    // parent dir must exist
                    if !d.is_empty() && !dirs.contains(d) {
                        vfs.mkdir(d)?;
                        dirs.insert(d.to_string());
                    }
                    vfs.create(&fname)?;
                }
                vfs.write_at(&fname, 0, &content)?;
                vfs.truncate(&fname, len as u64)?;
                files.insert(fname.clone(), content);
            } else if op < 75 {
                // append
                if let Some(existing) = files.get(&fname).cloned() {
                    let add = vec![rng.next() as u8; rng.below(5000)];
                    vfs.write_at(&fname, existing.len() as u64, &add)?;
                    let mut merged = existing;
                    merged.extend_from_slice(&add);
                    files.insert(fname.clone(), merged);
                }
            } else if op < 90 {
                // delete a file
                if files.contains_key(&fname) {
                    vfs.unlink(&fname)?;
                    files.remove(&fname);
                }
            } else {
                // rename a file within the same dir
                if files.contains_key(&fname) {
                    let to = format!("{}/r{}.bin", d, rng.below(40));
                    if !files.contains_key(&to) {
                        vfs.rename(&fname, &to)?;
                        let c = files.remove(&fname).unwrap();
                        files.insert(to, c);
                    }
                }
            }
            Ok(())
        })();
        if r.is_ok() {
            applied += 1;
        }

        if (step + 1) % CHECK_EVERY == 0 {
            // Drop our fs handle so the file is fully synced, mount the
            // reference, diff, then reopen.
            drop(vfs);
            let want = shadow_tree(&files, &dirs);
            let got = reference_tree(&img);
            assert_eq!(
                got, want,
                "divergence at op {step}: reference tree != shadow model"
            );
            eprintln!(
                "op {}: {} files, {} dirs — reference matches",
                step + 1,
                files.len(),
                dirs.len()
            );
            vfs = open_vfs(&img);
        }
    }
    eprintln!(
        "exfat fuzz: {applied}/{OPS} ops applied, all checkpoints matched the reference driver"
    );
    let _ = std::fs::remove_file(&img);
}
