//! The in-memory allocation bitmap must agree with the disk at every step:
//! free space from the live filesystem equals free space from a fresh open of
//! the same bytes, and every file reads back intact, across a churn of
//! creates, growth, deletes and refills. Uses our own mkfs so it runs without
//! system exFAT tools.

use norse_exfat::{ExfatFs, ReadAt, WriteAt};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
struct MemDev(Rc<RefCell<Vec<u8>>>);

impl ReadAt for MemDev {
    fn read_at(&mut self, o: u64, b: &mut [u8]) -> std::io::Result<()> {
        let d = self.0.borrow();
        let o = o as usize;
        if o + b.len() > d.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        b.copy_from_slice(&d[o..o + b.len()]);
        Ok(())
    }
    fn len(&mut self) -> std::io::Result<u64> {
        Ok(self.0.borrow().len() as u64)
    }
}

impl WriteAt for MemDev {
    fn write_at(&mut self, o: u64, b: &[u8]) -> std::io::Result<()> {
        let mut d = self.0.borrow_mut();
        let o = o as usize;
        if o + b.len() > d.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        d[o..o + b.len()].copy_from_slice(b);
        Ok(())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `fsck.exfat -n` over the image when exfatprogs is installed (skipped
/// otherwise, like the other reference-tool checks in this crate).
fn fsck_clean(disk: &MemDev, tag: &str) {
    if std::process::Command::new("fsck.exfat").arg("-V").output().is_err() {
        return;
    }
    let p = std::env::temp_dir().join(format!("vp-space-{tag}-{}.img", std::process::id()));
    std::fs::write(&p, &*disk.0.borrow()).unwrap();
    let out = std::process::Command::new("fsck.exfat")
        .args(["-n", p.to_str().unwrap()])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&p);
    assert!(
        out.status.success(),
        "fsck.exfat ({tag}): {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn content(i: usize) -> Vec<u8> {
    // Sizes from empty to several clusters, deterministic per index.
    let len = (i * 7919) % (300 * 1024);
    (0..len)
        .map(|j| (i as u8).wrapping_mul(31) ^ (j as u8))
        .collect()
}

fn read_all(fs: &mut ExfatFs<MemDev>, path: &str) -> Vec<u8> {
    let e = fs.lookup(path).unwrap().expect("file exists");
    let mut buf = vec![0u8; e.size as usize];
    let mut done = 0;
    while done < buf.len() {
        let n = fs.read_file(&e, done as u64, &mut buf[done..]).unwrap();
        assert!(n > 0, "short read on {path}");
        done += n;
    }
    buf
}

#[test]
fn cached_free_space_matches_a_fresh_open_through_churn() {
    let disk = MemDev(Rc::new(RefCell::new(vec![0u8; 64 << 20])));
    let mut d = disk.clone();
    norse_exfat::format::format(&mut d, 64 << 20, 0x1234_5678).unwrap();

    let mut fs = ExfatFs::open(disk.clone()).unwrap();
    let empty = fs.space().unwrap();
    assert!(empty.free_bytes > 0 && empty.free_bytes < empty.total_bytes);

    let check = |fs: &mut ExfatFs<MemDev>, live: &[usize]| {
        let live_space = fs.space().unwrap();
        let mut fresh = ExfatFs::open(disk.clone()).unwrap();
        assert_eq!(
            fresh.space().unwrap(),
            live_space,
            "cache drifted from disk"
        );
        for &i in live {
            assert_eq!(
                read_all(&mut fresh, &format!("/d/f{i}.bin")),
                content(i),
                "f{i}"
            );
        }
    };

    fs.make_dir("/d").unwrap();
    let mut live: Vec<usize> = Vec::new();
    for i in 0..120 {
        let p = format!("/d/f{i}.bin");
        fs.create_file(&p).unwrap();
        let c = content(i);
        // Write in two pieces so files grow across calls.
        let mid = c.len() / 2;
        fs.write_file(&p, 0, &c[..mid])
            .unwrap_or_else(|e| panic!("i={i} len={} {e:?}", c.len()));
        fs.write_file(&p, mid as u64, &c[mid..]).unwrap();
        live.push(i);
    }
    check(&mut fs, &live);
    fsck_clean(&disk, "filled");

    // Punch holes, then refill so allocation has to reuse freed clusters.
    for i in (0..120).step_by(3) {
        fs.remove(&format!("/d/f{i}.bin")).unwrap();
    }
    live.retain(|i| i % 3 != 0);
    check(&mut fs, &live);

    for i in 120..180 {
        let p = format!("/d/f{i}.bin");
        fs.create_file(&p).unwrap();
        fs.write_file(&p, 0, &content(i)).unwrap();
        live.push(i);
    }
    check(&mut fs, &live);
    fsck_clean(&disk, "refilled");

    // Removing everything gives back exactly the space we started with,
    // minus the directory's own cluster(s).
    for &i in &live {
        fs.remove(&format!("/d/f{i}.bin")).unwrap();
    }
    fs.remove("/d").unwrap();
    assert_eq!(fs.space().unwrap(), empty);
    check(&mut fs, &[]);
}

fn find_utf16(hay: &[u8], s: &str) -> usize {
    let needle: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    hay.windows(needle.len())
        .position(|w| w == needle.as_slice())
        .expect("name on disk")
}

/// Older builds could leave end-of-directory markers in front of live
/// entry sets, hiding those files from every reader. Recreate that layout by
/// hand, confirm the files are hidden, then show the next create in the same
/// folder heals it and everything is visible again.
#[test]
fn stray_end_markers_are_healed_on_the_next_create() {
    let disk = MemDev(Rc::new(RefCell::new(vec![0u8; 16 << 20])));
    let mut d = disk.clone();
    norse_exfat::format::format(&mut d, 16 << 20, 7).unwrap();
    let mut fs = ExfatFs::open(disk.clone()).unwrap();
    fs.make_dir("/d").unwrap();
    for i in 0..60 {
        let p = format!("/d/f{i}.bin");
        fs.create_file(&p).unwrap();
        fs.write_file(&p, 0, &content(i)).unwrap();
    }

    // Turn f20's three slots into end markers, leaving f21..f59 behind them.
    let name_at = find_utf16(&disk.0.borrow(), "f20.bin");
    let set_start = name_at - 2 - 64;
    {
        let mut raw = disk.0.borrow_mut();
        assert_eq!(raw[set_start], 0x85, "file entry of f20");
        for slot in 0..3 {
            let o = set_start + slot * 32;
            raw[o..o + 32].fill(0);
        }
    }
    let mut broken = ExfatFs::open(disk.clone()).unwrap();
    assert!(
        !matches!(broken.lookup("/d/f40.bin"), Ok(Some(_))),
        "hidden behind the marker"
    );

    broken.create_file("/d/new.bin").unwrap();
    let mut healed = ExfatFs::open(disk.clone()).unwrap();
    for i in (0..60).filter(|&i| i != 20) {
        assert_eq!(
            read_all(&mut healed, &format!("/d/f{i}.bin")),
            content(i),
            "f{i}"
        );
    }
    assert!(healed.lookup("/d/new.bin").unwrap().is_some());
    fsck_clean(&disk, "healed");
    assert!(!matches!(healed.lookup("/d/f20.bin"), Ok(Some(_))));
}
