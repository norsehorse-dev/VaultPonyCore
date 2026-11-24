//! The mount-time repair of a FAT32 top folder damaged by releases up to
//! 2.0.0 (vc_fs::fat_repair). Each test builds a volume the old way, with
//! unwritten space reading as noise the way a decrypted container does, and
//! checks what the repair leaves behind.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use vc_fs::io::DeviceIo;
use vc_fs::Vfs;
use vc_io::BlockDevice;
use vc_types::VcResult;

const BLOCK: usize = 4096;
const VOLUME: u64 = 1 << 30;

fn noise(block: u64, seed: u64) -> Box<[u8; BLOCK]> {
    let mut out = Box::new([0u8; BLOCK]);
    let mut x = block.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ seed;
    for chunk in out.chunks_mut(8) {
        // splitmix64
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
    }
    out
}

/// A sparse device whose unwritten blocks read as noise.
#[derive(Clone)]
struct NoisyDevice {
    seed: u64,
    blocks: Arc<Mutex<HashMap<u64, Box<[u8; BLOCK]>>>>,
    writes: Arc<AtomicU64>,
    read_only: bool,
}

impl NoisyDevice {
    fn new(seed: u64) -> Self {
        Self {
            seed,
            blocks: Arc::new(Mutex::new(HashMap::new())),
            writes: Arc::new(AtomicU64::new(0)),
            read_only: false,
        }
    }
}

impl BlockDevice for NoisyDevice {
    fn len(&mut self) -> VcResult<u64> {
        Ok(VOLUME)
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> VcResult<()> {
        let blocks = self.blocks.lock().unwrap();
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let within = (pos % BLOCK as u64) as usize;
            let n = (BLOCK - within).min(buf.len() - done);
            let index = pos / BLOCK as u64;
            match blocks.get(&index) {
                Some(b) => buf[done..done + n].copy_from_slice(&b[within..within + n]),
                None => buf[done..done + n]
                    .copy_from_slice(&noise(index, self.seed)[within..within + n]),
            }
            done += n;
        }
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> VcResult<()> {
        if self.read_only {
            return Err(vc_types::VcError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "read-only",
            )));
        }
        self.writes.fetch_add(1, Relaxed);
        let mut blocks = self.blocks.lock().unwrap();
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let within = (pos % BLOCK as u64) as usize;
            let n = (BLOCK - within).min(buf.len() - done);
            let index = pos / BLOCK as u64;
            let seed = self.seed;
            let block = blocks.entry(index).or_insert_with(|| noise(index, seed));
            block[within..within + n].copy_from_slice(&buf[done..done + n]);
            done += n;
        }
        Ok(())
    }

    fn flush(&mut self) -> VcResult<()> {
        Ok(())
    }
}

fn content(i: usize) -> Vec<u8> {
    // A few clusters for some files, so there are real chains to check.
    let len = 1 + (i % 7) * 3000;
    (0..len).map(|k| (i * 31 + k) as u8).collect()
}

/// A FAT32 volume written the way 2.0.0 wrote it: `files` in the top folder
/// (some then deleted), plus a subfolder with files of its own. Returns the
/// device and what should be in it, path to content.
fn old_volume(seed: u64, files: usize, legacy: bool) -> (NoisyDevice, BTreeMap<String, Vec<u8>>) {
    let dev = NoisyDevice::new(seed);
    vc_fs::fat::format(Box::new(dev.clone())).unwrap();
    let mut expected = BTreeMap::new();
    {
        let io = DeviceIo::new(Box::new(dev.clone())).unwrap();
        let options = fatfs::FsOptions::new().legacy_unzeroed_root(legacy);
        let fs = fatfs::FileSystem::new(io, options).unwrap();
        {
            let root = fs.root_dir();
            let sub = root.create_dir("Album").unwrap();
            for i in 0..20 {
                let name = format!("Inside {i:02}.jpg");
                let mut f = sub.create_file(&name).unwrap();
                f.write_all(&content(1000 + i)).unwrap();
                f.flush().unwrap();
                expected.insert(format!("/Album/{name}"), content(1000 + i));
            }
            for i in 0..files {
                // The import's own pattern: a temp name, then the real one.
                let temp = format!(".vaultpony-{i:012x}.part");
                let name = if i % 5 == 0 {
                    format!("SHORT{i:03}.JPG")
                } else {
                    format!("Photo {i:04}.jpg")
                };
                let mut f = root.create_file(&temp).unwrap();
                f.write_all(&content(i)).unwrap();
                f.flush().unwrap();
                drop(f);
                root.rename(&temp, &root, &name).unwrap();
                expected.insert(format!("/{name}"), content(i));
            }
            for i in (0..files).step_by(9) {
                let name = if i % 5 == 0 {
                    format!("SHORT{i:03}.JPG")
                } else {
                    format!("Photo {i:04}.jpg")
                };
                root.remove(&name).unwrap();
                expected.remove(&format!("/{name}"));
            }
        }
        fs.unmount().unwrap();
    }
    (dev, expected)
}

fn read_all(vfs: &mut dyn Vfs, path: &str, size: u64) -> Vec<u8> {
    let mut out = vec![0u8; size as usize];
    let mut done = 0usize;
    while done < out.len() {
        let n = vfs.read_at(path, done as u64, &mut out[done..]).unwrap();
        assert!(n > 0);
        done += n;
    }
    out
}

/// Every file under `/` and `/Album`, path to content.
fn snapshot(vfs: &mut dyn Vfs) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for dir in ["/", "/Album"] {
        for e in vfs.list(dir).unwrap() {
            let path = if dir == "/" {
                format!("/{}", e.name)
            } else {
                format!("{dir}/{}", e.name)
            };
            if e.is_dir {
                assert_eq!(path, "/Album", "a folder nobody created");
                continue;
            }
            let data = read_all(vfs, &path, e.size);
            out.insert(path, data);
        }
    }
    out
}

/// What fatfs itself lists in the top folder, junk included.
fn raw_root_count(dev: &NoisyDevice) -> usize {
    let io = DeviceIo::new(Box::new(dev.clone())).unwrap();
    let fs = fatfs::FileSystem::new(io, fatfs::FsOptions::new()).unwrap();
    let n = fs.root_dir().iter().filter(|e| e.is_ok()).count();
    fs.release_without_writing();
    n
}

#[test]
fn junk_goes_and_every_real_file_stays() {
    for seed in [1u64, 2] {
        let (dev, expected) = old_volume(seed, 150, true);
        let top = expected
            .keys()
            .filter(|p| !p.starts_with("/Album/"))
            .count();
        assert!(
            raw_root_count(&dev) > top + 1 + 50,
            "the volume should start out with junk"
        );

        let mut vfs = vc_fs::open_volume(Box::new(dev.clone())).unwrap();
        let report = vfs.take_repair_report().expect("a repair");
        assert!(report.junk_entries > 50);
        assert_eq!(report.damaged, Vec::<String>::new(), "seed {seed}");
        assert_eq!(report.damaged_total, 0);
        assert!(vfs.take_repair_report().is_none(), "handed over once");
        assert_eq!(snapshot(vfs.as_mut()), expected, "seed {seed}");
        vfs.flush().unwrap();
        drop(vfs);

        // New files land in a clean folder, and stay the only new entries.
        let mut vfs = vc_fs::open_volume(Box::new(dev.clone())).unwrap();
        assert!(vfs.take_repair_report().is_none(), "nothing left to repair");
        let mut expected = expected;
        for i in 0..150 {
            let path = format!("/Later {i:04}.jpg");
            vfs.create(&path).unwrap();
            vfs.write_at(&path, 0, &content(5000 + i)).unwrap();
            expected.insert(path, content(5000 + i));
        }
        vfs.flush().unwrap();
        assert_eq!(snapshot(vfs.as_mut()), expected, "seed {seed}");
    }
}

#[test]
fn a_second_mount_writes_nothing() {
    let (dev, _) = old_volume(7, 120, true);
    drop(vc_fs::open_volume(Box::new(dev.clone())).unwrap());
    let before = dev.writes.load(Relaxed);
    let mut vfs = vc_fs::open_volume(Box::new(dev.clone())).unwrap();
    assert!(vfs.take_repair_report().is_none());
    vfs.list("/").unwrap();
    vfs.release_without_writing();
    drop(vfs);
    assert_eq!(dev.writes.load(Relaxed), before);
}

#[test]
fn a_healthy_volume_is_left_alone() {
    let (dev, expected) = old_volume(8, 300, false);
    let before = dev.writes.load(Relaxed);
    let mut vfs = vc_fs::open_volume(Box::new(dev.clone())).unwrap();
    assert!(vfs.take_repair_report().is_none());
    assert_eq!(snapshot(vfs.as_mut()), expected);
    vfs.release_without_writing();
    drop(vfs);
    assert_eq!(dev.writes.load(Relaxed), before);
}

#[test]
fn a_read_only_vault_still_opens() {
    let (mut dev, _) = old_volume(9, 120, true);
    dev.read_only = true;
    let mut vfs = vc_fs::open_volume(Box::new(dev.clone())).unwrap();
    assert!(vfs.take_repair_report().is_none());
    assert!(!vfs.list("/").unwrap().is_empty());
    vfs.release_without_writing();
}

#[test]
fn a_file_with_freed_clusters_is_reported_and_kept() {
    let (dev, expected) = old_volume(10, 120, true);
    // Free the second cluster of one multi-cluster file, as deleting a junk
    // entry under an old release could.
    let victim = "/SHORT010.JPG";
    assert!(expected[victim].len() > 2 * 4096);
    // Its 8.3 entry, found in the blocks the volume has written.
    let first = {
        let blocks = dev.blocks.lock().unwrap();
        blocks
            .values()
            .flat_map(|b| b.chunks(32))
            .find(|e| &e[0..11] == b"SHORT010JPG")
            .map(|e| {
                (u16::from_le_bytes([e[20], e[21]]) as u32) << 16
                    | u16::from_le_bytes([e[26], e[27]]) as u32
            })
            .expect("the victim's entry")
    };
    let fat_offset = {
        let mut boot = [0u8; 512];
        dev.clone().read_at(0, &mut boot).unwrap();
        u16::from_le_bytes([boot[14], boot[15]]) as u64
            * u16::from_le_bytes([boot[11], boot[12]]) as u64
    };
    let mut d = dev.clone();
    let mut entry = [0u8; 4];
    d.read_at(fat_offset + first as u64 * 4, &mut entry)
        .unwrap();
    let second = u32::from_le_bytes(entry) & 0x0FFF_FFFF;
    d.write_at(fat_offset + second as u64 * 4, &[0u8; 4])
        .unwrap();

    let mut vfs = vc_fs::open_volume(Box::new(dev.clone())).unwrap();
    let report = vfs.take_repair_report().expect("a repair");
    assert_eq!(report.damaged, vec![victim.to_string()]);
    assert_eq!(report.damaged_total, 1);
    // Still listed: a damaged file's name is never taken away.
    assert!(vfs
        .list("/")
        .unwrap()
        .iter()
        .any(|e| e.name == "SHORT010.JPG"));
    vfs.release_without_writing();
}
