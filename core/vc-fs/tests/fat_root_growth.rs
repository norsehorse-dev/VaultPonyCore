//! A FAT32 root directory that grows past its first cluster must get cleared
//! clusters. Inside an encrypted container a cluster nobody has written reads
//! back as random bytes, and the directory code would take those for entries:
//! junk files in the vault's top folder, and no free run of entries for the
//! next file (2.1.0 plan 2, finding 1; third_party/fatfs/VAULTPONY.md).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use vc_fs::Vfs;
use vc_io::BlockDevice;
use vc_types::VcResult;

const BLOCK: usize = 4096;
// What an unwritten block reads as: never zero, never a deleted-entry mark,
// so as a directory entry it looks like a file in use.
const UNWRITTEN: u8 = 0xA7;

/// A sparse device whose unwritten blocks read as [`UNWRITTEN`], the way the
/// decrypted view of a fresh container reads as noise.
#[derive(Clone)]
struct NoisyDevice {
    len: u64,
    blocks: Arc<Mutex<HashMap<u64, Box<[u8; BLOCK]>>>>,
}

impl NoisyDevice {
    fn new(len: u64) -> Self {
        Self {
            len,
            blocks: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl BlockDevice for NoisyDevice {
    fn len(&mut self) -> VcResult<u64> {
        Ok(self.len)
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> VcResult<()> {
        let blocks = self.blocks.lock().unwrap();
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let within = (pos % BLOCK as u64) as usize;
            let n = (BLOCK - within).min(buf.len() - done);
            match blocks.get(&(pos / BLOCK as u64)) {
                Some(b) => buf[done..done + n].copy_from_slice(&b[within..within + n]),
                None => buf[done..done + n].fill(UNWRITTEN),
            }
            done += n;
        }
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> VcResult<()> {
        let mut blocks = self.blocks.lock().unwrap();
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let within = (pos % BLOCK as u64) as usize;
            let n = (BLOCK - within).min(buf.len() - done);
            let block = blocks
                .entry(pos / BLOCK as u64)
                .or_insert_with(|| Box::new([UNWRITTEN; BLOCK]));
            block[within..within + n].copy_from_slice(&buf[done..done + n]);
            done += n;
        }
        Ok(())
    }

    fn flush(&mut self) -> VcResult<()> {
        Ok(())
    }
}

fn fat32_volume() -> Box<dyn Vfs> {
    // 1 GiB: large enough that fatfs lays down FAT32, whose root directory
    // is a cluster chain that grows (FAT12/16 roots are a fixed area).
    let dev = NoisyDevice::new(1 << 30);
    vc_fs::fat::format(Box::new(dev.clone())).unwrap();
    vc_fs::open_volume(Box::new(dev)).unwrap()
}

/// Names that need a long-name record, so each file takes two entries.
fn name(i: usize) -> String {
    format!("Photo {i:04}.jpg")
}

fn fill(vfs: &mut dyn Vfs, dir: &str, files: usize) {
    for i in 0..files {
        let path = format!("{dir}/{}", name(i));
        vfs.create(&path).unwrap();
        vfs.write_at(&path, 0, b"x").unwrap();
    }
    vfs.flush().unwrap();
}

fn assert_only_ours(vfs: &mut dyn Vfs, dir: &str, files: usize) {
    let mut names: Vec<String> = vfs
        .list(if dir.is_empty() { "/" } else { dir })
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    names.sort();
    let expected: Vec<String> = (0..files).map(name).collect();
    assert_eq!(
        names.len(),
        files,
        "the listing holds entries nobody created"
    );
    assert_eq!(names, expected);
}

#[test]
fn root_directory_stays_clean_as_it_grows() {
    let mut vfs = fat32_volume();
    let cluster = vfs.space().unwrap().cluster_bytes as usize;
    // Enough two-entry files to need several directory clusters.
    let files = (cluster / 32) * 2;
    fill(vfs.as_mut(), "", files);
    assert_only_ours(vfs.as_mut(), "", files);
}

#[test]
fn subdirectory_stays_clean_as_it_grows() {
    let mut vfs = fat32_volume();
    let cluster = vfs.space().unwrap().cluster_bytes as usize;
    let files = (cluster / 32) * 2;
    vfs.mkdir("/photos").unwrap();
    fill(vfs.as_mut(), "/photos", files);
    assert_only_ours(vfs.as_mut(), "/photos", files);
}
