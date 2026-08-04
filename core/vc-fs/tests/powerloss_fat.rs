//! The FAT power-loss harness (doc §7/§13): record every device-level write
//! the FS layer produces during a realistic workload, then simulate a
//! power cut at *every* write boundary and check the invariants:
//!
//! 1. The truncated image never panics the reader; it either opens or
//!    fails with a clean error.
//! 2. Every file that was fully committed at the last completed barrier
//!    before the cut reads back byte-identical — no journal means later
//!    torn writes may lose *new* data, never committed data.
//! 3. At sampled cuts (and every barrier), `fsck.fat -y` on a copy exits
//!    as clean-or-repaired, and repaired images still satisfy invariant 2.
//!
//! FAT has no journal: correctness comes from write ordering plus this
//! harness (and its bigger sibling for exFAT in P5).

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Cursor;
use std::process::Command;
use std::sync::{Arc, Mutex};
use vc_fs::Vfs;
use vc_io::BlockDevice;
use vc_types::VcResult;

const IMG_MIB: usize = 8;

#[derive(Default)]
struct WriteLog {
    ops: Vec<(u64, Vec<u8>)>,
}

/// A device that applies writes to an in-memory image while recording them.
struct RecordingDevice {
    data: Vec<u8>,
    log: Arc<Mutex<WriteLog>>,
}

impl BlockDevice for RecordingDevice {
    fn len(&mut self) -> VcResult<u64> {
        Ok(self.data.len() as u64)
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> VcResult<()> {
        let o = offset as usize;
        buf.copy_from_slice(&self.data[o..o + buf.len()]);
        Ok(())
    }
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> VcResult<()> {
        let o = offset as usize;
        self.data[o..o + buf.len()].copy_from_slice(buf);
        self.log.lock().unwrap().ops.push((offset, buf.to_vec()));
        Ok(())
    }
    fn flush(&mut self) -> VcResult<()> {
        Ok(())
    }
}

fn sha(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32 * 37 + seed as u32) as u8)
        .collect()
}

/// Read `path` out of a FAT image via the fatfs reference reader; None if
/// the image or file is unreadable.
fn read_from_image(img: &[u8], path: &str) -> Option<Vec<u8>> {
    let fs = fatfs::FileSystem::new(Cursor::new(img.to_vec()), fatfs::FsOptions::new()).ok()?;
    let mut f = fs.root_dir().open_file(path).ok()?;
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut f, &mut out).ok()?;
    Some(out)
}

#[test]
fn power_cut_at_every_write_boundary_preserves_committed_files() {
    // Base image via mkfs.fat (skip when unavailable — Linux CI runs this).
    if Command::new("mkfs.fat").arg("--help").output().is_err() {
        eprintln!("SKIP: mkfs.fat not installed");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("vp-powerloss-{}.img", std::process::id()));
    std::fs::write(&tmp, vec![0u8; IMG_MIB << 20]).unwrap();
    let ok = Command::new("mkfs.fat")
        .args([tmp.to_str().unwrap()])
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "mkfs.fat failed");
    let base = std::fs::read(&tmp).unwrap();
    let _ = std::fs::remove_file(&tmp);

    // -- Run the workload, recording writes and barrier snapshots ---------
    let log = Arc::new(Mutex::new(WriteLog::default()));
    let dev = RecordingDevice {
        data: base.clone(),
        log: Arc::clone(&log),
    };
    let mut vfs =
        vc_fs::fat::FatVfs::open(vc_fs::io::DeviceIo::new(Box::new(dev)).unwrap()).unwrap();

    // (op_count_at_barrier, committed set: path -> hash)
    let mut barriers: Vec<(usize, HashMap<String, String>)> = Vec::new();
    let mut committed: HashMap<String, String> = HashMap::new();
    let mut barrier = |committed: &HashMap<String, String>| {
        barriers_push(&log, committed, &mut barriers);
    };

    fn barriers_push(
        log: &Arc<Mutex<WriteLog>>,
        committed: &HashMap<String, String>,
        barriers: &mut Vec<(usize, HashMap<String, String>)>,
    ) {
        barriers.push((log.lock().unwrap().ops.len(), committed.clone()));
    }

    // Phase 1: alpha.bin — committed at B1, never touched again.
    let alpha = pattern(1, 300_000);
    vfs.create("/alpha.bin").unwrap();
    vfs.write_at("/alpha.bin", 0, &alpha).unwrap();
    vfs.flush().unwrap();
    committed.insert("alpha.bin".into(), sha(&alpha));
    barrier(&committed);

    // Phase 2: a directory and a file inside it.
    let beta = pattern(2, 150_000);
    vfs.mkdir("/d1").unwrap();
    vfs.create("/d1/beta.bin").unwrap();
    vfs.write_at("/d1/beta.bin", 0, &beta).unwrap();
    vfs.flush().unwrap();
    committed.insert("d1/beta.bin".into(), sha(&beta));
    barrier(&committed);

    // Phase 3: write large, truncate to final size.
    let gamma_full = pattern(3, 500_000);
    vfs.create("/gamma.bin").unwrap();
    vfs.write_at("/gamma.bin", 0, &gamma_full).unwrap();
    vfs.truncate("/gamma.bin", 200_000).unwrap();
    vfs.flush().unwrap();
    committed.insert("gamma.bin".into(), sha(&gamma_full[..200_000]));
    barrier(&committed);

    // Phase 4: write-then-rename into place (the classic safe-save shape).
    let delta = pattern(4, 120_000);
    vfs.create("/delta.tmp").unwrap();
    vfs.write_at("/delta.tmp", 0, &delta).unwrap();
    vfs.rename("/delta.tmp", "/d1/delta.bin").unwrap();
    vfs.flush().unwrap();
    committed.insert("d1/delta.bin".into(), sha(&delta));
    barrier(&committed);

    // Phase 5: churn — create, delete, recreate small.
    vfs.create("/eps.bin").unwrap();
    vfs.write_at("/eps.bin", 0, &pattern(5, 80_000)).unwrap();
    vfs.unlink("/eps.bin").unwrap();
    let zeta = pattern(6, 4_000);
    vfs.create("/zeta.bin").unwrap();
    vfs.write_at("/zeta.bin", 0, &zeta).unwrap();
    vfs.flush().unwrap();
    committed.insert("zeta.bin".into(), sha(&zeta));
    barrier(&committed);

    let ops = std::mem::take(&mut log.lock().unwrap().ops);
    let total = ops.len();
    assert!(
        total > 50,
        "workload produced suspiciously few writes ({total})"
    );
    eprintln!("harness: {total} write ops, {} barriers", barriers.len());

    // -- Replay: cut after every op ----------------------------------------
    let mut image = base.clone();
    let fsck_available = Command::new("fsck.fat").arg("--help").output().is_ok();
    let barrier_cuts: std::collections::HashSet<usize> = barriers.iter().map(|(k, _)| *k).collect();

    for k in 1..=total {
        let (off, data) = &ops[k - 1];
        image[*off as usize..*off as usize + data.len()].copy_from_slice(data);

        // Committed set as of the last barrier at or before this cut.
        let Some((_, committed_now)) = barriers.iter().rev().find(|(b, _)| *b <= k) else {
            continue;
        };

        // Invariant 2: committed files read back exactly (no repair).
        for (path, want) in committed_now {
            let got = read_from_image(&image, path)
                .unwrap_or_else(|| panic!("cut {k}/{total}: committed {path} unreadable"));
            assert_eq!(
                &sha(&got),
                want,
                "cut {k}/{total}: committed {path} corrupted"
            );
        }

        // Invariant 3 at barriers + every 25th cut: repairable, and still
        // intact after repair.
        if fsck_available && (barrier_cuts.contains(&k) || k % 25 == 0) {
            let f = std::env::temp_dir().join(format!("vp-cut-{}-{k}.img", std::process::id()));
            std::fs::write(&f, &image).unwrap();
            let status = Command::new("fsck.fat")
                .args(["-y", f.to_str().unwrap()])
                .output()
                .unwrap();
            let code = status.status.code().unwrap_or(-1);
            assert!(
                code == 0 || code == 1,
                "cut {k}/{total}: fsck.fat exit {code}:\n{}",
                String::from_utf8_lossy(&status.stdout)
            );
            let repaired = std::fs::read(&f).unwrap();
            let _ = std::fs::remove_file(&f);
            for (path, want) in committed_now {
                let got = read_from_image(&repaired, path)
                    .unwrap_or_else(|| panic!("cut {k}: {path} lost by fsck repair"));
                assert_eq!(&sha(&got), want, "cut {k}: {path} changed by fsck repair");
            }
        }
    }
}
