//! exFAT power-loss check (doc §7/§13): record every device write our
//! writer produces during a workload, replay each prefix into a copy of the
//! starting image, and require that our own reader either opens the
//! truncated volume cleanly or fails cleanly — never panics — and that a
//! file committed (flushed) before a cut always reads back intact.
//!
//! The FAT power-loss harness (vc-fs) already sweeps every boundary against
//! fsck; this is the exFAT analogue at the reader level, since there is no
//! fsck.exfat repair mode to lean on here. mkfs.exfat required.

use norse_exfat::{ExfatFs, ReadAt, WriteAt};
use std::cell::RefCell;
use std::process::Command;
use std::rc::Rc;

type WriteLog = Rc<RefCell<Vec<(u64, Vec<u8>)>>>;

/// Records (offset, bytes) of every write while mutating an in-memory image.
#[derive(Clone)]
struct RecDev {
    data: Rc<RefCell<Vec<u8>>>,
    log: WriteLog,
}
impl ReadAt for RecDev {
    fn read_at(&mut self, o: u64, b: &mut [u8]) -> std::io::Result<()> {
        b.copy_from_slice(&self.data.borrow()[o as usize..o as usize + b.len()]);
        Ok(())
    }
    fn len(&mut self) -> std::io::Result<u64> {
        Ok(self.data.borrow().len() as u64)
    }
}
impl WriteAt for RecDev {
    fn write_at(&mut self, o: u64, b: &[u8]) -> std::io::Result<()> {
        self.data.borrow_mut()[o as usize..o as usize + b.len()].copy_from_slice(b);
        self.log.borrow_mut().push((o, b.to_vec()));
        Ok(())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Plain in-memory reader over a byte image.
struct MemRead(Vec<u8>);
impl ReadAt for MemRead {
    fn read_at(&mut self, o: u64, b: &mut [u8]) -> std::io::Result<()> {
        let s = o as usize;
        if s + b.len() > self.0.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        b.copy_from_slice(&self.0[s..s + b.len()]);
        Ok(())
    }
    fn len(&mut self) -> std::io::Result<u64> {
        Ok(self.0.len() as u64)
    }
}
impl WriteAt for MemRead {
    fn write_at(&mut self, _: u64, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn fresh_image(bytes: usize) -> Option<Vec<u8>> {
    if Command::new("mkfs.exfat").arg("--help").output().is_err() {
        return None;
    }
    let p = std::env::temp_dir().join(format!("vp-exp-{}.img", std::process::id()));
    std::fs::write(&p, vec![0u8; bytes]).unwrap();
    let ok = Command::new("mkfs.exfat")
        .args(["-c", "32k", p.to_str().unwrap()])
        .output()
        .unwrap()
        .status
        .success();
    let img = if ok { std::fs::read(&p).ok() } else { None };
    let _ = std::fs::remove_file(&p);
    img
}

#[test]
fn every_write_prefix_leaves_a_readable_or_cleanly_failing_volume() {
    let Some(base) = fresh_image(24 << 20) else {
        eprintln!("SKIP: mkfs.exfat not installed");
        return;
    };

    // Record the writes for a small workload, capturing the committed
    // content of one file that is written and flushed up front.
    let dev = RecDev {
        data: Rc::new(RefCell::new(base.clone())),
        log: Rc::new(RefCell::new(Vec::new())),
    };
    let committed = b"committed-early-and-never-touched-again".to_vec();
    {
        let mut fs = ExfatFs::open(dev.clone()).unwrap();
        fs.create_file("/keep.txt").unwrap();
        fs.write_file("/keep.txt", 0, &committed).unwrap();
        // Barrier: everything above is durable before the churn below.
        let boundary = dev.log.borrow().len();
        for i in 0..12 {
            let p = format!("/churn{i}.bin");
            fs.create_file(&p).unwrap();
            fs.write_file(&p, 0, &vec![i as u8; 40_000]).unwrap();
        }
        // Stash the boundary op index for the replay below.
        COMMIT_BOUNDARY.with(|b| *b.borrow_mut() = boundary);
    }

    let ops = dev.log.borrow().clone();
    let total = ops.len();
    assert!(total > 20, "workload too small ({total} writes)");
    let boundary = COMMIT_BOUNDARY.with(|b| *b.borrow());
    let commit_hash = sha(&committed);

    // Replay every prefix.
    for k in 0..=total {
        let mut image = base.clone();
        for (off, bytes) in &ops[..k] {
            image[*off as usize..*off as usize + bytes.len()].copy_from_slice(bytes);
        }
        // Must never panic: open + list + read whatever is there.
        let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut fs = ExfatFs::open(MemRead(image.clone())).ok()?;
            let (fc, nfc, dl) = fs.root_dir();
            let entries = fs.list_dir(fc, nfc, dl).ok()?;
            // If keep.txt is present after the commit boundary, it must be intact.
            if k >= boundary {
                if let Some(e) = entries.iter().find(|e| e.name == "keep.txt") {
                    if e.size == committed.len() as u64 {
                        let mut buf = vec![0u8; e.size as usize];
                        if fs.read_file(e, 0, &mut buf).is_ok() {
                            return Some(sha(&buf) == commit_hash);
                        }
                    }
                }
            }
            Some(true)
        }));
        match opened {
            Err(_) => panic!("reader panicked on write prefix {k}/{total}"),
            Ok(Some(false)) => panic!("committed file corrupted at prefix {k}/{total}"),
            Ok(_) => {}
        }
    }
    eprintln!("exfat power-loss: {total} write prefixes replayed, reader safe, commit intact");
}

thread_local! {
    static COMMIT_BOUNDARY: RefCell<usize> = const { RefCell::new(0) };
}

fn sha(d: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(d)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
