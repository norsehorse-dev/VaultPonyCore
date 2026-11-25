//! Bridge from our `BlockDevice` to `std::io` traits, for adapters built on
//! crates that expect Read/Write/Seek (`fatfs`, `ntfs`).
//!
//! Those crates read metadata a field at a time: a directory entry is a
//! dozen reads of one to four bytes, a FAT entry is four bytes. Each such
//! read reaches the decrypted device, which has to decrypt a whole 512-byte
//! unit for it. So small reads go through a block cache here: a miss reads
//! and decrypts one block, and the fields around it are then served from
//! memory. Writes go to the device first and then patch any cached block
//! they touch, so the cache never differs from the device. Reads of a block
//! or more bypass it.
//!
//! The cache holds decrypted bytes (directory and FAT blocks, the odd small
//! piece of a file). It is zeroed when dropped, which is when the session
//! locks or remounts. A remount is also what discards it after another
//! process wrote to the volume (`Session::remount`).

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use vc_io::BlockDevice;
use zeroize::Zeroize;

/// Cache block size. A multiple of the 512-byte cipher unit, and of every
/// FAT sector size.
const BLOCK: usize = 16 * 1024;
/// At most this many blocks are kept: 1 MiB.
const SLOTS: usize = 64;

struct Slot {
    index: u64,
    used: u64,
    data: Box<[u8; BLOCK]>,
}

/// Least-recently-used cache of device blocks.
#[derive(Default)]
struct BlockCache {
    slots: Vec<Slot>,
    by_index: HashMap<u64, usize>,
    clock: u64,
}

impl BlockCache {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn clear(&mut self) {
        for slot in &mut self.slots {
            slot.data.zeroize();
        }
        self.slots.clear();
        self.by_index.clear();
    }

    /// The slot holding block `index`, read from `dev` if it is not cached.
    fn load(
        &mut self,
        dev: &mut dyn BlockDevice,
        device_len: u64,
        index: u64,
    ) -> vc_types::VcResult<usize> {
        let now = self.tick();
        if let Some(&at) = self.by_index.get(&index) {
            self.slots[at].used = now;
            return Ok(at);
        }
        let start = index * BLOCK as u64;
        let len = (device_len - start).min(BLOCK as u64) as usize;
        let at = if self.slots.len() < SLOTS {
            self.slots.push(Slot {
                index,
                used: now,
                data: Box::new([0u8; BLOCK]),
            });
            self.slots.len() - 1
        } else {
            let at = (0..self.slots.len())
                .min_by_key(|&i| self.slots[i].used)
                .unwrap_or(0);
            self.by_index.remove(&self.slots[at].index);
            at
        };
        let slot = &mut self.slots[at];
        slot.index = index;
        slot.used = now;
        if let Err(e) = dev.read_at(start, &mut slot.data[..len]) {
            // The slot holds nothing usable; it is simply not indexed.
            slot.data.zeroize();
            slot.index = u64::MAX;
            slot.used = 0;
            return Err(e);
        }
        self.by_index.insert(index, at);
        Ok(at)
    }

    /// Copy a write that already reached the device into the cached blocks
    /// it overlaps.
    fn patch(&mut self, offset: u64, buf: &[u8]) {
        if self.by_index.is_empty() || buf.is_empty() {
            return;
        }
        let first = offset / BLOCK as u64;
        let last = (offset + buf.len() as u64 - 1) / BLOCK as u64;
        for index in first..=last {
            let Some(&at) = self.by_index.get(&index) else {
                continue;
            };
            let block_start = index * BLOCK as u64;
            let from = offset.max(block_start);
            let to = (offset + buf.len() as u64).min(block_start + BLOCK as u64);
            let slot = &mut self.slots[at];
            let (a, b) = ((from - block_start) as usize, (to - block_start) as usize);
            slot.data[a..b].copy_from_slice(&buf[(from - offset) as usize..(to - offset) as usize]);
        }
    }
}

impl Drop for BlockCache {
    fn drop(&mut self) {
        self.clear();
    }
}

pub struct DeviceIo {
    dev: Box<dyn BlockDevice>,
    pos: u64,
    len: u64,
    /// Written since the last flush. A flush with nothing written is a
    /// no-op, so read-only sessions never ask the OS to sync (Windows
    /// refuses FlushFileBuffers on a read-only handle).
    dirty: bool,
    cache: BlockCache,
}

impl DeviceIo {
    pub fn new(mut dev: Box<dyn BlockDevice>) -> vc_types::VcResult<Self> {
        let len = dev.len()?;
        Ok(Self {
            dev,
            pos: 0,
            len,
            dirty: false,
            cache: BlockCache::default(),
        })
    }
}

fn to_io(e: vc_types::VcError) -> std::io::Error {
    match e {
        vc_types::VcError::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    }
}

impl Read for DeviceIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.len.saturating_sub(self.pos);
        let n = (buf.len() as u64).min(remaining) as usize;
        if n == 0 {
            return Ok(0);
        }
        if n >= BLOCK {
            // File data in bulk: straight from the device.
            self.dev.read_at(self.pos, &mut buf[..n]).map_err(to_io)?;
            self.pos += n as u64;
            return Ok(n);
        }
        let mut done = 0usize;
        while done < n {
            let at = self.pos + done as u64;
            let within = (at % BLOCK as u64) as usize;
            let take = (BLOCK - within).min(n - done);
            let slot = self
                .cache
                .load(self.dev.as_mut(), self.len, at / BLOCK as u64)
                .map_err(to_io)?;
            buf[done..done + take]
                .copy_from_slice(&self.cache.slots[slot].data[within..within + take]);
            done += take;
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for DeviceIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.dirty = true;
        if let Err(e) = self.dev.write_at(self.pos, buf) {
            // How much of it landed is unknown, so nothing cached is trusted.
            self.cache.clear();
            return Err(to_io(e));
        }
        self.cache.patch(self.pos, buf);
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        self.dev.flush().map_err(to_io)?;
        self.dirty = false;
        Ok(())
    }
}

impl Seek for DeviceIo {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => Some(o),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        match new {
            Some(p) => {
                self.pos = p;
                Ok(p)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek out of range",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
    use std::sync::{Arc, Mutex};
    use vc_types::{VcError, VcResult};

    #[derive(Clone)]
    struct Mem {
        data: Arc<Mutex<Vec<u8>>>,
        reads: Arc<AtomicU64>,
        fail_writes: Arc<AtomicBool>,
    }

    impl BlockDevice for Mem {
        fn len(&mut self) -> VcResult<u64> {
            Ok(self.data.lock().unwrap().len() as u64)
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> VcResult<()> {
            self.reads.fetch_add(1, Relaxed);
            let o = offset as usize;
            buf.copy_from_slice(&self.data.lock().unwrap()[o..o + buf.len()]);
            Ok(())
        }
        fn write_at(&mut self, offset: u64, buf: &[u8]) -> VcResult<()> {
            let o = offset as usize;
            let mut data = self.data.lock().unwrap();
            if self.fail_writes.load(Relaxed) {
                // Half of it lands, as a torn write would.
                let half = buf.len() / 2;
                data[o..o + half].copy_from_slice(&buf[..half]);
                return Err(VcError::Io(std::io::Error::other("write failed")));
            }
            data[o..o + buf.len()].copy_from_slice(buf);
            Ok(())
        }
        fn flush(&mut self) -> VcResult<()> {
            Ok(())
        }
    }

    fn mem(len: usize) -> Mem {
        Mem {
            data: Arc::new(Mutex::new(
                (0..len).map(|i| (i * 7 + i / 251) as u8).collect(),
            )),
            reads: Arc::new(AtomicU64::new(0)),
            fail_writes: Arc::new(AtomicBool::new(false)),
        }
    }

    fn next(x: &mut u64) -> u64 {
        *x ^= *x << 13;
        *x ^= *x >> 7;
        *x ^= *x << 17;
        *x
    }

    /// Whatever mix of reads and writes goes through, a read returns what
    /// the device holds.
    #[test]
    fn reads_always_match_the_device() {
        // Not a whole number of blocks, and more blocks than the cache keeps.
        let len = BLOCK * (SLOTS + 9) + 1234;
        let dev = mem(len);
        let mut io = DeviceIo::new(Box::new(dev.clone())).unwrap();
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for step in 0..20_000 {
            let size = match next(&mut x) % 10 {
                0 => 1 + (next(&mut x) as usize % (3 * BLOCK)),
                1..=3 => 1 + (next(&mut x) as usize % 4096),
                _ => 1 + (next(&mut x) as usize % 32),
            };
            let pos = next(&mut x) as usize % len;
            let size = size.min(len - pos);
            io.seek(SeekFrom::Start(pos as u64)).unwrap();
            if next(&mut x).is_multiple_of(4) {
                let buf: Vec<u8> = (0..size).map(|i| (step + i) as u8).collect();
                io.write_all(&buf).unwrap();
            } else {
                let mut buf = vec![0u8; size];
                io.read_exact(&mut buf).unwrap();
                assert_eq!(
                    buf,
                    dev.data.lock().unwrap()[pos..pos + size],
                    "step {step}"
                );
            }
        }
        // The last byte, and nothing past it.
        io.seek(SeekFrom::Start(len as u64 - 1)).unwrap();
        let mut tail = [0u8; 8];
        assert_eq!(io.read(&mut tail).unwrap(), 1);
        assert_eq!(io.read(&mut tail).unwrap(), 0);
    }

    #[test]
    fn small_reads_share_one_device_read() {
        let dev = mem(BLOCK * 4);
        let mut io = DeviceIo::new(Box::new(dev.clone())).unwrap();
        let mut field = [0u8; 4];
        for i in 0..1000u64 {
            io.seek(SeekFrom::Start(i * 4)).unwrap();
            io.read_exact(&mut field).unwrap();
        }
        assert_eq!(dev.reads.load(Relaxed), 1);
    }

    #[test]
    fn a_failed_write_leaves_nothing_stale() {
        let dev = mem(BLOCK * 2);
        let mut io = DeviceIo::new(Box::new(dev.clone())).unwrap();
        let mut before = [0u8; 64];
        io.seek(SeekFrom::Start(100)).unwrap();
        io.read_exact(&mut before).unwrap();
        dev.fail_writes.store(true, Relaxed);
        io.seek(SeekFrom::Start(100)).unwrap();
        assert!(io.write(&[0xEE; 64]).is_err());
        dev.fail_writes.store(false, Relaxed);
        let mut after = [0u8; 64];
        io.seek(SeekFrom::Start(100)).unwrap();
        io.read_exact(&mut after).unwrap();
        assert_eq!(after[..], dev.data.lock().unwrap()[100..164]);
    }
}
