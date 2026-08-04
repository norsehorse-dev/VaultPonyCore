//! Hidden-volume write protection (planning doc §9).
//!
//! When the outer volume is mounted read-write, the hidden volume lives in
//! what the outer filesystem sees as free space — so an ordinary outer
//! write can allocate clusters straight over the hidden data and destroy
//! it. Protection unlocks the hidden header too (only to learn its region),
//! then wraps the outer device: any write intersecting the hidden region is
//! refused, and — mirroring desktop VeraCrypt — the first such hit latches
//! the *entire* volume read-only so the filesystem cannot continue into an
//! inconsistent state.
//!
//! Reads always pass through, before and after a latch, so the outer volume
//! stays browsable in read-only mode after protection triggers.

use vc_io::BlockDevice;
use vc_types::{VcError, VcResult};

pub struct ProtectedDevice {
    inner: Box<dyn BlockDevice>,
    /// Protected byte range in `inner`'s coordinate space (outer-fs offsets,
    /// i.e. 0 = start of the outer data area).
    protected_start: u64,
    protected_end: u64,
    /// Latched on the first blocked write; once set, every write fails.
    read_only: std::sync::atomic::AtomicBool,
}

impl ProtectedDevice {
    /// `protected_start`/`len` are in the wrapped device's coordinate space.
    pub fn new(inner: Box<dyn BlockDevice>, protected_start: u64, protected_len: u64) -> Self {
        Self {
            inner,
            protected_start,
            protected_end: protected_start.saturating_add(protected_len),
            read_only: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// True once a write into the hidden region has latched read-only mode.
    pub fn tripped(&self) -> bool {
        self.read_only.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn intersects_protected(&self, offset: u64, len: u64) -> bool {
        let end = offset.saturating_add(len);
        offset < self.protected_end && end > self.protected_start
    }
}

impl BlockDevice for ProtectedDevice {
    fn len(&mut self) -> VcResult<u64> {
        self.inner.len()
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> VcResult<()> {
        // Reads are never blocked — the volume stays readable read-only.
        self.inner.read_at(offset, buf)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> VcResult<()> {
        use std::sync::atomic::Ordering;
        if self.read_only.load(Ordering::Relaxed) {
            return Err(VcError::HiddenVolumeProtected);
        }
        if !buf.is_empty() && self.intersects_protected(offset, buf.len() as u64) {
            // First hit: latch the whole volume read-only (VC behavior).
            self.read_only.store(true, Ordering::Relaxed);
            return Err(VcError::HiddenVolumeProtected);
        }
        self.inner.write_at(offset, buf)
    }

    fn flush(&mut self) -> VcResult<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mem(Vec<u8>);
    impl BlockDevice for Mem {
        fn len(&mut self) -> VcResult<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_at(&mut self, o: u64, b: &mut [u8]) -> VcResult<()> {
            b.copy_from_slice(&self.0[o as usize..o as usize + b.len()]);
            Ok(())
        }
        fn write_at(&mut self, o: u64, b: &[u8]) -> VcResult<()> {
            self.0[o as usize..o as usize + b.len()].copy_from_slice(b);
            Ok(())
        }
        fn flush(&mut self) -> VcResult<()> {
            Ok(())
        }
    }

    fn dev() -> ProtectedDevice {
        // 4 KiB device, protected region [2048, 3072).
        ProtectedDevice::new(Box::new(Mem(vec![0u8; 4096])), 2048, 1024)
    }

    #[test]
    fn writes_outside_the_region_pass() {
        let mut d = dev();
        assert!(d.write_at(0, &[1u8; 512]).is_ok());
        assert!(d.write_at(1536, &[1u8; 512]).is_ok()); // ends exactly at 2048
        assert!(d.write_at(3072, &[1u8; 512]).is_ok()); // starts exactly at region end
        assert!(!d.tripped());
    }

    #[test]
    fn write_into_the_region_is_refused_and_latches_read_only() {
        let mut d = dev();
        // A write straddling the boundary is blocked.
        assert!(matches!(
            d.write_at(2000, &[1u8; 512]),
            Err(VcError::HiddenVolumeProtected)
        ));
        assert!(d.tripped());
        // After the latch, even a perfectly safe write fails.
        assert!(matches!(
            d.write_at(0, &[1u8; 16]),
            Err(VcError::HiddenVolumeProtected)
        ));
        // Reads still work in read-only mode.
        let mut buf = [0u8; 16];
        assert!(d.read_at(0, &mut buf).is_ok());
    }

    #[test]
    fn fully_inside_and_fully_covering_both_trip() {
        let mut d = dev();
        assert!(d.write_at(2100, &[1u8; 100]).is_err()); // fully inside
        let mut d2 = dev();
        assert!(d2.write_at(0, &[1u8; 4096]).is_err()); // covers everything
    }
}
