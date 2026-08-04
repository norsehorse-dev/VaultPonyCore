//! The decrypted view of a container's data area (doc §6).
//!
//! Wraps the raw container device + the volume's XTS engine and presents a
//! `BlockDevice` whose offset 0 is the first byte of the filesystem. Random
//! access is free by construction — plain sector-XTS with 512-byte data
//! units — which is what makes streaming (video seek) work on mobile.
//!
//! Writes (P4) read-modify-write at unit edges: unaligned spans pull the
//! containing units' plaintext, patch, re-encrypt, and write back whole
//! units. Callers above the FS layer never see the alignment.

use vc_crypto::SchemeXts;
use vc_io::BlockDevice;
use vc_types::{VcError, VcResult, VolumeGeometry};

const UNIT: u64 = vc_types::consts::XTS_DATA_UNIT_LEN as u64;

pub struct DecryptedDevice {
    inner: Box<dyn BlockDevice>,
    xts: SchemeXts,
    /// Absolute container offset of the data area.
    data_start: u64,
    /// Size of the data area (= the filesystem's size).
    data_size: u64,
}

impl DecryptedDevice {
    pub fn new(inner: Box<dyn BlockDevice>, xts: SchemeXts, geometry: &VolumeGeometry) -> Self {
        Self {
            inner,
            xts,
            data_start: geometry.encrypted_area_start,
            data_size: geometry.encrypted_area_size,
        }
    }
}

impl BlockDevice for DecryptedDevice {
    fn len(&mut self) -> VcResult<u64> {
        Ok(self.data_size)
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> VcResult<()> {
        let len = buf.len() as u64;
        if offset
            .checked_add(len)
            .is_none_or(|end| end > self.data_size)
        {
            return Err(VcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "read past end of data area",
            )));
        }
        if len == 0 {
            return Ok(());
        }

        // Widen to unit boundaries, decrypt, copy out the requested slice.
        // Data-unit numbers are absolute container offsets / 512 (doc §6).
        let abs = self.data_start + offset;
        let aligned_start = abs - (abs % UNIT);
        let aligned_end = (abs + len).div_ceil(UNIT) * UNIT;
        let mut block = vec![0u8; (aligned_end - aligned_start) as usize];
        self.inner.read_at(aligned_start, &mut block)?;
        self.xts.decrypt_units(&mut block, aligned_start / UNIT);
        let skip = (abs - aligned_start) as usize;
        buf.copy_from_slice(&block[skip..skip + buf.len()]);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> VcResult<()> {
        let len = buf.len() as u64;
        if offset
            .checked_add(len)
            .is_none_or(|end| end > self.data_size)
        {
            return Err(VcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "write past end of data area",
            )));
        }
        if len == 0 {
            return Ok(());
        }

        // Read-modify-write on the containing unit range: unaligned edges
        // need their neighbors' plaintext to re-encrypt the whole unit.
        let abs = self.data_start + offset;
        let aligned_start = abs - (abs % UNIT);
        let aligned_end = (abs + len).div_ceil(UNIT) * UNIT;
        let first_unit = aligned_start / UNIT;
        let mut block = vec![0u8; (aligned_end - aligned_start) as usize];

        let skip = (abs - aligned_start) as usize;
        let head_partial = skip != 0;
        let tail_partial = !(abs + len).is_multiple_of(UNIT);
        if head_partial || tail_partial {
            // Only the edge units actually need their old plaintext, but
            // reading the whole span keeps this simple and writes are
            // buffered by the FS layer anyway. Revisit if profiling says so.
            self.inner.read_at(aligned_start, &mut block)?;
            self.xts.decrypt_units(&mut block, first_unit);
        }
        block[skip..skip + buf.len()].copy_from_slice(buf);
        self.xts.encrypt_units(&mut block, first_unit);
        self.inner.write_at(aligned_start, &block)?;
        Ok(())
    }

    fn flush(&mut self) -> VcResult<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vc_types::VolumeGeometry;

    struct MemDevice(Vec<u8>);

    impl BlockDevice for MemDevice {
        fn len(&mut self) -> VcResult<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> VcResult<()> {
            let o = offset as usize;
            buf.copy_from_slice(&self.0[o..o + buf.len()]);
            Ok(())
        }
        fn write_at(&mut self, offset: u64, buf: &[u8]) -> VcResult<()> {
            let o = offset as usize;
            self.0[o..o + buf.len()].copy_from_slice(buf);
            Ok(())
        }
        fn flush(&mut self) -> VcResult<()> {
            Ok(())
        }
    }

    fn aes_xts() -> vc_crypto::SchemeXts {
        let scheme = vc_types::registry::ENCRYPTION_SCHEMES
            .iter()
            .find(|s| s.name == "AES")
            .unwrap();
        vc_crypto::SchemeXts::new(scheme, &[7u8; 64]).unwrap()
    }

    /// Model: plaintext shadow buffer. Every write pattern must leave the
    /// decrypted view equal to the shadow.
    #[test]
    fn unaligned_writes_round_trip_against_model() {
        let data_start = 1024u64;
        let data_size = 64 * 1024u64;
        let geometry = VolumeGeometry {
            volume_size: data_size,
            encrypted_area_start: data_start,
            encrypted_area_size: data_size,
            sector_size: 512,
            hidden_volume_size: 0,
        };
        // Build a container image whose data area is valid ciphertext of
        // an all-zero plaintext.
        let mut image = vec![0u8; (data_start + data_size) as usize];
        let mut zero_area = vec![0u8; data_size as usize];
        aes_xts().encrypt_units(&mut zero_area, data_start / 512);
        image[data_start as usize..].copy_from_slice(&zero_area);

        let mut dev = DecryptedDevice::new(Box::new(MemDevice(image)), aes_xts(), &geometry);
        let mut shadow = vec![0u8; data_size as usize];

        // (offset, len) patterns: aligned, head-partial, tail-partial,
        // sub-unit, spanning, and a rewrite over earlier data.
        let cases: &[(u64, usize, u8)] = &[
            (0, 512, 0xA1),
            (512, 1536, 0xB2),
            (100, 300, 0xC3),
            (700, 200, 0xD4),
            (1000, 5000, 0xE5),
            (250, 800, 0xF6),
            (63 * 1024 + 7, 500, 0x17),
        ];
        for &(off, len, fill) in cases {
            let data = vec![fill; len];
            dev.write_at(off, &data).unwrap();
            shadow[off as usize..off as usize + len].copy_from_slice(&data);

            let mut view = vec![0u8; data_size as usize];
            dev.read_at(0, &mut view).unwrap();
            assert_eq!(view, shadow, "mismatch after write at {off}+{len}");
        }
    }

    #[test]
    fn write_past_end_refused() {
        let geometry = VolumeGeometry {
            volume_size: 4096,
            encrypted_area_start: 0,
            encrypted_area_size: 4096,
            sector_size: 512,
            hidden_volume_size: 0,
        };
        let mut dev =
            DecryptedDevice::new(Box::new(MemDevice(vec![0u8; 4096])), aes_xts(), &geometry);
        assert!(dev.write_at(4000, &[0u8; 200]).is_err());
    }
}
