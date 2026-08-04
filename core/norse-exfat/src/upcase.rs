//! Up-case table (exFAT spec §7.2): the volume's own case-folding map,
//! stored identity-run compressed. Used for case-insensitive lookup.

use crate::boot::Geometry;
use crate::{ExfatError, ExfatResult, ReadAt};

pub struct UpcaseTable {
    map: Vec<u16>,
}

impl UpcaseTable {
    /// Identity table: used when a volume (out of spec, but seen in the
    /// wild) lacks an up-case entry — lookups become case-sensitive rather
    /// than failing.
    pub fn identity() -> Self {
        Self { map: Vec::new() }
    }

    pub fn map(&self, u: u16) -> u16 {
        match self.map.get(u as usize) {
            Some(&v) => v,
            None => u,
        }
    }

    /// A cheap owned copy (the table is at most 128 KiB). Used by the write
    /// path to sidestep borrow conflicts with `&mut disk`.
    pub fn snapshot(&self) -> Self {
        Self {
            map: self.map.clone(),
        }
    }

    /// Load and decompress from the cluster heap. Format: a sequence of
    /// u16 values; 0xFFFF is an escape whose following u16 is a count of
    /// identity mappings to emit at the current index.
    pub fn load<D: ReadAt>(
        disk: &mut D,
        geo: &Geometry,
        first_cluster: u32,
        data_len: u64,
    ) -> ExfatResult<Self> {
        if data_len > 2 * 65536 * 2 {
            return Err(ExfatError::Invalid("up-case table implausibly large"));
        }
        // The up-case table is written contiguously by formatters; walking
        // the FAT here too keeps fragmented-but-valid volumes working.
        let chain = crate::fat::read_chain(
            disk,
            geo,
            first_cluster,
            Some(data_len.div_ceil(geo.cluster_bytes())),
        )?;
        let mut raw = vec![0u8; data_len as usize];
        let cluster_bytes = geo.cluster_bytes() as usize;
        for (i, &cluster) in chain.iter().enumerate() {
            let start = i * cluster_bytes;
            let end = (start + cluster_bytes).min(raw.len());
            if start >= end {
                break;
            }
            let off = geo.cluster_offset(cluster)?;
            disk.read_at(off, &mut raw[start..end])?;
        }

        let mut map: Vec<u16> = Vec::with_capacity(65536);
        let mut words = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]));
        while let Some(w) = words.next() {
            if w == 0xFFFF {
                // 0xFFFF opens an identity run — unless it is the final
                // word, where it is the literal mapping for U+FFFF (the
                // standard 5836-byte table ends exactly this way).
                let Some(count) = words.next() else {
                    map.push(0xFFFF);
                    break;
                };
                let start = map.len();
                for i in 0..count as usize {
                    let cp = start + i;
                    if cp > u16::MAX as usize {
                        return Err(ExfatError::Invalid("up-case table overflows u16"));
                    }
                    map.push(cp as u16);
                }
            } else {
                if map.len() > u16::MAX as usize {
                    return Err(ExfatError::Invalid("up-case table overflows u16"));
                }
                map.push(w);
            }
        }
        Ok(Self { map })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_maps_everything_to_itself() {
        let t = UpcaseTable::identity();
        assert_eq!(t.map(0x61), 0x61);
        assert_eq!(t.map(0xFFFE), 0xFFFE);
    }
}
