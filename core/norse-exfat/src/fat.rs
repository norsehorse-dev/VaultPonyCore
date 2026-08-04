//! FAT chain walking (exFAT spec §4). Entries are little-endian u32 per
//! cluster; 0xFFFFFFFF ends a chain, 0xFFFFFFF7 marks a bad cluster.

use crate::boot::Geometry;
use crate::{ExfatError, ExfatResult, ReadAt};

pub const END_OF_CHAIN: u32 = 0xFFFF_FFFF;
pub const BAD_CLUSTER: u32 = 0xFFFF_FFF7;

pub fn fat_entry<D: ReadAt>(disk: &mut D, geo: &Geometry, cluster: u32) -> ExfatResult<u32> {
    if cluster < 2 || cluster >= geo.cluster_count + 2 {
        return Err(ExfatError::Invalid("FAT index out of range"));
    }
    let off = geo.bytes_per_sector as u64 * geo.fat_offset_sectors as u64 + cluster as u64 * 4;
    let mut e = [0u8; 4];
    disk.read_at(off, &mut e)?;
    Ok(u32::from_le_bytes(e))
}

/// Read a chain from `first`, bounded by `max_len` when the caller knows
/// the file's cluster count (guards against on-disk loops), else by the
/// volume's cluster count.
pub fn read_chain<D: ReadAt>(
    disk: &mut D,
    geo: &Geometry,
    first: u32,
    max_len: Option<u64>,
) -> ExfatResult<Vec<u32>> {
    let cap = max_len.unwrap_or(geo.cluster_count as u64);
    let mut chain = Vec::new();
    let mut cur = first;
    loop {
        if chain.len() as u64 >= cap {
            if max_len.is_some() {
                break; // caller-known length reached; trailing FAT noise is not our problem
            }
            return Err(ExfatError::Invalid("cluster chain loop"));
        }
        chain.push(cur);
        match fat_entry(disk, geo, cur)? {
            END_OF_CHAIN => break,
            BAD_CLUSTER => return Err(ExfatError::Invalid("chain hits bad cluster")),
            next => cur = next,
        }
    }
    Ok(chain)
}
