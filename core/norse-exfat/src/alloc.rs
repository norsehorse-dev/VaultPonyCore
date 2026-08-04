//! Cluster allocation: the allocation bitmap and FAT chain maintenance
//! (exFAT spec §7.1, §4). Everything this crate writes is FAT-chained
//! (NoFatChain = 0) for uniformity — see `write.rs`.
//!
//! The bitmap is treated as a flat contiguous span from its first cluster.
//! mkfs writes it contiguous and we never move or fragment it, so the byte
//! for cluster `c` is always `cluster_offset(bitmap.first_cluster) + (c-2)/8`.

use crate::boot::Geometry;
use crate::fat::{fat_entry, END_OF_CHAIN};
use crate::{BitmapLoc, ExfatError, ExfatResult, WriteAt};

fn bitmap_byte_offset(geo: &Geometry, bm: &BitmapLoc, cluster: u32) -> ExfatResult<u64> {
    let bit = (cluster - 2) as u64;
    let byte_index = bit / 8;
    if byte_index >= bm.length_bytes {
        return Err(ExfatError::Invalid("bitmap index out of range"));
    }
    Ok(geo.cluster_offset(bm.first_cluster)? + byte_index)
}

pub(crate) fn is_allocated<D: WriteAt>(
    disk: &mut D,
    geo: &Geometry,
    bm: &BitmapLoc,
    cluster: u32,
) -> ExfatResult<bool> {
    let off = bitmap_byte_offset(geo, bm, cluster)?;
    let mut b = [0u8; 1];
    disk.read_at(off, &mut b)?;
    Ok(b[0] & (1 << ((cluster - 2) % 8)) != 0)
}

fn set_bit<D: WriteAt>(
    disk: &mut D,
    geo: &Geometry,
    bm: &BitmapLoc,
    cluster: u32,
    allocated: bool,
) -> ExfatResult<()> {
    let off = bitmap_byte_offset(geo, bm, cluster)?;
    let mut b = [0u8; 1];
    disk.read_at(off, &mut b)?;
    let mask = 1u8 << ((cluster - 2) % 8);
    if allocated {
        b[0] |= mask;
    } else {
        b[0] &= !mask;
    }
    disk.write_at(off, &b)?;
    Ok(())
}

/// Write a FAT entry for `cluster`.
pub(crate) fn set_fat<D: WriteAt>(
    disk: &mut D,
    geo: &Geometry,
    cluster: u32,
    value: u32,
) -> ExfatResult<()> {
    if cluster < 2 || cluster >= geo.cluster_count + 2 {
        return Err(ExfatError::Invalid("FAT index out of range"));
    }
    let off = geo.bytes_per_sector as u64 * geo.fat_offset_sectors as u64 + cluster as u64 * 4;
    disk.write_at(off, &value.to_le_bytes())?;
    Ok(())
}

/// Find the first free cluster at or after `hint` (wrapping once).
fn find_free<D: WriteAt>(
    disk: &mut D,
    geo: &Geometry,
    bm: &BitmapLoc,
    hint: u32,
) -> ExfatResult<u32> {
    let total = geo.cluster_count;
    for i in 0..total {
        let cluster = 2 + ((hint - 2 + i) % total);
        if !is_allocated(disk, geo, bm, cluster)? {
            return Ok(cluster);
        }
    }
    Err(ExfatError::Invalid("no free clusters"))
}

/// Allocate `count` clusters as a FAT chain (not necessarily contiguous),
/// marking the bitmap and linking the FAT. Returns the chain. Ordering:
/// the caller writes cluster *data* and flushes before publishing a
/// directory entry that points here (doc §7).
pub(crate) fn alloc_chain<D: WriteAt>(
    disk: &mut D,
    geo: &Geometry,
    bm: &BitmapLoc,
    count: u32,
) -> ExfatResult<Vec<u32>> {
    let mut chain = Vec::with_capacity(count as usize);
    let mut hint = 2;
    for _ in 0..count {
        let c = find_free(disk, geo, bm, hint)?;
        set_bit(disk, geo, bm, c, true)?;
        chain.push(c);
        hint = c + 1;
    }
    for w in chain.windows(2) {
        set_fat(disk, geo, w[0], w[1])?;
    }
    if let Some(&last) = chain.last() {
        set_fat(disk, geo, last, END_OF_CHAIN)?;
    }
    Ok(chain)
}

/// Append `count` clusters to an existing chain whose last cluster is
/// `tail`. Returns the newly added clusters (already linked to `tail`).
pub(crate) fn extend_chain<D: WriteAt>(
    disk: &mut D,
    geo: &Geometry,
    bm: &BitmapLoc,
    tail: u32,
    count: u32,
) -> ExfatResult<Vec<u32>> {
    let added = alloc_chain(disk, geo, bm, count)?;
    if let Some(&first) = added.first() {
        set_fat(disk, geo, tail, first)?;
    }
    Ok(added)
}

/// Free an entire chain starting at `first`: clear the bitmap bits and the
/// FAT entries. Safe against a NoFatChain range only when `contiguous_len`
/// is given (used for foreign contiguous files we delete).
pub(crate) fn free_chain<D: WriteAt>(
    disk: &mut D,
    geo: &Geometry,
    bm: &BitmapLoc,
    first: u32,
    contiguous_len: Option<u64>,
) -> ExfatResult<()> {
    if first < 2 {
        return Ok(());
    }
    let clusters: Vec<u32> = match contiguous_len {
        // Cap the contiguous run at the volume's cluster count so a bogus
        // length from a foreign entry cannot request an enormous Vec.
        Some(n) => (0..n.min(geo.cluster_count as u64) as u32)
            .map(|i| first + i)
            .collect(),
        None => {
            // Walk the FAT chain.
            let mut out = Vec::new();
            let mut cur = first;
            let cap = geo.cluster_count;
            loop {
                out.push(cur);
                if out.len() as u32 > cap {
                    return Err(ExfatError::Invalid("free: chain loop"));
                }
                match fat_entry(disk, geo, cur)? {
                    END_OF_CHAIN => break,
                    next if next >= 2 && next < geo.cluster_count + 2 => cur = next,
                    _ => break,
                }
            }
            out
        }
    };
    for c in clusters {
        set_bit(disk, geo, bm, c, false)?;
        let _ = set_fat(disk, geo, c, 0);
    }
    Ok(())
}
