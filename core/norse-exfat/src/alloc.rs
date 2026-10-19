//! Cluster allocation: the allocation bitmap and FAT chain maintenance
//! (exFAT spec §7.1, §4). Everything this crate writes is FAT-chained
//! (NoFatChain = 0) for uniformity — see `write.rs`.
//!
//! The bitmap is treated as a flat contiguous span from its first cluster.
//! mkfs writes it contiguous and we never move or fragment it, so the byte
//! for cluster `c` is always `cluster_offset(bitmap.first_cluster) + (c-2)/8`.
//!
//! A copy of the bitmap is kept in memory ([`BitmapCache`]) once loaded, so
//! finding a free cluster and counting free space don't read the disk one
//! byte per cluster. The cache is write-through and only changes after the
//! disk write it mirrors has succeeded, so a failed write leaves the two in
//! agreement.

use crate::boot::Geometry;
use crate::fat::{fat_entry, END_OF_CHAIN};
use crate::{BitmapLoc, ExfatError, ExfatResult, ReadAt, WriteAt};

/// Bitmaps above this size are not cached (a volume this fragmented into
/// tiny clusters is not something mkfs produces); those fall back to the
/// on-disk path.
const MAX_CACHED_BITMAP_BYTES: u64 = 64 * 1024 * 1024;

/// In-memory mirror of the allocation bitmap plus a running free count.
#[derive(Debug, Default)]
pub(crate) struct BitmapCache {
    bytes: Option<Vec<u8>>,
    free: u32,
}

impl BitmapCache {
    /// Load the bitmap if it isn't loaded yet. Returns false when the bitmap
    /// is too large to cache (callers then use the disk).
    pub(crate) fn load<D: ReadAt>(
        &mut self,
        disk: &mut D,
        geo: &Geometry,
        bm: &BitmapLoc,
    ) -> ExfatResult<bool> {
        if self.bytes.is_some() {
            return Ok(true);
        }
        let needed = (geo.cluster_count as u64).div_ceil(8);
        if needed > bm.length_bytes {
            return Err(ExfatError::Invalid(
                "allocation bitmap shorter than the cluster heap",
            ));
        }
        if needed > MAX_CACHED_BITMAP_BYTES {
            return Ok(false);
        }
        let mut bytes = vec![0u8; needed as usize];
        disk.read_at(geo.cluster_offset(bm.first_cluster)?, &mut bytes)?;
        self.free = count_clear(&bytes, geo.cluster_count);
        self.bytes = Some(bytes);
        Ok(true)
    }

    /// Free clusters, if the bitmap is loaded.
    pub(crate) fn free(&self) -> Option<u32> {
        self.bytes.as_ref().map(|_| self.free)
    }

    fn get(&self, cluster: u32) -> Option<bool> {
        let bit = (cluster - 2) as usize;
        self.bytes
            .as_ref()
            .and_then(|b| b.get(bit / 8))
            .map(|byte| byte & (1 << (bit % 8)) != 0)
    }

    fn set(&mut self, cluster: u32, allocated: bool) {
        let bit = (cluster - 2) as usize;
        if let Some(byte) = self.bytes.as_mut().and_then(|b| b.get_mut(bit / 8)) {
            let mask = 1u8 << (bit % 8);
            let was = *byte & mask != 0;
            if allocated {
                *byte |= mask;
            } else {
                *byte &= !mask;
            }
            match (was, allocated) {
                (false, true) => self.free = self.free.saturating_sub(1),
                (true, false) => self.free += 1,
                _ => {}
            }
        }
    }

    /// First clear bit in `[start, end)` (bit = cluster - 2).
    fn first_clear(&self, start: u32, end: u32) -> Option<Option<u32>> {
        let bytes = self.bytes.as_ref()?;
        let mut bit = start;
        while bit < end {
            let byte = bytes[(bit / 8) as usize];
            if bit.is_multiple_of(8) && bit + 8 <= end && byte == 0xFF {
                bit += 8;
                continue;
            }
            if byte & (1 << (bit % 8)) == 0 {
                return Some(Some(bit));
            }
            bit += 1;
        }
        Some(None)
    }
}

/// Clear bits among the first `clusters` bits of `bytes`.
fn count_clear(bytes: &[u8], clusters: u32) -> u32 {
    let full = (clusters / 8) as usize;
    let mut free: u32 = bytes[..full].iter().map(|b| b.count_zeros()).sum();
    let rest = clusters % 8;
    if rest > 0 {
        let last = bytes[full];
        free += (0..rest).filter(|i| last & (1 << i) == 0).count() as u32;
    }
    free
}

/// Count free clusters straight from disk, in chunks, for a bitmap too large
/// to cache.
pub(crate) fn count_free_on_disk<D: ReadAt>(
    disk: &mut D,
    geo: &Geometry,
    bm: &BitmapLoc,
) -> ExfatResult<u32> {
    let needed = (geo.cluster_count as u64).div_ceil(8);
    if needed > bm.length_bytes {
        return Err(ExfatError::Invalid(
            "allocation bitmap shorter than the cluster heap",
        ));
    }
    let base = geo.cluster_offset(bm.first_cluster)?;
    let mut free = 0u32;
    let mut done: u64 = 0;
    let mut buf = vec![0u8; 1 << 20];
    while done < needed {
        let n = (needed - done).min(buf.len() as u64) as usize;
        disk.read_at(base + done, &mut buf[..n])?;
        let bits_here = ((geo.cluster_count as u64) - done * 8).min(n as u64 * 8) as u32;
        free += count_clear(&buf[..n], bits_here);
        done += n as u64;
    }
    Ok(free)
}

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
    cache: &BitmapCache,
    cluster: u32,
) -> ExfatResult<bool> {
    if cluster < 2 || cluster >= geo.cluster_count + 2 {
        return Err(ExfatError::Invalid("bitmap index out of range"));
    }
    if let Some(v) = cache.get(cluster) {
        return Ok(v);
    }
    let off = bitmap_byte_offset(geo, bm, cluster)?;
    let mut b = [0u8; 1];
    disk.read_at(off, &mut b)?;
    Ok(b[0] & (1 << ((cluster - 2) % 8)) != 0)
}

fn set_bit<D: WriteAt>(
    disk: &mut D,
    geo: &Geometry,
    bm: &BitmapLoc,
    cache: &mut BitmapCache,
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
    cache.set(cluster, allocated);
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
    cache: &mut BitmapCache,
    hint: u32,
) -> ExfatResult<u32> {
    let total = geo.cluster_count;
    if total == 0 {
        return Err(ExfatError::Invalid("no free clusters"));
    }
    let start = (hint.max(2) - 2) % total;
    if cache.load(disk, geo, bm)? {
        for (a, b) in [(start, total), (0, start)] {
            if let Some(Some(bit)) = cache.first_clear(a, b) {
                return Ok(bit + 2);
            }
        }
        return Err(ExfatError::Invalid("no free clusters"));
    }
    for i in 0..total {
        let cluster = 2 + ((start + i) % total);
        if !is_allocated(disk, geo, bm, cache, cluster)? {
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
    cache: &mut BitmapCache,
    count: u32,
) -> ExfatResult<Vec<u32>> {
    let mut chain = Vec::with_capacity(count as usize);
    let mut hint = 2;
    for _ in 0..count {
        let c = find_free(disk, geo, bm, cache, hint)?;
        set_bit(disk, geo, bm, cache, c, true)?;
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
    cache: &mut BitmapCache,
    tail: u32,
    count: u32,
) -> ExfatResult<Vec<u32>> {
    let added = alloc_chain(disk, geo, bm, cache, count)?;
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
    cache: &mut BitmapCache,
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
        set_bit(disk, geo, bm, cache, c, false)?;
        let _ = set_fat(disk, geo, c, 0);
    }
    Ok(())
}
