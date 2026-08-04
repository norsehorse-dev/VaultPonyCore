//! Stable-toolchain robustness sweep over the header parser: random and
//! mutated inputs must produce clean errors, never panics. The real
//! coverage-guided fuzzer (cargo-fuzz, nightly) lives in fuzz/ and runs in
//! its own CI lane; this test keeps a fast smoke version in every plain
//! `cargo test`.

use vc_format::parse::parse_decrypted_header;
use vc_types::HeaderPosition;

/// Deterministic xorshift64* — no RNG dependency, reproducible failures.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// A structurally valid header the mutation pass can start from.
fn valid_header() -> [u8; 448] {
    let mut h = [0u8; 448];
    h[0..4].copy_from_slice(b"VERA");
    h[4..6].copy_from_slice(&5u16.to_be_bytes());
    h[6..8].copy_from_slice(&0x010bu16.to_be_bytes());
    h[36..44].copy_from_slice(&(16u64 * 1024 * 1024).to_be_bytes());
    h[44..52].copy_from_slice(&131072u64.to_be_bytes());
    h[52..60].copy_from_slice(&(16u64 * 1024 * 1024 - 262144).to_be_bytes());
    h[64..68].copy_from_slice(&512u32.to_be_bytes());
    let mk_crc = crc32fast::hash(&h[192..448]);
    h[8..12].copy_from_slice(&mk_crc.to_be_bytes());
    let f_crc = crc32fast::hash(&h[..188]);
    h[188..192].copy_from_slice(&f_crc.to_be_bytes());
    h
}

#[test]
fn random_buffers_never_panic() {
    let mut rng = Rng(0x5EED_CAFE_F00D_D00D);
    let mut buf = [0u8; 448];
    for _ in 0..20_000 {
        rng.fill(&mut buf);
        let _ = parse_decrypted_header(&buf, HeaderPosition::Primary);
    }
}

#[test]
fn magic_prefixed_random_buffers_never_panic() {
    // Random bytes almost never pass the magic check; force the interesting
    // paths by fixing the magic and randomizing everything else.
    let mut rng = Rng(0xBADC_0FFE_E000_0001);
    let mut buf = [0u8; 448];
    for _ in 0..20_000 {
        rng.fill(&mut buf);
        buf[0..4].copy_from_slice(b"VERA");
        let _ = parse_decrypted_header(&buf, HeaderPosition::Primary);
    }
}

#[test]
fn single_byte_mutations_of_valid_header_never_panic() {
    let base = valid_header();
    for pos in 0..448 {
        for bit in 0..8u8 {
            let mut h = base;
            h[pos] ^= 1 << bit;
            let _ = parse_decrypted_header(&h, HeaderPosition::Primary);
        }
    }
}

#[test]
fn valid_header_with_recomputed_crcs_parses_after_field_fuzz() {
    // Mutate fields but keep CRCs consistent: the parser must either accept
    // or reject with a *specific* error, never HeaderDamaged (CRCs are
    // valid) and never a panic.
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for _ in 0..5_000 {
        let mut h = valid_header();
        rng.fill(&mut h[4..188]);
        h[0..4].copy_from_slice(b"VERA");
        let f_crc = crc32fast::hash(&h[..188]);
        h[188..192].copy_from_slice(&f_crc.to_be_bytes());
        match parse_decrypted_header(&h, HeaderPosition::Primary) {
            Ok(_) => {}
            Err(vc_types::VcError::HeaderDamaged) => {
                // Only legal here for a bad sector size (both CRCs are
                // valid by construction).
                let ss = u32::from_be_bytes([h[64], h[65], h[66], h[67]]);
                assert!(
                    !vc_types::consts::SECTOR_SIZES.contains(&ss),
                    "HeaderDamaged with valid CRCs and sector size {ss}"
                );
            }
            Err(_) => {}
        }
    }
}
