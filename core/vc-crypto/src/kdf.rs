//! Header-key derivation (doc §6): PBKDF2-HMAC over the candidate PRF, or
//! Argon2id for volumes made with VeraCrypt 1.26.29+.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use pbkdf2::pbkdf2_hmac;
use vc_types::registry::{argon2_cost, iterations_for_pim, Argon2Cost, ARGON2_SCHEDULE};
use vc_types::{Kdf, Prf, VcError, VcResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Derived header-key material: sized for the largest cascade
/// (3 layers x 64 bytes = 192), which is also Argon2id's fixed output. Only
/// the first `len` bytes are meaningful. For PBKDF2, deriving exactly what the
/// scheme needs matters, because every extra output block costs the full
/// iteration count again. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HeaderKey {
    bytes: [u8; 192],
    #[zeroize(skip)]
    len: usize,
}

impl HeaderKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// PBKDF2 with the given PRF over (passphrase, 64-byte salt, iterations),
/// producing `key_len` bytes (the scheme's `key_bytes()`).
///
/// Iterations come from `vc_types::registry::iterations_for_pim`. Keyfile
/// pool mixing (P10) slots in ahead of this call, not inside it.
///
/// P0 status: SHA-512 is fixture-verified. The other four are wired per the
/// upstream Pkcs5.c mapping (BLAKE2s-256 and Streebog use the 256-bit and
/// 512-bit digests respectively) but MUST be treated as unverified until
/// their P1 fixtures unlock.
pub fn derive_header_key(
    prf_name: &str,
    passphrase: &[u8],
    salt: &[u8; vc_types::consts::SALT_LEN],
    iterations: u32,
    key_len: usize,
) -> VcResult<HeaderKey> {
    debug_assert!(key_len <= 192);
    let mut key = HeaderKey {
        bytes: [0u8; 192],
        len: key_len,
    };
    let out = &mut key.bytes[..key_len];
    match prf_name {
        "SHA-512" => pbkdf2_hmac::<sha2::Sha512>(passphrase, salt, iterations, out),
        "SHA-256" => pbkdf2_hmac::<sha2::Sha256>(passphrase, salt, iterations, out),
        "Whirlpool" => pbkdf2_hmac::<whirlpool::Whirlpool>(passphrase, salt, iterations, out),
        // BLAKE2 is a "lazy" digest in RustCrypto; it needs SimpleHmac
        // rather than the eager-core Hmac that pbkdf2_hmac assumes.
        "BLAKE2s-256" => {
            pbkdf2::pbkdf2::<hmac::SimpleHmac<blake2::Blake2s256>>(
                passphrase, salt, iterations, out,
            )
            .map_err(|e| VcError::Internal(format!("pbkdf2: {e}")))?;
        }
        "Streebog" => pbkdf2_hmac::<streebog::Streebog512>(passphrase, salt, iterations, out),
        other => return Err(VcError::Internal(format!("unknown PRF {other}"))),
    }
    Ok(key)
}

/// TrueCrypt mode (plan 6.2): PBKDF2 with one of TrueCrypt's PRFs at its
/// fixed iteration count (`prf.default_iterations` from
/// `registry::TRUECRYPT_PRFS`; TrueCrypt has no PIM). The only place
/// RIPEMD-160 is derived: [`derive_header_key`] keeps refusing it, so a
/// VeraCrypt unlock can never try it.
pub fn derive_truecrypt_header_key(
    prf: &Prf,
    passphrase: &[u8],
    salt: &[u8; vc_types::consts::SALT_LEN],
    key_len: usize,
) -> VcResult<HeaderKey> {
    debug_assert!(key_len <= 192);
    if prf.kdf != Kdf::Pbkdf2 {
        return Err(VcError::Internal(format!(
            "{} is not a TrueCrypt PRF",
            prf.name
        )));
    }
    match prf.name {
        "RIPEMD-160" => {
            let mut key = HeaderKey {
                bytes: [0u8; 192],
                len: key_len,
            };
            pbkdf2_hmac::<ripemd::Ripemd160>(
                passphrase,
                salt,
                prf.default_iterations,
                &mut key.bytes[..key_len],
            );
            Ok(key)
        }
        "SHA-512" | "Whirlpool" => {
            derive_header_key(prf.name, passphrase, salt, prf.default_iterations, key_len)
        }
        other => Err(VcError::Internal(format!("{other} is not a TrueCrypt PRF"))),
    }
}

/// Derive the header key for one KDF candidate at a PIM. PBKDF2 derives
/// exactly `key_len` bytes; Argon2id always derives its fixed 192 bytes and
/// keeps the first `key_len`, because asking Argon2 for fewer bytes changes
/// the output rather than truncating it.
///
/// Argon2id allocates its working memory for this one call. Callers
/// deriving several Argon2id keys in a row should hold one [`Argon2Memory`]
/// and use [`derive_argon2id`] instead.
pub fn derive_header_key_for(
    prf: &Prf,
    passphrase: &[u8],
    salt: &[u8; vc_types::consts::SALT_LEN],
    pim: u32,
    key_len: usize,
) -> VcResult<HeaderKey> {
    match prf.kdf {
        Kdf::Pbkdf2 => derive_header_key(
            prf.name,
            passphrase,
            salt,
            iterations_for_pim(prf, pim),
            key_len,
        ),
        Kdf::Argon2id => {
            let mut memory = Argon2Memory::for_pim(pim)?;
            derive_argon2id(&mut memory, passphrase, salt, pim, key_len)
        }
    }
}

/// Working memory for Argon2id derivations: `memory_kib` 1 KiB blocks.
///
/// Allocated fallibly, so a phone that cannot spare the memory gets
/// [`VcError::KdfOutOfMemory`] instead of an allocator abort that takes the
/// whole app down. The blocks are the password-dependent Argon2 state, so
/// they are wiped on drop.
pub struct Argon2Memory {
    blocks: Vec<Block>,
}

impl Argon2Memory {
    /// Memory for every derivation at `pim` (PIM 0 is upstream's default).
    pub fn for_pim(pim: u32) -> VcResult<Self> {
        Self::for_cost(argon2_cost(pim))
    }

    fn for_cost(cost: Argon2Cost) -> VcResult<Self> {
        let count = params(cost, ARGON2_SCHEDULE.output_len)?.block_count();
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(count)
            .map_err(|_| VcError::KdfOutOfMemory {
                needed_mib: cost.memory_mib(),
            })?;
        blocks.resize(count, Block::new());
        Ok(Self { blocks })
    }

    /// MiB held, for progress and diagnostics.
    pub fn mib(&self) -> usize {
        self.blocks.len() / 1024
    }
}

impl Drop for Argon2Memory {
    fn drop(&mut self) {
        wipe(&mut self.blocks);
    }
}

/// Argon2id header-key derivation into caller-held memory, which must have
/// been sized for the same PIM (it can be reused across salts).
pub fn derive_argon2id(
    memory: &mut Argon2Memory,
    passphrase: &[u8],
    salt: &[u8; vc_types::consts::SALT_LEN],
    pim: u32,
    key_len: usize,
) -> VcResult<HeaderKey> {
    let full = ARGON2_SCHEDULE.output_len;
    debug_assert!(key_len <= full && full <= 192);
    let mut key = HeaderKey {
        bytes: [0u8; 192],
        len: key_len,
    };
    argon2id_raw(
        memory,
        argon2_cost(pim),
        passphrase,
        salt,
        &mut key.bytes[..full],
    )?;
    Ok(key)
}

fn wipe(blocks: &mut [Block]) {
    for b in blocks {
        b.zeroize();
    }
}

fn params(cost: Argon2Cost, out_len: usize) -> VcResult<Params> {
    Params::new(cost.memory_kib, cost.passes, 1, Some(out_len))
        .map_err(|e| VcError::Internal(format!("argon2 params: {e}")))
}

/// Plain Argon2id v0x13, parallelism 1: what upstream's
/// `derive_key_argon2` computes. `out.len()` is part of the hash input.
fn argon2id_raw(
    memory: &mut Argon2Memory,
    cost: Argon2Cost,
    passphrase: &[u8],
    salt: &[u8],
    out: &mut [u8],
) -> VcResult<()> {
    let ctx = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params(cost, out.len())?,
    );
    let need = ctx.params().block_count();
    if memory.blocks.len() < need {
        return Err(VcError::Internal(format!(
            "argon2 memory holds {} blocks, derivation needs {need}",
            memory.blocks.len()
        )));
    }
    let result =
        ctx.hash_password_into_with_memory(passphrase, salt, out, &mut memory.blocks[..need]);
    // The blocks are reused for the next salt; wipe between derivations too,
    // not only on drop.
    wipe(&mut memory.blocks[..need]);
    result.map_err(|e| {
        out.zeroize();
        VcError::Internal(format!("argon2: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_kdf_is_deterministic_and_length_scoped() {
        let salt = [7u8; 64];
        let a = derive_header_key("SHA-512", b"pw", &salt, 1000, 64).unwrap();
        let b = derive_header_key("SHA-512", b"pw", &salt, 1000, 64).unwrap();
        let c = derive_header_key("SHA-512", b"pw", &salt, 1000, 128).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.as_bytes().len(), 64);
        // PBKDF2 output blocks are independent: a longer derivation shares
        // its prefix with a shorter one.
        assert_eq!(&c.as_bytes()[..64], a.as_bytes());
        assert_ne!(a.as_bytes(), &[0u8; 64][..]);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn argon2id_matches_reference_vector() {
        // Argon2 reference implementation test vector (phc-winner-argon2
        // test.c): Argon2id v0x13, t=2, m=2^16 KiB, p=1, "password",
        // "somesalt", 32-byte tag.
        let cost = Argon2Cost {
            memory_kib: 65_536,
            passes: 2,
        };
        let mut mem = Argon2Memory::for_cost(cost).unwrap();
        let mut out = [0u8; 32];
        argon2id_raw(&mut mem, cost, b"password", b"somesalt", &mut out).unwrap();
        assert_eq!(
            hex(&out),
            "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"
        );
        // Wiped after use.
        assert!(mem
            .blocks
            .iter()
            .all(|b| b.as_ref().iter().all(|w| *w == 0)));
    }

    #[test]
    fn argon2id_header_key_is_a_prefix_of_the_192_byte_output() {
        // PIM 1 = 64 MiB, 3 passes. Expected value computed with libargon2
        // (argon2-cffi hash_secret_raw, Type.ID, version 19, 192 bytes).
        let salt: [u8; 64] = core::array::from_fn(|i| i as u8);
        let argon = vc_types::registry::PRFS
            .iter()
            .find(|p| p.kdf == Kdf::Argon2id)
            .unwrap();
        let aes = derive_header_key_for(argon, b"vaultpony", &salt, 1, 64).unwrap();
        let cascade = derive_header_key_for(argon, b"vaultpony", &salt, 1, 192).unwrap();
        assert_eq!(
            hex(cascade.as_bytes()),
            "c2a418968280b57acc33f3e7c59484c6c64497ba9c0cc177ee6b06612f794597\
             776843698a7173554a4d4656c551b8817a4258ed02840ba7e241c0c0c619fed9\
             24fbee1361b93cadd7b960216ae64ff2c795077006fe88dabbb056aacc704ea2\
             1eb893f0ee31ca2ce3802690d53878d7e4455d166d01fdea09482cb64adf1e47\
             69313197b410f62732b45a31303e2eb18b09e1fb66d80571c5a8866f55c44200\
             faf24db83034dadfc2c0bad6aaeeafbde0050928466117f4fd704e6c151a4718"
        );
        assert_eq!(aes.as_bytes(), &cascade.as_bytes()[..64]);

        // The trap upstream documents: a 64-byte request is a different hash.
        let cost = argon2_cost(1);
        let mut mem = Argon2Memory::for_cost(cost).unwrap();
        let mut short = [0u8; 64];
        argon2id_raw(&mut mem, cost, b"vaultpony", &salt, &mut short).unwrap();
        assert_ne!(&short[..], aes.as_bytes());
    }

    #[test]
    fn argon2_memory_is_reusable_across_salts() {
        let mut mem = Argon2Memory::for_pim(1).unwrap();
        assert_eq!(mem.mib(), 64);
        let a = derive_argon2id(&mut mem, b"pw", &[1u8; 64], 1, 64).unwrap();
        let b = derive_argon2id(&mut mem, b"pw", &[2u8; 64], 1, 64).unwrap();
        let a2 = derive_argon2id(&mut mem, b"pw", &[1u8; 64], 1, 64).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.as_bytes(), a2.as_bytes());
    }

    #[test]
    fn argon2_memory_too_small_is_refused() {
        let mut mem = Argon2Memory::for_pim(1).unwrap();
        assert!(derive_argon2id(&mut mem, b"pw", &[0u8; 64], 2, 64).is_err());
    }

    #[test]
    fn pbkdf2_dispatch_matches_direct_call() {
        let sha512 = &vc_types::registry::PRFS[0];
        let salt = [9u8; 64];
        let via = derive_header_key_for(sha512, b"pw", &salt, 1, 64).unwrap();
        let direct = derive_header_key("SHA-512", b"pw", &salt, 16_000, 64).unwrap();
        assert_eq!(via.as_bytes(), direct.as_bytes());
    }

    #[test]
    fn truecrypt_ripemd160_matches_reference() {
        // Python hashlib.pbkdf2_hmac("ripemd160", b"vaultpony",
        // bytes(range(64)), 2000, 192): OpenSSL, independent of the crate.
        let salt: [u8; 64] = core::array::from_fn(|i| i as u8);
        let prf = &vc_types::registry::TRUECRYPT_PRFS[0];
        let key = derive_truecrypt_header_key(prf, b"vaultpony", &salt, 192).unwrap();
        assert_eq!(
            hex(key.as_bytes()),
            "1bbfb74f5cb00660a549ef94add29601295fdf1fedb341817ab2327eaea682f9\
             ea983925794ff653f5ff1d7bf696dc5fc23d680a89527ed1b6fb9358e54861cc\
             71aae565d47835a08e7114dcdfd54b0a8e7013247e310e571fb5d29da14f33a6\
             25ea0a06d797518bf4e7d3a3c91c21abf1fd396e11f6d03f1520fe3c72692db9\
             1d89b3bdd68d2a35021c68711aba0052a4631b915d1675c5fd750dba882cefa6\
             0bb9db66357d2399f08bd0ba48dccbd2869c7ab3a151f5ea282a4a11db1139aa"
        );
        // SHA-512 and Whirlpool reuse the VeraCrypt code at 1000 iterations.
        let sha = &vc_types::registry::TRUECRYPT_PRFS[1];
        let a = derive_truecrypt_header_key(sha, b"pw", &salt, 64).unwrap();
        let b = derive_header_key("SHA-512", b"pw", &salt, 1000, 64).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        // Argon2id is never a TrueCrypt PRF.
        let argon = vc_types::registry::PRFS.last().unwrap();
        assert!(derive_truecrypt_header_key(argon, b"pw", &salt, 64).is_err());
    }

    #[test]
    fn unknown_prf_is_an_error() {
        let salt = [0u8; 64];
        assert!(derive_header_key("RIPEMD-160", b"pw", &salt, 1, 64).is_err());
    }
}
