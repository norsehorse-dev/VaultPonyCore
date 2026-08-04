//! XTS over single ciphers and cascades (doc §5).
//!
//! Key material layout (both the derived header key and the master-key
//! area), verified against VeraCrypt's `EAInit`/`EncryptionModeXTS` and the
//! fixture corpus: all primary keys in layer order, then all secondary
//! (tweak) keys in the same order — 32 bytes each.
//!
//! Cascade application order (per `EncryptDataUnitsCurrentThread` /
//! `DecryptDataUnitsCurrentThread` in the pinned checkout): encryption
//! applies layers first→last (innermost-first, as the registry stores
//! them); decryption applies last→first. Each layer is an independent
//! full-buffer XTS pass with its own key pair and the same unit numbers.
//!
//! Data path: 512-byte XTS data units regardless of sector size, unit
//! numbers absolute from the start of the container (doc §6). The header is
//! its own single 448-byte unit with unit number 0.

use aes::cipher::KeyInit;
use vc_types::{Cipher, EncryptionScheme, VcError, VcResult};
use xts_mode::{get_tweak_default, Xts128};

const KEY_LEN: usize = 32;

/// One XTS layer: a cipher with its (primary, secondary) key pair.
enum LayerXts {
    Aes(Box<Xts128<aes::Aes256>>),
    Serpent(Box<Xts128<serpent::Serpent>>),
    Twofish(Box<Xts128<twofish::Twofish>>),
    Camellia(Box<Xts128<camellia::Camellia256>>),
    Kuznyechik(Box<Xts128<kuznyechik::Kuznyechik>>),
}

macro_rules! layer_dispatch {
    ($self:expr, $x:ident => $body:expr) => {
        match $self {
            LayerXts::Aes($x) => $body,
            LayerXts::Serpent($x) => $body,
            LayerXts::Twofish($x) => $body,
            LayerXts::Camellia($x) => $body,
            LayerXts::Kuznyechik($x) => $body,
        }
    };
}

impl LayerXts {
    fn new(cipher: Cipher, primary: &[u8], secondary: &[u8]) -> Self {
        // Both slices are always exactly 32 bytes (KEY_LEN), checked by the
        // caller; new_from_slice therefore cannot fail. Serpent declares a
        // 16-byte default KeySize but accepts 16–32 via new_from_slice.
        macro_rules! xts {
            ($variant:ident, $ty:ty) => {
                LayerXts::$variant(Box::new(Xts128::new(
                    <$ty>::new_from_slice(primary).expect("32-byte key"),
                    <$ty>::new_from_slice(secondary).expect("32-byte key"),
                )))
            };
        }
        match cipher {
            Cipher::Aes => xts!(Aes, aes::Aes256),
            Cipher::Serpent => xts!(Serpent, serpent::Serpent),
            Cipher::Twofish => xts!(Twofish, twofish::Twofish),
            Cipher::Camellia => xts!(Camellia, camellia::Camellia256),
            Cipher::Kuznyechik => xts!(Kuznyechik, kuznyechik::Kuznyechik),
        }
    }

    fn decrypt_area(&self, buf: &mut [u8], sector_size: usize, first_sector: u128) {
        layer_dispatch!(self, x => x.decrypt_area(buf, sector_size, first_sector, get_tweak_default))
    }

    fn encrypt_area(&self, buf: &mut [u8], sector_size: usize, first_sector: u128) {
        layer_dispatch!(self, x => x.encrypt_area(buf, sector_size, first_sector, get_tweak_default))
    }
}

/// An assembled XTS engine for one encryption scheme: one layer per cipher,
/// applied in cascade order.
pub struct SchemeXts {
    layers: Vec<LayerXts>,
}

impl SchemeXts {
    /// Whether an XTS engine exists for this scheme. The full 1.26.x matrix
    /// is implemented; this remains for forward compatibility with schemes
    /// a future registry regeneration might add.
    pub fn supported(_scheme: &EncryptionScheme) -> bool {
        true
    }

    /// Build from key material laid out as documented above: layer `i`'s
    /// primary key at `i * 32`, secondary at `(n_layers + i) * 32`.
    pub fn new(scheme: &'static EncryptionScheme, key_material: &[u8]) -> VcResult<Self> {
        if key_material.len() != scheme.key_bytes() {
            return Err(VcError::Internal(format!(
                "scheme {} needs {} key bytes, got {}",
                scheme.name,
                scheme.key_bytes(),
                key_material.len()
            )));
        }
        let n = scheme.layers.len();
        let layers = scheme
            .layers
            .iter()
            .enumerate()
            .map(|(i, &cipher)| {
                let primary = &key_material[i * KEY_LEN..(i + 1) * KEY_LEN];
                let secondary = &key_material[(n + i) * KEY_LEN..(n + i + 1) * KEY_LEN];
                LayerXts::new(cipher, primary, secondary)
            })
            .collect();
        Ok(Self { layers })
    }

    /// Decrypt the 448-byte encrypted header region in place (XTS data unit
    /// 0, blocks 0..27).
    pub fn decrypt_header(&self, buf: &mut [u8; vc_types::consts::HEADER_ENC_LEN]) {
        let len = buf.len();
        for layer in self.layers.iter().rev() {
            layer.decrypt_area(buf, len, 0);
        }
    }

    /// Encrypt the 448-byte header region in place (XTS data unit 0).
    /// Cascade layers apply innermost-first — the inverse of `decrypt_header`
    /// (container creation, P10).
    pub fn encrypt_header(&self, buf: &mut [u8; vc_types::consts::HEADER_ENC_LEN]) {
        let len = buf.len();
        for layer in self.layers.iter() {
            layer.encrypt_area(buf, len, 0);
        }
    }

    /// Decrypt `buf` in place; `first_data_unit` is the absolute 512-byte
    /// unit number of the first unit in `buf` (container offset / 512).
    /// `buf.len()` must be a multiple of 512.
    pub fn decrypt_units(&self, buf: &mut [u8], first_data_unit: u64) {
        debug_assert_eq!(buf.len() % vc_types::consts::XTS_DATA_UNIT_LEN, 0);
        for layer in self.layers.iter().rev() {
            layer.decrypt_area(
                buf,
                vc_types::consts::XTS_DATA_UNIT_LEN,
                first_data_unit as u128,
            );
        }
    }

    /// Encrypt `buf` in place (write path, P4+).
    pub fn encrypt_units(&self, buf: &mut [u8], first_data_unit: u64) {
        debug_assert_eq!(buf.len() % vc_types::consts::XTS_DATA_UNIT_LEN, 0);
        for layer in self.layers.iter() {
            layer.encrypt_area(
                buf,
                vc_types::consts::XTS_DATA_UNIT_LEN,
                first_data_unit as u128,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scheme(name: &str) -> &'static EncryptionScheme {
        vc_types::registry::ENCRYPTION_SCHEMES
            .iter()
            .find(|s| s.name == name)
            .unwrap()
    }

    #[test]
    fn every_scheme_round_trips() {
        for s in vc_types::registry::ENCRYPTION_SCHEMES {
            let key: Vec<u8> = (0..s.key_bytes() as u32)
                .map(|i| (i * 7 + 3) as u8)
                .collect();
            let xts = SchemeXts::new(s, &key).unwrap();
            let plain = [0xA5u8; 1024];
            let mut buf = plain;
            xts.encrypt_units(&mut buf, 256);
            assert_ne!(buf[..], plain[..], "{} did not change data", s.name);
            xts.decrypt_units(&mut buf, 256);
            assert_eq!(buf[..], plain[..], "{} did not round-trip", s.name);
        }
    }

    #[test]
    fn cascade_differs_from_its_layers() {
        // AES(Twofish) must not equal AES alone or Twofish alone.
        let single = scheme("AES");
        let cascade = scheme("AES(Twofish)");
        let key: Vec<u8> = (0..cascade.key_bytes()).map(|i| i as u8).collect();
        let xts_single = SchemeXts::new(single, &key[..64]).unwrap();
        let xts_cascade = SchemeXts::new(cascade, &key).unwrap();
        let mut a = [9u8; 512];
        let mut b = [9u8; 512];
        xts_single.encrypt_units(&mut a, 0);
        xts_cascade.encrypt_units(&mut b, 0);
        assert_ne!(a[..], b[..]);
    }

    #[test]
    fn unit_number_matters() {
        let xts = SchemeXts::new(scheme("AES"), &[42u8; 64]).unwrap();
        let mut a = [1u8; 512];
        let mut b = [1u8; 512];
        xts.encrypt_units(&mut a, 0);
        xts.encrypt_units(&mut b, 1);
        assert_ne!(a[..], b[..]);
    }

    #[test]
    fn wrong_key_len_rejected() {
        assert!(SchemeXts::new(scheme("AES"), &[0u8; 63]).is_err());
        assert!(SchemeXts::new(scheme("AES(Twofish(Serpent))"), &[0u8; 64]).is_err());
    }
}
