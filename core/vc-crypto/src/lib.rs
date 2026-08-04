//! XTS engine and header-key derivation over the RustCrypto crates
//! (planning doc §5).
//!
//! The `aes` crate picks up AES-NI / ARMv8-CE automatically, which carries
//! the common case; Serpent/Twofish are software-speed and that is
//! acceptable. Every key container is zeroized on drop.

pub mod kdf;
pub mod keyfile;
pub mod xts;

pub use kdf::{derive_header_key, HeaderKey};
pub use keyfile::apply_keyfiles;
pub use xts::SchemeXts;
