//! Coverage-guided fuzzing of the decrypted-header parser (doc §13).
//! Run (nightly toolchain): cargo +nightly fuzz run header_parse

#![no_main]

use libfuzzer_sys::fuzz_target;
use vc_format::parse::parse_decrypted_header;
use vc_types::HeaderPosition;

fuzz_target!(|data: &[u8]| {
    if data.len() < vc_types::consts::HEADER_ENC_LEN {
        return;
    }
    let mut buf = [0u8; vc_types::consts::HEADER_ENC_LEN];
    buf.copy_from_slice(&data[..vc_types::consts::HEADER_ENC_LEN]);
    let _ = parse_decrypted_header(&buf, HeaderPosition::Primary);
    // Also exercise the interesting paths past the magic gate.
    buf[0..4].copy_from_slice(b"VERA");
    let _ = parse_decrypted_header(&buf, HeaderPosition::Primary);
});
