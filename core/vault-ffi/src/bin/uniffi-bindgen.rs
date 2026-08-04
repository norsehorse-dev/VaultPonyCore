//! Binding generator entry point. Usage (from repo root):
//!
//! cargo run -p vault-ffi --features cli --bin uniffi-bindgen -- \
//!     generate --library target/debug/libvault_ffi.dylib \
//!     --language kotlin --language swift --out-dir bindings/

fn main() {
    uniffi::uniffi_bindgen_main()
}
