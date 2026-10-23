//! The low-memory profile (iOS File Provider extension): with the exFAT
//! bitmap copy disabled, allocation, free space and frees go through the
//! on-disk path and agree with a normal session. Its own test binary because
//! the cap is process-wide.

use vault_core::{ContainerFs, Session};
use vc_format::{CreateParams, UnlockSecret};
use vc_io::FileDevice;
use vc_types::KdfFilter;

const PW: &[u8] = b"low-memory-gate-password-01";

#[test]
fn exfat_without_the_bitmap_cache_matches_with_it() {
    let path = std::env::temp_dir().join(format!("vaultpony-lowmem-{}.vc", std::process::id()));
    let f = std::fs::File::create(&path).unwrap();
    f.set_len(8 << 20).unwrap();
    drop(f);
    let params = CreateParams {
        scheme: &vc_types::registry::ENCRYPTION_SCHEMES[0],
        prf: &vc_types::registry::PRFS[0],
        pim: 1,
        passphrase: PW,
        keyfiles: &[],
        size: 8 << 20,
        sector_size: 512,
    };
    vault_core::create_container(
        Box::new(FileDevice::open_rw(&path).unwrap()),
        &params,
        ContainerFs::Exfat,
    )
    .unwrap();
    let unlock = || {
        Session::unlock_device_with(
            Box::new(FileDevice::open_rw(&path).unwrap()),
            &UnlockSecret {
                kdf: KdfFilter::Pbkdf2Only,
                ..UnlockSecret::new(PW, 1)
            },
            &mut |_, _, _| {},
        )
        .unwrap()
    };

    norse_exfat::alloc::set_max_cached_bitmap_bytes(0);
    let mut s = unlock();
    let before = s.space().unwrap();
    for i in 0..12u8 {
        let name = format!("/f{i}.bin");
        s.vfs().create(&name).unwrap();
        let data = vec![i; 40_000 + i as usize * 3_000];
        s.vfs().write_at(&name, 0, &data).unwrap();
    }
    s.vfs().unlink("/f3.bin").unwrap();
    s.vfs().unlink("/f7.bin").unwrap();
    s.vfs().flush().unwrap();
    let low = s.space().unwrap();
    assert!(low.free_bytes < before.free_bytes);
    s.lock();

    norse_exfat::alloc::set_max_cached_bitmap_bytes(
        norse_exfat::alloc::DEFAULT_MAX_CACHED_BITMAP_BYTES,
    );
    let mut cached = unlock();
    assert_eq!(cached.space().unwrap(), low);
    assert_eq!(cached.vfs().list("/").unwrap().len(), 10);
    let mut buf = vec![0u8; 61_000];
    assert!(cached.vfs().read_at("/f7.bin", 0, &mut buf).is_err());
    assert_eq!(
        cached.vfs().read_at("/f11.bin", 0, &mut buf).unwrap(),
        61_000
    );
    assert!(buf.iter().all(|&b| b == 11));
    cached.lock();
    std::fs::remove_file(&path).ok();
}
