//! NTFS-RO parity vs the ntfs-3g reference driver (doc §7): every file in
//! the reference image reads back byte-identical through NtfsVfs. Images
//! from tools/gen-fixtures/create_ntfs_images.py; $NTFS_IMAGES to locate,
//! skips politely when absent.

use sha2::{Digest, Sha256};
use std::path::PathBuf;
use vc_fs::Vfs;
use vc_io::{BlockDevice, FileDevice};

fn images_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("NTFS_IMAGES").map(PathBuf::from)?;
    dir.join("manifest.json").exists().then_some(dir)
}

fn collect(vfs: &mut dyn Vfs, prefix: &str, out: &mut Vec<(String, u64)>) {
    for e in vfs.list(prefix).unwrap() {
        let path = if prefix == "/" {
            format!("/{}", e.name)
        } else {
            format!("{prefix}/{}", e.name)
        };
        if e.is_dir {
            collect(vfs, &path, out);
        } else {
            out.push((path, e.size));
        }
    }
}

#[test]
fn ntfs_reference_files_read_back_byte_identical() {
    let Some(dir) = images_dir() else {
        eprintln!("SKIP: NTFS reference images not present (set NTFS_IMAGES)");
        return;
    };
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();

    for (name, img) in manifest["images"].as_object().unwrap() {
        let path = dir.join(img["file"].as_str().unwrap());
        let dev: Box<dyn BlockDevice> = Box::new(FileDevice::open_read(&path).unwrap());
        let mut vfs =
            vc_fs::ntfs_ro::NtfsVfs::open(dev).unwrap_or_else(|e| panic!("{name}: open: {e}"));

        let mut ours = Vec::new();
        collect(&mut vfs, "/", &mut ours);

        let want = img["tree"].as_object().unwrap();
        assert_eq!(
            ours.len(),
            want.len(),
            "{name}: file count mismatch (ours: {:?})",
            ours.iter().map(|(p, _)| p).collect::<Vec<_>>()
        );

        for (path, size) in &ours {
            let rel = path.trim_start_matches('/');
            let want_hex = want
                .get(rel)
                .unwrap_or_else(|| panic!("{name}: unexpected file {rel}"))
                .as_str()
                .unwrap();
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 256 * 1024];
            let mut offset = 0u64;
            loop {
                let n = vfs.read_at(path, offset, &mut buf).unwrap();
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                offset += n as u64;
            }
            assert_eq!(offset, *size, "{name}/{rel}: length");
            let got: String = hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(got, want_hex, "{name}/{rel}: content mismatch");
        }
        eprintln!("{name}: {} files parity-verified", ours.len());
    }
}
