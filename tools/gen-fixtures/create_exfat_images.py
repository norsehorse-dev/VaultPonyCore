#!/usr/bin/env python3
"""Build raw exFAT reference images for norse-exfat's differential tests
(planning doc §7: every FS op result checksums identical to a reference
driver's view of the same fixture).

These are plain exFAT images, not VeraCrypt containers — the FS layer is
tested below the crypto layer on purpose. Reference implementation:
mkfs.exfat (exfatprogs) + the FUSE exFAT driver, via a loop device.
Requires root (losetup + mount). Linux only.

Usage:
  create_exfat_images.py --out /path/to/images

Images:
  default-16m    default cluster size, the standard plaintext tree
  cluster128k    128 KiB clusters + deliberately fragmented files
                 (exercises FAT chain walking vs NoFatChain fast path)
  manyfiles      400 files in one directory (multi-cluster directory,
                 entry sets spanning cluster boundaries), 255-char name,
                 unicode names beyond the BMP tree file
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from create_fixtures import make_plaintext_tree, sha256  # noqa: E402


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def hash_tree(root: Path) -> dict:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def with_mounted(img: Path, populate) -> dict:
    """losetup + FUSE-mount img, run populate(mnt), unmount, return tree."""
    loop = run(["losetup", "-f", "--show", str(img)]).stdout.strip()
    mnt = img.with_suffix(".mnt")
    mnt.mkdir(exist_ok=True)
    try:
        run(["mount.exfat-fuse", loop, str(mnt)])
        try:
            populate(mnt)
            run(["sync"])
        finally:
            run(["fusermount3", "-u", str(mnt)])
        # Re-mount read-only for the authoritative reference listing, so the
        # recorded tree is what the reference driver reads back, not what we
        # think we wrote.
        run(["mount.exfat-fuse", "-o", "ro", loop, str(mnt)])
        try:
            return hash_tree(mnt)
        finally:
            run(["fusermount3", "-u", str(mnt)])
    finally:
        run(["losetup", "-d", loop])
        mnt.rmdir()


def populate_standard(mnt: Path):
    make_plaintext_tree(mnt)


def populate_fragmented(mnt: Path):
    make_plaintext_tree(mnt)
    # Interleaved appends force at least one file onto a non-contiguous
    # cluster chain (NoFatChain=0), the path a fresh mkfs+copy never hits.
    a, b = mnt / "frag_a.bin", mnt / "frag_b.bin"
    with a.open("ab") as fa, b.open("ab") as fb:
        for i in range(48):
            fa.write(bytes([i]) * 65536)
            fa.flush()
            fb.write(bytes([255 - i]) * 65536)
            fb.flush()
    # And a hole-refill: delete an early file, then grow another into it.
    hole = mnt / "hole.bin"
    hole.write_bytes(b"H" * (1 << 20))
    grow = mnt / "grow.bin"
    grow.write_bytes(b"G" * (1 << 18))
    hole.unlink()
    with grow.open("ab") as f:
        f.write(b"g" * (3 << 20))


def populate_manyfiles(mnt: Path):
    d = mnt / "many"
    d.mkdir()
    for i in range(400):
        (d / f"file_{i:04d}_{'pad' * 10}.txt").write_bytes(f"content {i}\n".encode())
    (mnt / ("n" * 251 + ".txt")).write_bytes(b"max name\n")
    (mnt / "emoji \U0001f40e\U0001f512.bin").write_bytes(b"beyond the BMP\n")


IMAGES = [
    ("default-16m", 16, [], populate_standard),
    ("cluster128k", 64, ["-c", "128k"], populate_fragmented),
    ("manyfiles", 16, [], populate_manyfiles),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    manifest = {"images": {}}
    for name, size_mib, mkfs_args, populate in IMAGES:
        img = args.out / f"exfat-{name}.img"
        print(f"[{name}]")
        run(["truncate", "-s", f"{size_mib}M", str(img)])
        run(["mkfs.exfat", "-L", f"VP{name[:9].upper()}", *mkfs_args, str(img)])
        tree = with_mounted(img, populate)
        manifest["images"][name] = {
            "file": img.name,
            "size_mib": size_mib,
            "mkfs_args": mkfs_args,
            "tree": tree,
            "image_sha256": sha256(img),
        }
        print(f"  {len(tree)} files recorded")

    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"done: {len(IMAGES)} images -> {args.out}")


if __name__ == "__main__":
    main()
