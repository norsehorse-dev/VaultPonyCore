#!/usr/bin/env python3
"""Build raw NTFS reference images for the vc-fs NTFS-RO adapter's
differential tests (planning doc §7: parity vs a reference driver).

Reference implementation: mkntfs (ntfs-3g) + the ntfs-3g FUSE driver via a
loop device. Requires root. Linux only.

The standard tree doubles as NTFS-specific coverage: its small files land
as MFT-resident data attributes, clusters.bin (2 MiB) is non-resident,
and the unicode/long names exercise the $UpCase-backed index lookup.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from create_exfat_images import hash_tree, run  # noqa: E402
from create_fixtures import make_plaintext_tree, sha256  # noqa: E402


def with_mounted_ntfs(img: Path, populate) -> dict:
    loop = run(["losetup", "-f", "--show", str(img)]).stdout.strip()
    mnt = img.with_suffix(".mnt")
    mnt.mkdir(exist_ok=True)
    try:
        run(["ntfs-3g", loop, str(mnt)])
        try:
            populate(mnt)
            run(["sync"])
        finally:
            run(["fusermount3", "-u", str(mnt)])
        run(["ntfs-3g", "-o", "ro", loop, str(mnt)])
        try:
            return hash_tree(mnt)
        finally:
            run(["fusermount3", "-u", str(mnt)])
    finally:
        run(["losetup", "-d", loop])
        mnt.rmdir()


def populate(mnt: Path):
    make_plaintext_tree(mnt)
    # A sparse-ish tail: NTFS valid-data-length behaves like exFAT's; a
    # file extended with a seek-hole reads back zeros in the gap.
    with (mnt / "tail.bin").open("wb") as f:
        f.write(b"head")
        f.seek(300_000)
        f.write(b"tail")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    img = args.out / "ntfs-default-20m.img"
    print("[ntfs-default-20m]")
    run(["truncate", "-s", "20M", str(img)])
    run(["mkntfs", "-F", "-Q", "-L", "VPNTFS", str(img)])
    tree = with_mounted_ntfs(img, populate)

    manifest = {
        "images": {
            "ntfs-default-20m": {
                "file": img.name,
                "tree": tree,
                "image_sha256": sha256(img),
            }
        }
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"  {len(tree)} files recorded")


if __name__ == "__main__":
    main()
