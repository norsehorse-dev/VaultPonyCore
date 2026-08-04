#!/usr/bin/env python3
"""Build the fixture corpus by driving desktop `veracrypt --text` over
tools/fixtures/matrix.json (planning doc §13: fixtures are the specification).

Runs on Linux with the VeraCrypt CLI installed (CI container or a dev box).
For each fixture entry: create the container, mount it, populate a known
plaintext tree, unmount, checksum the container, and record everything in
manifest.json. Loop-mount diffing against vault-core output is a separate CI
job that consumes the same manifest.

Usage:
  create_fixtures.py --out /path/to/corpus [--only ID ...] [--dry-run]

Notes:
- Kuznyechik-family schemes have format_enabled=0 in pinned VeraCrypt (CLI
  refuses creation); they are skipped with a warning and need a one-time
  build from an older release. Tracked in the manifest as "missing".
- Hidden-volume fixtures create an outer volume first, then the hidden one.
- NTFS fixtures require mkfs.ntfs (ntfs-3g) present.
- The known plaintext tree exercises: long filenames, unicode names, a 0-byte
  file, a file spanning many clusters, deep nesting, and (non-FAT32) a >4 GiB
  sparse-ish file is deliberately NOT included yet — large-file fixtures are
  a P5 addition so the corpus stays clone-able.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MATRIX = HERE.parent / "fixtures" / "matrix.json"

FS_MAP = {"FAT": "FAT", "exFAT": "exFAT", "NTFS": "NTFS"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def make_plaintext_tree(root: Path) -> dict:
    """Create the known tree; return {relative_path: sha256} for files."""
    spec = {
        "readme.txt": b"VaultPony fixture tree v1\n",
        "empty.bin": b"",
        "big/clusters.bin": bytes(range(256)) * 8192,        # 2 MiB
        "unicode/åéî øü–風水.txt": b"unicode name\n",
        "deep/a/b/c/d/e/f/leaf.txt": b"nested\n",
        "long/" + ("x" * 200) + ".dat": b"long name\n",
    }
    manifest = {}
    for rel, data in spec.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        manifest[rel] = hashlib.sha256(data).hexdigest()
    return manifest


def vc_scheme_name(display_name: str) -> str:
    """Registry display name -> CLI --encryption syntax: the CLI wants
    cascades dash-separated outermost-first ("AES-Twofish-Serpent"), the UI
    shows them nested ("AES(Twofish(Serpent))")."""
    return display_name.replace("(", "-").replace(")", "")


def vc(args, password, pim, extra_input=""):
    """Run veracrypt --text non-interactively."""
    cmd = ["veracrypt", "--text", "--non-interactive",
           "--password", password, "--pim", str(pim)] + args
    return subprocess.run(cmd, input=extra_input, text=True,
                          capture_output=True, check=True)


def create_one(fx, out_dir: Path, dry: bool, populate: bool = True):
    container = out_dir / f"{fx['id']}.vc"
    if dry:
        print(f"  would create {container.name}")
        return None
    size_bytes = fx["size_mib"] * 1024 * 1024
    create_args = [
        "--create", str(container),
        "--size", str(size_bytes),
        "--volume-type", "normal",
        "--encryption", vc_scheme_name(fx["scheme"]),
        "--hash", fx["prf"],
        "--filesystem", FS_MAP[fx["filesystem"]],
        # Deterministic-ish corpus beats operator wrist motion; fixtures are
        # test data, not secrets.
        "--random-source", "/dev/urandom",
    ]
    vc(create_args, fx["password"], fx["pim"])

    if fx["hidden"]:
        vc(["--create", str(container),
            "--size", str(size_bytes // 2),
            "--volume-type", "hidden",
            "--encryption", vc_scheme_name(fx["scheme"]),
            "--hash", fx["prf"],
            "--filesystem", FS_MAP[fx["filesystem"]],
            "--random-source", "/dev/urandom"],
           fx["password"] + "-hidden", fx["pim"])

    tree = None
    if populate:
        with tempfile.TemporaryDirectory() as mnt:
            vc(["--mount", str(container), mnt], fx["password"], fx["pim"])
            try:
                tree = make_plaintext_tree(Path(mnt))
                subprocess.run(["sync"], check=True)
            finally:
                subprocess.run(["veracrypt", "--text", "--dismount", str(container)],
                               capture_output=True, text=True, check=True)
    return {"container_sha256": sha256(container), "tree": tree,
            "populated": populate}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--only", nargs="*", help="fixture ids to build")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-populate", action="store_true",
                    help="create containers only; skip mounting and the "
                    "plaintext tree (for hosts without kernel FS mounting — "
                    "unlock-matrix testing needs only the headers)")
    args = ap.parse_args()

    if not args.dry_run and shutil.which("veracrypt") is None:
        sys.exit("create_fixtures: veracrypt CLI not found on PATH")

    matrix = json.loads(MATRIX.read_text())
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = {"veracrypt_pin": matrix["veracrypt_pin"], "fixtures": {}}
    skipped, failed = [], []

    for fx in matrix["fixtures"]:
        if args.only and fx["id"] not in args.only:
            continue
        if not fx["creatable_with_pinned_vc"]:
            skipped.append(fx["id"])
            manifest["fixtures"][fx["id"]] = {"status": "missing",
                                              "reason": "format_enabled=0 in pinned VC"}
            continue
        print(f"[{fx['id']}]")
        try:
            result = create_one(fx, args.out, args.dry_run,
                                populate=not args.no_populate)
        except subprocess.CalledProcessError as e:
            failed.append(fx["id"])
            print(f"  FAILED: {e.stderr.strip()[:200]}", file=sys.stderr)
            continue
        if result is not None:
            manifest["fixtures"][fx["id"]] = {"status": "ok", "params": fx, **result}

    if not args.dry_run:
        (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"done: {len(manifest['fixtures'])} recorded, "
          f"{len(skipped)} skipped (legacy-VC needed), {len(failed)} failed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
