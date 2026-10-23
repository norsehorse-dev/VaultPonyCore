#!/usr/bin/env python3
"""Build the 2.0.0 rc5 fixtures: TrueCrypt 7.1a containers (TrueCrypt mode,
plan 6.2) and VeraCrypt containers holding ext4 (read-only ext4, plan 6.3).

Run as root on a Linux box with both CLIs on PATH:
  - `truecrypt`: TrueCrypt 7.1a console (needs libfuse2 and dmsetup)
  - `veracrypt`: VeraCrypt 1.26.x console or GUI build
  - mkfs.ext4 (e2fsprogs)

Usage:
  sudo python3 create_rc5_fixtures.py --out /path/to/rc5-fixtures

Writes one container per fixture plus manifest-rc5.json (parameters,
container SHA-256, and the SHA-256 of every file written inside). The
TrueCrypt fixtures are never written again after creation; the ext4 ones
are populated through the kernel mount.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from create_fixtures import make_plaintext_tree, sha256  # noqa: E402

PASSWORD = "vaultpony-fixture"
HIDDEN_PASSWORD = "vaultpony-fixture-hidden"
MIB = 1024 * 1024

# TrueCrypt 7.1a: three PRFs, eight ciphers and cascades, FAT made by
# TrueCrypt itself. Hidden and keyfile cases cover the other header paths.
TC_FIXTURES = [
    {"id": "tc-aes-ripemd160-fat", "encryption": "AES", "hash": "RIPEMD-160"},
    {"id": "tc-aes-sha512-fat", "encryption": "AES", "hash": "SHA-512"},
    {"id": "tc-serpent-whirlpool-fat", "encryption": "Serpent", "hash": "Whirlpool"},
    {"id": "tc-twofish-ripemd160-fat", "encryption": "Twofish", "hash": "RIPEMD-160"},
    {"id": "tc-aes_twofish_serpent-ripemd160-fat", "encryption": "AES-Twofish-Serpent", "hash": "RIPEMD-160"},
    {"id": "tc-serpent_twofish_aes-sha512-fat", "encryption": "Serpent-Twofish-AES", "hash": "SHA-512"},
    {"id": "tc-twofish_serpent-whirlpool-fat", "encryption": "Twofish-Serpent", "hash": "Whirlpool"},
    {"id": "tc-aes-ripemd160-fat-keyfile", "encryption": "AES", "hash": "RIPEMD-160", "keyfile": True},
    {"id": "tc-aes-sha512-fat-hidden", "encryption": "AES", "hash": "SHA-512", "hidden": True},
]


def run(cmd, **kw):
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw)


def keyfile_bytes() -> bytes:
    out, block = b"", b"vaultpony-rc5-keyfile"
    while len(out) < 1024:
        block = hashlib.sha256(block).digest()
        out += block
    return out[:1024]


def tc(args, password, keyfile=""):
    return run(["truecrypt", "--text", "--non-interactive",
                "--password", password, "--keyfiles", keyfile] + args)


def tc_create(container: Path, size: int, fx, password, volume_type, keyfile=""):
    tc(["--create", str(container), "--size", str(size),
        "--volume-type", volume_type, "--encryption", fx["encryption"],
        "--hash", fx["hash"], "--filesystem", "FAT",
        "--random-source", "/dev/urandom"], password, keyfile)


def tc_populate(container: Path, password, keyfile="", protect_hidden="no"):
    with tempfile.TemporaryDirectory() as mnt:
        tc(["--protect-hidden", protect_hidden, str(container), mnt], password, keyfile)
        try:
            tree = make_plaintext_tree(Path(mnt))
            run(["sync"])
        finally:
            run(["truecrypt", "--text", "--dismount", str(container)])
    return tree


def build_tc(out: Path):
    entries = {}
    for fx in TC_FIXTURES:
        container = out / f"{fx['id']}.tc"
        container.unlink(missing_ok=True)
        keyfile = ""
        if fx.get("keyfile"):
            kf = out / f"{fx['id']}.key"
            kf.write_bytes(keyfile_bytes())
            keyfile = str(kf)
        size = 16 * MIB if fx.get("hidden") else 8 * MIB
        tc_create(container, size, fx, PASSWORD, "normal", keyfile)
        entry = {"params": dict(fx, password=PASSWORD, size_mib=size // MIB,
                                program="TrueCrypt 7.1a")}
        entry["tree"] = tc_populate(container, PASSWORD, keyfile)
        if fx.get("hidden"):
            tc_create(container, 4 * MIB, fx, HIDDEN_PASSWORD, "hidden")
            entry["hidden_password"] = HIDDEN_PASSWORD
            entry["hidden_tree"] = tc_populate(container, HIDDEN_PASSWORD)
        entry["container_sha256"] = sha256(container)
        entries[fx["id"]] = entry
    return entries


def vc(args, password, pim=0, keyfile=""):
    return run(["veracrypt", "--text", "--non-interactive",
                "--password", password, "--pim", str(pim),
                "--keyfiles", keyfile] + args)


def vc_create(container: Path, size: int, password, filesystem, volume_type="normal"):
    vc(["--create", str(container), "--size", str(size),
        "--volume-type", volume_type, "--encryption", "AES", "--hash", "SHA-512",
        "--filesystem", filesystem, "--random-source", "/dev/urandom"], password)


def ext4_extras(root: Path) -> dict:
    """What ext4 adds over the shared tree: a symlink inside the volume, one
    pointing outside it, a name that isn't UTF-8, a sparse file, a FIFO, and a
    file spanning several extents."""
    extra = {}
    (root / "links").mkdir()
    os.symlink("../readme.txt", root / "links" / "to-readme")
    os.symlink("/etc/passwd", root / "links" / "escape")
    extra["links/to-readme"] = "symlink:../readme.txt"
    extra["links/escape"] = "symlink:/etc/passwd"
    raw = b"names/latin1-\xe9.txt"
    os.makedirs(root / "names", exist_ok=True)
    data = b"not utf-8\n"
    with open(os.fsencode(root) + b"/" + raw, "wb") as f:
        f.write(data)
    extra["hex:" + raw.hex()] = hashlib.sha256(data).hexdigest()
    sparse = root / "sparse.bin"
    with open(sparse, "wb") as f:
        f.truncate(8 * MIB)
        f.seek(4 * MIB)
        f.write(b"middle")
    extra["sparse.bin"] = sha256(sparse)
    os.mkfifo(root / "fifo")
    extra["fifo"] = "fifo"
    frag = root / "big" / "extents.bin"
    with open(frag, "wb") as f:
        for i in range(48):
            f.write(hashlib.sha256(i.to_bytes(4, "big")).digest() * 4096)
            f.flush()
            os.fsync(f.fileno())
    extra["big/extents.bin"] = sha256(frag)
    return extra


def vc_populate(container: Path, password, extras=True):
    with tempfile.TemporaryDirectory() as mnt:
        vc(["--protect-hidden", "no", str(container), mnt], password)
        try:
            tree = make_plaintext_tree(Path(mnt))
            if extras:
                tree.update(ext4_extras(Path(mnt)))
            run(["sync"])
        finally:
            run(["veracrypt", "--text", "--dismount", str(container)])
    return tree


def mapped_device(container: Path) -> str:
    listing = run(["veracrypt", "--text", "--list"]).stdout
    for line in listing.splitlines():
        if str(container) in line:
            m = re.search(r"(/dev/mapper/\S+|/dev/loop\d+)", line)
            if m:
                return m.group(1)
    sys.exit(f"no mapped device for {container}:\n{listing}")


def build_ext4(out: Path):
    entries = {}

    c = out / "vc-aes-sha512-ext4.vc"
    c.unlink(missing_ok=True)
    vc_create(c, 64 * MIB, PASSWORD, "ext4")
    entries[c.stem] = {"params": {"filesystem": "ext4", "mkfs": "veracrypt default",
                                  "password": PASSWORD, "size_mib": 64},
                       "tree": vc_populate(c, PASSWORD)}

    # A 1 KiB block size and no journal, made by hand inside the mapped
    # volume: options VeraCrypt's own mkfs call doesn't use. (inline_data is
    # left out: the reader refuses it by name, which the in-process gate
    # covers.)
    c2 = out / "vc-aes-sha512-ext4-1k.vc"
    c2.unlink(missing_ok=True)
    vc_create(c2, 32 * MIB, PASSWORD, "none")
    with tempfile.TemporaryDirectory() as mnt:
        vc(["--filesystem", "none", "--protect-hidden", "no", str(c2)], PASSWORD)
        dev = mapped_device(c2)
        try:
            run(["mkfs.ext4", "-q", "-b", "1024", "-O", "^has_journal", dev])
            run(["mount", dev, mnt])
            try:
                tree = make_plaintext_tree(Path(mnt))
                for i in range(20):
                    data = f"tiny {i}\n".encode()
                    (Path(mnt) / f"tiny-{i:02}.txt").write_bytes(data)
                    tree[f"tiny-{i:02}.txt"] = hashlib.sha256(data).hexdigest()
                run(["sync"])
            finally:
                run(["umount", mnt])
        finally:
            run(["veracrypt", "--text", "--dismount", str(c2)])
    entries[c2.stem] = {"params": {"filesystem": "ext4", "mkfs": "-b 1024 -O ^has_journal",
                                   "password": PASSWORD, "size_mib": 32},
                        "tree": tree}

    c3 = out / "vc-aes-sha512-fat-outer-ext4-hidden.vc"
    c3.unlink(missing_ok=True)
    vc_create(c3, 64 * MIB, PASSWORD, "FAT")
    outer_tree = vc_populate(c3, PASSWORD, extras=False)
    vc_create(c3, 24 * MIB, HIDDEN_PASSWORD, "ext4", volume_type="hidden")
    entries[c3.stem] = {"params": {"filesystem": "FAT outer, ext4 hidden",
                                   "password": PASSWORD, "size_mib": 64},
                        "tree": outer_tree,
                        "hidden_password": HIDDEN_PASSWORD,
                        "hidden_tree": vc_populate(c3, HIDDEN_PASSWORD)}

    for name, e in entries.items():
        e["container_sha256"] = sha256(out / f"{name}.vc")
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--only", choices=["truecrypt", "ext4"])
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root (mounting needs it)")
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = {}
    if args.only in (None, "truecrypt"):
        if shutil.which("truecrypt") is None:
            sys.exit("truecrypt (7.1a console) not on PATH")
        version = run(["truecrypt", "--text", "--version"]).stdout.strip()
        manifest["truecrypt_version"] = version
        manifest["truecrypt"] = build_tc(args.out)
    if args.only in (None, "ext4"):
        if shutil.which("veracrypt") is None:
            sys.exit("veracrypt not on PATH")
        manifest["veracrypt_version"] = run(["veracrypt", "--text", "--version"]).stdout.strip()
        manifest["ext4"] = build_ext4(args.out)
    path = args.out / "manifest-rc5.json"
    old = json.loads(path.read_text()) if path.exists() else {}
    old.update(manifest)
    path.write_text(json.dumps(old, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
