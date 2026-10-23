#!/usr/bin/env python3
"""Write small TrueCrypt 7.x-format containers with an implementation that
shares no code with the core (OpenSSL PBKDF2 and AES-XTS through Python's
hashlib and `cryptography`), so the TrueCrypt-mode tests have something to
open before real TrueCrypt 7.1a fixtures exist. AES only: OpenSSL has no
Serpent or Twofish. The real corpus (create_rc5_fixtures.py) covers the
cascades and is the release gate.

Usage:
  synth_truecrypt.py --out DIR

Needs mkfs.fat and mtools (mcopy) to build the FAT inside.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from create_fixtures import make_plaintext_tree  # noqa: E402

KIB = 1024
MIB = 1024 * KIB
GROUP = 128 * KIB  # header group: normal header slot + hidden header slot
ITER = {"ripemd160": 2000, "sha512": 1000}


def det_bytes(seed: str, n: int) -> bytes:
    out, block = b"", seed.encode()
    while len(out) < n:
        block = hashlib.sha512(block).digest()
        out += block
    return out[:n]


def xts(key64: bytes, unit: int, data: bytes, encrypt=True) -> bytes:
    c = Cipher(algorithms.AES(key64), modes.XTS(unit.to_bytes(16, "little")))
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


def header(master: bytes, volume_size: int, area_start: int, area_size: int,
           hidden_size: int, version=5, program=0x0700) -> bytes:
    h = bytearray(448)
    h[0:4] = b"TRUE"
    struct.pack_into(">HH", h, 4, version, program)
    h[192:448] = master
    struct.pack_into(">I", h, 8, zlib.crc32(bytes(h[192:448])))
    struct.pack_into(">QQQQ", h, 28, hidden_size, volume_size, area_start, area_size)
    struct.pack_into(">I", h, 60, 0)
    if version >= 5:
        struct.pack_into(">I", h, 64, 512)
    struct.pack_into(">I", h, 188, zlib.crc32(bytes(h[0:188])))
    return bytes(h)


def header_region(seed: str, prf: str, password: bytes, plain: bytes) -> bytes:
    salt = det_bytes(seed + "/salt", 64)
    key = hashlib.pbkdf2_hmac(prf, password, salt, ITER[prf], 64)
    region = salt + xts(key, 0, plain)
    return region + det_bytes(seed + "/pad", 64 * KIB - len(region))


def fat_image(size: int) -> tuple[bytes, dict]:
    with tempfile.TemporaryDirectory() as d:
        img = Path(d) / "fat.img"
        with open(img, "wb") as f:
            f.truncate(size)
        subprocess.run(["mkfs.fat", "-n", "TCFIXTURE", str(img)], check=True,
                       capture_output=True)
        tree_root = Path(d) / "tree"
        tree_root.mkdir()
        tree = make_plaintext_tree(tree_root)
        env = dict(os.environ, MTOOLS_SKIP_CHECK="1")
        for entry in sorted(tree_root.iterdir()):
            subprocess.run(["mcopy", "-s", "-i", str(img), str(entry), "::/"],
                           check=True, env=env, capture_output=True)
        return img.read_bytes(), tree


def encrypt_area(master: bytes, start: int, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 512):
        out += xts(master[:64], (start + i) // 512, data[i:i + 512])
    return bytes(out)


def build(out: Path, name: str, prf: str, password: bytes, size: int,
          hidden: tuple[bytes, int] | None = None, version=5, program=0x0700):
    """One container: header group, data, backup header group. With `hidden`
    (password, size), a hidden volume sits at the end of the outer data area
    with its header in the hidden slot, as TrueCrypt lays it out."""
    area_start, area_size = GROUP, size - 2 * GROUP
    master = det_bytes(name + "/master", 256)
    data, tree = fat_image(area_size)
    body = bytearray(size)
    plain = header(master, area_size, area_start, area_size, 0, version, program)
    body[0:64 * KIB] = header_region(name + "/primary", prf, password, plain)
    body[64 * KIB:GROUP] = det_bytes(name + "/hidden-slot", 64 * KIB)
    body[area_start:area_start + area_size] = encrypt_area(master, area_start, data)
    body[size - GROUP:size - 64 * KIB] = header_region(name + "/backup", prf, password, plain)
    body[size - 64 * KIB:] = det_bytes(name + "/backup-hidden-slot", 64 * KIB)
    entry = {"prf": prf, "password": password.decode(), "size": size,
             "header_version": version, "program_version": program, "tree": tree}
    if hidden:
        hpw, hsize = hidden
        hstart = size - GROUP - hsize
        hmaster = det_bytes(name + "/hidden-master", 256)
        hdata, htree = fat_image(hsize)
        hplain = header(hmaster, hsize, hstart, hsize, hsize, version, program)
        body[64 * KIB:GROUP] = header_region(name + "/hidden", prf, hpw, hplain)
        body[hstart:hstart + hsize] = encrypt_area(hmaster, hstart, hdata)
        body[size - 64 * KIB:] = header_region(name + "/backup-hidden", prf, hpw, hplain)
        entry["hidden_password"] = hpw.decode()
        entry["hidden_tree"] = htree
    path = out / f"{name}.tc"
    path.write_bytes(bytes(body))
    entry["container_sha256"] = hashlib.sha256(body).hexdigest()
    return entry


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    pw = b"vaultpony-fixture"
    manifest = {
        "synth-tc-aes-ripemd160": build(args.out, "synth-tc-aes-ripemd160", "ripemd160", pw, 8 * MIB),
        "synth-tc-aes-sha512": build(args.out, "synth-tc-aes-sha512", "sha512", pw, 8 * MIB),
        "synth-tc6-aes-ripemd160": build(args.out, "synth-tc6-aes-ripemd160", "ripemd160", pw,
                                         8 * MIB, version=4, program=0x0600),
        "synth-tc-aes-ripemd160-hidden": build(
            args.out, "synth-tc-aes-ripemd160-hidden", "ripemd160", pw, 16 * MIB,
            hidden=(b"vaultpony-fixture-hidden", 4 * MIB)),
        "synth-tc5-aes-sha512": build(args.out, "synth-tc5-aes-sha512", "sha512", pw,
                                      8 * MIB, version=3, program=0x0500),
    }
    (args.out / "manifest-synth.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print("wrote", len(manifest), "containers")


if __name__ == "__main__":
    main()
