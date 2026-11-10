#!/usr/bin/env python3
"""Carve the kernel Image out of an Android boot.img.

Usage: python extract_kernel.py <boot.img> <out_dir>

Handles the boot header v3 layout used by the HONOR FNE-AN00 builds:
    offset 0x00  "ANDROID!" magic
    offset 0x08  kernel_size    (u32)
    offset 0x0C  ramdisk_size   (u32)
    offset 0x14  kernel_offset  (u32, pages of 4096)

Writes <out_dir>/kernel (raw ARM64 Image, uncompressed on these builds).
"""
import os
import struct
import sys


def main(src, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    with open(src, "rb") as f:
        d = f.read(4096)
        if d[:8] != b"ANDROID!":
            sys.exit("not a boot.img (magic=%r)" % d[:8])
        kernel_size, ramdisk_size = struct.unpack("<II", d[8:16])
        page = 4096
        koff = (struct.unpack("<I", d[20:24])[0] + page - 1) // page * page
        print("kernel_size=%d ramdisk_size=%d kernel_off=%d" % (kernel_size, ramdisk_size, koff))

        f.seek(koff)
        data = f.read(kernel_size)
        if len(data) != kernel_size:
            sys.exit("short read: %d of %d" % (len(data), kernel_size))
        kp = os.path.join(out_dir, "kernel")
        with open(kp, "wb") as o:
            o.write(data)
        print("wrote %s (%d bytes) head=%s arm64_magic=%r"
              % (kp, len(data), data[:4].hex(), data[0x38:0x3C]))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
