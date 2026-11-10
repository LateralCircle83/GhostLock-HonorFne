#!/usr/bin/env python3
"""Rewrite one kernel_offsets entry inside the prebuilt `ghostlock` binary.

Usage: python patch_table.py <offsets.h> <src_binary> <out_binary> [from] [to]

`from` / `to` are kernel release strings; the defaults rewrite the
8.0.0.221 entry (5.4.289-qgki-gf6cb1f712a6e) into the values of the
8.0.0.202 entry (5.4.289-qgki-gc5b795a0f72f), producing a binary that runs on
an 8.0.0.202 unit without an NDK toolchain rebuild.

How it works: `known_offsets[]` is static data (.data.rel.ro), one 8-byte word
per field. The source entry is located by its distinctive 6-word signature
(kernel_phys_load, phys_offset, off_init_task, off_init_cred, off_init_uts_ns,
off_empty_zero_page), every slot is checked against offsets.h before touching
anything, then the differing symbols are rewritten in place and the kernel
release string is renamed with an equal-length string (so the RELA-provided
.uname_r pointer stays valid).

The script refuses to write unless the signature matches exactly once and the
pre-patch entry matches offsets.h word for word.
"""
import re
import struct
import sys

DEFAULT_FROM = "5.4.289-qgki-gf6cb1f712a6e"
DEFAULT_TO = "5.4.289-qgki-gc5b795a0f72f"

# u64 field order exactly as `struct kernel_offsets` declares it (after uname_r).
U64_FIELDS = [
    "kernel_phys_load", "phys_offset",
    "off_init_task", "off_init_cred", "off_init_uts_ns", "off_empty_zero_page",
    "off_root_task_group", "off_selinux_enforcing", "off_sig_enforce",
    "off_kptr_restrict",
    "off_selinux_blob_sizes", "off_security_hook_heads", "off_kmalloc_caches",
    "off_anon_pipe_buf_ops", "off_ashmem_misc_fops", "off_ashmem_fops",
    "off_ashmem_ioctl", "off_ashmem_compat_ioctl", "off_ashmem_mmap",
    "off_ashmem_open", "off_ashmem_release", "off_ashmem_show_fdinfo",
    "off_configfs_read_iter", "off_configfs_bin_write_iter",
    "off_copy_splice_read", "off_noop_llseek", "off_cap_capable_active",
    "off_slide_nfulnl_logger", "off_slide_loggers_0_1", "off_slide_boot_id",
    "off_system_unbound_wq", "off_call_usermodehelper_exec_work",
]
# uname_r is the first word; the u64 fields follow it.
SLOT = {name: 0x08 + 8 * i for i, name in enumerate(U64_FIELDS)}

SIGNATURE_FIELDS = ("kernel_phys_load", "phys_offset", "off_init_task",
                    "off_init_cred", "off_init_uts_ns", "off_empty_zero_page")


def parse_entry(text, uname):
    try:
        i = text.index('OFFSETS_ENTRY("%s"' % uname)
    except ValueError:
        sys.exit("entry for %s not found in offsets.h" % uname)
    end = text.index("\n),", i) + 3
    block = text[i:end]
    # Any field, not just off_*: kernel_phys_load/phys_offset take part in the
    # signature and are written without the off_ prefix.
    vals = {m.group(1): int(m.group(2), 16)
            for m in re.finditer(r"\.([a-z0-9_]+)\s*=\s*0x([0-9A-Fa-f]+)", block)}
    # Kernel release strings in this table are 26 chars; an in-place rename
    # keeps the .uname_r pointer (and the strcmp match) valid.
    if len(uname) != 26:
        sys.exit("uname %r is not 26 chars" % uname)
    return vals


def main(header, src, out, from_uname, to_uname):
    text = open(header, encoding="utf-8", errors="replace").read()
    v_from = parse_entry(text, from_uname)
    v_to = parse_entry(text, to_uname)
    if len(from_uname) != len(to_uname):
        sys.exit("kernel release strings must have equal length")

    data = bytearray(open(src, "rb").read())
    sig = struct.pack("<6Q", *[v_from.get(f, 0) for f in SIGNATURE_FIELDS])

    hits, start = [], 0
    while True:
        p = data.find(sig, start)
        if p < 0:
            break
        hits.append(p)
        start = p + 1
    print("signature hits:", [hex(h) for h in hits])
    if len(hits) != 1:
        sys.exit("expected exactly one signature hit, got %d" % len(hits))

    phys = hits[0]                 # kernel_phys_load sits at entry + 0x08
    entry = phys - 0x08
    print("entry base   :", hex(entry))

    uname_ptr = struct.unpack_from("<Q", data, entry)[0]
    print("uname_r slot :", hex(uname_ptr), "(0 => RELA-controlled, pointer lives in .rela.dyn)")

    str_off = data.find(from_uname.encode())
    print("source string:", hex(str_off) if str_off >= 0 else "NOT FOUND")
    if str_off < 0 or data.find(from_uname.encode(), str_off + 1) >= 0:
        sys.exit("the source kernel release string must occur exactly once")

    bad = 0
    for name, off in SLOT.items():
        exp = v_from.get(name)
        if exp is None:
            continue
        got = struct.unpack_from("<Q", data, entry + off)[0]
        if got != exp:
            print("  mismatch %-34s bin=%s hdr=%s" % (name, hex(got), hex(exp)))
            bad += 1
    print("pre-patch mismatches:", bad)
    if bad:
        sys.exit("binary entry does not match the header's source entry")

    changed = 0
    for name, off in SLOT.items():
        if name not in v_to:
            continue
        old = struct.unpack_from("<Q", data, entry + off)[0]
        new = v_to[name]
        if old != new:
            struct.pack_into("<Q", data, entry + off, new)
            changed += 1
            print("  %-34s %s -> %s" % (name, hex(old), hex(new)))
    data[str_off:str_off + len(from_uname)] = to_uname.encode()
    print("changed %d symbol slots + kernel release string" % changed)
    open(out, "wb").write(data)

    chk = open(out, "rb").read()
    problems = sum(1 for name, off in SLOT.items()
                   if name in v_to
                   and struct.unpack_from("<Q", chk, entry + off)[0] != v_to[name])
    print("verify problems:", problems)
    print("uname now:", chk[str_off:str_off + len(to_uname)].decode())
    return 1 if problems else 0


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3],
                  sys.argv[4] if len(sys.argv) > 4 else DEFAULT_FROM,
                  sys.argv[5] if len(sys.argv) > 5 else DEFAULT_TO))
