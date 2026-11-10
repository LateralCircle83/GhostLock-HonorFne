#!/usr/bin/env python3
"""Verify one OFFSETS_ENTRY block against a real kallsyms dump.

Usage: python verify_entry.py <offsets.h> <kallsyms> [uname] [kimage_text_base]

Reads the `OFFSETS_ENTRY("<uname>", ...)` block from offsets.h, recomputes every
field from the kallsyms symbol addresses as `addr - kimage_text_base (+addend)`,
and reports OK / MISMATCH per field.

This is the gate that must stay green (29 fields, 0 problems) before a new
device entry is trusted: a single wrong slot is an arbitrary kernel write to
the wrong address at exploit time.
"""
import re
import sys

DEFAULT_UNAME = "5.4.289-qgki-gc5b795a0f72f"
DEFAULT_BASE = 0xFFFFFFC010080000

# field -> (symbol, addend)
MAP = {
    "off_init_task": ("init_task", 0),
    "off_init_cred": ("init_cred", 0),
    "off_init_uts_ns": ("init_uts_ns", 0),
    "off_empty_zero_page": ("empty_zero_page", 0),
    "off_root_task_group": ("root_task_group", 0),
    "off_selinux_enforcing": ("selinux_state", 1),
    "off_sig_enforce": ("sig_enforce", 0),
    "off_kptr_restrict": ("kptr_restrict", 0),
    "off_selinux_blob_sizes": ("selinux_blob_sizes", 0),
    "off_security_hook_heads": ("security_hook_heads", 0),
    "off_kmalloc_caches": ("kmalloc_caches", 0),
    "off_anon_pipe_buf_ops": ("anon_pipe_buf_ops", 0),
    "off_ashmem_misc_fops": ("ashmem_misc", 0),
    "off_ashmem_fops": ("ashmem_fops", 0),
    "off_ashmem_ioctl": ("ashmem_ioctl", 0),
    "off_ashmem_compat_ioctl": ("ashmem_ioctl", 0),
    "off_ashmem_mmap": ("ashmem_mmap", 0),
    "off_ashmem_open": ("ashmem_open", 0),
    "off_ashmem_release": ("ashmem_release", 0),
    "off_ashmem_show_fdinfo": ("ashmem_show_fdinfo", 0),
    "off_configfs_read_iter": ("configfs_read_file", 0),
    "off_configfs_bin_write_iter": ("configfs_write_bin_file", 0),
    "off_copy_splice_read": ("default_file_splice_read", 0),
    "off_noop_llseek": ("noop_llseek", 0),
    "off_slide_nfulnl_logger": ("nfulnl_logger", 0),
    "off_slide_loggers_0_1": ("loggers", 0x10),
    "off_slide_boot_id": ("sysctl_bootid", 0),
    "off_system_unbound_wq": ("system_unbound_wq", 0),
    "off_call_usermodehelper_exec_work": ("call_usermodehelper_exec_work", 0),
}


def main(header, kallsyms, uname, base):
    syms = {}
    with open(kallsyms, "r", errors="replace") as f:
        for line in f:
            p = line.split()
            if len(p) < 3:
                continue
            try:
                a = int(p[0], 16)
            except ValueError:
                continue
            syms.setdefault(p[2].split("$")[0], a)

    text = open(header, encoding="utf-8", errors="replace").read()
    try:
        i = text.index('OFFSETS_ENTRY("%s"' % uname)
    except ValueError:
        sys.exit("entry for %s not found in %s" % (uname, header))
    end = text.index("\n),", i) + 3
    block = text[i:end]
    vals = {m.group(1): int(m.group(2), 16)
            for m in re.finditer(r"\.(off_[a-z0-9_]+)\s*=\s*0x([0-9A-Fa-f]+)", block)}

    bad = 0
    for field, (sym, add) in MAP.items():
        want = vals.get(field)
        addr = syms.get(sym)
        if want is None:
            print("%-38s MISSING in header" % field)
            bad += 1
            continue
        if addr is None:
            print("%-38s symbol %s not found" % (field, sym))
            bad += 1
            continue
        exp = addr - base + add
        ok = want == exp
        print("%-38s hdr=%-11s kallsyms=%-11s %s"
              % (field, hex(want), hex(exp), "OK" if ok else "MISMATCH"))
        if not ok:
            bad += 1
    print("\n%d field(s) checked, %d problem(s)" % (len(MAP), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2],
                  sys.argv[3] if len(sys.argv) > 3 else DEFAULT_UNAME,
                  int(sys.argv[4], 0) if len(sys.argv) > 4 else DEFAULT_BASE))
