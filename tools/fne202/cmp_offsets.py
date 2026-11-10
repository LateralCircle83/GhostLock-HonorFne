#!/usr/bin/env python3
"""Diff the symbol offsets of two kernels, field by field.

Usage: python cmp_offsets.py <kallsyms_old> <kallsyms_new> [kimage_text_base]

Each input is a `nm`-style symbol list (`address type name`), e.g. the
.kallsyms file produced by kallsyms_finder for a boot.img kernel Image, or
root/ksu-late-load/fne_syms.txt for the 8.0.0.221 build.

Prints the offset of every field that `struct kernel_offsets` needs, for both
kernels, plus SAME / DIFF verdicts -- that is exactly the table used to write
the 8.0.0.202 entry in root/exploit/src/devices/fne/offsets.h.
"""
import sys

DEFAULT_BASE = 0xFFFFFFC010080000

# field -> symbol name; comments note the addend applied when writing offsets.h
SPEC = [
    ("off_init_task", "init_task"),
    ("off_init_cred", "init_cred"),
    ("off_init_uts_ns", "init_uts_ns"),
    ("off_empty_zero_page", "empty_zero_page"),
    ("off_root_task_group", "root_task_group"),
    ("off_selinux_enforcing", "selinux_state"),      # +1
    ("off_sig_enforce", "sig_enforce"),
    ("off_kptr_restrict", "kptr_restrict"),
    ("off_selinux_blob_sizes", "selinux_blob_sizes"),
    ("off_security_hook_heads", "security_hook_heads"),
    ("off_kmalloc_caches", "kmalloc_caches"),
    ("off_anon_pipe_buf_ops", "anon_pipe_buf_ops"),
    ("off_ashmem_misc_fops", "ashmem_misc"),
    ("off_ashmem_fops", "ashmem_fops"),
    ("off_ashmem_ioctl", "ashmem_ioctl"),
    ("off_ashmem_compat_ioctl", "ashmem_ioctl"),
    ("off_ashmem_mmap", "ashmem_mmap"),
    ("off_ashmem_open", "ashmem_open"),
    ("off_ashmem_release", "ashmem_release"),
    ("off_ashmem_show_fdinfo", "ashmem_show_fdinfo"),
    ("off_configfs_read_iter", "configfs_read_file"),
    ("off_configfs_bin_write_iter", "configfs_write_bin_file"),
    ("off_copy_splice_read", "default_file_splice_read"),
    ("off_noop_llseek", "noop_llseek"),
    ("off_slide_nfulnl_logger", "nfulnl_logger"),
    ("off_slide_loggers_0_1", "loggers"),            # +0x10
    ("off_slide_boot_id", "sysctl_bootid"),
    ("off_system_unbound_wq", "system_unbound_wq"),
    ("off_call_usermodehelper_exec_work", "call_usermodehelper_exec_work"),
]


def load(path):
    m = {}
    with open(path, "r", errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            try:
                a = int(parts[0], 16)
            except ValueError:
                continue
            name = parts[2].split("$")[0]
            if a and name not in m:
                m[name] = a
    return m


def main(old, new, base):
    a_old, a_new = load(old), load(new)
    print("syms old=%d new=%d base=%#x" % (len(a_old), len(a_new), base))
    print("%-38s %12s %12s %s" % ("field", "old", "new", "verdict"))

    same = diff = missing = 0
    for field, sym in SPEC:
        v1, v2 = a_old.get(sym), a_new.get(sym)
        if v1 is None or v2 is None:
            print("%-38s %12s %12s MISSING(%s)" % (
                field,
                "-" if v1 is None else hex(v1 - base),
                "-" if v2 is None else hex(v2 - base), sym))
            missing += 1
            continue
        o1, o2 = v1 - base, v2 - base
        if o1 == o2:
            same += 1
            verdict = "SAME"
        else:
            diff += 1
            verdict = "DIFF %+#x" % (o2 - o1)
        print("%-38s %12s %12s %s" % (field, hex(o1), hex(o2), verdict))
    print("\nsame=%d differ=%d missing=%d (of %d fields)"
          % (same, diff, missing, len(SPEC)))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2],
         int(sys.argv[3], 0) if len(sys.argv) > 3 else DEFAULT_BASE)
