# FNE-AN00 8.0.0.202 offset kit

Tooling used to add `5.4.289-qgki-gc5b795a0f72f` (HONOR 70 / FNE-AN00,
MagicOS 8.0.0.202) to the FNE offset table. Everything here runs offline on a
PC — only the boot image is needed, no root and no device access.

The entry produced by these tools lives in
`root/exploit/src/devices/fne/offsets.h`; the full write-up is
`docs/FNE-AN00-8.0.0.202.md`.

## Pipeline

```bash
# 1) boot.img -> raw ARM64 Image
python extract_kernel.py boot202.img work

# 2) Image -> kallsyms (see root/exploit/tools/kallsyms/GUIDE.md)
#    vmlinux-to-elf + llvm-nm, or kallsyms_finder --bit-size 64
#    -> work/kernel.kallsyms   (176,143 symbols on this build)

# 3) compare against a known-good table for the same SoC family
python cmp_offsets.py root/ksu-late-load/fne_syms.txt work/kernel.kallsyms

# 4) write the entry into offsets.h, then prove it against the real kallsyms
python verify_entry.py root/exploit/src/devices/fne/offsets.h work/kernel.kallsyms
#    -> 29 field(s) checked, 0 problem(s)

# 5) optional: patch the prebuilt binary instead of rebuilding with the NDK
python patch_table.py root/exploit/src/devices/fne/offsets.h \
    root/exploit/ghostlock ghostlock_202
```

`verify_entry.py` must report **29/29 OK** before the entry is trusted: one
wrong slot is an arbitrary kernel write to the wrong address.

## Notes

- `cmp_offsets.py` takes an optional third argument for
  `kimage_text_base` (default `0xffffffc010080000`, i.e. VA_BITS=39 with the
  FNE 5.4 layout).
- `patch_table.py` locates the entry by its 6-word signature
  (`kernel_phys_load`, `phys_offset`, `off_init_task`, `off_init_cred`,
  `off_init_uts_ns`, `off_empty_zero_page`), verifies every slot against
  `offsets.h`, then rewrites only the differing symbols. The kernel release
  string is renamed with an equal-length string, so the RELA-provided
  `.uname_r` pointer stays valid.
- `patch_table.py` output for the 8.0.0.202 entry is byte-identical to the
  binary that was validated on hardware:
  `sha256 fa1f494ead1000d59a8f5c44714da7cf64c422b0d1d26313977f51e0668976c5`.
