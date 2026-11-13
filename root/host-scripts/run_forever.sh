#!/bin/bash
# Outer loop: relaunch run_w2.sh until root lands. Unattended overnight grind.
#
# 2026-11-05 修复（run_root.command / run_root.bat 共用，macOS + Windows Git Bash）：
#   旧实现 `bash run_w2.sh 2>&1 | tee -a run_w2_driver.log` 会永久卡死。
#   tee 必须读到管道 EOF 才退出，而 EOF 要求「所有持有写端的进程」全部退出；
#   run_w2.sh 里 run_to() 用 & 起的 `tail -f` 与看门狗子进程都继承了该写端，
#   只要残留一个，管道就永不关闭 —— 实测 root 已成功后日志停在 FINAL 行，
#   "OUTER LOOP: SUCCESS" 永不落盘，run_root.command 因此走不到
#   wait_ksu.sh / install_managers.sh（root 成功但三件套没装）。
#   现改为：子进程直接 >> 日志文件，父进程按行号增量读取回显。
#   全程无管道、无长命 tail，结构上不可能再因残留 fd 卡住。
#
# NOTE: the driver log is APPENDED across invocations, so success detection
# must only look at lines written by the CURRENT run_w2.sh invocation.
cd "$(dirname "$0")" || exit 1
LOG=run_w2_driver.log
touch "$LOG"

DRAIN_AT=0
KSU_MISS=0
# 打印 (DRAIN_AT, 当前末行] 的增量并推进 DRAIN_AT。
# 用一次性 tail -n +N（BSD/GNU 同语义），不驻留任何跟随进程。
drain() {
    local total
    total=$(wc -l < "$LOG" 2>/dev/null | tr -d ' ')
    case "$total" in ''|*[!0-9]*) total=$DRAIN_AT ;; esac
    if [ "$total" -gt "$DRAIN_AT" ]; then
        tail -n "+$((DRAIN_AT + 1))" "$LOG" | head -n $((total - DRAIN_AT))
        DRAIN_AT=$total
    fi
}

while true; do
  MARK=$(wc -l < "$LOG" | tr -d ' ')
  case "$MARK" in ''|*[!0-9]*) MARK=0 ;; esac
  DRAIN_AT=$MARK

  # 跨 boot 残留的 gl_w1/gl_w2 日志是假成功的根源（2026-11-12 实测），每轮先删。
  adb shell "rm -f /data/local/tmp/gl_w1.log /data/local/tmp/gl_w2.log" >/dev/null 2>&1
  # 子进程直接写日志（无管道）；父进程轮询增量回显
  bash run_w2.sh >> "$LOG" 2>&1 &
  RPID=$!
  # jobs -pr 而非 kill -0：已退出但未被回收的僵尸不会被误判为存活，避免空转。
  while jobs -pr 2>/dev/null | grep -qx "$RPID"; do
    drain
    sleep 1
  done
  wait "$RPID" 2>/dev/null; RC=$?
  drain
  # 127 = run_w2.sh 顶部"bash 里没有 adb"的快速失败。继续重启只会无限空转，
  # 直接把原因摆到屏幕/日志上再停。
  if [ "$RC" = "127" ]; then
    echo "=== OUTER LOOP: FATAL rc=127 (adb not found in this bash) - stopping ===" | tee -a "$LOG"
    break
  fi

  # rc=3 = W1/W2 拿到了 child is root，但 KernelSU late-load 没完成（su 不可用）。
  # 这不是「成功」，重启后重跑一轮（最多 3 次），避免把 root-no-ksu 当成功。
  if [ "$RC" = "3" ]; then
    KSU_MISS=$((KSU_MISS + 1))
    if [ "$KSU_MISS" -le 3 ]; then
      echo "=== OUTER LOOP: root-no-ksu rc=3, reboot + retry ($KSU_MISS/3) $(date +%T) ===" | tee -a "$LOG"
      adb reboot >/dev/null 2>&1
      sleep 45
      adb wait-for-device >/dev/null 2>&1
      sleep 30
      continue
    fi
    echo "=== OUTER LOOP: root-no-ksu x$KSU_MISS - stopping ===" | tee -a "$LOG"
    break
  fi

  # 用 grep -E（ERE）而非 "a\|b"：\| 是 GNU/BSD 的 BRE 扩展，toybox/busybox
  # 的 grep 不认（实测返回 1），会让成功判定永远不命中。
  if tail -n "+$((MARK + 1))" "$LOG" | grep -qE "W2 ROOT ACHIEVED|KSU READY"; then
    echo "=== OUTER LOOP: SUCCESS $(date +%T) - stopping ===" | tee -a "$LOG"
    break
  fi
  echo "=== OUTER LOOP: relaunching runner $(date +%T) ===" | tee -a "$LOG"
  sleep 10
done
