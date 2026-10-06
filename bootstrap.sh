#!/data/data/com.termux/files/usr/bin/bash
# termux-router 引导脚本：一条命令从零到跑起来。
#
# 做这些事（每一步都会告诉你结果，不会默默跳过）：
#   1. 确认是在 Termux 原生环境（PRoot 里直接拒绝，并说明为什么）
#   2. 装依赖：git / python / tsu
#   3. 拉取或更新代码
#   4. 安装 trm 命令、生成配置
#   5. 检查 root 是否真的可用
#   6. 尽力打开系统热点；开不了就**等你手动开**并轮询等待
#   7. 启动服务（下发 NAT + DHCP/DNS + 面板）
#   8. 打印状态与免密面板链接
#
# 用法：
#   bash bootstrap.sh              # 正常引导
#   bash bootstrap.sh --dry-run    # 只打印将要做什么，什么都不执行
#
# 一条命令完成（推荐这种，不用 curl | bash）：
#   pkg install -y git python tsu && \
#   git clone --depth 1 https://github.com/zhuzijiang/termux-router.git ~/termux-router && \
#   bash ~/termux-router/bootstrap.sh

set -eu

REPO_URL=${TRM_REPO_URL:-https://github.com/zhuzijiang/termux-router.git}
REPO_DIR=${TRM_REPO_DIR:-$HOME/termux-router}
PREFIX_DIR=${PREFIX:-/data/data/com.termux/files/usr}
HOTSPOT_WAIT=${TRM_HOTSPOT_WAIT:-90}
DRY_RUN=0

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数: $arg" >&2; exit 2 ;;
  esac
done

# ------------------------------------------------------------------ 输出
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_OK=$(printf '\033[32m'); C_WARN=$(printf '\033[33m'); C_BAD=$(printf '\033[31m')
  C_DIM=$(printf '\033[2m'); C_BOLD=$(printf '\033[1m'); C_END=$(printf '\033[0m')
else
  C_OK=''; C_WARN=''; C_BAD=''; C_DIM=''; C_BOLD=''; C_END=''
fi
ok()   { printf '%s✓%s %s\n' "$C_OK" "$C_END" "$1"; }
warn() { printf '%s!%s %s\n' "$C_WARN" "$C_END" "$1"; }
bad()  { printf '%s✗%s %s\n' "$C_BAD" "$C_END" "$1"; }
dim()  { printf '%s  %s%s\n' "$C_DIM" "$1" "$C_END"; }
step() { printf '\n%s==> %s%s\n' "$C_BOLD" "$1" "$C_END"; }

# ------------------------------------------------------------- dry-run 预览
if [ "$DRY_RUN" -eq 1 ]; then
  cat <<EOF
${C_BOLD}bootstrap.sh 将要执行的步骤（dry-run，不做任何改动）${C_END}

  1. 检查环境：必须是 Termux 原生 shell（PRoot 容器会被拒绝）
  2. pkg install -y git python tsu          （只装缺的）
  3. 拉取/更新代码到 $REPO_DIR
  4. bash $REPO_DIR/install.sh --yes         （装 trm 命令 + 生成配置）
  5. sudo id                                  （确认 root 真的可用）
  6. 尝试 trm hotspot start
     失败则提示你手动打开热点，并轮询等待接口出现，最多 ${HOTSPOT_WAIT} 秒
  7. 启动服务：sudo trm up -d
  8. sudo trm status && trm token             （状态 + 免密面板链接）

  其他环境变量：
    TRM_REPO_URL      换仓库地址
    TRM_REPO_DIR      换本地目录（默认 ~/termux-router）
    TRM_HOTSPOT_WAIT  热点等待秒数（默认 90，设 0 表示不等待）

EOF
  exit 0
fi

# --------------------------------------------------------------- 1. 环境
step "1/8 检查环境"

case "$PREFIX_DIR" in
  *com.termux*) ;;
  *)
    bad "这看起来不是 Termux（PREFIX=$PREFIX_DIR）"
    dim "本项目需要 Android + Termux 才能访问系统命令与内核 netfilter。"
    exit 1
    ;;
esac

if [ -n "${PROOT_L2S_DIR:-}" ] || [ "${container:-}" = "proot-distro" ]; then
  bad "当前在 PRoot 容器里，无法作为路由器工作"
  dim "PRoot 只是用户态系统调用翻译，碰不到 Android 内核的 netfilter；"
  dim "而且它会谎报 uid=0，让很多 root 检测代码误判。"
  dim "请敲 exit 退出容器，在 Termux 原生 shell 里重新运行本脚本。"
  exit 1
fi
ok "Termux 原生环境"

if ! command -v pkg >/dev/null 2>&1; then
  bad "找不到 pkg，这不像标准的 Termux 环境"
  exit 1
fi

# 安全护栏：后面可能会 rm -rf $REPO_DIR，先确认它确实在 $HOME 底下。
# 放在所有动作之前，参数不对就立刻停下。
case "$REPO_DIR" in
  "$HOME"/*) ;;
  *)
    bad "TRM_REPO_DIR 必须在 \$HOME 目录内（当前：$REPO_DIR）"
    exit 1
    ;;
esac

# --------------------------------------------------------------- 2. 依赖
step "2/8 安装依赖（只装缺的）"
missing=""
for p in git python tsu; do
  command -v "$p" >/dev/null 2>&1 || missing="$missing $p"
done
if [ -n "$missing" ]; then
  dim "需要安装:$missing"
  # shellcheck disable=SC2086
  pkg install -y $missing || { bad "依赖安装失败，请手动执行：pkg install -y$missing"; exit 1; }
  ok "依赖安装完成"
else
  ok "git / python / tsu 都已存在"
fi
command -v python3 >/dev/null 2>&1 || { bad "python3 不可用"; exit 1; }

# --------------------------------------------------------------- 3. 代码
step "3/8 拉取代码"
if [ -d "$REPO_DIR/.git" ]; then
  dim "已存在 $REPO_DIR，尝试更新"
  if (cd "$REPO_DIR" && git pull --ff-only --quiet); then
    ok "已更新到最新"
  else
    warn "更新失败（可能本地有改动），继续使用当前代码"
  fi
else
  [ -e "$REPO_DIR" ] && rm -rf "$REPO_DIR"
  if ! git clone --depth 1 --quiet "$REPO_URL" "$REPO_DIR"; then
    bad "clone 失败，检查网络：$REPO_URL"
    exit 1
  fi
  ok "已克隆到 $REPO_DIR"
fi

# --------------------------------------------------------------- 4. 安装
step "4/8 安装 trm 命令"
if ! bash "$REPO_DIR/install.sh" --yes > /tmp/trm_bootstrap_install.log 2>&1; then
  bad "安装失败，最后 20 行日志："
  tail -20 /tmp/trm_bootstrap_install.log
  exit 1
fi

# 决定用哪个入口调用 trm：PATH 里的，或直接调仓库里的脚本
TRM=$(command -v trm || true)
if [ -n "$TRM" ]; then
  ok "trm 命令就绪：$TRM"
else
  TRM="$REPO_DIR/bin/trm"
  chmod +x "$TRM" 2>/dev/null || true
  warn "trm 还没进 PATH，本次直接用 $TRM"
fi
run_trm() { "$TRM" "$@"; }

# --------------------------------------------------------------- 5. root
step "5/8 检查 root"
ROOT_OK=0
if command -v sudo >/dev/null 2>&1 && sudo -n id >/dev/null 2>&1; then
  ROOT_OK=1
  ok "root 可用（sudo），uid=$(sudo id -u)"
elif command -v tsu >/dev/null 2>&1 && tsu -c id >/dev/null 2>&1; then
  ROOT_OK=1
  ok "root 可用（tsu）"
fi

if [ "$ROOT_OK" -eq 1 ]; then
  run_priv() { sudo "$TRM" "$@"; }
else
  run_priv() { "$TRM" "$@"; }
  warn "拿不到 root —— 将以「监控模式」运行"
  dim "监控模式：面板可用、能看到接口与状态，但没有转发 / NAT / DHCP / DNS / 限速。"
  dim "要变成真路由器：用 KernelSU / Magisk 获取 root（并 pkg install tsu），然后重跑本脚本。"
  if command -v sudo >/dev/null 2>&1; then
    dim "（sudo 存在但执行失败：可能是授权弹窗被拒，或设备其实没有 root）"
  fi
fi

# --------------------------------------------------------------- 6. 热点
step "6/8 打开系统热点"

# 不同 ROM 的热点接口名差别很大，按常见前缀匹配
hotspot_iface() {
  ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' \
    | grep -E '^(ap|softap|swlan|wlan1|wlan2)' | head -1 || true
}

IFACE=""
if [ "$ROOT_OK" -eq 0 ]; then
  warn "没有 root，无法用命令开热点"
  dim "请手动打开：设置 → 连接与共享 → 便携式热点"
else
  IFACE=$(hotspot_iface)
  if [ -z "$IFACE" ]; then
    dim "尝试用命令打开热点…"
    run_priv hotspot start >/dev/null 2>&1 || true
    waited=0
    while [ "$waited" -lt "$HOTSPOT_WAIT" ]; do
      IFACE=$(hotspot_iface)
      [ -n "$IFACE" ] && break
      if [ "$waited" -eq 0 ]; then
        warn "自动开热点没成功（各家 ROM 命令不同）。请现在手动打开："
        dim "设置 → 连接与共享 → 便携式热点 → 打开"
        printf '%s  正在等待热点接口出现，最多 %s 秒，Ctrl+C 可放弃…%s' \
          "$C_DIM" "$HOTSPOT_WAIT" "$C_END"
      fi
      sleep 3
      waited=$((waited + 3))
      printf '.'
    done
    [ "$HOTSPOT_WAIT" -gt 0 ] && printf '\n'
  fi
fi

if [ -n "$IFACE" ]; then
  ok "热点接口：$IFACE"
  # 把接口名写进配置，避免下次再靠猜
  run_trm config set lan.iface "$IFACE" >/dev/null 2>&1 || true
else
  warn "没检测到热点接口"
  dim "此时数据面会被拒绝下发 —— 这是刻意的：iptables 不校验接口名，"
  dim "给不存在的接口下规则会“成功”但永远匹配不到流量，表现为“规则都在却不通”。"
  dim "热点开好后重跑一次即可：sudo trm up -d"
fi

# --------------------------------------------------------------- 7. 启动
step "7/8 启动服务"
run_priv up -d || warn "启动过程中有报错，看下面的状态与日志"
sleep 2

# --------------------------------------------------------------- 8. 结果
step "8/8 结果"
run_priv status || true

printf '\n'
run_trm token | sed 's/^/  /'

cat <<EOF

${C_BOLD}下一步${C_END}
  • 看谁在连：        ${C_DIM}sudo trm clients${C_END}
  • 给设备限速：      ${C_DIM}sudo trm limit <IP> 4096 1024${C_END}    （下行 4M / 上行 1M）
  • 拦截广告域名：    ${C_DIM}sudo trm dns block ads.example.com${C_END}
  • 停止并清理规则：  ${C_DIM}sudo trm down${C_END}
  • 出问题先看：      ${C_DIM}sudo trm doctor${C_END}  与  ${C_DIM}tail -50 ~/.trm/log/trm.log${C_END}

EOF

if [ -z "$IFACE" ]; then
  warn "热点还没就绪，数据面没有下发。开好热点后执行：sudo trm up -d"
  exit 2
fi
ok "全部完成"
