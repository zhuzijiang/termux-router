# termux-router 一键安装 / 卸载脚本（Termux 专用）
#
# 设计原则：
#   * 不装任何用不上的东西。默认只确认 python3 存在（Termux 自带仓库里的包）。
#   * 需要 root 才用得到的工具（iptables / iproute2）单独询问，
#     因为很多人根本没 root，装了也是浪费手机存储。
#   * 装完就告诉你"现在能做什么、还差什么"，不画饼。
#
# 用法：
#   bash install.sh                 # 交互安装
#   bash install.sh --yes           # 全部默认（不装 root 工具、不配置开机自启）
#   bash install.sh --with-root-tools
#   bash install.sh --boot          # 额外安装 Termux:Boot 开机自启
#   bash install.sh --uninstall     # 卸载

set -eu

REPO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX_DIR=${PREFIX:-/data/data/com.termux/files/usr}
BIN_DIR="$PREFIX_DIR/bin"
WRAPPER="$BIN_DIR/trm"
BOOT_DIR="$HOME/.termux/boot"
BOOT_SCRIPT="$BOOT_DIR/termux-router.sh"

ASSUME_YES=0
WITH_ROOT_TOOLS=0
WITH_BOOT=0
UNINSTALL=0

for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --with-root-tools) WITH_ROOT_TOOLS=1 ;;
    --boot) WITH_BOOT=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "未知参数: $arg" >&2; exit 2 ;;
  esac
done

# ----------------------------------------------------------------- 输出工具
has_color() { [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; }
c_ok()   { if has_color; then printf '\033[32m%s\033[0m\n' "$1"; else printf '%s\n' "$1"; fi; }
c_warn() { if has_color; then printf '\033[33m%s\033[0m\n' "$1"; else printf '%s\n' "$1"; fi; }
c_bad()  { if has_color; then printf '\033[31m%s\033[0m\n' "$1"; else printf '%s\n' "$1"; fi; }
c_dim()  { if has_color; then printf '\033[2m%s\033[0m\n' "$1"; else printf '%s\n' "$1"; fi; }
step()   { printf '\n==> %s\n' "$1"; }

ask() {
  # ask "问题" -> 返回 0 表示 yes
  [ "$ASSUME_YES" -eq 1 ] && return 0
  printf '%s [y/N] ' "$1"
  read -r answer || answer=""
  case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# 统一用 sh 显式执行，而不是依赖 bin/trm 的 shebang。
# 原因：bin/trm 的 shebang 是 Termux 专用绝对路径，在容器/CI 里跑不动；
# 而本脚本的所有自检都应该在任何 POSIX 环境里都能验证。
run_trm() {
  sh "$WRAPPER" "$@"
}

# --------------------------------------------------------------- 环境检查
check_environment() {
  step "检查运行环境"

  case "$PREFIX_DIR" in
    *com.termux*) : ;;
    *)
      c_bad "这看起来不是 Termux 环境（PREFIX=$PREFIX_DIR）。"
      echo "本项目必须运行在 Termux 里，原因："
      echo "  * 需要调用 Android 系统命令（cmd wifi / ip / iptables）"
      echo "  * PRoot / chroot 容器无法操作 Android 内核的 netfilter，装了 iptables 也没用"
      echo "如果你确实要装在别处，请设置 PREFIX 环境变量后重试。"
      exit 1
      ;;
  esac
  c_ok "Termux 环境正常（PREFIX=$PREFIX_DIR）"

  if [ -n "${PROOT_L2S_DIR:-}" ] || [ "${container:-}" = "proot-distro" ]; then
    c_warn "检测到当前处在 PRoot 容器中。"
    c_warn "在 PRoot 里本项目只能以『监控模式』运行：面板能看，但转发/NAT/限速/DHCP 都无法工作。"
    c_warn "要当真正的路由器，请在 Termux 原生 shell 里安装并运行（不是 proot-distro 里）。"
    if ! ask "仍然继续安装？"; then
      echo "已取消。"
      exit 0
    fi
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    c_warn "没有找到 python3。"
    if ask "现在用 pkg 安装 python？（约 40MB）"; then
      pkg update -y && pkg install -y python
    else
      c_bad "缺少 python3，无法继续。请先执行：pkg install python"
      exit 1
    fi
  fi

  py_version=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  c_ok "python3 $py_version"
  case "$py_version" in
    3.8|3.9|3.10|3.11|3.12|3.13|3.14|3.15) : ;;
    *) c_warn "python3 $py_version 未在测试矩阵里，理论上可用（本项目只用标准库）。" ;;
  esac

  # 本项目零第三方依赖，但仍然确认一下标准库完整
  if ! python3 -c "import socket, ssl, json, http.server" 2>/dev/null; then
    c_bad "python3 标准库不完整，请重装：pkg install python"
    exit 1
  fi
}

# ------------------------------------------------------------ 可选 root 工具
install_root_tools() {
  step "安装 root 专用工具（可选）"
  c_dim "iptables 用于 NAT 转发；iproute2 提供 tc（限速）。"
  c_dim "注意：Termux 自带的 /system/bin/iptables 通常已经够用，"
  c_dim "      但部分机型需要 Termux 自己这份 iptables 才能正常操作 netfilter。"

  if ! command -v pkg >/dev/null 2>&1; then
    c_warn "找不到 pkg，跳过。"
    return 0
  fi

  if [ "$WITH_ROOT_TOOLS" -eq 0 ]; then
    if [ "$ASSUME_YES" -eq 1 ]; then
      c_dim "非交互模式：跳过 root 工具（想装请加 --with-root-tools）"
      return 0
    fi
    if ! ask "是否安装 iptables 与 iproute2？"; then
      c_dim "已跳过。之后需要时执行：pkg install root-repo && pkg install iptables iproute2"
      return 0
    fi
  fi

  c_dim "正在添加 root-repo 并安装…"
  pkg install -y root-repo || c_warn "root-repo 安装失败，稍后可手动执行 pkg install root-repo"
  pkg install -y iptables iproute2 || c_warn "iptables/iproute2 安装失败，数据面可能不可用"
  c_ok "root 工具安装完成"
}

# ------------------------------------------------------------------- 安装
do_install() {
  check_environment

  step "检查依赖"
  if [ ! -f "$REPO_DIR/trm/cli.py" ]; then
    c_bad "在 $REPO_DIR 里找不到 trm/cli.py，请确认在仓库根目录运行本脚本。"
    exit 1
  fi
  c_ok "项目文件完整"

  if command -v python3 >/dev/null 2>&1; then
    install_root_tools
  fi

  step "安装 trm 命令"
  mkdir -p "$BIN_DIR"
  if [ -e "$WRAPPER" ] && [ ! -L "$WRAPPER" ]; then
    backup="$WRAPPER.bak.$(date +%s)"
    mv -- "$WRAPPER" "$backup"
    c_warn "已备份已存在的 $WRAPPER -> $backup"
  fi
  chmod +x "$REPO_DIR/bin/trm"
  ln -sfn "$REPO_DIR/bin/trm" "$WRAPPER"
  c_ok "已创建软链：$WRAPPER -> $REPO_DIR/bin/trm"

  step "生成默认配置"
  if [ -f "$HOME/.trm/config.json" ]; then
    c_dim "配置已存在，保留不动：$HOME/.trm/config.json"
  else
    run_trm config path >/dev/null
    run_trm doctor >/dev/null 2>&1 || true
    c_ok "已生成：$HOME/.trm/config.json"
  fi

  step "自检"
  run_trm doctor || true

  if [ "$WITH_BOOT" -eq 1 ]; then
    install_boot
  elif [ "$ASSUME_YES" -eq 1 ]; then
    c_dim "非交互模式：跳过开机自启（需要时用 --boot）"
  elif ask "是否配置开机自启（需要安装 Termux:Boot 应用）？"; then
    install_boot
  fi

  print_summary
}

install_boot() {
  step "配置开机自启"
  mkdir -p "$BOOT_DIR"
  cat > "$BOOT_SCRIPT" <<EOF
#!/data/data/com.termux/files/usr/bin/sh
# termux-router 开机自启（由 install.sh 生成）
# 需要安装 Termux:Boot 应用并至少手动启动它一次，否则脚本不会被执行。
termux-wake-lock 2>/dev/null || true
sleep 8                       # 等 Android 把网络准备好，太早启动会拿不到接口
exec "$WRAPPER" up -d >> "\$HOME/.trm/log/boot.log" 2>&1
EOF
  chmod +x "$BOOT_SCRIPT"
  c_ok "已写入：$BOOT_SCRIPT"
  c_warn "别忘了：安装 Termux:Boot 应用，并手动打开它一次（Android 的限制）。"
}

print_summary() {
  cat <<'EOF'

================================================================
 安装完成
================================================================
EOF
  printf ' 面板地址 : '
  run_trm token 2>/dev/null | sed -n 's/^面板地址 *//p' || echo "（运行 trm token 查看）"
  cat <<'EOF'

 接下来（有 root 的话）：
   sudo trm up -d          # 启动：下发 NAT 规则 + DHCP + DNS + 面板
   sudo trm status         # 看状态
   sudo trm clients        # 看谁在蹭网
   sudo trm down           # 停止并清理本项目下发的全部规则

 没有 root 也能用：
   trm up -d               # 以监控模式启动，只提供只读面板
   trm doctor              # 看还差什么才能变成真路由器
   trm rules --assume-root # 预览"如果有 root 会执行哪些 iptables 命令"

 注意：本项目只增删自己的 TRM_* 链，不会动你系统里别的防火墙规则。
EOF
}

# ------------------------------------------------------------------- 卸载
do_uninstall() {
  step "卸载 termux-router"
  if [ -L "$WRAPPER" ]; then
    rm -f -- "$WRAPPER"
    c_ok "已删除 $WRAPPER"
  elif [ -e "$WRAPPER" ]; then
    c_warn "$WRAPPER 不是软链，未删除（请自行确认）。"
  else
    c_dim "没有找到 $WRAPPER"
  fi

  if [ -f "$BOOT_SCRIPT" ]; then
    rm -f -- "$BOOT_SCRIPT"
    c_ok "已删除开机自启脚本"
  fi

  # 先停服务，避免留下规则
  if command -v trm >/dev/null 2>&1; then
    step "停止服务并清理规则"
    trm down || c_warn "停止失败（可能本来就没在运行）"
  fi

  cat <<'EOF'

用户数据保留在 ~/.trm（配置、租约、日志、拦截名单）。
确认不再需要后手动删除：
   rm -rf ~/.trm

EOF
  if ask "现在就删除 ~/.trm 吗？"; then
    rm -rf -- "$HOME/.trm"
    c_ok "已删除 ~/.trm"
  else
    c_dim "已保留 ~/.trm"
  fi
}

main() {
  echo "termux-router 安装脚本"
  echo "仓库目录: $REPO_DIR"
  if [ "$UNINSTALL" -eq 1 ]; then
    do_uninstall
  else
    do_install
  fi
}

main
