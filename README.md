# termux-router

用 Termux 把一台 Android 手机变成**可管理的软路由**：内核级 NAT 转发 + 自建 DHCP/DNS + 按设备限速 + 手机浏览器就能用的管理面板。

**零第三方依赖**：只用 Python 标准库，不装 pip 包、不编译、不用 npm。常驻内存约 25–35 MB。

---

## ⚠️ 先读这一段，否则你会浪费时间

网上"手机变路由器"的教程很多，但绝大多数没有告诉你一件事：

> **真正的路由转发、NAT、限速，全部需要 root。**
> 没有 root 时，任何 App 都拿不到 `CAP_NET_ADMIN`，碰不到内核 netfilter。
> 这时所谓的"软路由"其实是 Android **系统自带的热点**在做 NAT，那个 App 只是在旁边看。

所以本项目的原则是：**能做什么就说什么，做不到的直接告诉你缺什么。**

| 能力 | 有 root | 无 root（监控模式） |
|---|---|---|
| 网页面板 / CLI | ✅ | ✅ |
| 能力体检（告诉我还差什么） | ✅ | ✅ |
| 接口流量统计 | ✅ | ⚠️ 取决于 `/sys/class/net` 权限 |
| WiFi/电池状态（Termux:API） | ✅ | ✅ |
| 内核 NAT 转发（`iptables`/`nft`） | ✅ | ❌ |
| 自建 DHCP 服务器（纯 Python） | ✅ | ❌ 端口 67 需要特权 |
| 自建 DNS 转发 + 缓存 + 广告拦截 | ✅ | ❌ 端口 53 需要特权 |
| 按设备限速（`tc` HTB） | ✅ | ❌ |
| 一键开关系统热点 | ✅ | ❌ 需 `TETHER_PRIVILEGED` |

无 root 时运行 `trm up` 不会装死，也不会假装成功 —— 它以**监控模式**启动面板，并在界面上明确列出"还差什么才能变成真路由器"。

### 🔴 另外：不要装在 PRoot 容器里

如果你用的是 `proot-distro` 装的 Ubuntu/Debian，**在里面装本项目是没有意义的**：

- PRoot 只是用户态系统调用翻译，无法操作 Android 内核的 netfilter
- 更坑的是，PRoot 里 `id -u` 会返回 `0`、`geteuid()` 也返回 `0`，**看起来像 root**
- 本项目专门处理了这个陷阱：读 `/proc/self/status` 拿真实 uid 来判定（见下文"真假 root"），并会把你引导到 Termux 原生环境

要在**Termux 原生 shell** 里运行（不是 `proot-distro login` 之后）。

---

## 安装

### 一行拉取

```bash
git clone https://github.com/zhuzijiang/termux-router.git
cd termux-router
bash install.sh
```

### 安装脚本做了什么

1. 检查是不是 Termux 环境（不是就直接拒绝，并说明原因）
2. 确认 `python3` 存在，缺了会问你要不要 `pkg install python`
3. **询问**是否安装 `iptables`/`iproute2`（没 root 的话装了也是浪费存储，默认不装）
4. 把 `bin/trm` 软链到 `$PREFIX/bin/trm`
5. 生成默认配置 `~/.trm/config.json`（权限 600）
6. 跑一遍自检，并打印"现在能做什么、还差什么"

可选参数：

```bash
bash install.sh --yes               # 全部默认（不装 root 工具、不配置自启）
bash install.sh --with-root-tools   # 直接装 iptables + iproute2
bash install.sh --boot              # 配置 Termux:Boot 开机自启
bash install.sh --uninstall         # 卸载
```

### 关于依赖：为什么几乎不用装东西

数据面优先使用**系统自带的**工具。以 Redmi / Android 17 为例，实测：

```
/system/bin/iptables   -> iptables v1.8.11 (legacy)
/system/bin/tc         -> 可用
/system/bin/ip         -> 可用
```

也就是说，**只要有 root，通常不需要额外安装任何软件包**就能跑起来。
`termux-api` 是可选的，装上后面板能多显示 WiFi 信号强度和电池状态。

---

## 快速开始

### 有 root

```bash
sudo trm up -d        # 启动：sysctl 转发 + NAT 规则 + DHCP + DNS + 面板
sudo trm status       # 查看状态
sudo trm clients      # 看谁在连我的热点、用了多少流量
sudo trm limit 192.168.43.55 4096 1024   # 给某台设备限速（下行 4M / 上行 1M）
sudo trm down         # 停止，并清理本项目下发的全部规则
```

**启动前先开系统热点**（本项目不抢 Android 的 AP 控制权，理由见下）：

```
设置 → 连接与共享 → 便携式热点 → 打开
```

> 如果热点命令在你的 ROM 上能用，也可以：`sudo trm hotspot start`

### 没有 root（监控模式）

```bash
trm up -d             # 以监控模式启动，只提供只读面板
trm doctor            # 体检：把"还差什么"逐条列出来
trm rules --assume-root   # 预览：如果有 root，会执行哪些 iptables 命令
```

`trm doctor` 的典型输出（本项目的开发机就是一台没 root 的 Redmi）：

```
工作模式             监控模式（无 root，只能看不能改）

还差什么才能作为真路由器工作：
  • 当前运行在 PRoot 容器里（container=proot-distro）。PRoot 只是用户态系统调用翻译，
    无法操作 Android 内核的 netfilter，装了 iptables 也没用。请直接在 Termux 里运行本项目。
  • 没有真正的 root（真实 uid=10408，run-as 身份是 Termux 应用）。
    需要 KernelSU / Magisk 提供 su，并用 tsu 或 sudo 提权运行。
```

### 打开管理面板

```bash
trm token             # 显示面板地址与访问令牌
```

默认监听 `127.0.0.1:8080`，也就是**只有手机本机能访问**。

想在局域网里用别的设备管理（比如你在电脑上看手机的面板）：

```bash
trm config set web.host 0.0.0.0
trm down && trm up -d      # 改监听地址需要重启
trm token                  # 拿到令牌
# 然后在电脑浏览器打开 http://<手机IP>:8080/ ，粘贴令牌
```

⚠️ 面板能改防火墙规则。**只要不是 `127.0.0.1`，就一定要用强令牌**，并且别在不可信网络里暴露。

### 开机自启

```bash
bash install.sh --boot
```

需要安装 **Termux:Boot** 应用，并且**手动打开它一次**（Android 的限制，不打开不会生效）。
启动脚本会 `sleep 8` 等网络就绪 —— 起太早会拿不到网络接口。

---

## 网页面板

面板是**单个 HTML 文件**，不引用 CDN、不引框架，断网也能打开。

| 页签 | 内容 |
|---|---|
| **概览** | 工作模式、数据面后端、接口、流量、DHCP/DNS 状态、热点开关、WiFi/电池 |
| **设备** | 每台设备的 IP/MAC/主机名/在线状态/上下行流量/租约剩余；限速、备注名、踢掉租约 |
| **DNS** | 查询量、缓存命中率、拦截数、最近查询日志；手动加/取消拦截、清空缓存 |
| **设置** | 网段/地址池/上游 DNS/限速开关/热点命令模板/面板监听与令牌；最近日志；危险操作 |

面板顶部的模式徽章会直接告诉你是"软路由模式"还是"监控模式"；监控模式下会把缺失条件列在最上方，而不是让你对着一堆 0 猜。

---

## 命令行参考

```
trm doctor                  体检：能不能当路由器，还差什么
trm rules [--assume-root]   只打印将要下发的 iptables/nft 命令，不执行
trm up [-d] [--dry-run]     启动（-d 后台，--dry-run 只打印命令）
trm down                    停止并清理本项目下发的全部规则
trm status [--json]         运行状态
trm clients [--json]        列出上网设备
trm limit <ip> <下行> [上行]  限速（kbps，0 = 该方向不限）
trm unlimit <ip>            解除限速
trm name <ip> <备注>         给设备起名
trm kick <ip>               清除 DHCP 租约，逼它重新申请
trm dns block <域名>         拦截域名
trm dns unblock <域名>       放行域名
trm dns queries             最近查询日志
trm dns list                当前拦截规则
trm dns clear               清空 DNS 缓存
trm hotspot start|stop|status
trm config show|get|set|path
trm token                   面板地址与令牌
trm version
```

小技巧：

```bash
trm up --dry-run -d     # 完整预演一遍：假装有 root，把每一步命令都打进日志，什么都不改
```

---

## 配置说明

配置文件：`~/.trm/config.json`（权限 600），也可以用 `trm config set <key> <value>` 修改。

| 键 | 默认 | 说明 |
|---|---|---|
| `lan.iface` | `auto` | 内网（热点）接口。`auto` 会按 `ap*`/`softap*`/`wlan1` 等名字猜，**猜不准就手动填** |
| `lan.subnet` | `192.168.43.0/24` | 内网网段 |
| `lan.gateway` | `192.168.43.1` | 网关（本机在热点侧地址） |
| `lan.pool_start` / `pool_end` | `.50` / `.200` | DHCP 地址池 |
| `wan.iface` | `auto` | 外网接口。Android 上 `/proc/net/route` 常被限制读取，所以这项**经常需要手动指定**（如 `rmnet_data1`） |
| `dns.upstream` | `1.1.1.1`, `8.8.8.8` | 上游 DNS |
| `dns.block_response` | `0.0.0.0` | 命中拦截时 A 记录返回什么；也可设为 `nxdomain` |
| `dns.blocklists` | `[]` | 本地 hosts 格式 / 域名列表文件路径，支持多个 |
| `netfilter.mss_clamp` | `true` | **建议一直开着**，修手机热点最常见的"能连不能开网页" |
| `netfilter.hijack_dns` | `false` | 强制把内网 53 端口重定向到本机 DNS，防止设备绕过拦截 |
| `shaper.enabled` | `false` | 开启 `tc` 限速（需 root 和 `tc`） |
| `hotspot.start_cmd` | 空 | 自定义启动热点命令，支持 `{ssid}` `{passphrase}` 占位符 |
| `web.host` / `web.port` | `127.0.0.1` / `8080` | 面板监听地址与端口 |
| `static_leases` | `{}` | 固定租约：`{"aa:bb:cc:dd:ee:ff": "192.168.43.10"}` |

DNS 拦截文件的格式（`/etc/hosts` 风格，直接用 AdGuard/StevenBlack 的列表就行）：

```
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.net
*.metrics.example.org      # 通配只拦子域，不拦 domain 本身
```

---

## 安全

- 面板默认只监听 `127.0.0.1`
- 所有接口都要求令牌（`X-TRM-Token` 头、`Authorization: Bearer`、或 `?token=`），用 `hmac.compare_digest` 做定时安全比较
- 令牌为空时**只允许回环地址**访问 —— "忘了设密码"不会变成"对全网开放"
- 配置文件权限 600，含令牌
- 不提供目录遍历，静态资源只有内置的一个 HTML
- 响应头带 CSP、`no-store`、`nosniff`

面板能改防火墙规则，所以请像对待路由器管理密码一样对待这个令牌。

---

## 设计取舍（为什么这么做）

**为什么转发用 iptables 而不是 Python 转发？**
性能。Python 转发需要收包→用户态→发回，几百 Mbps 就到顶且吃满 CPU。
内核 netfilter 转发接近线速，且协议栈由内核维护。**"高性能"来自内核，跟控制面用什么语言写无关。**

**为什么自己写 DHCP/DNS，而不用 dnsmasq？**
本项目的第一原则是零依赖 —— 手机上每多装一个包，就多占一份存储和常驻内存。
DHCP 是一天几十个包的低频协议，DNS 是每设备每秒几个查询，Python 完全够。
真正的压力在转发路径上，跟这两个服务无关。

**为什么不自己跑 hostapd 开热点？**
手机 WiFi 芯片的 AP 模式由厂商驱动 + Android framework 共同管理，
hostapd 在绝大多数机型上**根本起不来**（nl80211 接口被 framework 占着）。
系统热点已经实现了 AP + DHCP + NAPT，稳定又省电。
本项目把 AP 层交给系统，专注做系统做不到的部分：**按设备限速、DNS 拦截、细粒度统计、统一管理**。

**为什么限速的上行用 police 而不是 ifb？**
标准做法需要 `modprobe ifb`，而 Android 的 GKI 内核通常不带 ifb 模块。
所以：下行用 HTB 流量整形（我们的主方向，效果精确），上行用 ingress `police`（超限丢包）。
两者都失败时，`trm` 会**明说没生效**，不会谎报成功。

**为什么不用 `os.getuid()` 判断 root？**
因为 PRoot 下它会撒谎。见下文。

---

## 一个容易踩的坑：真假 root

```python
os.getuid()            # PRoot 里返回 0    ← 假的
/proc/self/status Uid  # PRoot 里返回 10408 ← 真的（Termux 应用 uid）
```

本项目的 `caps.py` 一律读 `/proc/self/status` 拿真实 uid，并且：

- 真实 uid 为 0 **且** 能读到 `/data/misc/wifi`（或 `/proc/net/ip_tables_names`）才判定为真 root
- 顺带发现 `getuid() != 真实 uid` 就是最可靠的 PRoot 判定
- PRoot 里的 `su` 会被明确标注为"假 root，不能用于数据面"，而不是拿它去误导用户

这是本项目最核心的一段防御性代码 —— 否则你会看到"工作模式：软路由"然后一脸问号地发现网络没通。

---

## 已知限制（诚实清单）

- **只处理 IPv4**。IPv6 转发、IPv6 DNS 拦截都**没有**实现；需要的话建议在系统热点里关掉 IPv6
- 上行限速是 `police`（丢包）而非整形，时延表现不如专业路由器
- 热点开关命令因 ROM 而异，`hotspot.start_cmd` 可能需要你按自己机型调整
- 外网接口在部分机型上只能靠命名推测（`/proc/net/route` 权限受限）
- 不处理 PPPoE、不处理 VLAN、不做多 WAN 负载均衡 —— 这是手机软路由，不是 OpenWRT
- 设备列表依赖 ARP/conntrack，无 root 时为空（**空就是空，不会编造数据**）

---

## 开发与测试

```bash
python3 run_tests.py          # 213 个测试，约 5 秒，不联网、不需要 root
python3 run_tests.py -v       # 详细输出
python3 run_tests.py dhcp     # 只跑 DHCP 相关

python3 scripts/check_no_deps.py   # 守住"零第三方依赖"这条底线
```

`check_no_deps.py` 会解析真实 import 并检查来源是否落在 site-packages 里，
而且它**自己也有测试**（包括"故意写一个坏 import，检查器必须报出来"的反向验证）——
一个永远通过的检查等于没有检查。

测试不需要 root、不需要 iptables、不需要网络，因为：

- 数据面规则由**纯函数**生成（`net.plan_enable()`），可以直接断言命令内容
- DHCP/DNS 的协议逻辑与套接字层是分开的，可以只测逻辑层
- `Runner(dry_run=True)` 让所有系统调用变成"只记录不执行"
- 面板测试真的起一个 HTTP 服务（监听随机端口）并真的发请求

代码结构与数据流见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，遇到问题见 [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)。

---

## License

[MIT](LICENSE)
