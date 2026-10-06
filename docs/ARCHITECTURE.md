# 架构说明

## 一句话

**内核转发数据包，Python 管理规则。** 所有性能相关的工作交给内核 netfilter，
Python 只做控制面（下发规则、提供面板、统计），因此控制面的语言选择不影响吞吐。

## 数据流

```
                    ┌──────────────── Android 系统热点（AP + NAPT）────────────────┐
                    │  提供 SSID / 认证 / 射频                                             │
                    └───────────────────────────────┬────────────────────────────────┘
                                                    │  客户端上网流量
   ┌───────────────┐                                ▼
   │  局域网设备   │  DHCP 请求 ────► ┌───────────────────────────────┐
   │  (手机/平板)  │  DNS 查询  ────► │   termux-router (Python 进程) │
   └───────┬───────┘                  │                               │
           │                          │  dhcpd.py   纯 Python DHCP    │
           │  数据包                  │  dnsd.py    转发+缓存+拦截     │
           │                          │  web.py     面板 API           │
           │                          │  daemon.py  编排 + 状态聚合     │
           │                          └───────────────┬───────────────┘
           │                                          │ 下发规则（一次性，之后不参与转发）
           ▼                                          ▼
   ╔═══════════════════════════════════════════════════════════════════╗
   ║                    内核 netfilter  ← 性能在这里                    ║
   ║  ip_forward=1                                                     ║
   ║  nat POSTROUTING → TRM_NAT → MASQUERADE                           ║
   ║  FILTER FORWARD  → TRM_FWD → 内网→外网 ACCEPT / conntrack 回程放行  ║
   ║  mangle FORWARD  → TRM_MSS → TCPMSS --clamp-mss-to-pmtu           ║
   ║  tc HTB（下行整形） / ingress police（上行丢包）                    ║
   ╚═══════════════════════════════╤═══════════════════════════════════╝
                                   ▼
                            运营商 / 外网上行
```

关键点：**规则下发之后，Python 不在数据路径上。** 就算 Python 进程被 Android 杀掉，
只要规则还在，转发就继续工作（当然面板会没）。

## 模块职责

| 模块 | 职责 | 是否依赖特权 |
|---|---|---|
| `caps.py` | 能力探测：真假 root、iptables/nft/tc、接口、proot 识别 | 只读探测 |
| `exec.py` | 统一的命令执行层，支持 `dry_run`（只记录不执行） | — |
| `net.py` | sysctl、iptables/nft 规则**生成**与下发、conntrack 统计 | 下发需要 root |
| `shaper.py` | `tc` HTB/police 规则生成、classid 分配、统计解析 | 需要 root |
| `dhcpd.py` | 纯 Python DHCP 服务器（编解码 / 响应逻辑 / 套接字三层） | 端口 67 需要 root |
| `dnsd.py` | 纯 Python DNS 转发、缓存、拦截（含 HTTPS 记录） | 端口 53 需要 root |
| `clients.py` | 租约 + ARP + conntrack + 配置 → 统一的设备视图 | 读 ARP/conntrack 需要 root |
| `hotspot.py` | 系统热点控制（命令模板）、WiFi/电池信息 | 开关需要 root |
| `daemon.py` | 编排上述服务、聚合状态、执行面板动作 | — |
| `web.py` + `webui/` | HTTP API 与单文件面板 | — |
| `cli.py` | 命令行界面 | — |
| `config.py` / `paths.py` / `store.py` / `iputil.py` | 配置、路径、原子 JSON 存储、IP/MAC 工具 | — |

## 三层拆分：为什么 DHCP 要拆成三个类

`dhcpd.py` 刻意分成：

1. `parse_packet()` / `build_reply()` —— 纯字节编解码，无副作用
2. `DHCPResponder` —— 纯逻辑：给定报文决定回什么，**不碰套接字**
3. `DHCPServer` —— 只管收发（UDP 或 AF_PACKET 原始帧）

代价是多写一层抽象，收益是**协议行为可以在没有 root、没有网络的机器上完整测试**
（`tests/test_dhcp.py` 覆盖了 OFFER/ACK/NAK/RELEASE/DECLINE/INFORM、固定租约、
地址池耗尽、过期复用等）。DHCP 写错会导致设备拿不到地址，这种错误必须靠测试而不是靠运气。

同样地，`net.plan_enable()` 是纯函数，`tests/test_rules.py` 逐条断言生成的 iptables 命令，
包括"必须先删旧跳转再加新的"这类幂等性细节。

## 请求路径（面板）

```
浏览器 ──POST /api/clients/192.168.43.50/limit──► web.py Handler
                                                     │ 1. 令牌校验（hmac.compare_digest）
                                                     │ 2. 路由匹配（提取 ip 路径参数）
                                                     │ 3. 交给 daemon.handle_action()
                                                     ▼
                                          RouterDaemon._action_client_limit
                                                     │ 改配置 → 生成 tc 命令 → Runner 执行
                                                     ▼
                                            内核 tc / iptables
```

命令行工具走的是**同一个** `handle_action`：

```
trm limit 192.168.43.50 4096 1024
        └─ HTTP（带令牌）─► /api/clients/.../limit ─► handle_action
```

这样权限只集中在守护进程一处，也避免了"命令行能做、面板做不到"的行为分叉。

## 状态与文件

```
~/.trm/
├── config.json          # 配置（含面板令牌，权限 600）
├── state/
│   ├── leases.json      # DHCP 租约（脏标记 + 最多 5 秒写一次）
│   └── shaper.json      # IP → tc classid/prio 的稳定映射
├── blocklists/          # 用户放拦截名单的地方
├── log/trm.log          # 日志
└── run/trm.pid          # pid 文件（含启动时间、模式、版本）
```

所有写盘都是"写临时文件 + `os.replace`"的原子写，避免被 Android 杀进程时留下半截 JSON。

内存中的有界缓冲：DNS 查询日志（默认 500 条）、面板日志（400 条）——
手机上内存比磁盘贵，这两处都**不落盘、不无界增长**。

## 两种工作模式

| | `router` | `monitor` |
|---|---|---|
| 判定条件 | 真 root **且** netfilter 可用 **且** 有 iptables/nft | 其余情况 |
| 启动内容 | sysctl + 规则 + DHCP + DNS + 限速 + 面板 | 仅面板 + 只读监控 |
| 行为准则 | 下发前打印/记录每一步；失败项逐条上报 | 明确列出缺失条件，不显示编造的数据 |

`partial` 是中间态：有 root 但缺工具或被内核挡住，此时会提示具体缺什么。

## dry-run 的意义

`Runner(dry_run=True)` 下所有命令只记录不执行，`caps` 会被显式标注为"假设有 root"，
日志里每条命令带 `[dry-run]` 前缀。

它有两个用途：

1. 用户在没 root 的手机上**预览**自己将会改动什么（安全审计）
2. 开发者在没有 root 的环境里做端到端集成测试（本项目就是在无 root 的 PRoot 里开发的）
