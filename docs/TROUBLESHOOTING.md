# 排障手册

先跑这两条命令，90% 的问题能自己定位：

```bash
trm doctor              # 我缺什么
trm status              # 现在是什么状态
trm rules --assume-root # 如果有 root 会执行哪些命令（安全审计）
```

---

## 一、核心问题：为什么是"监控模式"

### 症状

`trm status` 显示 `监控模式（无 root，只能看不能改）`，面板里设备列表是空的。

### 原因与处理

按顺序排查这三条（`trm doctor` 会直接列出来）：

**1. 我在 PRoot 容器里**

症状：`trm doctor` 里出现 `运行环境: Termux + PRoot 容器`，
或者 `container=proot-distro`。

```bash
# 确认
echo "$container"; echo "$PROOT_L2S_DIR"
```

**PRoot 里永远不可能当路由器**，因为 PRoot 只是用户态系统调用翻译，
无法操作 Android 内核的 netfilter。就算你在里面装了 iptables 也没用。

处理：退出 PRoot，在 **Termux 原生 shell** 里操作：

```bash
exit                        # 退出 proot-distro
# 回到 Termux 提示符（提示符里应该是 ~ 而不是容器的 root@localhost）
cd ~/termux-router && bash install.sh
```

**2. 没有真 root**

症状：`真实 uid（/proc）` 不是 0，而 `getuid() 报告` 是 0。

这个"不一致"本身就是 PRoot 的特征。如果两者都是 0 但 `真 root = 否`，
说明 uid 是 0 却读不到 `/data/misc/wifi` —— 通常是 SELinux 或命名空间限制。

处理：
- 用 KernelSU 或 Magisk 获取 root
- 安装 `tsu`：`pkg install tsu`
- 用 `sudo trm up -d`（或 `tsu -c 'trm up -d'`）运行

**3. 有 root 但 netfilter 不可见**

```
真 root           是
netfilter 可用     否
iptables        未找到
```

处理：

```bash
pkg install root-repo
pkg install iptables iproute2
sudo trm doctor
```

> 很多机型其实自带 `/system/bin/iptables`（实测 Redmi/Android 17 是 iptables v1.8.11 legacy），
> 本项目会自动搜索 `/system/bin`、`/vendor/bin`、`/sbin` 等目录，所以常常不需要装。

---

## 二、能连上热点，但打不开网页 / 网页转圈

**这是手机热点最经典的问题，99% 是 MTU/MSS。**

症状：设备能拿到 IP、能 ping 通、DNS 也能解析，但网页打不开或只能打开一部分。

原因：运营商的上行 MTU 小于 1500（常见 1400/1420），而客户端按 1500 发大包，
中间设备丢弃且没有正确回 ICMP，形成"PMTU 黑洞"。

处理：确认 MSS 钳制开着（**默认就是开的**）：

```bash
trm config get netfilter.mss_clamp     # 应该是 true
trm config set netfilter.mss_clamp true
trm down && sudo trm up -d
```

验证规则真的下发了：

```bash
sudo iptables -t mangle -S TRM_MSS
# 期望看到：
# -A TRM_MSS -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

还不行的话，试试把热点侧 MTU 也调小：

```bash
trm config set dhcp.mtu 1400
trm down && sudo trm up -d
```

---

## 三、DHCP 起不来

### 症状

日志里出现 `DHCP 启动失败: 绑定 0.0.0.0:67 失败: [Errno 13] Permission denied`

### 原因

端口 67 是特权端口，**必须 root**。另外 Android 系统热点自带的 DHCP
可能已经占用了 67 端口。

### 处理

1. 用 root 运行：`sudo trm up -d`
2. 如果系统热点自带的 DHCP 还在跑，二者会冲突。两个选择：
   - **推荐**：让系统热点继续管 DHCP，本项目只做限速/拦截/统计
     （`trm config set dhcp.enabled false`）
   - 或者关掉系统的 DHCP（不同 ROM 方式不同，一般不建议折腾）

### 客户端拿到的是别的网段

系统热点的默认网段通常是 `192.168.43.0/24`，但也可能是 `192.168.93.x` 等。
先看客户端实际拿到的地址，然后把本项目改成一致：

```bash
trm config set lan.subnet   192.168.93.0/24
trm config set lan.gateway  192.168.93.1
trm config set lan.pool_start 192.168.93.50
trm config set lan.pool_end   192.168.93.200
trm down && sudo trm up -d
```

---

## 四、DNS 不生效 / 拦截无效

### 检查顺序

```bash
# 1. 服务在跑吗
trm status | grep DNS

# 2. 端口占用/权限（53 也是特权端口）
sudo ss -lunp | grep :53

# 3. 设备真的在用我们的 DNS 吗
#    在客户端上执行：nslookup example.com
#    返回的 Server 应该是网关地址（如 192.168.43.1）

# 4. 拦截规则加载了吗
trm dns list
```

### 拦截了但设备还能访问

原因通常是这两个：

**1. 设备绕过了我们的 DNS**（用了硬编码的 8.8.8.8，或 DoH/DoT）

处理：打开 DNS 劫持（把所有去 53 端口的查询强行拉回本机）：

```bash
trm config set netfilter.hijack_dns true
trm down && sudo trm up -d
sudo iptables -t nat -S PREROUTING | grep REDIRECT   # 验证
```

注意：劫持只对明文 DNS（53 端口）有效，**DoH/DoT（443/853）绕不过去**，
需要在客户端侧关闭"私人 DNS"。

**2. 只拦了 A 记录，浏览器走了 HTTPS 记录**

本项目已经处理：命中拦截时，`A` 返回 `0.0.0.0`，`AAAA`/`HTTPS`/`SVCB` 返回 NODATA。
如果你的拦截名单只包含域名而浏览器仍能打开，检查是不是客户端缓存了：

```bash
trm dns clear
```

### 上游全挂

`trm status` 里 `错误` 计数一直涨，日志出现 `SERVFAIL`：

```bash
trm config get dns.upstream
trm config set dns.upstream "223.5.5.5, 119.29.29.29"   # 换成国内可达的
trm down && sudo trm up -d
```

---

## 五、限速不生效

### 症状

面板上设置了限速，但测速没变化。或者返回"已记录限速，但 shaper 未启用"。

**这是设计行为，不是 bug**：没真正下发时限速就明确告诉你没生效。

### 检查

```bash
# 1. 开关开了吗（默认是关的）
trm config get shaper.enabled
trm config set shaper.enabled true

# 2. 有 tc 吗
trm doctor | grep tc

# 3. 重启后重新应用
trm down && sudo trm up -d && trm limit 192.168.43.55 4096 1024

# 4. 内核里真的有规则吗
trm rules --assume-root | grep -A2 tc      # 预览
sudo tc -s class show dev ap0              # 实际
sudo tc -s filter show dev ap0
```

### 限速不精确 / 上行时延大

**已知限制**：上行用的是 ingress `police`（超限丢包），不是整形。
标准做法需要 `ifb` 模块，而 Android GKI 内核通常没有。
下行用 HTB 整形，是精确的。

---

## 六、热点命令失败

### 症状

`trm hotspot start` 失败，提示"不同 ROM 的热点命令不同"。

### 原因

`cmd wifi start-softap` 的语法在各 Android 版本/ROM 上都不一样，**没有通用写法**。

### 处理

先手动开一次热点，然后在自己的机器上找正确命令：

```bash
# 有 root 的前提下逐个试
sudo cmd wifi start-softap MySSID wpa2 MyPassword
sudo cmd wifi start-softap MySSID MyPassword
sudo cmd wifi start-softap MySSID open

# 看看系统支持哪些子命令
sudo cmd wifi -h
```

找到能用的那条，写进配置（`{ssid}` / `{passphrase}` 是占位符）：

```bash
trm config set hotspot.ssid MySSID
trm config set hotspot.passphrase MyPassword
trm config set hotspot.start_cmd "cmd wifi start-softap {ssid} wpa2 {passphrase}"
trm config set hotspot.stop_cmd  "cmd wifi stop-softap"
```

其实**手动开热点完全够用**：AP 层交给系统反而更省电更稳定，
本项目的价值在限速、DNS 拦截、统计和管理面板。

---

## 七、面板打不开

```bash
# 1. 服务在跑吗
trm status

# 2. 监听地址和令牌
trm token

# 3. 从本机验证
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/     # 期望 200
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/api/status  # 期望 401（没带令牌）
```

### 想从别的设备访问

```bash
trm config set web.host 0.0.0.0
trm down && trm up -d
trm token      # 用这个令牌在浏览器里登录
```

浏览器里一直提示"令牌无效"：确认没多复制空格，或用 `?token=xxx` 直接访问：

```
http://<手机IP>:8080/?token=<令牌>
```

### 端口冲突

```bash
trm config set web.port 9090
trm down && trm up -d
```

---

## 八、进程被 Android 杀掉

Android 会回收后台进程，Termux 尤其容易被杀。

处理：

```bash
# 1. 获取唤醒锁（install.sh 的 boot 脚本里已经加了）
termux-wake-lock

# 2. 在 Termux 通知栏里把会话锁住（下拉通知 → Acquire wakelock）

# 3. 关闭省电优化：设置 → 应用 → Termux → 省电策略 → 无限制
#    MIUI 额外需要：设置 → 应用设置 → Termux → 省电策略 → 无限制 + 允许自启动
```

**重要**：即使 Python 进程被杀，**已下发的 iptables 规则仍然生效**（它们在内核里），
转发不会中断。重启进程后面板恢复。

想彻底清理规则：

```bash
sudo trm down
# 或者内核侧强制清理（应急）
sudo iptables -t nat -D POSTROUTING -o <外网接口> -j TRM_NAT
sudo iptables -t nat -F TRM_NAT && sudo iptables -t nat -X TRM_NAT
sudo iptables -D FORWARD -j TRM_FWD && sudo iptables -F TRM_FWD && sudo iptables -X TRM_FWD
sudo iptables -t mangle -D FORWARD -j TRM_MSS && sudo iptables -t mangle -F TRM_MSS && sudo iptables -t mangle -X TRM_MSS
```

---

## 九、接口识别错了

### 症状

日志里出现 `警告：内网接口 ap0 不在当前接口列表中（实际有：...）`，
或者面板上接口标着"推测"徽章。

### 原因

- 热点还没开，所以看不到 `ap0`/`softap0` 之类的接口
- `/proc/net/route` 和 `/sys/class/net` 在 Android 上对普通应用常常不可读，
  外网接口只能靠命名推测（`rmnet*`/`wwan*`/`wlan0`）

### 处理

先开热点，再看真实接口名，然后**显式写进配置**：

```bash
sudo ip -o link show | awk -F': ' '{print $2}'     # 列出全部接口
trm config set lan.iface ap0          # 换成你实际的
trm config set wan.iface rmnet_data1  # 换成你实际的
trm down && sudo trm up -d
```

---

## 十、流量显示"不可读"

面板上外网/内网流量显示 `不可读（无权限）` 而不是 `0 B`。

**这是刻意设计**：`/sys/class/net/*/statistics` 读不到时，
显示 0 是在骗人。PRoot 容器里通常就是这样。

处理：在 Termux 原生环境（非 PRoot）里运行本项目。

---

## 十一、卸载干净

```bash
bash install.sh --uninstall     # 会先 trm down，再删软链和自启脚本
rm -rf ~/.trm                   # 数据（配置/租约/日志/拦截名单）
```

确认内核里没有残留规则：

```bash
sudo iptables -t nat -S | grep TRM
sudo iptables -S | grep TRM
sudo iptables -t mangle -S | grep TRM
sudo tc qdisc show | grep htb
```

以上命令**不应该有任何输出**。

---

## 还是不行？

把这三样贴出来，问题基本就清楚了：

```bash
trm doctor
trm status --json | head -60
tail -50 ~/.trm/log/trm.log
```
