"""termux-router —— 把 Android 手机变成一台可管理的软路由。

设计原则（针对手机这种内存紧张的环境）：

1. **零第三方依赖**：只用 Python 标准库，不装 pip 包、不编译、不需要 npm。
   常驻内存约 20~30 MB。
2. **数据面交给内核**：真正的转发、NAT、限速由 iptables/nftables/tc 完成，
   Python 只做控制面。所以"高性能"来自内核，跟本项目用什么语言写无关。
3. **能力自动降级**：有 root 就是软路由，没 root 就退化成只读监控面板，
   绝不假装自己能做到做不到的事。
4. **规则生成是纯函数**：所有 iptables/tc 命令由纯函数生成，
   可以在没有 root 的机器上做单元测试（dry-run）。
"""

from __future__ import annotations

APP_NAME = "termux-router"
CLI_NAME = "trm"
__version__ = "1.0.0"

__all__ = ["APP_NAME", "CLI_NAME", "__version__"]
