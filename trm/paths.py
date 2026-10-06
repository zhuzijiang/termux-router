"""运行期目录布局。

所有可写状态默认落在 ``~/.trm``，可用环境变量 ``TRM_HOME`` 覆盖。

这里有一个**很重要**的细节：为什么不用 ``Path.home()`` 了。

在 Android 上用 ``sudo``/``tsu`` 以 root 身份运行时，root 的 ``$HOME``
通常是 ``/`` 或 ``/data``，而不是 Termux 的家目录。如果直接用它：

* ``sudo trm up`` 会把配置写到 ``/.trm`` 或 ``/data/.trm``
* 之后你用普通身份敲 ``trm status`` 去找 ``~/.trm``，什么也找不到，
  于是报"守护进程没有在运行"—— 明明进程就在跑

所以这里改成：**只要 Termux 的家目录存在就用它**，不管当前是哪个 uid。
这样 ``sudo trm`` 和 ``trm`` 永远看到同一份配置、同一个令牌、同一份租约。

另外 ``adopt()`` 负责把 root 创建的文件交还给 Termux 应用 uid：
文件归属不还回去，普通身份就既读不了也改不了（``sudo trm up`` 之后
``trm config set`` 会因权限失败）。
"""

from __future__ import annotations

import os
from pathlib import Path

HOME_ENV = "TRM_HOME"
DEFAULT_DIRNAME = ".trm"

# Termux 的固定布局（Android 上写死的，可以放心依赖）
TERMUX_DATA = Path("/data/data/com.termux")
TERMUX_HOME = TERMUX_DATA / "files" / "home"


def termux_home() -> Path | None:
    """如果这是 Termux 环境，返回它的家目录，否则 None。"""
    try:
        if TERMUX_HOME.is_dir():
            return TERMUX_HOME
    except OSError:
        pass
    return None


def home() -> Path:
    """返回配置根目录。

    优先级：``TRM_HOME`` 环境变量 > Termux 家目录 > 当前用户的 ``~``。
    """
    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override).expanduser()
    found = termux_home()
    if found is not None:
        return found / DEFAULT_DIRNAME
    return Path.home() / DEFAULT_DIRNAME


def termux_app_uid() -> int | None:
    """Termux 应用在 Android 上的 uid（例如 u0_a408 = 10408）。"""
    try:
        return os.stat(TERMUX_DATA).st_uid
    except OSError:
        return None


def adopt(path: Path) -> None:
    """以 root 运行时，把新建的文件/目录的属主交还给 Termux 应用 uid。

    目的：让 ``sudo trm up`` 之后的 ``trm status`` / ``trm config set``
    在普通身份下照样能读能写。非 root 运行时是空操作。
    """
    try:
        from .caps import real_uid  # 延迟导入，避免模块级循环依赖

        if real_uid() != 0:
            return
    except Exception:
        return

    uid = termux_app_uid()
    if uid is None or uid == 0:
        return
    try:
        gid = os.stat(TERMUX_DATA).st_gid
    except OSError:
        gid = uid
    try:
        os.chown(path, uid, gid)
    except OSError:
        # 文件系统不支持 chown（如部分 FUSE 挂载）时忽略，不影响功能
        pass


def config_file() -> Path:
    return home() / "config.json"


def state_dir() -> Path:
    return home() / "state"


def log_dir() -> Path:
    return home() / "log"


def run_dir() -> Path:
    return home() / "run"


def blocklist_dir() -> Path:
    return home() / "blocklists"


def pid_file() -> Path:
    return run_dir() / "trm.pid"


def log_file() -> Path:
    return log_dir() / "trm.log"


def leases_file() -> Path:
    return state_dir() / "leases.json"


def stats_file() -> Path:
    return state_dir() / "stats.json"


def ensure_dirs() -> None:
    """创建全部运行期目录，并把根目录权限收紧到 0700。"""
    root = home()
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        # 某些 Android 文件系统（如 sdcard/fuse）不支持 chmod，忽略即可
        pass
    adopt(root)
    for d in (state_dir(), log_dir(), run_dir(), blocklist_dir()):
        d.mkdir(parents=True, exist_ok=True)
        adopt(d)
