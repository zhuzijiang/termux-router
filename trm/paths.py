"""运行期目录布局。

所有可写状态默认落在 ``~/.trm``，可用环境变量 ``TRM_HOME`` 覆盖。
这样在 Termux 里就是 ``/data/data/com.termux/files/home/.trm``，
卸载项目时删掉一个目录即可，不污染系统。
"""

from __future__ import annotations

import os
from pathlib import Path

HOME_ENV = "TRM_HOME"
DEFAULT_DIRNAME = ".trm"


def home() -> Path:
    """返回配置根目录。"""
    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override).expanduser()
    return Path.home() / DEFAULT_DIRNAME


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
    for d in (state_dir(), log_dir(), run_dir(), blocklist_dir()):
        d.mkdir(parents=True, exist_ok=True)
