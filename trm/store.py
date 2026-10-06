"""轻量 JSON / 文本状态存储。

所有状态文件都做原子写（写临时文件再 ``os.replace``），避免手机被杀进程时
留下半截文件导致下次启动崩溃。
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

PathLike = Union[str, Path]


def now() -> float:
    return time.time()


def read_json(path: PathLike, default: Any = None) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return default


def write_json(path: PathLike, data: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, p)


def read_text(path: PathLike, default: str = "") -> str:
    p = Path(path)
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def append_line(path: PathLike, line: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(line.rstrip("\n") + "\n")


class RingBuffer:
    """固定长度的内存环形缓冲，用来存最近的 DNS 查询日志。

    刻意不落盘、不无界增长——手机上内存比磁盘更宝贵。
    """

    def __init__(self, capacity: int = 500) -> None:
        self.capacity = max(1, int(capacity))
        self._items: List[Dict[str, Any]] = []

    def add(self, item: Dict[str, Any]) -> None:
        self._items.append(item)
        if len(self._items) > self.capacity:
            del self._items[: len(self._items) - self.capacity]

    def latest(self, count: int = 100) -> List[Dict[str, Any]]:
        if count <= 0:
            return []
        return list(reversed(self._items[-count:]))

    def all(self) -> List[Dict[str, Any]]:
        return list(self._items)

    def clear(self) -> None:
        self._items.clear()

    def __len__(self) -> int:
        return len(self._items)
