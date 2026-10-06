"""统一的命令执行层。

存在的意义有两个：

* **可注入**：上层所有对 iptables/tc/ip 的调用都走这里，于是可以用
  ``dry_run=True`` 把命令"记录下来但不执行"，从而在没有 root 的机器上
  单元测试规则生成逻辑。
* **可控**：统一超时、统一日志、统一错误处理，避免某个命令卡死拖垮手机。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Sequence

# Android 上有些工具不在 PATH 里，需要额外搜这几个目录
EXTRA_BIN_DIRS: tuple[str, ...] = (
    "/system/bin",
    "/system/xbin",
    "/sbin",
    "/vendor/bin",
    "/debug_ramdisk",
    "/data/data/com.termux/files/usr/bin",
)


@dataclass
class Result:
    """一次命令执行的结果。"""

    cmd: List[str]
    code: int = 0
    out: str = ""
    err: str = ""
    duration: float = 0.0
    dry_run: bool = False
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.code == 0

    @property
    def text(self) -> str:
        """优先返回 stdout，为空时退回 stderr，均已 strip。"""
        return (self.out or self.err or "").strip()

    def lines(self) -> List[str]:
        return [ln for ln in self.text.splitlines() if ln.strip()]

    def __str__(self) -> str:  # pragma: no cover - 仅用于日志
        return " ".join(self.cmd)


class Runner:
    """命令执行器。``dry_run=True`` 时不真正执行，只记录。"""

    def __init__(
        self,
        dry_run: bool = False,
        timeout: float = 15.0,
        log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.dry_run = dry_run
        self.timeout = timeout
        self.log = log or (lambda _msg: None)
        self.history: List[List[str]] = []
        self._which_cache: dict[str, Optional[str]] = {}

    # ------------------------------------------------------------------ 查询
    def which(self, name: str, extra_dirs: Iterable[str] = ()) -> Optional[str]:
        """在 PATH 与 Android 常见目录里查找可执行文件。

        查询不受 dry_run 影响（它不改变系统状态），因为能力探测必须真实。
        """
        if name in self._which_cache:
            return self._which_cache[name]

        found: Optional[str] = None
        if os.sep in name:
            found = name if os.access(name, os.X_OK) else None
        else:
            found = shutil.which(name)
            if not found:
                search = list(extra_dirs) + list(EXTRA_BIN_DIRS)
                for d in search:
                    cand = os.path.join(d, name)
                    if os.access(cand, os.X_OK):
                        found = cand
                        break

        self._which_cache[name] = found
        return found

    def first_available(self, names: Sequence[str]) -> Optional[str]:
        for n in names:
            p = self.which(n)
            if p:
                return p
        return None

    # ------------------------------------------------------------------ 执行
    def run(
        self,
        cmd: Sequence[str],
        timeout: Optional[float] = None,
        check: bool = False,
        env: Optional[dict] = None,
        cwd: Optional[str] = None,
        input_text: Optional[str] = None,
        quiet: bool = False,
    ) -> Result:
        argv = [str(c) for c in cmd]
        self.history.append(argv)

        if not quiet:
            self.log("$ " + " ".join(argv))

        if self.dry_run:
            return Result(cmd=argv, code=0, out="", err="", dry_run=True)

        started = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout if timeout is not None else self.timeout,
                env=env,
                cwd=cwd,
                input=input_text,
            )
            res = Result(
                cmd=argv,
                code=proc.returncode,
                out=proc.stdout or "",
                err=proc.stderr or "",
                duration=time.monotonic() - started,
            )
        except subprocess.TimeoutExpired:
            res = Result(
                cmd=argv,
                code=124,
                err="命令超时",
                duration=time.monotonic() - started,
                timed_out=True,
            )
        except FileNotFoundError:
            res = Result(
                cmd=argv,
                code=127,
                err=f"找不到可执行文件: {argv[0]}",
                duration=time.monotonic() - started,
            )
        except PermissionError:
            res = Result(
                cmd=argv,
                code=126,
                err=f"权限不足: {argv[0]}",
                duration=time.monotonic() - started,
            )
        except OSError as exc:
            res = Result(
                cmd=argv,
                code=125,
                err=f"执行失败: {exc}",
                duration=time.monotonic() - started,
            )

        if check and not res.ok:
            raise CommandError(res)
        return res

    def run_script(self, script: str, timeout: Optional[float] = None) -> Result:
        """执行一段 shell 片段（仅在确有必要时使用）。"""
        return self.run(
            ["/system/bin/sh" if os.path.exists("/system/bin/sh") else "/bin/sh", "-c", script],
            timeout=timeout,
        )


class CommandError(RuntimeError):
    """``check=True`` 且命令失败时抛出。"""

    def __init__(self, result: Result) -> None:
        self.result = result
        super().__init__(f"命令失败({result.code}): {' '.join(result.cmd)} :: {result.text}")
