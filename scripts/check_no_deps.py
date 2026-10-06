#!/usr/bin/env python3
"""零依赖检查：确保 ``trm`` 包里没有 ``import`` 任何第三方模块。

这是本项目的核心承诺之一（手机上不装 pip 包），所以必须由机器来守，
而不是靠自觉。CI 与本地都用同一个脚本，避免两边规则不一致。

判定方式：对每个顶层模块名调用 ``importlib.util.find_spec``，
如果它的来源落在 site-packages / dist-packages 里，就是第三方依赖。

不用 ``sys.stdlib_module_names``（3.10+ 才有），也不用"在 stdlib 目录下找文件"
（``unicodedata`` 这类扩展模块在 lib-dynload 里，那样会误判）。

用法::

    python3 scripts/check_no_deps.py        # 检查 trm/
    python3 scripts/check_no_deps.py trm tests
"""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import sys
from typing import Iterable, List, Set, Tuple

THIRD_PARTY_MARKERS = ("site-packages", "dist-packages", ".egg", "vendor")


def top_level_imports(path: pathlib.Path) -> Set[str]:
    """取出一个文件里所有绝对导入的顶层模块名。"""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            # level > 0 是相对导入（from . import x），属于本项目内部
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def classify(name: str) -> Tuple[str, str]:
    """返回 ``(类别, 说明)``，类别为 stdlib / third-party / missing。"""
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ValueError, ModuleNotFoundError) as exc:
        return "missing", str(exc)
    if spec is None:
        return "missing", "找不到该模块"

    origin = spec.origin or ""
    if origin in ("built-in", "frozen"):
        return "stdlib", origin
    for marker in THIRD_PARTY_MARKERS:
        if marker in origin:
            return "third-party", origin
    if not origin:
        # 命名空间包之类，看它的搜索路径
        for location in (spec.submodule_search_locations or []):
            for marker in THIRD_PARTY_MARKERS:
                if marker in str(location):
                    return "third-party", str(location)
        return "stdlib", "namespace"
    return "stdlib", origin


def collect(paths: Iterable[pathlib.Path], local: Set[str]) -> List[Tuple[str, str, str]]:
    problems: List[Tuple[str, str, str]] = []
    for root in paths:
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            for name in sorted(top_level_imports(path)):
                if name in local:
                    continue
                kind, detail = classify(name)
                if kind != "stdlib":
                    problems.append((str(path), name, f"{kind}: {detail}"))
    return problems


def main(argv: List[str]) -> int:
    targets = argv or ["trm"]
    paths = [pathlib.Path(t) for t in targets if pathlib.Path(t).exists()]
    local = {p.name for p in paths} | {"trm", "tests", "scripts"}

    problems = collect(paths, local)
    if problems:
        print("发现非标准库依赖（违反『零第三方依赖』原则）:")
        for path, name, detail in problems:
            print(f"  {path}: import {name}  <- {detail}")
        print()
        print("本项目支持的所有功能都必须只用 Python 标准库实现。")
        return 1

    files = sum(1 for root in paths for _ in root.rglob("*.py"))
    print(f"零第三方依赖检查通过：{files} 个文件，Python {sys.version.split()[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
