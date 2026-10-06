#!/usr/bin/env python3
"""轻量测试入口：不需要 pytest，也不需要任何第三方包。

手机上跑测试的原则是"越省越久越好"，所以这里直接用标准库 unittest：

    python3 run_tests.py            # 跑全部
    python3 run_tests.py -v         # 详细输出
    python3 run_tests.py test_dhcp  # 只跑某个模块（可写多个）

内存占用约 25~35 MB，全程不联网、不需要 root。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def main(argv: list) -> int:
    verbosity = 2 if ("-v" in argv or "--verbose" in argv) else 1
    names = [a for a in argv if not a.startswith("-")]
    loader = unittest.TestLoader()
    if names:
        pattern = names[0] if names[0].startswith("test_") else f"test_{names[0]}"
        suite = loader.discover(str(ROOT / "tests"), pattern=f"{pattern}.py", top_level_dir=str(ROOT))
    else:
        suite = loader.discover(str(ROOT / "tests"), pattern="test_*.py", top_level_dir=str(ROOT))
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
