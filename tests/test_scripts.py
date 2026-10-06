"""零依赖检查器自身的测试。

一个"永远通过"的检查等于没有检查，所以这里既验证它对干净代码放行，
也验证它**真的能抓到**违规代码（用不存在的模块触发 missing 分支）。
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import check_no_deps  # noqa: E402


class TestImportExtraction(unittest.TestCase):
    def _extract(self, source: str):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.py"
            path.write_text(source, encoding="utf-8")
            return check_no_deps.top_level_imports(path)

    def test_plain_imports(self):
        names = self._extract("import os\nimport socket\nimport json\n")
        self.assertEqual(names, {"os", "socket", "json"})

    def test_from_imports_and_dotted(self):
        names = self._extract("from http.server import BaseHTTPRequestHandler\nimport xml.etree.ElementTree\n")
        self.assertEqual(names, {"http", "xml"})

    def test_relative_imports_are_ignored(self):
        names = self._extract("from . import config\nfrom .net import plan_enable\nfrom .. import x\n")
        self.assertEqual(names, set(), "相对导入属于项目内部，不该算依赖")

    def test_conditional_import_still_detected(self):
        """函数内、try 块里的导入也必须被发现。"""
        names = self._extract("def f():\n    import unicodedata\n    return unicodedata\n")
        self.assertEqual(names, {"unicodedata"})


class TestClassify(unittest.TestCase):
    def test_stdlib_modules(self):
        for name in ("os", "sys", "socket", "json", "unicodedata", "sqlite3"):
            kind, _detail = check_no_deps.classify(name)
            self.assertEqual(kind, "stdlib", f"{name} 应被识别为标准库")

    def test_missing_module(self):
        kind, _detail = check_no_deps.classify("definitely_not_a_real_module_xyz")
        self.assertEqual(kind, "missing")


class TestRealTree(unittest.TestCase):
    def test_project_has_no_dependencies(self):
        problems = check_no_deps.collect([ROOT / "trm"], {"trm"})
        self.assertEqual(problems, [], f"项目里出现了非标准库依赖: {problems}")

    def test_detects_violation(self):
        """反向验证：故意写一个坏文件，检查器必须报出来。"""
        with tempfile.TemporaryDirectory() as tmp:
            bad_dir = Path(tmp) / "fake"
            bad_dir.mkdir()
            (bad_dir / "bad.py").write_text(
                "import os\nimport this_module_does_not_exist_xyz\n", encoding="utf-8")
            problems = check_no_deps.collect([bad_dir], {"fake"})
            self.assertEqual(len(problems), 1)
            self.assertEqual(problems[0][1], "this_module_does_not_exist_xyz")

    def test_local_package_names_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "pkg"
            d.mkdir()
            (d / "a.py").write_text("import pkg\nimport os\n", encoding="utf-8")
            problems = check_no_deps.collect([d], {"pkg"})
            self.assertEqual(problems, [], "项目内部的包名不该被当成依赖")


class TestCliEntry(unittest.TestCase):
    def test_main_returns_zero_on_clean_tree(self):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = check_no_deps.main([str(ROOT / "trm")])
        self.assertEqual(code, 0)
        self.assertIn("检查通过", buf.getvalue())

    def test_main_returns_one_on_violation(self):
        import io
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "pkg"
            d.mkdir()
            (d / "a.py").write_text("import nope_xyz_not_real\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = check_no_deps.main([str(d)])
            self.assertEqual(code, 1)
            self.assertIn("nope_xyz_not_real", buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
