"""Static guards for the shared Qwen3Guard contract.

These tests do not execute any model.  They read the package sources and fail
the suite for two structural defects that would otherwise ship silently:

* a module that does not parse at all -- an unimportable product, and
* a second copy of the verdict parser or of the safety taxonomy -- the drift
  the shared contract exists to remove.

They are deliberately fast and dependency-free: standard library only.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "nasi_lemak"

#: The verdict parser's entry points.  Exactly one module may define each.
PARSER_FUNCTIONS = ("parse_verdict", "parse_verdict_fields", "parse_categories")

#: The safety taxonomy.  Exactly one module may define each.
TAXONOMY_ASSIGNMENTS = ("CATEGORY_VALUES", "SAFETY_VALUES", "REFUSAL_VALUES")


def _package_modules() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


class PackageParsesTest(unittest.TestCase):
    def test_every_package_module_parses(self) -> None:
        modules = _package_modules()
        self.assertTrue(modules, "no package modules were found to parse")
        for path in modules:
            with self.subTest(module=path.name):
                _parse(path)


class SingleSourceOfTruthTest(unittest.TestCase):
    def _module_level_names(self) -> dict[str, list[str]]:
        """Map each contract name to the modules that define it at module scope."""
        found: dict[str, list[str]] = {
            name: [] for name in PARSER_FUNCTIONS + TAXONOMY_ASSIGNMENTS
        }
        for path in _package_modules():
            for node in _parse(path).body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for name in PARSER_FUNCTIONS:
                        if node.name == name:
                            found[name].append(path.name)
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if (
                            isinstance(target, ast.Name)
                            and target.id in TAXONOMY_ASSIGNMENTS
                        ):
                            found[target.id].append(path.name)
        return found

    def test_verdict_parser_has_one_implementation(self) -> None:
        for name, owners in self._module_level_names().items():
            if name not in PARSER_FUNCTIONS:
                continue
            with self.subTest(name=name):
                self.assertEqual(
                    len(owners),
                    1,
                    f"{name} must be defined once, found in {owners}",
                )

    def test_safety_taxonomy_has_one_implementation(self) -> None:
        for name, owners in self._module_level_names().items():
            if name not in TAXONOMY_ASSIGNMENTS:
                continue
            with self.subTest(name=name):
                self.assertEqual(
                    len(owners),
                    1,
                    f"{name} must be defined once, found in {owners}",
                )


if __name__ == "__main__":
    unittest.main()
