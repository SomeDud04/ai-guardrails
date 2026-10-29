"""Static guards for the shared Qwen3Guard contract.

These tests do not execute any model.  They read the package sources and fail
the suite for two structural defects that would otherwise ship silently:

* a module that does not parse at all -- an unimportable product, and
* a second copy of the verdict parser or of the safety taxonomy -- the drift
  the shared contract exists to remove.

Historical private spellings in ``guard_api`` (``_CATEGORY_VALUES``,
``_SAFETY_VALUES``, ``_REFUSAL_VALUES`` and ``_parse_categories``) are counted
as the same contract slot as their public names.  A literal private taxonomy
tuple is a second implementation even when the public name still exists.

They are deliberately fast and dependency-free: standard library only.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "nasi_lemak"

#: Contract slot -> every module-scope name that historically implemented it.
CONTRACT_GROUPS: dict[str, tuple[str, ...]] = {
    "parse_verdict": ("parse_verdict",),
    "parse_verdict_fields": ("parse_verdict_fields",),
    "parse_categories": ("parse_categories", "_parse_categories"),
    "CATEGORY_VALUES": ("CATEGORY_VALUES", "_CATEGORY_VALUES"),
    "SAFETY_VALUES": ("SAFETY_VALUES", "_SAFETY_VALUES"),
    "REFUSAL_VALUES": ("REFUSAL_VALUES", "_REFUSAL_VALUES"),
}

PARSER_GROUPS = ("parse_verdict", "parse_verdict_fields", "parse_categories")
TAXONOMY_GROUPS = ("CATEGORY_VALUES", "SAFETY_VALUES", "REFUSAL_VALUES")

NAME_TO_GROUP = {
    name: group for group, names in CONTRACT_GROUPS.items() for name in names
}

#: The only private-name re-exports the shared contract allows: a direct alias
#: to the canonical public name, or the frozenset re-export of CATEGORY_VALUES.
_REEXPORT_TARGETS = {
    "_CATEGORY_VALUES": "CATEGORY_VALUES",
    "_SAFETY_VALUES": "SAFETY_VALUES",
    "_REFUSAL_VALUES": "REFUSAL_VALUES",
    "_parse_categories": "parse_categories",
}


def _package_modules() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _package_asts() -> dict[str, ast.Module]:
    return {path.name: _parse(path) for path in _package_modules()}


def _is_allowed_reexport(name: str, value: ast.expr | None) -> bool:
    target = _REEXPORT_TARGETS.get(name)
    if target is None or value is None:
        return False
    if isinstance(value, ast.Name):
        return value.id == target
    if name != "_CATEGORY_VALUES":
        return False
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "frozenset"
        and not value.keywords
        and len(value.args) == 1
        and isinstance(value.args[0], ast.Name)
        and value.args[0].id == "CATEGORY_VALUES"
    )


def _iter_contract_implementations(module: ast.Module):
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            group = NAME_TO_GROUP.get(node.name)
            if group in PARSER_GROUPS:
                yield group, node.name
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                group = NAME_TO_GROUP.get(target.id)
                if group is None or _is_allowed_reexport(target.id, node.value):
                    continue
                yield group, target.id
        elif isinstance(node, ast.AnnAssign):
            target = node.target
            if not isinstance(target, ast.Name):
                continue
            group = NAME_TO_GROUP.get(target.id)
            if group is None or node.value is None:
                continue
            if _is_allowed_reexport(target.id, node.value):
                continue
            yield group, target.id


def _contract_implementations(
    modules: dict[str, ast.Module],
) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {group: [] for group in CONTRACT_GROUPS}
    for module_name, module in modules.items():
        for group, local_name in _iter_contract_implementations(module):
            found[group].append(f"{module_name}:{local_name}")
    return found


_ORIGINAL_PRIVATE_TAXONOMY = {
    "_CATEGORY_VALUES": (
        'frozenset({"Violent", "Non-violent Illegal Acts", '
        '"Sexual Content or Sexual Acts", "PII", "Suicide & Self-Harm", '
        '"Unethical Acts", "Politically Sensitive Topics", '
        '"Copyright Violation"})'
    ),
    "_SAFETY_VALUES": '("Safe", "Unsafe", "Controversial")',
    "_REFUSAL_VALUES": '("Yes", "No")',
}


class PackageParsesTest(unittest.TestCase):
    def test_every_package_module_parses(self) -> None:
        modules = _package_modules()
        self.assertTrue(modules, "no package modules were found to parse")
        for path in modules:
            with self.subTest(module=path.name):
                _parse(path)


class SingleSourceOfTruthTest(unittest.TestCase):
    def test_verdict_parser_has_one_implementation(self) -> None:
        found = _contract_implementations(_package_asts())
        for group in PARSER_GROUPS:
            with self.subTest(group=group):
                owners = found[group]
                self.assertEqual(
                    len(owners),
                    1,
                    f"{group} must be defined once, found in {owners}",
                )

    def test_safety_taxonomy_has_one_implementation(self) -> None:
        found = _contract_implementations(_package_asts())
        for group in TAXONOMY_GROUPS:
            with self.subTest(group=group):
                owners = found[group]
                self.assertEqual(
                    len(owners),
                    1,
                    f"{group} must be defined once, found in {owners}",
                )


class HistoricalNameRegressionTest(unittest.TestCase):
    def _mutated_package(self, module_name: str, source: str) -> dict[str, ast.Module]:
        modules = _package_asts()
        modules[module_name].body.extend(ast.parse(source, filename="<mutation>").body)
        return modules

    def test_original_private_taxonomy_literals_are_rejected(self) -> None:
        for name, value in _ORIGINAL_PRIVATE_TAXONOMY.items():
            with self.subTest(name=name):
                modules = self._mutated_package(
                    "guard_api.py", f"{name} = {value}"
                )
                found = _contract_implementations(modules)
                group = NAME_TO_GROUP[name]
                self.assertEqual(
                    len(found[group]),
                    2,
                    f"literal {name} must count as a second {group}",
                )

    def test_annotated_private_taxonomy_literal_is_rejected(self) -> None:
        modules = self._mutated_package(
            "guard_api.py",
            "_SAFETY_VALUES: tuple[str, ...] = "
            '("Safe", "Unsafe", "Controversial")',
        )
        found = _contract_implementations(modules)
        self.assertEqual(
            len(found["SAFETY_VALUES"]),
            2,
            "an annotated private taxonomy literal must still be rejected",
        )

    def test_duplicate_parser_definitions_are_rejected(self) -> None:
        declarations = {
            "_parse_categories": (
                "def _parse_categories(value):\n"
                "    return None\n"
            ),
            "parse_categories": (
                "def parse_categories(value):\n"
                "    return None\n"
            ),
            "parse_verdict": (
                "def parse_verdict(text):\n"
                "    return True\n"
            ),
        }
        for name, source in declarations.items():
            with self.subTest(name=name):
                modules = self._mutated_package("guard_api.py", source)
                found = _contract_implementations(modules)
                group = NAME_TO_GROUP[name]
                self.assertEqual(
                    len(found[group]),
                    2,
                    f"duplicate {name} parser must be rejected",
                )

    def test_current_aliases_pass(self) -> None:
        modules = _package_asts()
        self.assertEqual(
            list(_iter_contract_implementations(modules["guard_api.py"])),
            [],
            "the current direct aliases and frozenset re-export are not copies",
        )
        found = _contract_implementations(modules)
        for group in CONTRACT_GROUPS:
            with self.subTest(group=group):
                self.assertEqual(len(found[group]), 1)

    def test_annotated_current_alias_passes(self) -> None:
        modules = self._mutated_package(
            "guard_api.py",
            "_SAFETY_VALUES: tuple[str, ...] = SAFETY_VALUES",
        )
        found = _contract_implementations(modules)
        self.assertEqual(len(found["SAFETY_VALUES"]), 1)

    def test_package_ast_mutations_are_in_memory_only(self) -> None:
        before = {path: path.read_bytes() for path in _package_modules()}
        modules = self._mutated_package(
            "guard_api.py",
            '_SAFETY_VALUES = ("Safe", "Unsafe", "Controversial")',
        )
        _contract_implementations(modules)
        after = {path: path.read_bytes() for path in _package_modules()}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
