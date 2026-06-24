from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "dumpit_tool"


def _python_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if path.is_file())


def _quota_rank(path: Path) -> int | None:
    try:
        rel = path.relative_to(PACKAGE_ROOT)
    except ValueError:
        return None
    for part in rel.parts:
        if len(part) >= 2 and part[0] == "q" and part[1:].isdigit():
            return int(part[1:])
    return None


def _imported_quota_rank(module: str) -> int | None:
    parts = module.split(".")
    if not parts or parts[0] != "dumpit_tool":
        return None
    for part in parts[1:]:
        if len(part) >= 2 and part[0] == "q" and part[1:].isdigit():
            return int(part[1:])
    return None


def _imports(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                out.append((node.lineno, "." * node.level + (node.module or "")))
            elif node.module:
                out.append((node.lineno, node.module))
    return out


def test_q0_has_no_internal_dumpit_imports() -> None:
    q0_root = PACKAGE_ROOT / "q0"
    for path in _python_files(q0_root):
        for lineno, module in _imports(path):
            assert not module.startswith("dumpit_tool"), f"{path}:{lineno} imports {module}"
            assert not module.startswith("."), f"{path}:{lineno} uses relative import {module}"


def test_quota_rank_adjacency_for_package_modules() -> None:
    for path in _python_files(PACKAGE_ROOT):
        source_rank = _quota_rank(path)
        if source_rank is None:
            continue
        for lineno, module in _imports(path):
            target_rank = _imported_quota_rank(module)
            if target_rank is None:
                continue
            assert target_rank == source_rank - 1, (
                f"{path}:{lineno} Q{source_rank} imports Q{target_rank}: {module}"
            )


def test_q0_is_not_ui_layer() -> None:
    q0_root = PACKAGE_ROOT / "q0"
    for path in _python_files(q0_root):
        modules = {module for _lineno, module in _imports(path)}
        assert "tkinter" not in modules


def test_legacy_exporter_uses_physical_q0_boundary() -> None:
    exporter = ROOT / "exporter_gui.py"
    modules = {module for _lineno, module in _imports(exporter)}
    assert "dumpit_tool.q0.basics" in modules
