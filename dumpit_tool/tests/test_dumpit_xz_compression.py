"""Backward-compatibility tests for XZ archives created before the ZIP transition."""
from __future__ import annotations

import lzma
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import exporter_gui as e


def test_existing_xz_archive_is_compatible_with_import_and_diff(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "source.py").write_text("message = '€'\n", encoding="utf-8")
    plain = tmp_path / "plain.txt"
    e.export_to_file(
        root=root, out_path=plain, exclude_dirs=set(), patterns=["*.py"],
        skip_binary=True, header_full_path=False, export_format="llm",
    )
    legacy = tmp_path / "legacy.txt.xz"
    legacy.write_bytes(lzma.compress(plain.read_bytes()))
    diff = e.load_dump_diff(plain, legacy)
    assert diff.changed_count == 0
    assert diff.unchanged == ["source.py"]
    dest = tmp_path / "restored"
    plan = e.build_dump_import_plan(dump_path=legacy, target_root=dest, overwrite_existing=True)
    result = e.execute_dump_import_plan(plan, overwrite_existing=True, backup_overwritten=True)
    assert result.created == 1
    assert (dest / "source.py").read_text(encoding="utf-8") == "message = '€'\n"


def test_corrupt_legacy_xz_is_rejected(tmp_path):
    invalid = tmp_path / "invalid.txt.xz"
    invalid.write_bytes(b"broken xz")
    with pytest.raises(ValueError, match="XZ dump"):
        e.read_dump_text(invalid)
