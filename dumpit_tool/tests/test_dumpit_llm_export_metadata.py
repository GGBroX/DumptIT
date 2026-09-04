from __future__ import annotations

import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import exporter_gui as e


def _collect(root: Path) -> list[e.ExportFileEntry]:
    entries, skipped = e.collect_export_entries(
        root=root,
        exclude_dirs=set(),
        patterns=["*.txt", "*.py"],
        skip_binary=True,
        header_full_path=False,
    )
    assert skipped == 0
    return entries


def test_stable_id_depends_on_relative_path_not_content(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    path = root / "a.txt"
    path.write_text("alpha\n", encoding="utf-8")

    first = _collect(root)[0]
    path.write_text("beta\n", encoding="utf-8")
    second = _collect(root)[0]

    assert first.stable_id == second.stable_id
    assert first.stable_id == e.build_export_file_stable_id("a.txt")
    assert first.content_sha256 != second.content_sha256


def test_stable_id_changes_when_relative_path_changes(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    first_path = root / "a.txt"
    first_path.write_text("same\n", encoding="utf-8")
    first = _collect(root)[0]

    first_path.rename(root / "b.txt")
    second = _collect(root)[0]

    assert first.stable_id != second.stable_id
    assert first.content_sha256 == second.content_sha256


def test_export_metadata_describes_utf8_payload(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    text = "alpha €\n"
    (root / "Mixed.PY").write_text(text, encoding="utf-8")

    entry = _collect(root)[0]
    payload = text.encode("utf-8")

    assert entry.extension == ".py"
    assert entry.byte_count == len(payload)
    assert entry.content_sha256 == hashlib.sha256(payload).hexdigest()


def test_file_stable_id_normalizes_path_separators() -> None:
    assert e.build_export_file_stable_id(r"src\pkg\a.py") == e.build_export_file_stable_id("src/pkg/a.py")
    assert e.build_export_file_stable_id("./src/pkg/a.py") == e.build_export_file_stable_id("src/pkg/a.py")


def test_standard_renderer_output_does_not_include_llm1_metadata(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.txt").write_text("alpha\n", encoding="utf-8")
    entry = _collect(root)[0]

    rendered = e.render_export_text(
        root=root,
        out_path=tmp_path / "out.txt",
        profile_name="Contract",
        entries=[entry],
    )

    assert entry.stable_id not in rendered
    assert entry.content_sha256 not in rendered
    assert "bytes=" not in rendered
