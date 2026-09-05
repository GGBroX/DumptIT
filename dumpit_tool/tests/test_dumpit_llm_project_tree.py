from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import exporter_gui as e


def _entry(root: Path, rel_path: str, text: str, modified: str = "2026-09-04 10:00:00") -> e.ExportFileEntry:
    byte_count, digest = e.build_export_text_metadata(text)
    return e.ExportFileEntry(
        path=root.joinpath(*rel_path.split("/")),
        rel_path=rel_path,
        header_path=rel_path,
        text=text,
        line_count=e.count_lines(text),
        modified_at=modified,
        stable_id=e.build_export_file_stable_id(rel_path),
        extension=Path(rel_path).suffix.lower(),
        byte_count=byte_count,
        content_sha256=digest,
    )


def test_llm_project_tree_uses_stable_id_lines_and_bytes(tmp_path: Path) -> None:
    root = tmp_path / "project"
    entry = _entry(root, "src/main.py", "print('hello')\n")

    rendered = e.build_llm_project_tree([entry])

    assert rendered == (
        "src/\n"
        f"  main.py [{entry.stable_id} | 1 lines | {entry.byte_count} bytes]"
    )
    assert "modified:" not in rendered
    assert entry.modified_at not in rendered


def test_llm_project_tree_preserves_deterministic_directory_first_order(tmp_path: Path) -> None:
    root = tmp_path / "project"
    entries = [
        _entry(root, "z.txt", "z\n"),
        _entry(root, "src/B.py", "b\n"),
        _entry(root, "a.txt", "a\n"),
        _entry(root, "src/a.py", "a\n"),
    ]

    rendered = e.build_llm_project_tree(entries)

    assert rendered.splitlines() == [
        "src/",
        f"  a.py [{entries[3].stable_id} | 1 lines | {entries[3].byte_count} bytes]",
        f"  B.py [{entries[1].stable_id} | 1 lines | {entries[1].byte_count} bytes]",
        f"a.txt [{entries[2].stable_id} | 1 lines | {entries[2].byte_count} bytes]",
        f"z.txt [{entries[0].stable_id} | 1 lines | {entries[0].byte_count} bytes]",
    ]


def test_standard_project_tree_keeps_legacy_modified_metadata(tmp_path: Path) -> None:
    root = tmp_path / "project"
    entry = _entry(root, "src/main.py", "x\n", "2026-09-04 12:34:56")

    rendered = e.build_project_tree([entry])

    assert rendered == "src/\n  main.py [lines: 1 | modified: 2026-09-04 12:34:56]"
    assert entry.stable_id not in rendered
    assert "bytes" not in rendered


def test_llm_renderer_uses_compact_project_tree(tmp_path: Path) -> None:
    root = tmp_path / "project"
    entry = _entry(root, "src/main.py", "x\n", "2026-09-04 12:34:56")

    rendered = e.render_llm_export_text(
        root=root,
        out_path=tmp_path / "out.txt",
        profile_name="Contract",
        entries=[entry],
    )
    project_tree = rendered.split("===== PROJECT TREE =====\n", 1)[1].split("\n\n===== FILE INDEX =====", 1)[0]

    assert f"main.py [{entry.stable_id} | 1 lines | {entry.byte_count} bytes]" in project_tree
    assert "modified:" not in project_tree
    assert entry.modified_at not in project_tree
