from __future__ import annotations

from datetime import datetime as RealDatetime
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import exporter_gui as e


class _FixedDatetime:
    @classmethod
    def utcnow(cls) -> RealDatetime:
        return RealDatetime(2026, 9, 4, 8, 30, 0)


def test_standard_render_contract_is_frozen(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(e, "datetime", _FixedDatetime)
    root = tmp_path / "project"
    out = tmp_path / "project.txt"
    entry = e.ExportFileEntry(
        path=root / "src" / "a.txt",
        rel_path="src/a.txt",
        header_path="src/a.txt",
        text="alpha\n",
        line_count=1,
        modified_at="2026-09-04 10:20:30",
    )

    rendered = e.render_export_text(
        root=root,
        out_path=out,
        profile_name="Contract",
        entries=[entry],
    )

    assert rendered == (
        "===== DUMPIT EXPORT =====\n"
        "timestamp_utc: 2026-09-04 08:30:00 UTC\n"
        f"root: {root}\n"
        f"output: {out}\n"
        "profile: Contract\n"
        "files_included: 1\n"
        "\n"
        "===== PROJECT TREE =====\n"
        "src/\n"
        "  a.txt [lines: 1 | modified: 2026-09-04 10:20:30]\n"
        "\n"
        "===== FILE: src/a.txt | lines=1 | modified=2026-09-04 10:20:30 =====\n"
        "alpha\n"
        "\n"
    )


def test_legacy_file_header_remains_parseable(tmp_path: Path) -> None:
    source = tmp_path / "legacy.txt"
    snapshot = e.parse_dump_text(
        source,
        "===== DUMPIT EXPORT =====\n"
        "root: /repo\n"
        "\n"
        "===== FILE: src/a.txt =====\n"
        "alpha\n"
        "\n",
    )

    assert snapshot.files == {"src/a.txt": "alpha\n"}


def test_parser_ignores_future_prefile_sections_and_header_metadata(tmp_path: Path) -> None:
    source = tmp_path / "future.txt"
    snapshot = e.parse_dump_text(
        source,
        "===== DUMPIT EXPORT =====\n"
        "format_version: 2\n"
        "export_format: llm\n"
        "root: /repo\n"
        "\n"
        "===== FILE INDEX =====\n"
        "F-a1 | src/a.txt | ext=.txt | bytes=6 | lines=1 | sha256=abc\n"
        "F-b2 | src/b.txt | ext=.txt | bytes=11 | lines=2 | sha256=def\n"
        "\n"
        "===== FILE: src/a.txt | lines=1 | id=F-a1 | bytes=6 | sha256=abc | modified=2026-09-04 10:20:30 =====\n"
        "alpha\n"
        "\n"
        "===== FILE: src/b.txt | lines=2 | id=F-b2 | bytes=11 | sha256=def | modified=2026-09-04 10:20:31 =====\n"
        "beta\n"
        "gamma\n"
        "\n",
    )

    assert snapshot.files == {
        "src/a.txt": "alpha\n",
        "src/b.txt": "beta\ngamma\n",
    }


def test_import_accepts_future_prefile_index_and_extended_file_header(tmp_path: Path) -> None:
    dump_path = tmp_path / "llm.txt"
    dump_path.write_text(
        "===== DUMPIT EXPORT =====\n"
        "format_version: 2\n"
        "export_format: llm\n"
        "root: /source-project\n"
        "\n"
        "===== FILE INDEX =====\n"
        "F-a1 | src/a.txt | ext=.txt | bytes=6 | lines=1 | sha256=abc\n"
        "\n"
        "===== FILE: src/a.txt | lines=1 | id=F-a1 | bytes=6 | sha256=abc | modified=2026-09-04 10:20:30 =====\n"
        "alpha\n"
        "\n",
        encoding="utf-8",
    )
    target = tmp_path / "target"
    target.mkdir()

    plan = e.build_dump_import_plan(
        dump_path=dump_path,
        target_root=target,
        overwrite_existing=True,
    )

    assert plan.source_root == "/source-project"
    assert len(plan.entries) == 1
    assert plan.entries[0].rel_path == "src/a.txt"
    assert plan.entries[0].text == "alpha\n"
    assert not plan.skipped

    result = e.execute_dump_import_plan(
        plan,
        overwrite_existing=True,
        backup_overwritten=True,
    )

    assert result.created == 1
    assert (target / "src" / "a.txt").read_text(encoding="utf-8") == "alpha\n"


def test_standard_and_future_llm_wrappers_diff_as_same_snapshot(tmp_path: Path) -> None:
    standard_text = (
        "===== DUMPIT EXPORT =====\n"
        "root: /repo\n"
        "\n"
        "===== PROJECT TREE =====\n"
        "src/\n"
        "  a.txt [lines: 1 | modified: 2026-09-04 10:20:30]\n"
        "\n"
        "===== FILE: src/a.txt | lines=1 | modified=2026-09-04 10:20:30 =====\n"
        "alpha\n"
        "\n"
    )
    llm_text = (
        "===== DUMPIT EXPORT =====\n"
        "format_version: 2\n"
        "export_format: llm\n"
        "root: /repo\n"
        "\n"
        "===== FILE INDEX =====\n"
        "F-a1 | src/a.txt | ext=.txt | bytes=6 | lines=1 | sha256=abc\n"
        "\n"
        "===== FILE: src/a.txt | lines=1 | id=F-a1 | bytes=6 | sha256=abc | modified=2026-09-04 10:20:30 =====\n"
        "alpha\n"
        "\n"
    )

    old = e.parse_dump_text(tmp_path / "standard.txt", standard_text)
    new = e.parse_dump_text(tmp_path / "llm.txt", llm_text)
    diff = e.compare_dump_snapshots(old, new)

    assert diff.added == []
    assert diff.removed == []
    assert diff.modified == []
    assert diff.unchanged == ["src/a.txt"]
