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
        return RealDatetime(2026, 9, 4, 16, 0, 0)


def _entry(root: Path, rel_path: str, text: str, modified: str) -> e.ExportFileEntry:
    byte_count, digest = e.build_export_text_metadata(text)
    return e.ExportFileEntry(
        path=root.joinpath(*rel_path.split('/')),
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


def test_llm_file_index_uses_deterministic_entry_order(tmp_path: Path) -> None:
    root = tmp_path / "project"
    first = _entry(root, "src/a.py", "print('a')\n", "2026-09-04 10:00:00")
    second = _entry(root, "src/b.txt", "beta\n", "2026-09-04 10:00:01")

    rendered = e.build_llm_file_index([first, second])

    assert rendered.splitlines() == [
        f"{first.stable_id} | src/a.py | ext=.py | bytes={first.byte_count} | lines=1 | sha256={first.content_sha256}",
        f"{second.stable_id} | src/b.txt | ext=.txt | bytes={second.byte_count} | lines=1 | sha256={second.content_sha256}",
    ]


def test_llm_renderer_adds_index_and_extended_headers_without_changing_payload(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(e, "datetime", _FixedDatetime)
    root = tmp_path / "project"
    out = tmp_path / "project.txt"
    entry = _entry(root, "src/a.txt", "alpha\n", "2026-09-04 10:20:30")

    rendered = e.render_llm_export_text(
        root=root,
        out_path=out,
        profile_name="Contract",
        entries=[entry],
    )

    assert "format_version: 2\n" in rendered
    assert "export_format: llm\n" in rendered
    assert "===== FILE INDEX =====\n" in rendered
    assert (
        f"{entry.stable_id} | src/a.txt | ext=.txt | bytes={entry.byte_count} | "
        f"lines=1 | sha256={entry.content_sha256}\n"
    ) in rendered
    assert (
        f"===== FILE: src/a.txt | lines=1 | id={entry.stable_id} | bytes={entry.byte_count} | "
        f"sha256={entry.content_sha256} | modified=2026-09-04 10:20:30 =====\n"
    ) in rendered

    snapshot = e.parse_dump_text(out, rendered)
    assert snapshot.files == {"src/a.txt": "alpha\n"}


def test_llm_renderer_empty_export_has_explicit_empty_index(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(e, "datetime", _FixedDatetime)
    rendered = e.render_llm_export_text(
        root=tmp_path / "project",
        out_path=tmp_path / "project.txt",
        profile_name="Empty",
        entries=[],
    )

    assert rendered.count("[[NO FILES INCLUDED]]") == 2
    assert "===== FILE INDEX =====\n[[NO FILES INCLUDED]]\n" in rendered


def test_export_to_file_dispatches_llm_without_changing_default_standard(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.txt").write_text("alpha\n", encoding="utf-8")

    standard = tmp_path / "standard.txt"
    llm = tmp_path / "llm.txt"

    e.export_to_file(
        root=root,
        out_path=standard,
        exclude_dirs=set(),
        patterns=["*.txt"],
        skip_binary=True,
        header_full_path=False,
        profile_name="Contract",
    )
    e.export_to_file(
        root=root,
        out_path=llm,
        exclude_dirs=set(),
        patterns=["*.txt"],
        skip_binary=True,
        header_full_path=False,
        profile_name="Contract",
        export_format="llm",
    )

    standard_text = standard.read_text(encoding="utf-8")
    llm_text = llm.read_text(encoding="utf-8")
    assert "export_format: llm" not in standard_text
    assert "===== FILE INDEX =====" not in standard_text
    assert "export_format: llm" in llm_text
    assert "===== FILE INDEX =====" in llm_text

    diff = e.compare_dump_snapshots(
        e.parse_dump_text(standard, standard_text),
        e.parse_dump_text(llm, llm_text),
    )
    assert diff.changed_count == 0
    assert diff.unchanged == ["a.txt"]


def test_export_to_file_rejects_unknown_format(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.txt").write_text("alpha\n", encoding="utf-8")

    try:
        e.export_to_file(
            root=root,
            out_path=tmp_path / "out.txt",
            exclude_dirs=set(),
            patterns=["*.txt"],
            skip_binary=True,
            header_full_path=False,
            export_format="compressed-magic",
        )
    except ValueError as exc:
        assert "Unsupported export format" in str(exc)
    else:
        raise AssertionError("unknown export formats must fail explicitly")
