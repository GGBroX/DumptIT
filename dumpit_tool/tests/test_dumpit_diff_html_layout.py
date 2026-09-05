from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import exporter_gui as e


def _sample_diff() -> e.DumpDiffResult:
    old_lines = [f"line {i}" for i in range(1, 90)]
    new_lines = list(old_lines)
    new_lines[59] = "line 60 changed"
    old_text = "\n".join(old_lines) + "\n"
    new_text = "\n".join(new_lines) + "\n"
    path = "src/example.py"
    return e.DumpDiffResult(
        old=e.DumpSnapshot(source=Path("old.dump"), files={path: old_text}),
        new=e.DumpSnapshot(source=Path("new.dump"), files={path: new_text}),
        added=[],
        removed=[],
        modified=[path],
        unchanged=[],
    )


def test_diff_table_declares_four_columns_before_body_and_skip_spans_all_columns() -> None:
    diff = _sample_diff()
    table = e._render_html_diff_table(
        diff.old.files["src/example.py"],
        diff.new.files["src/example.py"],
    )

    expected_colgroup = (
        "<colgroup>"
        "<col class='col-ln'><col class='col-code'>"
        "<col class='col-ln'><col class='col-code'>"
        "</colgroup>"
    )
    assert table.startswith("<table class='diff-table'>" + expected_colgroup + "<tbody>")
    assert "<tr class='skip'><td class='skip-code' colspan='4'>" in table
    assert "colspan='3'" not in table


def test_visual_diff_css_sizes_columns_from_colgroup_not_content_cells() -> None:
    html = e.build_delta_html(_sample_diff())

    assert ".diff-table col.col-ln { width: 56px; }" in html
    assert ".diff-table col.col-code { width: calc((100% - 112px) / 2); }" in html
    assert ".ln { width: 56px;" not in html
    assert ".code { width: calc(50% - 56px);" not in html
