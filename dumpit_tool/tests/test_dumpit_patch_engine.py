from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import exporter_gui as e


def _write_patch(path: Path, text: str) -> None:
    path.write_text(text.strip() + "\n", encoding="utf-8")


def test_dumpit_apply_exact_line_match(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_text("a\nb\nc\n", encoding="utf-8")
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """
        diff --git a/src/x.txt b/src/x.txt
        --- a/src/x.txt
        +++ b/src/x.txt
        @@ -2,1 +2,1 @@
        -b
        +B
        """.replace("        ", ""),
    )

    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert not plan.failed
    assert plan.files[0].hunk_results[0].status == e.DUMPIT_PATCH_STATUS_APPLICABLE_EXACT
    e.execute_dumpit_patch_plan(plan)
    assert target.read_text(encoding="utf-8") == "a\nB\nc\n"


def test_dumpit_apply_relocated_exact_match(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_text("header\na\nb\nc\n", encoding="utf-8")
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """
        diff --git a/src/x.txt b/src/x.txt
        --- a/src/x.txt
        +++ b/src/x.txt
        @@ -1,3 +1,3 @@
         a
        -b
        +B
         c
        """.replace("        ", ""),
    )

    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert not plan.failed
    assert plan.files[0].hunk_results[0].status == e.DUMPIT_PATCH_STATUS_APPLICABLE_RELOCATED
    e.execute_dumpit_patch_plan(plan)
    assert target.read_text(encoding="utf-8") == "header\na\nB\nc\n"


def test_dumpit_apply_already_applied(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_text("a\nB\nc\n", encoding="utf-8")
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """
        diff --git a/src/x.txt b/src/x.txt
        --- a/src/x.txt
        +++ b/src/x.txt
        @@ -1,3 +1,3 @@
         a
        -b
        +B
         c
        """.replace("        ", ""),
    )

    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert not plan.failed
    assert plan.files[0].hunk_results[0].status == e.DUMPIT_PATCH_STATUS_ALREADY_APPLIED
    assert plan.changed_files == 0


def test_dumpit_apply_ambiguous_old_block_fails(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_text("a\nb\na\nb\n", encoding="utf-8")
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """
        diff --git a/src/x.txt b/src/x.txt
        --- a/src/x.txt
        +++ b/src/x.txt
        @@ -10,2 +10,2 @@
         a
        -b
        +B
        """.replace("        ", ""),
    )

    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert plan.failed
    assert plan.files[0].hunk_results[0].status == e.DUMPIT_PATCH_STATUS_FAILED_AMBIGUOUS
    try:
        e.execute_dumpit_patch_plan(plan)
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected transactional failure")
    assert target.read_text(encoding="utf-8") == "a\nb\na\nb\n"


def test_dumpit_apply_transaction_writes_nothing_on_failed_hunk(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    a = tmp_path / "src" / "a.txt"
    b = tmp_path / "src" / "b.txt"
    a.write_text("a\nb\nc\n", encoding="utf-8")
    b.write_text("x\ny\nz\n", encoding="utf-8")
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """
        diff --git a/src/a.txt b/src/a.txt
        --- a/src/a.txt
        +++ b/src/a.txt
        @@ -2,1 +2,1 @@
        -b
        +B
        diff --git a/src/b.txt b/src/b.txt
        --- a/src/b.txt
        +++ b/src/b.txt
        @@ -2,1 +2,1 @@
        -missing
        +Y
        """.replace("        ", ""),
    )

    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert plan.failed
    try:
        e.execute_dumpit_patch_plan(plan)
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected transactional failure")
    assert a.read_text(encoding="utf-8") == "a\nb\nc\n"
    assert b.read_text(encoding="utf-8") == "x\ny\nz\n"


def test_dumpit_apply_preserves_crlf(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_bytes(b"a\r\nb\r\nc\r\n")
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """
        diff --git a/src/x.txt b/src/x.txt
        --- a/src/x.txt
        +++ b/src/x.txt
        @@ -2,1 +2,1 @@
        -b
        +B
        """.replace("        ", ""),
    )

    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)
    assert not plan.failed
    e.execute_dumpit_patch_plan(plan)
    assert target.read_bytes() == b"a\r\nB\r\nc\r\n"
