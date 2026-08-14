from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import exporter_gui as e


def _write_patch(path: Path, text: str) -> None:
    path.write_text(text.strip() + "\n", encoding="utf-8")


def _write_treehouse_scaffold_patch(path: Path) -> None:
    _write_patch(
        path,
        """
        diff --git a/BRIDGES/README.md b/BRIDGES/README.md
        new file mode 100644
        --- /dev/null
        +++ b/BRIDGES/README.md
        @@ -0,0 +1 @@
        +bridges
        diff --git a/HOUSES/README.md b/HOUSES/README.md
        new file mode 100644
        --- /dev/null
        +++ b/HOUSES/README.md
        @@ -0,0 +1 @@
        +houses
        diff --git a/WAREHOUSE/README.md b/WAREHOUSE/README.md
        new file mode 100644
        --- /dev/null
        +++ b/WAREHOUSE/README.md
        @@ -0,0 +1 @@
        +warehouse
        diff --git a/tests/test_example.py b/tests/test_example.py
        new file mode 100644
        --- /dev/null
        +++ b/tests/test_example.py
        @@ -0,0 +1 @@
        +def test_example(): pass
        """.replace("        ", ""),
    )


def test_patch_mapping_rejects_treehouse_many_to_one_strip_collapse(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "README.md").write_bytes(b"root-readme\n")
    patch = tmp_path / "th1.patch"
    _write_treehouse_scaffold_patch(patch)

    mapping = e.resolve_patch_target_mapping(
        root=tmp_path,
        patch_path=patch,
        strip_level=1,
        reverse=False,
    )
    assert [item.rel_path for item in mapping] == [
        "BRIDGES/README.md",
        "HOUSES/README.md",
        "WAREHOUSE/README.md",
        "tests/test_example.py",
    ]

    try:
        e.resolve_patch_target_mapping(
            root=tmp_path,
            patch_path=patch,
            strip_level=2,
            reverse=False,
        )
    except ValueError as exc:
        assert "multiple patch files resolve to the same target" in str(exc)
        assert "README.md" in str(exc)
    else:
        raise AssertionError("-p2 many-to-one mapping must be rejected")


def test_dumpit_auto_detect_selects_p1_for_treehouse_scaffold(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "README.md").write_text("root-readme\n", encoding="utf-8")
    patch = tmp_path / "th1.patch"
    _write_treehouse_scaffold_patch(patch)

    resolved = e.detect_dumpit_apply_plan(
        profile_root=tmp_path,
        patch_path=patch,
        preferred_strip_level=1,
        reverse=False,
    )

    assert resolved.root == tmp_path
    assert resolved.strip_level == 1
    assert resolved.patch_directory is None
    assert not resolved.plan.failed
    assert resolved.plan.changed_files == 4
    assert any("INVALID" in attempt and "-p2" in attempt for attempt in resolved.attempts)


def test_git_auto_detect_selects_p1_for_treehouse_scaffold(tmp_path: Path) -> None:
    if e.shutil.which("git") is None:
        return
    (tmp_path / "tests").mkdir()
    (tmp_path / "README.md").write_text("root-readme\n", encoding="utf-8")
    patch = tmp_path / "th1.patch"
    _write_treehouse_scaffold_patch(patch)

    resolved = e.detect_git_apply_plan(
        profile_root=tmp_path,
        patch_path=patch,
        preferred_strip_level=1,
        reverse=False,
    )

    assert resolved.root == tmp_path
    assert resolved.strip_level == 1
    assert resolved.patch_directory is None
    assert any("INVALID" in attempt and "-p2" in attempt for attempt in resolved.attempts)


def test_dumpit_treehouse_forward_reverse_preserves_root_readme(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    root_readme = tmp_path / "README.md"
    root_readme.write_bytes(b"root-readme\n")
    root_before = root_readme.read_bytes()
    patch = tmp_path / "th1.patch"
    _write_treehouse_scaffold_patch(patch)

    forward = e.build_dumpit_patch_plan(
        root=tmp_path,
        patch_path=patch,
        strip_level=1,
        reverse=False,
    )
    assert not forward.failed
    e.execute_dumpit_patch_plan(forward)

    assert (tmp_path / "BRIDGES" / "README.md").read_text(encoding="utf-8") == "bridges\n"
    assert (tmp_path / "HOUSES" / "README.md").read_text(encoding="utf-8") == "houses\n"
    assert (tmp_path / "WAREHOUSE" / "README.md").read_text(encoding="utf-8") == "warehouse\n"
    assert (tmp_path / "tests" / "test_example.py").is_file()
    assert root_readme.read_bytes() == root_before

    reverse = e.build_dumpit_patch_plan(
        root=tmp_path,
        patch_path=patch,
        strip_level=1,
        reverse=True,
    )
    assert not reverse.failed
    e.execute_dumpit_patch_plan(reverse)

    assert not (tmp_path / "BRIDGES" / "README.md").exists()
    assert not (tmp_path / "HOUSES" / "README.md").exists()
    assert not (tmp_path / "WAREHOUSE" / "README.md").exists()
    assert not (tmp_path / "tests" / "test_example.py").exists()
    assert root_readme.read_bytes() == root_before


def test_patch_receipt_reuses_forward_resolution_and_rejects_drift(tmp_path: Path) -> None:
    old_xdg = e.os.environ.get("XDG_CONFIG_HOME")
    e.os.environ["XDG_CONFIG_HOME"] = str(tmp_path / "config")
    try:
        target = tmp_path / "project"
        target.mkdir()
        (target / "tests").mkdir()
        (target / "README.md").write_text("root-readme\n", encoding="utf-8")
        patch = tmp_path / "th1.patch"
        _write_treehouse_scaffold_patch(patch)
        mapping = e.resolve_patch_target_mapping(
            root=target, patch_path=patch, strip_level=1, reverse=False
        )
        resolution = e.PatchOperationResolution(
            engine="dumpit",
            patch_path=patch,
            patch_sha256=e._patch_sha256(patch),
            requested_root=target,
            requested_strip_level=1,
            reverse=False,
            auto_detect=True,
            root=target,
            strip_level=1,
            patch_directory=None,
            mapping=mapping,
            attempts=(),
        )
        pre_state = e._snapshot_patch_resolution_state(
            root=target, patch_path=patch, strip_level=1, patch_directory=None, containment_root=target
        )
        plan = e.build_dumpit_patch_plan(
            root=target, patch_path=patch, strip_level=1, reverse=False
        )
        e.execute_dumpit_patch_plan(plan)
        post_state = e._snapshot_patch_resolution_state(
            root=target, patch_path=patch, strip_level=1, patch_directory=None, containment_root=target
        )
        receipt_path = e._save_patch_apply_receipt(
            resolution, pre_state=pre_state, post_state=post_state
        )
        assert receipt_path.is_file()

        reverse_resolution, loaded_path, receipt = e._resolution_from_receipt(
            patch_path=patch,
            requested_root=target,
            requested_strip_level=99,
            engine="dumpit",
        )
        assert loaded_path == receipt_path
        assert reverse_resolution.strip_level == 1
        assert reverse_resolution.root == target
        assert receipt["resolved_strip"] == 1

        (target / "BRIDGES" / "README.md").write_text("drift\n", encoding="utf-8")
        try:
            e._resolution_from_receipt(
                patch_path=patch,
                requested_root=target,
                requested_strip_level=1,
                engine="dumpit",
            )
        except RuntimeError as exc:
            assert "does not match the recorded post-Apply state" in str(exc)
        else:
            raise AssertionError("drifted filesystem must refuse automatic reverse")
    finally:
        if old_xdg is None:
            e.os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            e.os.environ["XDG_CONFIG_HOME"] = old_xdg


def test_plain_unified_diff_maps_one_file_not_two(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_text("a\n", encoding="utf-8")
    patch = tmp_path / "plain.patch"
    _write_patch(
        patch,
        """
        --- a/src/x.txt
        +++ b/src/x.txt
        @@ -1 +1 @@
        -a
        +b
        """.replace("        ", ""),
    )

    mapping = e.resolve_patch_target_mapping(
        root=tmp_path, patch_path=patch, strip_level=1, reverse=False
    )
    assert len(mapping) == 1
    assert mapping[0].rel_path == "src/x.txt"


def test_candidate_mapping_cannot_escape_selected_target_via_parent_cwd(tmp_path: Path) -> None:
    selected = tmp_path / "selected"
    selected.mkdir()
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """
        diff --git a/outside.txt b/outside.txt
        new file mode 100644
        --- /dev/null
        +++ b/outside.txt
        @@ -0,0 +1 @@
        +x
        """.replace("        ", ""),
    )

    try:
        e.resolve_patch_target_mapping(
            root=tmp_path,
            patch_path=patch,
            strip_level=1,
            reverse=False,
            containment_root=selected,
        )
    except ValueError as exc:
        assert "outside selected target" in str(exc)
    else:
        raise AssertionError("candidate cwd must not allow writes outside selected target")


def test_auto_detect_keeps_canonical_p1_when_nested_and_basename_both_match(tmp_path: Path) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "x.txt").write_text("old\n", encoding="utf-8")
    (tmp_path / "x.txt").write_text("old\n", encoding="utf-8")
    patch = tmp_path / "nested.patch"
    _write_patch(
        patch,
        """
        diff --git a/nested/x.txt b/nested/x.txt
        --- a/nested/x.txt
        +++ b/nested/x.txt
        @@ -1 +1 @@
        -old
        +new
        """.replace("        ", ""),
    )

    dumpit_plan = e.detect_dumpit_apply_plan(
        profile_root=tmp_path,
        patch_path=patch,
        preferred_strip_level=1,
        reverse=False,
    )
    assert dumpit_plan.strip_level == 1
    assert dumpit_plan.plan.files[0].rel_path == "nested/x.txt"

    if e.shutil.which("git") is not None:
        git_plan = e.detect_git_apply_plan(
            profile_root=tmp_path,
            patch_path=patch,
            preferred_strip_level=1,
            reverse=False,
        )
        assert git_plan.strip_level == 1


def test_git_treehouse_forward_reverse_preserves_root_readme(tmp_path: Path) -> None:
    if e.shutil.which("git") is None:
        return
    (tmp_path / "tests").mkdir()
    root_readme = tmp_path / "README.md"
    root_readme.write_bytes(b"root-readme\n")
    root_before = root_readme.read_bytes()
    patch = tmp_path / "th1.patch"
    _write_treehouse_scaffold_patch(patch)

    check_ok, check_output = e.run_git_apply_patch(
        root=tmp_path,
        patch_path=patch,
        strip_level=1,
        reverse=False,
        check_only=True,
    )
    assert check_ok, check_output
    apply_ok, apply_output = e.run_git_apply_patch(
        root=tmp_path,
        patch_path=patch,
        strip_level=1,
        reverse=False,
        check_only=False,
    )
    assert apply_ok, apply_output
    assert (tmp_path / "BRIDGES" / "README.md").is_file()
    assert (tmp_path / "HOUSES" / "README.md").is_file()
    assert (tmp_path / "WAREHOUSE" / "README.md").is_file()
    assert (tmp_path / "tests" / "test_example.py").is_file()
    assert root_readme.read_bytes() == root_before

    reverse_check_ok, reverse_check_output = e.run_git_apply_patch(
        root=tmp_path,
        patch_path=patch,
        strip_level=1,
        reverse=True,
        check_only=True,
    )
    assert reverse_check_ok, reverse_check_output
    reverse_ok, reverse_output = e.run_git_apply_patch(
        root=tmp_path,
        patch_path=patch,
        strip_level=1,
        reverse=True,
        check_only=False,
    )
    assert reverse_ok, reverse_output
    assert not (tmp_path / "BRIDGES" / "README.md").exists()
    assert not (tmp_path / "HOUSES" / "README.md").exists()
    assert not (tmp_path / "WAREHOUSE" / "README.md").exists()
    assert not (tmp_path / "tests" / "test_example.py").exists()
    assert root_readme.read_bytes() == root_before


def test_auto_detect_rejects_create_candidate_that_hits_existing_basename(tmp_path: Path) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "README.md").write_text("root\n", encoding="utf-8")
    patch = tmp_path / "create.patch"
    _write_patch(
        patch,
        """
        diff --git a/nested/README.md b/nested/README.md
        new file mode 100644
        --- /dev/null
        +++ b/nested/README.md
        @@ -0,0 +1 @@
        +nested
        """.replace("        ", ""),
    )

    try:
        e.resolve_patch_target_mapping(
            root=tmp_path,
            patch_path=patch,
            strip_level=2,
            reverse=False,
            reject_existing_creates=True,
        )
    except ValueError as exc:
        assert "create-file patch maps onto an existing target" in str(exc)
    else:
        raise AssertionError("existing basename must invalidate create auto-detect candidate")

    resolved = e.detect_dumpit_apply_plan(
        profile_root=tmp_path,
        patch_path=patch,
        preferred_strip_level=1,
        reverse=False,
    )
    assert resolved.strip_level == 1
    assert any("INVALID" in attempt and "-p2" in attempt for attempt in resolved.attempts)
