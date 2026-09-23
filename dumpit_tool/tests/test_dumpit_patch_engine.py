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


def test_dumpit_apply_lf_patch_matches_crlf_utf8_bom_target(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_bytes(b"\xef\xbb\xbfa\r\nb\r\nc\r\n")
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
    assert plan.files[0].encoding == "utf-8-sig"
    assert plan.files[0].newline == "\r\n"
    e.execute_dumpit_patch_plan(plan)
    assert target.read_bytes() == b"\xef\xbb\xbfa\r\nB\r\nc\r\n"


def test_dumpit_apply_ignores_trailing_whitespace_during_matching(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_bytes(b"a  \r\nb\t\r\nc \r\n")
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
    assert plan.files[0].hunk_results[0].status in {
        e.DUMPIT_PATCH_STATUS_APPLICABLE_EXACT,
        e.DUMPIT_PATCH_STATUS_APPLICABLE_RELOCATED,
    }
    e.execute_dumpit_patch_plan(plan)
    raw = target.read_bytes()
    assert b"\r\n" in raw
    assert b"\n" not in raw.replace(b"\r\n", b"")
    assert target.read_text(encoding="utf-8").splitlines() == ["a", "B", "c"]


def test_dumpit_already_applied_uses_same_trailing_whitespace_normalization(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    original = b"a  \r\nB\t\r\nc \r\n"
    target.write_bytes(original)
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
    assert plan.changed_files == 0
    assert plan.files[0].hunk_results[0].status == e.DUMPIT_PATCH_STATUS_ALREADY_APPLIED
    e.execute_dumpit_patch_plan(plan)
    assert target.read_bytes() == original


def test_dumpit_preview_and_apply_use_the_same_matcher(tmp_path: Path) -> None:
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

    preview_plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)
    preview_diff = e.dumpit_patch_plan_to_diff(preview_plan)
    apply_plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert not preview_plan.failed
    assert not apply_plan.failed
    assert preview_plan.files[0].hunk_results == apply_plan.files[0].hunk_results
    assert preview_diff.modified
    e.execute_dumpit_patch_plan(apply_plan)
    assert target.read_text(encoding="utf-8") == "header\na\nB\nc\n"


def test_dumpit_failed_not_found_reports_real_match_diagnostics(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_bytes(
        b"before\n\n"
        b"existing indirect feature with different operational scope\n\n"
        b"after\n"
    )
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        (
            "diff --git a/src/x.txt b/src/x.txt\n"
            "--- a/src/x.txt\n"
            "+++ b/src/x.txt\n"
            "@@ -1,3 +1,5 @@\n"
            " before\n"
            " \n"
            "+intended indirect feature with passenger-security topology\n"
            "+\n"
            " after\n"
        ),
    )

    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert plan.failed
    hunk = plan.files[0].hunk_results[0]
    assert hunk.status == e.DUMPIT_PATCH_STATUS_FAILED_NOT_FOUND
    detail = e._dumpit_patch_plan_failure_detail(plan, 8)
    assert "src/x.txt hunk 1" in detail
    assert "expected_start=1" in detail
    assert "newline=LF" in detail
    assert "encoding=utf-8" in detail
    assert "bom=no" in detail
    assert "old_head=" in detail
    assert "old_tail=" in detail
    assert "best_candidate_start=" in detail
    assert "similarity=" in detail
    assert "mismatch=text_different" in detail


def test_dumpit_safe_context_fallback_applies_unique_minor_removed_line_drift(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_text(
        "before\n"
        "configuration_mode = \"strcit\"\n"
        "after\n",
        encoding="utf-8",
    )
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """
        diff --git a/src/x.txt b/src/x.txt
        --- a/src/x.txt
        +++ b/src/x.txt
        @@ -1,3 +1,3 @@
         before
        -configuration_mode = "strict"
        +configuration_mode = "hardened"
         after
        """.replace("        ", ""),
    )

    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert not plan.failed
    hunk = plan.files[0].hunk_results[0]
    assert hunk.status == e.DUMPIT_PATCH_STATUS_APPLICABLE_CONTEXT_FUZZY
    assert "similarity=" in hunk.detail
    e.execute_dumpit_patch_plan(plan)
    assert target.read_text(encoding="utf-8") == (
        "before\nconfiguration_mode = \"hardened\"\nafter\n"
    )


def test_dumpit_safe_context_fallback_refuses_ambiguous_candidates(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_text(
        "before\nconfiguration_mode = \"strcit\"\nafter\n"
        "separator\n"
        "before\nconfiguration_mode = \"strcit\"\nafter\n",
        encoding="utf-8",
    )
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """
        diff --git a/src/x.txt b/src/x.txt
        --- a/src/x.txt
        +++ b/src/x.txt
        @@ -20,3 +20,3 @@
         before
        -configuration_mode = "strict"
        +configuration_mode = "hardened"
         after
        """.replace("        ", ""),
    )

    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert plan.failed
    hunk = plan.files[0].hunk_results[0]
    assert hunk.status == e.DUMPIT_PATCH_STATUS_FAILED_AMBIGUOUS
    assert "safe context fallback matched 2 candidates" in hunk.detail


def test_dumpit_safe_positional_fuzzy_fallback_preserves_drifted_context(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_text(
        "header version 1234567891\n"
        "old value = alpha\n"
        "footer\n",
        encoding="utf-8",
    )
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """
        diff --git a/src/x.txt b/src/x.txt
        --- a/src/x.txt
        +++ b/src/x.txt
        @@ -1,3 +1,3 @@
         header version 1234567890
        -old value = alpha
        +new value = beta
         footer
        """.replace("        ", ""),
    )

    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert not plan.failed
    hunk = plan.files[0].hunk_results[0]
    assert hunk.status == e.DUMPIT_PATCH_STATUS_APPLICABLE_FUZZY_POSITIONAL
    assert hunk.line_no == 1
    e.execute_dumpit_patch_plan(plan)
    assert target.read_text(encoding="utf-8") == (
        "header version 1234567891\n"
        "new value = beta\n"
        "footer\n"
    )


def test_dumpit_safe_fuzzy_fallback_does_not_cross_bounded_position_window(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    filler = "\n".join(f"filler-{idx}" for idx in range(100)) + "\n"
    target.write_text(
        filler
        + "header version 1234567891\n"
        + "old value = alpha\n"
        + "footer\n",
        encoding="utf-8",
    )
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """
        diff --git a/src/x.txt b/src/x.txt
        --- a/src/x.txt
        +++ b/src/x.txt
        @@ -1,3 +1,3 @@
         header version 1234567890
        -old value = alpha
        +new value = beta
         footer
        """.replace("        ", ""),
    )

    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert plan.failed
    assert plan.files[0].hunk_results[0].status == e.DUMPIT_PATCH_STATUS_FAILED_NOT_FOUND


def test_dumpit_safe_fuzzy_fallback_does_not_apply_conflicting_insertion_between_context_anchors(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_text(
        "before\n\n"
        "existing indirect feature with different operational scope\n\n"
        "after\n",
        encoding="utf-8",
    )
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        (
            "diff --git a/src/x.txt b/src/x.txt\n"
            "--- a/src/x.txt\n"
            "+++ b/src/x.txt\n"
            "@@ -1,3 +1,5 @@\n"
            " before\n"
            " \n"
            "+intended indirect feature with passenger-security topology\n"
            "+\n"
            " after\n"
        ),
    )


    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert plan.failed
    hunk = plan.files[0].hunk_results[0]
    assert hunk.status == e.DUMPIT_PATCH_STATUS_FAILED_NOT_FOUND
    assert target.read_text(encoding="utf-8") == (
        "before\n\nexisting indirect feature with different operational scope\n\nafter\n"
    )


def test_dumpit_safe_context_fallback_rejects_semantic_clause_drift_even_with_high_similarity(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "x.txt"
    target.write_text(
        "before\n"
        "Examples include a newly established deployment or retrieval advantage, alternative spawn / retrieval surface eligibility, pad-access distinction, capability-realization constraint, supported configuration, recurring workflow advantage, acquisition / access distinction, hidden practical limitation or competitor difference that changes the autonomous buying case.\n"
        "after\n",
        encoding="utf-8",
    )
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """
        diff --git a/src/x.txt b/src/x.txt
        --- a/src/x.txt
        +++ b/src/x.txt
        @@ -1,3 +1,3 @@
         before
        -Examples include a newly established deployment or retrieval advantage, pad-access distinction, capability-realization constraint, supported configuration, recurring workflow advantage, acquisition / access distinction, hidden practical limitation or competitor difference that changes the autonomous buying case.
        +Examples include a newly established deployment or retrieval advantage, size-class-dependent vehicle-pad / Platinum Bay eligibility, secure seated-passenger transport, pad-access distinction, capability-realization constraint, supported configuration, recurring workflow advantage, acquisition / access distinction, hidden practical limitation or competitor difference that changes the autonomous buying case.
         after
        """.replace("        ", ""),
    )

    plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)

    assert plan.failed
    hunk = plan.files[0].hunk_results[0]
    assert hunk.status == e.DUMPIT_PATCH_STATUS_FAILED_NOT_FOUND
    assert "mismatch=text_different" in hunk.detail


def test_dumpit_git_compatible_count_driven_parser_accepts_physical_blank_context_lines(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "specialization_prewarm.rs"
    lines = [f"filler-{idx}" for idx in range(1, 281)]

    replacements = {
        189: [
            "        };",
            "        let future_entries = future_cache",
            "            .iter()",
            "            .map(|(entity, (_tick, pipeline_id))| (*entity, pipeline_id.id()))",
            "            .collect::<Vec<_>>();",
            "        snapshots.push(ShadowSpecializationResidualViewSnapshot {",
            "            cascade_index: usize::try_from(planned.future_view.subview_index)",
        ],
        229: [
            "        let template_cache = shadow_material_cache.get(&snapshot.template_view);",
            "        let mut view_added = 0usize;",
            "",
            "        for (entity, (_tick, after_pipeline_id)) in after_cache.iter() {",
            "            let after_pipeline_id = after_pipeline_id.id();",
            "            let before_pipeline_id = snapshot",
            "                .future_entries",
        ],
        253: [
            "",
            "            let template_pipeline_id = template_cache",
            "                .and_then(|cache| cache.get(entity))",
            "                .map(|(_tick, pipeline_id)| pipeline_id.id());",
            "            let template_present = template_pipeline_id.is_some();",
            "            let template_pipeline_same = template_pipeline_id == Some(after_pipeline_id);",
            "            if change_kind == 1 {",
        ],
        271: [
            "                C8_4D_RESIDUAL_ENTRY_EVENT,",
            "                c8_4d_residual_entry_values(",
            "                    snapshot.cascade_index,",
            "                    entity.id().index(),",
            "                    change_kind,",
            "                    template_present,",
            "                    template_pipeline_same,",
        ],
    }
    for start, block in replacements.items():
        lines[start - 1 : start - 1 + len(block)] = block

    original_bytes = ("\r\n".join(lines) + "\r\n").encode("utf-8")
    target.write_bytes(original_bytes)

    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """diff --git a/src/specialization_prewarm.rs b/src/specialization_prewarm.rs
--- a/src/specialization_prewarm.rs
+++ b/src/specialization_prewarm.rs
@@ -189,7 +189,7 @@
         };
         let future_entries = future_cache
             .iter()
-            .map(|(entity, (_tick, pipeline_id))| (*entity, pipeline_id.id()))
+            .map(|(entity, (pipeline_id, _draw_function_id))| (*entity, pipeline_id.id()))
             .collect::<Vec<_>>();
         snapshots.push(ShadowSpecializationResidualViewSnapshot {
             cascade_index: usize::try_from(planned.future_view.subview_index)
@@ -229,7 +229,7 @@
         let template_cache = shadow_material_cache.get(&snapshot.template_view);
         let mut view_added = 0usize;

-        for (entity, (_tick, after_pipeline_id)) in after_cache.iter() {
+        for (entity, (after_pipeline_id, _draw_function_id)) in after_cache.iter() {
             let after_pipeline_id = after_pipeline_id.id();
             let before_pipeline_id = snapshot
                 .future_entries
@@ -253,7 +253,7 @@

             let template_pipeline_id = template_cache
                 .and_then(|cache| cache.get(entity))
-                .map(|(_tick, pipeline_id)| pipeline_id.id());
+                .map(|(pipeline_id, _draw_function_id)| pipeline_id.id());
             let template_present = template_pipeline_id.is_some();
             let template_pipeline_same = template_pipeline_id == Some(after_pipeline_id);
             if change_kind == 1 {
@@ -271,7 +271,7 @@
                 C8_4D_RESIDUAL_ENTRY_EVENT,
                 c8_4d_residual_entry_values(
                     snapshot.cascade_index,
-                    entity.id().index(),
+                    entity.id().index_u32(),
                     change_kind,
                     template_present,
                     template_pipeline_same,
""",
    )

    parsed = e.parse_unified_patch(patch)
    assert len(parsed) == 1
    assert len(parsed[0].hunks) == 4
    assert parsed[0].hunks[1].lines[2] == " "
    assert parsed[0].hunks[2].lines[0] == " "

    preview_plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)
    assert not preview_plan.failed
    assert preview_plan.total_hunks == 4
    assert all(not h.failed for h in preview_plan.files[0].hunk_results)

    apply_plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)
    assert apply_plan.files[0].hunk_results == preview_plan.files[0].hunk_results
    e.execute_dumpit_patch_plan(apply_plan)
    assert target.read_bytes().count(b"\r\n") == 280
    applied_text = target.read_text(encoding="utf-8")
    assert ".map(|(entity, (pipeline_id, _draw_function_id))| (*entity, pipeline_id.id()))" in applied_text
    assert "for (entity, (after_pipeline_id, _draw_function_id)) in after_cache.iter()" in applied_text
    assert ".map(|(pipeline_id, _draw_function_id)| pipeline_id.id());" in applied_text
    assert "entity.id().index_u32()," in applied_text

    already_plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=False)
    assert not already_plan.failed
    assert all(
        h.status == e.DUMPIT_PATCH_STATUS_ALREADY_APPLIED
        for h in already_plan.files[0].hunk_results
    )

    reverse_plan = e.build_dumpit_patch_plan(root=tmp_path, patch_path=patch, strip_level=1, reverse=True)
    assert not reverse_plan.failed
    e.execute_dumpit_patch_plan(reverse_plan)
    assert target.read_bytes() == original_bytes


def test_dumpit_count_driven_parser_rejects_truncated_hunk_instead_of_silently_parsing_it(tmp_path: Path) -> None:
    patch = tmp_path / "p.patch"
    _write_patch(
        patch,
        """diff --git a/src/x.txt b/src/x.txt
--- a/src/x.txt
+++ b/src/x.txt
@@ -1,3 +1,3 @@
 a
-b
+B
""",
    )

    try:
        e.parse_unified_patch(patch)
    except ValueError as exc:
        assert "declared line counts were not satisfied" in str(exc)
    else:
        raise AssertionError("expected truncated hunk to be rejected")


def test_dumpit_count_driven_parser_does_not_guess_unprefixed_blank_as_one_sided_change(tmp_path: Path) -> None:
    patch = tmp_path / "p.patch"
    patch.write_text(
        "diff --git a/src/x.txt b/src/x.txt\n"
        "--- a/src/x.txt\n"
        "+++ b/src/x.txt\n"
        "@@ -1,0 +1,1 @@\n"
        "\n",
        encoding="utf-8",
        newline="",
    )

    try:
        e.parse_unified_patch(patch)
    except ValueError as exc:
        assert "physical blank line cannot satisfy only one side" in str(exc)
    else:
        raise AssertionError("expected ambiguous physical blank to be rejected")
