from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import exporter_gui as e


class _Var:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class _Label:
    def __init__(self):
        self.values = {}

    def configure(self, **kwargs):
        self.values.update(kwargs)


def _write_project(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.txt").write_text("alpha\n", encoding="utf-8")
    (root / "src" / "b.txt").write_text("beta €\ngamma\n", encoding="utf-8")


def _export(root: Path, out: Path, *, export_format: str, header_full_path: bool = False) -> None:
    included, skipped = e.export_to_file(
        root=root,
        out_path=out,
        exclude_dirs=set(),
        patterns=["*.txt"],
        skip_binary=True,
        header_full_path=header_full_path,
        profile_name="Closure",
        export_format=export_format,
    )
    assert included == 2
    assert skipped == 0


def test_generated_standard_and_llm_exports_parse_to_identical_snapshots(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _write_project(root)
    standard = tmp_path / "standard.dump.txt"
    llm = tmp_path / "llm.dump.txt"

    _export(root, standard, export_format=e.EXPORT_FORMAT_STANDARD)
    _export(root, llm, export_format=e.EXPORT_FORMAT_LLM)

    diff = e.load_dump_diff(standard, llm)
    assert diff.added == []
    assert diff.removed == []
    assert diff.modified == []
    assert diff.unchanged == ["src/a.txt", "src/b.txt"]


def test_generated_llm_dump_import_round_trip_restores_all_text_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_project(source)
    dump = tmp_path / "source.llm.txt"
    target = tmp_path / "target"
    target.mkdir()

    _export(source, dump, export_format=e.EXPORT_FORMAT_LLM)
    plan = e.build_dump_import_plan(
        dump_path=dump,
        target_root=target,
        overwrite_existing=True,
    )
    result = e.execute_dump_import_plan(
        plan,
        overwrite_existing=True,
        backup_overwritten=True,
    )

    assert not plan.skipped
    assert result.created == 2
    assert (target / "src" / "a.txt").read_text(encoding="utf-8") == "alpha\n"
    assert (target / "src" / "b.txt").read_text(encoding="utf-8") == "beta €\ngamma\n"


def test_llm_full_path_headers_remain_importable_and_index_paths_stay_relative(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_project(source)
    dump = tmp_path / "full-path.llm.txt"
    target = tmp_path / "target"
    target.mkdir()

    _export(
        source,
        dump,
        export_format=e.EXPORT_FORMAT_LLM,
        header_full_path=True,
    )
    text = dump.read_text(encoding="utf-8")

    assert f"===== FILE: {source / 'src' / 'a.txt'} | lines=1 |" in text
    file_index = text.split("===== FILE INDEX =====\n", 1)[1].split("\n\n===== FILE:", 1)[0]
    assert " | src/a.txt | " in file_index
    assert " | src/b.txt | " in file_index
    assert str(source / "src" / "a.txt") not in file_index

    plan = e.build_dump_import_plan(
        dump_path=dump,
        target_root=target,
        overwrite_existing=True,
    )
    assert [item.rel_path for item in plan.entries] == ["src/a.txt", "src/b.txt"]
    assert not plan.skipped


def test_stable_id_is_independent_of_repository_root(tmp_path: Path) -> None:
    first_root = tmp_path / "one"
    second_root = tmp_path / "two"
    _write_project(first_root)
    _write_project(second_root)

    first, skipped_first = e.collect_export_entries(
        root=first_root,
        exclude_dirs=set(),
        patterns=["*.txt"],
        skip_binary=True,
        header_full_path=False,
    )
    second, skipped_second = e.collect_export_entries(
        root=second_root,
        exclude_dirs=set(),
        patterns=["*.txt"],
        skip_binary=True,
        header_full_path=False,
    )

    assert skipped_first == skipped_second == 0
    assert [(x.rel_path, x.stable_id) for x in first] == [
        (x.rel_path, x.stable_id) for x in second
    ]


def _batch_app(root: Path, out: Path, export_format: str) -> e.DumpItApp:
    app = object.__new__(e.DumpItApp)
    app._batch_queue = ["Closure"]
    app._batch_results = []
    app._batch_mode = "export"
    app.lbl_batch_status = _Label()
    app._read_profile_settings = lambda _name: (
        root,
        out,
        ["*.txt"],
        set(),
        True,
        False,
        False,
        10,
        export_format,
    )
    app._log = lambda _msg: None
    app.after = lambda *_args, **_kwargs: None
    return app


def test_batch_actual_export_supports_standard_and_llm(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _write_project(root)

    standard = tmp_path / "batch-standard.txt"
    standard_app = _batch_app(root, standard, e.EXPORT_FORMAT_STANDARD)
    e.DumpItApp._batch_step(standard_app)
    assert standard_app._batch_results == [("Closure", "OK")]
    assert "===== FILE INDEX =====" not in standard.read_text(encoding="utf-8")

    llm = tmp_path / "batch-llm.txt"
    llm_app = _batch_app(root, llm, e.EXPORT_FORMAT_LLM)
    e.DumpItApp._batch_step(llm_app)
    assert llm_app._batch_results == [("Closure", "OK")]
    assert "===== FILE INDEX =====" in llm.read_text(encoding="utf-8")


def _watch_app(root: Path, out: Path, export_format: str) -> e.DumpItApp:
    app = object.__new__(e.DumpItApp)
    app.project_dir = _Var(str(root))
    app.include_patterns = _Var("*.txt")
    app.exclude_dirs = _Var("")
    app.add_timestamp = _Var(False)
    app.timestamp_keep_old = _Var(e.DEFAULT_TIMESTAMP_KEEP_OLD)
    app.output_file = _Var(str(out))
    app.skip_binary = _Var(True)
    app.header_full_path = _Var(False)
    app.export_format = _Var(export_format)
    app.profile_name = _Var("Closure")
    app._save_config = lambda silent=True: None
    app._log = lambda _msg: None
    app._parse_timestamp_keep_old = lambda: 10
    app._watch_pending_export_id = "pending"
    app._watch_running = True
    app._watch_export_in_progress = False
    app._watch_profile_name = "Closure"
    app._watch_after_id = "scheduled"
    app._watch_snapshot = {}
    app._watch_last_export_summary = ""
    app._set_watch_status = lambda _status: None
    app._build_watch_snapshot = lambda: {}
    app._schedule_watch_tick = lambda: None
    return app


def test_watch_actual_export_supports_standard_and_llm(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _write_project(root)

    standard = tmp_path / "watch-standard.txt"
    standard_app = _watch_app(root, standard, e.EXPORT_FORMAT_STANDARD)
    e.DumpItApp._watch_export_now(standard_app)
    assert standard_app._watch_export_in_progress is False
    assert "===== FILE INDEX =====" not in standard.read_text(encoding="utf-8")

    llm = tmp_path / "watch-llm.txt"
    llm_app = _watch_app(root, llm, e.EXPORT_FORMAT_LLM)
    e.DumpItApp._watch_export_now(llm_app)
    assert llm_app._watch_export_in_progress is False
    llm_output = llm.with_name("watch-llm_LLM.txt")
    assert "===== FILE INDEX =====" in llm_output.read_text(encoding="utf-8")


def test_llm_index_metadata_matches_generated_payload(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _write_project(root)
    dump = tmp_path / "llm.txt"

    _export(root, dump, export_format=e.EXPORT_FORMAT_LLM)
    entries, skipped = e.collect_export_entries(
        root=root,
        exclude_dirs=set(),
        patterns=["*.txt"],
        skip_binary=True,
        header_full_path=False,
        exclude_files={e.canon_path(dump)},
    )
    assert skipped == 0
    text = dump.read_text(encoding="utf-8")

    for entry in entries:
        expected = (
            f"{entry.stable_id} | {entry.rel_path} | ext={entry.extension} | "
            f"bytes={entry.byte_count} | lines={entry.line_count} | sha256={entry.content_sha256}"
        )
        assert expected in text
        assert (
            f"===== FILE: {entry.rel_path} | lines={entry.line_count} | id={entry.stable_id} | "
            f"bytes={entry.byte_count} | sha256={entry.content_sha256} |"
        ) in text
