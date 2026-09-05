from __future__ import annotations

import configparser
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


def _app_with_profile_config(tmp_path: Path, *, export_format: str | None) -> e.DumpItApp:
    app = object.__new__(e.DumpItApp)
    app._cp = configparser.ConfigParser()
    section = "profile:Example"
    app._cp[section] = {
        "project_dir": str(tmp_path / "project"),
        "output_file": str(tmp_path / "out.txt"),
        "include_patterns": "*.txt",
        "exclude_dirs": ".git",
        "add_timestamp": "False",
        "timestamp_keep_old": "10",
        "skip_binary": "True",
        "header_full_path": "False",
    }
    if export_format is not None:
        app._cp[section]["export_format"] = export_format
    return app


def test_export_format_normalization_defaults_legacy_configs_to_standard() -> None:
    assert e.normalize_export_format("") == e.EXPORT_FORMAT_STANDARD
    assert e.normalize_export_format("STANDARD") == e.EXPORT_FORMAT_STANDARD
    assert e.normalize_export_format("llm") == e.EXPORT_FORMAT_LLM
    assert e.normalize_export_format("future-format") == e.EXPORT_FORMAT_STANDARD

    try:
        e.normalize_export_format("future-format", strict=True)
    except ValueError as exc:
        assert "Unsupported export format" in str(exc)
    else:
        raise AssertionError("strict normalization must reject unknown formats")


def test_output_path_suffix_is_llm_only_and_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    raw = tmp_path / "DumpIt.txt"

    standard = e.resolve_export_output_path(root, str(raw), False, e.EXPORT_FORMAT_STANDARD)
    llm = e.resolve_export_output_path(root, str(raw), False, e.EXPORT_FORMAT_LLM)
    llm_again = e.resolve_export_output_path(root, str(llm), False, e.EXPORT_FORMAT_LLM)

    assert standard.name == "DumpIt.txt"
    assert llm.name == "DumpIt_LLM.txt"
    assert llm_again.name == "DumpIt_LLM.txt"


def test_llm_suffix_precedes_timestamp() -> None:
    raw = Path("DumpIt_2026-09-05_113000.txt")
    suffixed = e.apply_export_format_output_suffix(raw, e.EXPORT_FORMAT_LLM)
    assert suffixed.name == "DumpIt_LLM_2026-09-05_113000.txt"


def test_output_exclusion_covers_standard_and_llm_variants(tmp_path: Path) -> None:
    standard = tmp_path / "DumpIt.txt"
    llm = tmp_path / "DumpIt_LLM.txt"
    standard.write_text("standard", encoding="utf-8")
    llm.write_text("llm", encoding="utf-8")

    excluded_from_standard = e.build_output_exclude_files(standard, False)
    excluded_from_llm = e.build_output_exclude_files(llm, False)

    expected = {e.canon_path(standard), e.canon_path(llm)}
    assert expected <= excluded_from_standard
    assert expected <= excluded_from_llm


def test_batch_profile_settings_read_llm_and_legacy_standard(tmp_path: Path) -> None:
    (tmp_path / "project").mkdir()

    llm_app = _app_with_profile_config(tmp_path, export_format="llm")
    llm_settings = e.DumpItApp._read_profile_settings(llm_app, "Example")
    assert llm_settings[-1] == e.EXPORT_FORMAT_LLM
    assert llm_settings[1].name == "out_LLM.txt"

    legacy_app = _app_with_profile_config(tmp_path, export_format=None)
    legacy_settings = e.DumpItApp._read_profile_settings(legacy_app, "Example")
    assert legacy_settings[-1] == e.EXPORT_FORMAT_STANDARD
    assert legacy_settings[1].name == "out.txt"


def test_run_export_forwards_current_profile_format(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    out = tmp_path / "out.txt"

    app = object.__new__(e.DumpItApp)
    app.project_dir = _Var(str(root))
    app.include_patterns = _Var("*.txt")
    app.exclude_dirs = _Var("")
    app.add_timestamp = _Var(False)
    app.timestamp_keep_old = _Var(e.DEFAULT_TIMESTAMP_KEEP_OLD)
    app.output_file = _Var(str(out))
    app.skip_binary = _Var(True)
    app.header_full_path = _Var(False)
    app.export_format = _Var("llm")
    app.profile_name = _Var("Example")
    app._save_config = lambda silent=True: None
    app._log = lambda _msg: None

    captured = {}

    def fake_export_to_file(**kwargs):
        captured.update(kwargs)
        return 0, 0

    monkeypatch.setattr(e, "export_to_file", fake_export_to_file)

    included, skipped, resolved_out = e.DumpItApp._run_export(app, show_message=False)

    assert (included, skipped) == (0, 0)
    assert resolved_out == out.with_name("out_LLM.txt").resolve()
    assert captured["out_path"] == resolved_out
    assert captured["export_format"] == e.EXPORT_FORMAT_LLM


def test_batch_export_forwards_saved_profile_format(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    out = tmp_path / "out.txt"

    app = object.__new__(e.DumpItApp)
    app._batch_queue = ["Example"]
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
        e.EXPORT_FORMAT_LLM,
    )
    app._log = lambda _msg: None
    app.after = lambda *_args, **_kwargs: None

    captured = {}

    def fake_export_to_file(**kwargs):
        captured.update(kwargs)
        return 0, 0

    monkeypatch.setattr(e, "export_to_file", fake_export_to_file)

    e.DumpItApp._batch_step(app)

    assert app._batch_results == [("Example", "OK")]
    assert captured["export_format"] == e.EXPORT_FORMAT_LLM


def _attach_profile_vars(app: e.DumpItApp, tmp_path: Path) -> None:
    app.project_dir = _Var(str(tmp_path / "project"))
    app.output_file = _Var(str(tmp_path / "out.txt"))
    app.import_dump_file = _Var("")
    app.import_target_dir = _Var(str(tmp_path / "project"))
    app.import_overwrite = _Var(True)
    app.import_backup = _Var(True)
    app.include_patterns = _Var("*.txt")
    app.exclude_dirs = _Var(".git")
    app.add_timestamp = _Var(False)
    app.timestamp_keep_old = _Var(e.DEFAULT_TIMESTAMP_KEEP_OLD)
    app.skip_binary = _Var(True)
    app.header_full_path = _Var(False)
    app.export_format = _Var(e.EXPORT_FORMAT_LLM)
    app.watch_poll_ms = _Var("1500")
    app.watch_quiet_ms = _Var("1200")
    app.watch_export_on_start = _Var(True)
    app.patch_file = _Var("")
    app.patch_target_dir = _Var(str(tmp_path / "project"))
    app.patch_strip_level = _Var("1")
    app.patch_reverse = _Var(False)
    app.patch_backup = _Var(True)
    app.patch_auto_detect = _Var(True)
    app.patch_engine = _Var("dumpit")


def test_profile_write_persists_llm_format(tmp_path: Path) -> None:
    app = object.__new__(e.DumpItApp)
    app._cp = configparser.ConfigParser()
    _attach_profile_vars(app, tmp_path)

    e.DumpItApp._write_ui_to_profile(app, "Example")

    assert app._cp["profile:Example"]["export_format"] == e.EXPORT_FORMAT_LLM


def test_profile_load_restores_llm_and_legacy_defaults_standard(tmp_path: Path) -> None:
    app = object.__new__(e.DumpItApp)
    app._cp = configparser.ConfigParser()
    _attach_profile_vars(app, tmp_path)
    app._loading_ui = False
    app._ensure_output_default = lambda: None
    app._normalize_patch_engine = lambda value: value

    base = {
        "project_dir": str(tmp_path / "project"),
        "output_file": str(tmp_path / "out.txt"),
        "include_patterns": "*.txt",
        "exclude_dirs": ".git",
        "add_timestamp": "False",
        "timestamp_keep_old": "10",
        "skip_binary": "True",
        "header_full_path": "False",
    }
    app._cp["profile:LLM"] = dict(base, export_format="llm")
    app._cp["profile:Legacy"] = base

    e.DumpItApp._apply_profile_to_ui(app, "LLM")
    assert app.export_format.get() == e.EXPORT_FORMAT_LLM

    e.DumpItApp._apply_profile_to_ui(app, "Legacy")
    assert app.export_format.get() == e.EXPORT_FORMAT_STANDARD
