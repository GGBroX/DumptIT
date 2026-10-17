"""XZ envelope regression coverage: no change to the logical dump format."""
from __future__ import annotations

import configparser
import hashlib
import lzma
from datetime import datetime
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
        self.value = ""

    def configure(self, **kw):
        self.value = kw.get("text", self.value)


def _source(tmp_path):
    root = tmp_path / "source"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("print('€')\n", encoding="utf-8")
    (root / "src" / "b.py").write_text("value=42\n" * 500, encoding="utf-8")
    return root


def _export(root, output, *, fmt="llm", compression="none", level=6):
    return e.export_to_file(
        root=root, out_path=output, exclude_dirs=set(), patterns=["*.py"],
        skip_binary=True, header_full_path=False, profile_name="Test",
        export_format=fmt, compression=compression, xz_level=level,
        exclude_files=e.build_output_exclude_files(output, False),
    )


def test_xz_roundtrip_matches_plain_dump_in_both_formats(tmp_path):
    root = _source(tmp_path)
    for fmt in ("standard", "llm"):
        plain = tmp_path / f"{fmt}.txt"
        xz = tmp_path / f"{fmt}.txt.xz"
        assert _export(root, plain, fmt=fmt) == (2, 0)
        assert _export(root, xz, fmt=fmt, compression="xz", level=6) == (2, 0)
        assert xz.read_bytes()[:6] == b"\xfd7zXZ\x00"
        assert xz.stat().st_size < plain.stat().st_size
        assert "===== DUMPIT EXPORT =====" in lzma.decompress(xz.read_bytes()).decode("utf-8")
        before = e.load_dump_diff(plain, xz)
        assert before.changed_count == 0
        assert before.unchanged == ["src/a.py", "src/b.py"]
        assert "===== FILE INDEX =====" in e.read_dump_text(xz) if fmt == "llm" else "===== FILE INDEX =====" not in e.read_dump_text(xz)


def test_xz_import_plan_and_import_produce_same_files(tmp_path):
    root = _source(tmp_path)
    xz = tmp_path / "project_LLM.txt.xz"
    _export(root, xz, compression="xz")
    destination = tmp_path / "restored"
    plan = e.build_dump_import_plan(dump_path=xz, target_root=destination, overwrite_existing=True)
    assert not plan.skipped
    result = e.execute_dump_import_plan(plan, overwrite_existing=True, backup_overwritten=True)
    assert result.created == 2
    for rel in ("src/a.py", "src/b.py"):
        assert (destination / rel).read_bytes() == (root / rel).read_bytes()


def test_compression_path_timestamp_and_retention(tmp_path):
    root = _source(tmp_path)
    raw = tmp_path / "DumpIt.txt"
    path = e.resolve_export_output_path(root, str(raw), False, "llm", "xz")
    assert path.name == "DumpIt_LLM.txt.xz"
    assert e.resolve_export_output_path(root, str(path), False, "llm", "xz") == path
    ts1 = e.add_timestamp_to_output_path(path, datetime(2026, 10, 15, 12, 0, 0))
    ts2 = e.add_timestamp_to_output_path(path, datetime(2026, 10, 16, 12, 0, 0))
    ts3 = e.add_timestamp_to_output_path(path, datetime(2026, 10, 17, 12, 0, 0))
    assert ts1.name == "DumpIt_LLM_2026-10-15_120000.txt.xz"
    assert e.get_output_base_path(ts1) == path
    for file in (ts1, ts2, ts3):
        file.write_bytes(b"xz")
    # Non-XZ and standard variants must not be removed as part of XZ cleanup.
    other = tmp_path / "DumpIt_LLM_2026-10-14_120000.txt"
    other.write_text("old", encoding="utf-8")
    deleted, failed = e.cleanup_old_timestamped_outputs(ts3, 1)
    assert (deleted, failed) == (1, 0)
    assert not ts1.exists() and ts2.exists() and ts3.exists() and other.exists()


def test_export_excludes_plain_xz_and_llm_variants(tmp_path):
    root = _source(tmp_path)
    for suffix in ("DumpIt.txt", "DumpIt.txt.xz", "DumpIt_LLM.txt", "DumpIt_LLM.txt.xz", "DumpIt_LLM_2026-10-16_120000.txt.xz"):
        (root / suffix).write_bytes(b"old")
    excludes = e.build_output_exclude_files(root / "DumpIt_LLM_2026-10-17_120000.txt.xz", True)
    for suffix in ("DumpIt.txt", "DumpIt.txt.xz", "DumpIt_LLM.txt", "DumpIt_LLM.txt.xz", "DumpIt_LLM_2026-10-16_120000.txt.xz"):
        assert e.canon_path(root / suffix) in excludes


def test_xz_invalid_archive_rejected_for_import_and_diff(tmp_path):
    corrupt = tmp_path / "invalid.txt.xz"
    corrupt.write_bytes(b"not xz")
    good = tmp_path / "good.txt"
    root = _source(tmp_path)
    _export(root, good)
    for operation in (
        lambda: e.build_dump_import_plan(dump_path=corrupt, target_root=tmp_path / "dest", overwrite_existing=True),
        lambda: e.load_dump_diff(corrupt, good),
    ):
        try:
            operation()
        except ValueError as exc:
            assert "XZ dump" in str(exc)
        else:
            raise AssertionError("Invalid XZ accepted")


def test_failed_xz_write_preserves_existing_output_and_cleans_temp(monkeypatch, tmp_path):
    root = _source(tmp_path)
    out = tmp_path / "existing.txt.xz"
    original = b"previous valid archive"
    out.write_bytes(original)

    class FailingWriter:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def write(self, _bytes):
            raise OSError("simulated I/O failure")

    monkeypatch.setattr(e.lzma, "LZMAFile", FailingWriter)
    try:
        _export(root, out, compression="xz")
    except OSError as exc:
        assert "simulated I/O failure" in str(exc)
    else:
        raise AssertionError("Expected failure")
    assert out.read_bytes() == original
    assert not list(tmp_path.glob(".existing.txt.xz.*.tmp"))


def test_batch_saved_profile_uses_xz_settings(tmp_path):
    root = _source(tmp_path)
    app = object.__new__(e.DumpItApp)
    app._cp = configparser.ConfigParser()
    app._cp["profile:Dev"] = {
        "project_dir": str(root), "output_file": str(tmp_path / "out.txt"),
        "include_patterns": "*.py", "exclude_dirs": "", "add_timestamp": "False",
        "skip_binary": "True", "header_full_path": "False", "export_format": "llm",
        "export_compression": "xz", "xz_level": "4",
    }
    app._batch_queue = ["Dev"]
    app._batch_results = []
    app._batch_mode = "export"
    app.lbl_batch_status = _Label()
    app._log = lambda _msg: None
    app.after = lambda *_args, **_kwargs: None
    e.DumpItApp._batch_step(app)
    assert app._batch_results == [("Dev", "OK")]
    out = tmp_path / "out_LLM.txt.xz"
    assert out.is_file()
    assert "===== FILE INDEX =====" in e.read_dump_text(out)


def test_watch_uses_profile_compression(tmp_path):
    root = _source(tmp_path)
    app = object.__new__(e.DumpItApp)
    app.project_dir = _Var(str(root))
    app.output_file = _Var(str(tmp_path / "watch.txt"))
    app.include_patterns = _Var("*.py")
    app.exclude_dirs = _Var("")
    app.add_timestamp = _Var(False)
    app.timestamp_keep_old = _Var("10")
    app.skip_binary = _Var(True)
    app.header_full_path = _Var(False)
    app.export_format = _Var("llm")
    app.export_compression = _Var("xz")
    app.xz_level = _Var("5")
    app.profile_name = _Var("Example")
    app._save_config = lambda silent=True: None
    app._log = lambda _msg: None
    app._parse_timestamp_keep_old = lambda: 10
    app._watch_pending_export_id = "pending"
    app._watch_running = True
    app._watch_export_in_progress = False
    app._watch_profile_name = "Example"
    app._watch_after_id = "scheduled"
    app._set_watch_status = lambda _status: None
    app._build_watch_snapshot = lambda: {}
    app._schedule_watch_tick = lambda: None
    e.DumpItApp._watch_export_now(app)
    assert (tmp_path / "watch_LLM.txt.xz").is_file()
    assert app._watch_export_in_progress is False


def test_profile_roundtrip_and_legacy_defaults(tmp_path):
    # Persisting compression remains opt-in for all older configurations.
    assert e.normalize_export_compression("future") == "none"
    assert e.normalize_xz_level("bad") == 6
    assert e.normalize_export_compression("XZ", strict=True) == "xz"
    assert e.normalize_xz_level("9", strict=True) == 9
    for invalid in ("-1", "10", "junk"):
        try:
            e.normalize_xz_level(invalid, strict=True)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid level accepted")
    app = object.__new__(e.DumpItApp)
    app._cp = configparser.ConfigParser()
    app.project_dir = _Var(str(tmp_path / "source"))
    app.output_file = _Var(str(tmp_path / "out.txt"))
    app.import_dump_file = _Var("")
    app.import_target_dir = _Var("")
    app.import_overwrite = _Var(True)
    app.import_backup = _Var(True)
    app.include_patterns = _Var("*.py")
    app.exclude_dirs = _Var("")
    app.add_timestamp = _Var(False)
    app.timestamp_keep_old = _Var("10")
    app.skip_binary = _Var(True)
    app.header_full_path = _Var(False)
    app.export_format = _Var("llm")
    app.export_compression = _Var("xz")
    app.xz_level = _Var("7")
    app.watch_poll_ms = _Var("1500")
    app.watch_quiet_ms = _Var("1200")
    app.watch_export_on_start = _Var(True)
    app.patch_file = _Var("")
    app.patch_target_dir = _Var("")
    app.patch_strip_level = _Var("1")
    app.patch_reverse = _Var(False)
    app.patch_backup = _Var(True)
    app.patch_auto_detect = _Var(True)
    app.patch_engine = _Var("dumpit")
    app._normalize_patch_engine = lambda mode: mode
    app._ensure_output_default = lambda: None
    app._loading_ui = False
    e.DumpItApp._write_ui_to_profile(app, "Dev")
    assert app._cp["profile:Dev"]["export_compression"] == "xz"
    assert app._cp["profile:Dev"]["xz_level"] == "7"
    app.export_compression.set("none")
    app.xz_level.set("6")
    e.DumpItApp._apply_profile_to_ui(app, "Dev")
    assert app.export_compression.get() == "xz"
    assert app.xz_level.get() == "7"
    app._cp["profile:Legacy"] = {"project_dir": str(tmp_path / "source")}
    e.DumpItApp._apply_profile_to_ui(app, "Legacy")
    assert app.export_compression.get() == "none"
    assert app.xz_level.get() == "6"
