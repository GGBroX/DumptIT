from __future__ import annotations

import configparser
from datetime import datetime
from pathlib import Path
import sys
import zipfile

import pytest

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
    def configure(self, **kwargs):
        pass


def _project(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("print('€')\n", encoding="utf-8")
    (root / "src" / "b.py").write_text("value=42\n" * 500, encoding="utf-8")
    return root


def _export(root, path, fmt="llm", compression="none", level=6):
    return e.export_to_file(
        root=root, out_path=path, exclude_dirs=set(), patterns=["*.py"],
        skip_binary=True, header_full_path=False, profile_name="Test",
        export_format=fmt, compression=compression, zip_level=level,
        exclude_files=e.build_output_exclude_files(path, False),
    )


@pytest.mark.parametrize("fmt", ["standard", "llm"])
def test_zip_roundtrip_matches_plain_dump_for_both_formats(tmp_path, fmt):
    root = _project(tmp_path)
    plain = tmp_path / f"{fmt}.txt"
    zipped = tmp_path / f"{fmt}.txt.zip"
    assert _export(root, plain, fmt=fmt) == (2, 0)
    assert _export(root, zipped, fmt=fmt, compression="zip") == (2, 0)
    assert zipped.read_bytes().startswith(b"PK\x03\x04")
    assert zipped.stat().st_size < plain.stat().st_size
    with zipfile.ZipFile(zipped) as archive:
        assert archive.namelist() == [f"{fmt}.txt"]
        assert archive.read(f"{fmt}.txt") == e.read_dump_text(zipped).encode("utf-8")
    diff = e.load_dump_diff(plain, zipped)
    assert diff.changed_count == 0
    assert diff.unchanged == ["src/a.py", "src/b.py"]
    assert ("===== FILE INDEX =====" in e.read_dump_text(zipped)) == (fmt == "llm")


def test_zip_import_roundtrip(tmp_path):
    root = _project(tmp_path)
    zipped = tmp_path / "project_LLM.txt.zip"
    _export(root, zipped, compression="zip")
    dest = tmp_path / "destination"
    plan = e.build_dump_import_plan(dump_path=zipped, target_root=dest, overwrite_existing=True)
    assert not plan.skipped
    result = e.execute_dump_import_plan(plan, overwrite_existing=True, backup_overwritten=True)
    assert result.created == 2
    for name in ("a.py", "b.py"):
        assert (dest / "src" / name).read_bytes() == (root / "src" / name).read_bytes()


def test_zip_output_names_timestamp_and_retention(tmp_path):
    root = _project(tmp_path)
    raw = tmp_path / "DumpIt.txt"
    zipped = e.resolve_export_output_path(root, str(raw), False, "llm", "zip")
    assert zipped.name == "DumpIt_LLM.txt.zip"
    assert e.resolve_export_output_path(root, str(zipped), False, "llm", "zip") == zipped
    assert e.resolve_export_output_path(root, str(raw) + ".xz", False, "llm", "zip") == zipped
    assert e.resolve_export_output_path(root, str(zipped), False, "llm", "none") == tmp_path / "DumpIt_LLM.txt"
    dates = [datetime(2026, 10, day, 12, 0) for day in (15, 16, 17)]
    stamped = [e.add_timestamp_to_output_path(zipped, date) for date in dates]
    assert stamped[0].name == "DumpIt_LLM_2026-10-15_120000.txt.zip"
    assert e.get_output_base_path(stamped[0]) == zipped
    for path in stamped:
        path.write_bytes(b"test")
    legacy = tmp_path / "DumpIt_LLM_2026-10-14_120000.txt.xz"
    legacy.write_bytes(b"old")
    plain = tmp_path / "DumpIt_LLM_2026-10-14_120000.txt"
    plain.write_text("old", encoding="utf-8")
    assert e.cleanup_old_timestamped_outputs(stamped[-1], 1) == (1, 0)
    assert not stamped[0].exists()
    assert all(path.exists() for path in (stamped[1], stamped[2], legacy, plain))


def test_export_excludes_plain_zip_xz_and_format_variants(tmp_path):
    root = _project(tmp_path)
    variants = (
        "DumpIt.txt", "DumpIt.txt.zip", "DumpIt.txt.xz",
        "DumpIt_LLM.txt", "DumpIt_LLM.txt.zip", "DumpIt_LLM.txt.xz",
        "DumpIt_LLM_2026-10-16_120000.txt.zip",
        "DumpIt_LLM_2026-10-16_120000.txt.xz",
    )
    for name in variants:
        (root / name).write_bytes(b"old")
    excludes = e.build_output_exclude_files(root / "DumpIt_LLM_2026-10-17_120000.txt.zip", True)
    assert all(e.canon_path(root / name) in excludes for name in variants)


def test_zip_corrupt_multi_member_and_unsafe_member_rejected(tmp_path):
    root = _project(tmp_path)
    good = tmp_path / "good.txt"
    _export(root, good)
    invalid = tmp_path / "invalid.txt.zip"
    invalid.write_bytes(b"not a zip")
    with pytest.raises(ValueError, match="ZIP dump"):
        e.load_dump_diff(invalid, good)
    with pytest.raises(ValueError, match="ZIP dump"):
        e.build_dump_import_plan(dump_path=invalid, target_root=tmp_path / "dest", overwrite_existing=True)
    for entries in (("first.txt", "second.txt"), ("../evil.txt",), ("folder/file.txt",)):
        unsafe = tmp_path / "unsafe.txt.zip"
        with zipfile.ZipFile(unsafe, "w") as archive:
            for member in entries:
                archive.writestr(member, good.read_bytes())
        with pytest.raises(ValueError, match="ZIP dump"):
            e.read_dump_text(unsafe)


def test_zip_bounded_decompression(tmp_path, monkeypatch):
    source = tmp_path / "large.txt.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.txt", "a" * 200)
    monkeypatch.setattr(e, "MAX_DUMP_DECOMPRESSED_BYTES", 100)
    with pytest.raises(ValueError, match="safety limit"):
        e.read_dump_text(source)


def test_failed_zip_write_is_atomic(tmp_path, monkeypatch):
    root = _project(tmp_path)
    target = tmp_path / "existing.txt.zip"
    original = b"untouched original"
    target.write_bytes(original)

    def fail(*args, **kwargs):
        raise OSError("simulated ZIP failure")

    monkeypatch.setattr(e.zipfile.ZipFile, "writestr", fail)
    with pytest.raises(OSError, match="simulated ZIP failure"):
        _export(root, target, compression="zip")
    assert target.read_bytes() == original
    assert not list(tmp_path.glob(".existing.txt.zip.*.tmp"))


def test_zip_level_validation_and_saved_xz_migration(tmp_path):
    assert e.normalize_export_compression("future") == "none"
    assert e.normalize_export_compression("ZIP", strict=True) == "zip"
    assert e.normalize_export_compression("xz", strict=True) == "zip"
    assert e.normalize_zip_level("junk") == 6
    assert e.normalize_zip_level("9", strict=True) == 9
    for invalid in ("-1", "10", "junk"):
        with pytest.raises(ValueError, match="ZIP compression level"):
            e.normalize_zip_level(invalid, strict=True)
    app = object.__new__(e.DumpItApp)
    app._cp = configparser.ConfigParser()
    app._cp["profile:Old"] = {
        "project_dir": str(tmp_path), "output_file": str(tmp_path / "out.txt.xz"),
        "export_compression": "xz", "xz_level": "4",
    }
    profile = e.DumpItApp._read_profile_settings(app, "Old")
    assert profile[1].name == "out.txt.zip"
    assert e.DumpItApp._read_profile_compression(app, "Old") == ("zip", 4)
    app.project_dir = _Var(str(tmp_path))
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
    app.export_compression = _Var("none")
    app.zip_level = _Var("6")
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
    app._normalize_patch_engine = lambda x: x
    app._ensure_output_default = lambda: None
    app._loading_ui = False
    e.DumpItApp._apply_profile_to_ui(app, "Old")
    assert app.export_compression.get() == "zip"
    assert app.zip_level.get() == "4"
    e.DumpItApp._write_ui_to_profile(app, "Old")
    assert app._cp["profile:Old"]["export_compression"] == "zip"
    assert app._cp["profile:Old"]["zip_level"] == "4"
    assert "xz_level" not in app._cp["profile:Old"]


def test_batch_uses_saved_zip_settings(tmp_path):
    root = _project(tmp_path)
    app = object.__new__(e.DumpItApp)
    app._cp = configparser.ConfigParser()
    app._cp["profile:Dev"] = {
        "project_dir": str(root), "output_file": str(tmp_path / "out.txt"),
        "include_patterns": "*.py", "exclude_dirs": "", "add_timestamp": "False",
        "skip_binary": "True", "header_full_path": "False", "export_format": "llm",
        "export_compression": "zip", "zip_level": "4",
    }
    app._batch_queue = ["Dev"]
    app._batch_results = []
    app._batch_mode = "export"
    app.lbl_batch_status = _Label()
    app._log = lambda _msg: None
    app.after = lambda *_args, **_kwargs: None
    e.DumpItApp._batch_step(app)
    assert app._batch_results == [("Dev", "OK")]
    assert "===== FILE INDEX =====" in e.read_dump_text(tmp_path / "out_LLM.txt.zip")


def test_watch_uses_zip_profile_settings(tmp_path):
    root = _project(tmp_path)
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
    app.export_compression = _Var("zip")
    app.zip_level = _Var("5")
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
    assert (tmp_path / "watch_LLM.txt.zip").is_file()
    assert app._watch_export_in_progress is False


def test_unsupported_raw_xz_export_fails_fast(tmp_path):
    root = _project(tmp_path)
    with pytest.raises(ValueError, match="extension"):
        _export(root, tmp_path / "bad.txt.xz", compression="xz")
