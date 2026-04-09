#!/usr/bin/env python3
from __future__ import annotations

from typing import Optional, Set
from dataclasses import dataclass

import os
import sys
import platform
import fnmatch
import configparser
import hashlib
from pathlib import Path
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog


APP_NAME = "DumpIt"
CONFIG_FILE_NAME = "dumpit.ini"

DEFAULT_INCLUDE = "*.al,app.json,*.gd,*.tscn,*.tres,*.cfg,*.ini,*.json,*.md,*.txt"
DEFAULT_EXCLUDE_DIRS = ".git,.vscode,.alpackages,bin,obj,node_modules,.idea,.vs,.devcontainer,.godot,.import"

SECTION_APP = "app"
PROFILE_PREFIX = "profile:"  # es: profile:Default
APP_BATCH_SELECTED_KEY = "batch_selected_profiles"  # csv list of profile names


def get_default_project_dir() -> Path:
    # Se è un exe (PyInstaller), usa la cartella dell'exe; altrimenti cwd
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path.cwd()


def get_config_path() -> Path:
    system = platform.system().lower()
    if system.startswith("win"):
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / APP_NAME / CONFIG_FILE_NAME
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else (Path.home() / ".config")
    return base / APP_NAME / CONFIG_FILE_NAME


def ensure_parent_dir(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)


def parse_csv_list(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def normalize_patterns(patterns: list[str]) -> list[str]:
    out: list[str] = []
    for p in patterns:
        p = p.strip()
        if not p:
            continue
        if p.startswith(".") and "*" not in p and "/" not in p and "\\" not in p:
            out.append(f"*{p.lower()}")
        else:
            out.append(p.lower())
    return out



def normalize_ui_path(p: str) -> str:
    """Normalize a path string for the current OS (fixes Tk forward slashes on Windows)."""
    p = (p or "").strip()
    if not p:
        return p
    return os.path.normpath(p)


def canon_path(p: Path) -> str:
    """Canonical path string for comparisons (case-insensitive on Windows)."""
    return os.path.normcase(os.path.normpath(str(p)))


def rel_posix(root: Path, file_path: Path) -> str:
    return file_path.relative_to(root).as_posix()


def should_skip_by_dir(rel_path: Path, exclude_dirs: set[str]) -> bool:
    return any(part.lower() in exclude_dirs for part in rel_path.parts)


def is_probably_binary(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            chunk = f.read(8192)
        return b"\x00" in chunk
    except Exception:
        return True


def read_text_safely(p: Path) -> str:
    for enc in ("utf-8-sig", "utf-8"):
        try:
            return p.read_text(encoding=enc)
        except UnicodeDecodeError:
            pass
    return p.read_text(encoding="utf-8", errors="replace")


def matches_any(rel_path_posix: str, name: str, patterns: list[str]) -> bool:
    rp = rel_path_posix.lower()
    nm = name.lower()
    for pat in patterns:
        if ("/" in pat) or ("\\" in pat):
            if fnmatch.fnmatch(rp, pat.replace("\\", "/")):
                return True
        else:
            if fnmatch.fnmatch(nm, pat):
                return True
    return False


def collect_files(root: Path, exclude_dirs: set[str], patterns: list[str], skip_binary: bool, exclude_files: Optional[Set[str]] = None) -> list[Path]:
    files: list[Path] = []
    exclude_files = exclude_files or set()
    for p in root.rglob("*"):
        if p.is_dir():
            continue

        # Avoid including the output file itself (can cause huge/infinite-looking exports)
        if exclude_files and canon_path(p) in exclude_files:
            continue
        rel = p.relative_to(root)
        if should_skip_by_dir(rel, exclude_dirs):
            continue

        rp = rel.as_posix()
        if not matches_any(rp, p.name, patterns):
            continue

        if skip_binary and is_probably_binary(p):
            continue

        files.append(p)

    files.sort(key=lambda x: str(x).lower())
    return files


def build_default_output(root: Path, add_ts: bool) -> Path:
    name = root.name
    if add_ts:
        name += "_" + datetime.now().strftime("%Y-%m-%d_%H%M%S")
    return root / f"{name}.txt"


@dataclass(slots=True)
class ExportFileEntry:
    path: Path
    rel_path: str
    header_path: str
    text: str
    line_count: int
    modified_at: str


def format_file_mtime(p: Path) -> str:
    try:
        return datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "unknown"


def count_lines(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def collect_export_entries(
    root: Path,
    exclude_dirs: set[str],
    patterns: list[str],
    skip_binary: bool,
    header_full_path: bool,
    exclude_files: Optional[Set[str]] = None,
) -> tuple[list[ExportFileEntry], int]:
    files = collect_files(root, exclude_dirs, patterns, skip_binary, exclude_files=exclude_files)
    entries: list[ExportFileEntry] = []
    skipped = 0

    for p in files:
        try:
            text = read_text_safely(p)
        except Exception:
            skipped += 1
            continue

        rel_path = rel_posix(root, p)
        header_path = str(p) if header_full_path else rel_path
        entries.append(
            ExportFileEntry(
                path=p,
                rel_path=rel_path,
                header_path=header_path,
                text=text,
                line_count=count_lines(text),
                modified_at=format_file_mtime(p),
            )
        )

    return entries, skipped


def build_project_tree(entries: list[ExportFileEntry]) -> str:
    tree: dict[str, dict] = {}

    for entry in entries:
        parts = entry.rel_path.split("/")
        node = tree
        for part in parts[:-1]:
            node = node.setdefault(part + "/", {})
        node[parts[-1]] = entry

    lines: list[str] = []

    def walk(node: dict[str, dict | ExportFileEntry], depth: int) -> None:
        names = sorted(node.keys(), key=lambda name: (0 if name.endswith("/") else 1, name.lower()))
        for name in names:
            value = node[name]
            indent = "  " * depth
            if isinstance(value, ExportFileEntry):
                lines.append(
                    f"{indent}{name} [lines: {value.line_count} | modified: {value.modified_at}]"
                )
            else:
                lines.append(f"{indent}{name}")
                walk(value, depth + 1)

    walk(tree, 0)
    return "\n".join(lines)


def render_export_text(
    root: Path,
    out_path: Path,
    profile_name: str,
    entries: list[ExportFileEntry],
) -> str:
    parts: list[str] = []
    timestamp_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    project_tree = build_project_tree(entries)

    parts.append("===== DUMPIT EXPORT =====\n")
    parts.append(f"timestamp_utc: {timestamp_utc}\n")
    parts.append(f"root: {root}\n")
    parts.append(f"output: {out_path}\n")
    parts.append(f"profile: {profile_name}\n")
    parts.append(f"files_included: {len(entries)}\n")
    parts.append("\n")

    parts.append("===== PROJECT TREE =====\n")
    if project_tree:
        parts.append(project_tree)
        parts.append("\n")
    else:
        parts.append("[[NO FILES INCLUDED]]\n")
    parts.append("\n")

    for entry in entries:
        parts.append(
            f"===== FILE: {entry.header_path} | lines={entry.line_count} | modified={entry.modified_at} =====\n"
        )
        parts.append(entry.text)
        if not parts[-1].endswith("\n"):
            parts.append("\n")
        parts.append("\n")

    return "".join(parts)


def export_to_file(
    root: Path,
    out_path: Path,
    exclude_dirs: set[str],
    patterns: list[str],
    skip_binary: bool,
    header_full_path: bool,
    profile_name: str = "Default",
) -> tuple[int, int]:
    exclude_files = {canon_path(out_path)}
    entries, skipped = collect_export_entries(
        root=root,
        exclude_dirs=exclude_dirs,
        patterns=patterns,
        skip_binary=skip_binary,
        header_full_path=header_full_path,
        exclude_files=exclude_files,
    )

    content = render_export_text(
        root=root,
        out_path=out_path,
        profile_name=profile_name,
        entries=entries,
    )

    ensure_parent_dir(out_path)
    out_path.write_text(content, encoding="utf-8")
    return (len(entries), skipped)


def sanitize_profile_name(name: str) -> str:
    name = (name or "").strip()
    name = name.replace("\n", " ").replace("\r", " ").strip()
    # evita caratteri “problematici” per sezioni ini
    for bad in [":", "[", "]"]:
        name = name.replace(bad, "-")
    return name


class DumpItApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("DumpIt — Source Exporter")

        # Base safe size
        self.geometry("980x680")
        self.minsize(980, 680)

        # State base
        self.project_dir = tk.StringVar(value=str(get_default_project_dir()))
        self.include_patterns = tk.StringVar(value=DEFAULT_INCLUDE)
        self.exclude_dirs = tk.StringVar(value=DEFAULT_EXCLUDE_DIRS)
        self.add_timestamp = tk.BooleanVar(value=False)
        self.skip_binary = tk.BooleanVar(value=True)
        self.header_full_path = tk.BooleanVar(value=False)
        self.output_file = tk.StringVar(value="")

        # Profiles
        self.profile_name = tk.StringVar(value="Default")
        self._loading_ui = False
        self._cp = configparser.ConfigParser()
        self.config_path = get_config_path()
        self._active_profile = "Default"

        # Watch settings (per profile)
        self.watch_poll_ms = tk.StringVar(value="1500")
        self.watch_quiet_ms = tk.StringVar(value="1200")
        self.watch_export_on_start = tk.BooleanVar(value=True)

        # Watch runtime state
        self._watch_running = False
        self._watch_after_id: str | None = None
        self._watch_pending_export_id: str | None = None
        self._watch_export_in_progress = False
        self._watch_profile_name = ""
        self._watch_snapshot: dict[str, tuple[int, int]] = {}
        self._watch_root: Path | None = None
        self._watch_out_path: Path | None = None
        self._watch_patterns: list[str] = []
        self._watch_exclude_dirs: set[str] = set()
        self._watch_skip_binary = True
        self._watch_header_full_path = False
        self._watch_poll_interval_ms = 1500
        self._watch_quiet_period_ms = 1200
        self._watch_last_change_summary = "No changes detected yet."
        self._watch_last_export_summary = "No automatic export yet."

        self._build_ui()

        self._loading_config = True
        self._load_config()
        self._loading_config = False
        self._ensure_output_default()

        self.after(0, self._apply_dynamic_min_size)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _apply_dynamic_min_size(self) -> None:
        self.update_idletasks()
    
        pad_w = 24
        pad_h = 32
    
        req_w = self.winfo_reqwidth() + pad_w
        req_h = self.winfo_reqheight() + pad_h
    
        min_w = max(980, req_w)
        min_h = max(680, req_h)
    
        self.minsize(min_w, min_h)
    
        cur_w = self.winfo_width()
        cur_h = self.winfo_height()
        self.geometry(f"{max(cur_w, min_w)}x{max(cur_h, min_h)}")

    # ---------- UI ----------
    def _build_ui(self) -> None:
        pad = {"padx": 10, "pady": 6}
        root = ttk.Frame(self)
        root.pack(fill="both", expand=True, **pad)

        # Tabs
        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True, **pad)

        self.tab_export = ttk.Frame(self.nb)
        self.tab_watch = ttk.Frame(self.nb)
        self.tab_batch = ttk.Frame(self.nb)

        self.nb.add(self.tab_export, text="Export")
        self.nb.add(self.tab_watch, text="Watch")
        self.nb.add(self.tab_batch, text="Batch")

        # ---------- EXPORT TAB ----------
        export_root = self.tab_export

        # Profiles frame
        lf0 = ttk.LabelFrame(export_root, text="Profile")
        lf0.pack(fill="x", **pad)
        row0 = ttk.Frame(lf0)
        row0.pack(fill="x", padx=8, pady=8)

        ttk.Label(row0, text="Config:").pack(side="left")
        self.cb_profiles = ttk.Combobox(row0, textvariable=self.profile_name, state="readonly", width=24)
        self.cb_profiles.pack(side="left", padx=8)
        self.cb_profiles.bind("<<ComboboxSelected>>", self._on_profile_selected)

        ttk.Button(row0, text="New…", command=self._profile_new).pack(side="left", padx=4)
        ttk.Button(row0, text="Rename…", command=self._profile_rename).pack(side="left", padx=4)
        ttk.Button(row0, text="Delete", command=self._profile_delete).pack(side="left", padx=4)

        # Profile actions (keep near profile selector)
        row0_actions = ttk.Frame(lf0)
        row0_actions.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(row0_actions, text="Reset defaults", command=self._reset_defaults).pack(side="right", padx=4)
        ttk.Button(row0_actions, text="Save profile", command=self._save_config).pack(side="right", padx=4)

        # Project folder
        lf1 = ttk.LabelFrame(export_root, text="Project folder")
        lf1.pack(fill="x", **pad)
        ttk.Entry(lf1, textvariable=self.project_dir).pack(side="left", fill="x", expand=True, padx=8, pady=8)
        ttk.Button(lf1, text="Browse…", command=self._browse_project).pack(side="left", padx=8, pady=8)

        # Include patterns
        lf2 = ttk.LabelFrame(export_root, text="Include patterns (comma-separated, ex: *.al,app.json,*.gd)")
        lf2.pack(fill="x", **pad)
        ttk.Entry(lf2, textvariable=self.include_patterns).pack(fill="x", padx=8, pady=8)

        # Exclude dirs
        lf3 = ttk.LabelFrame(export_root, text="Exclude folders (comma-separated, match by folder name)")
        lf3.pack(fill="x", **pad)
        ttk.Entry(lf3, textvariable=self.exclude_dirs).pack(fill="x", padx=8, pady=8)

        # Output
        lf4 = ttk.LabelFrame(export_root, text="Output file")
        lf4.pack(fill="x", **pad)
        ttk.Entry(lf4, textvariable=self.output_file).pack(side="left", fill="x", expand=True, padx=8, pady=8)
        ttk.Button(lf4, text="Choose…", command=self._choose_output).pack(side="left", padx=8, pady=8)

        # Options
        lf5 = ttk.LabelFrame(export_root, text="Options")
        lf5.pack(fill="x", **pad)
        opt = ttk.Frame(lf5)
        opt.pack(fill="x", padx=8, pady=8)

        ttk.Checkbutton(opt, text="Add timestamp to output name", variable=self.add_timestamp,
                        command=self._suggest_output_if_default).grid(row=0, column=0, sticky="w", padx=6, pady=2)
        ttk.Checkbutton(opt, text="Skip binary files (recommended)", variable=self.skip_binary).grid(
            row=0, column=1, sticky="w", padx=6, pady=2
        )
        ttk.Checkbutton(opt, text="Header = full path (instead of relative)", variable=self.header_full_path).grid(
            row=1, column=0, sticky="w", padx=6, pady=2
        )

        # Actions
        actions = ttk.Frame(export_root)
        actions.pack(fill="x", **pad)
        ttk.Button(actions, text="Preview", command=self._preview).pack(side="left", padx=4)
        ttk.Button(actions, text="Export", command=self._export).pack(side="left", padx=4)

        # ---------- WATCH TAB ----------
        self._build_watch_tab(self.tab_watch, pad)

        # ---------- BATCH TAB ----------
        self._build_batch_tab(self.tab_batch, pad)

        # ---------- SHARED LOG ----------
        self.log = tk.Text(root, height=5, wrap="word")
        self.log.pack(fill="both", expand=True, **pad)
        self.log.configure(state="disabled")

        # Footer
        footer = ttk.Frame(root)
        footer.pack(fill="x", **pad)
        self.lbl_cfg = ttk.Label(footer, text=f"Config: {self.config_path}")
        self.lbl_cfg.pack(side="left")

        self._set_watch_status("Stopped")

    def _log(self, msg: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    # ---------- Project / Output ----------
    def _browse_project(self) -> None:
        d = filedialog.askdirectory(title="Select project folder", initialdir=self.project_dir.get() or str(get_default_project_dir()))
        if d:
            self.project_dir.set(normalize_ui_path(d))
            self._suggest_output_if_default()

    def _choose_output(self) -> None:
        root = Path(normalize_ui_path(self.project_dir.get())).resolve()
        initial = build_default_output(root, self.add_timestamp.get())
        f = filedialog.asksaveasfilename(
            title="Choose output file",
            initialdir=str(root),
            initialfile=initial.name,
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")]
        )
        if f:
            self.output_file.set(normalize_ui_path(f))

    def _ensure_output_default(self) -> None:
        if not self.output_file.get().strip():
            root = Path(normalize_ui_path(self.project_dir.get())).resolve()
            self.output_file.set(normalize_ui_path(str(build_default_output(root, self.add_timestamp.get()))))

    def _suggest_output_if_default(self) -> None:
        try:
            root = Path(normalize_ui_path(self.project_dir.get())).resolve()
            current = self.output_file.get().strip()
            if not current:
                self.output_file.set(normalize_ui_path(str(build_default_output(root, self.add_timestamp.get()))))
                return
            curp = Path(current).resolve()
            if curp.parent == root and curp.stem.startswith(root.name):
                self.output_file.set(normalize_ui_path(str(build_default_output(root, self.add_timestamp.get()))))
        except Exception:
            pass

    # ---------- Export ----------
    def _preview(self) -> None:
        try:
            root = Path(normalize_ui_path(self.project_dir.get())).resolve()
            if not root.exists():
                messagebox.showerror("Error", "Project folder does not exist.")
                return

            patterns = normalize_patterns(parse_csv_list(self.include_patterns.get()))
            exclude = {x.lower() for x in parse_csv_list(self.exclude_dirs.get())}
            out = normalize_ui_path(self.output_file.get().strip())
            out_path = Path(out).resolve() if out else None
            exclude_files = {canon_path(out_path)} if out_path else set()
            files = collect_files(root, exclude, patterns, self.skip_binary.get(), exclude_files=exclude_files)
            self._log(f"Preview: {len(files)} files will be included from: {root}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _export(self) -> None:
        try:
            root = Path(normalize_ui_path(self.project_dir.get())).resolve()
            if not root.exists():
                messagebox.showerror("Error", "Project folder does not exist.")
                return

            patterns = normalize_patterns(parse_csv_list(self.include_patterns.get()))
            exclude = {x.lower() for x in parse_csv_list(self.exclude_dirs.get())}

            out = normalize_ui_path(self.output_file.get().strip())
            out_path = Path(out).resolve() if out else build_default_output(root, self.add_timestamp.get())

            included, skipped = export_to_file(
                root=root,
                out_path=out_path,
                exclude_dirs=exclude,
                patterns=patterns,
                skip_binary=self.skip_binary.get(),
                header_full_path=self.header_full_path.get(),
                profile_name=(self.profile_name.get().strip() or "Default"),
            )

            self._save_config(silent=True)
            self._log(f"OK: exported {included} files -> {out_path} (skipped read errors: {skipped})")
            messagebox.showinfo("Done", f"Export completed.\nIncluded: {included}\nSkipped read errors: {skipped}\nOutput: {out_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------- Profiles / Config ----------
    def _sec_ci(self, wanted: str) -> Optional[str]:
        """Return the actual section name matching wanted (case-insensitive), if any."""
        w = wanted.lower()
        for sec in self._cp.sections():
            if sec.lower() == w:
                return sec
        return None

    def _normalize_config(self) -> None:
        """Repair legacy configs: section name case, duplicated profile sections, etc."""
        # Normalize APP section casing: 'App' -> 'app'
        existing_app = self._sec_ci(SECTION_APP)
        if existing_app and existing_app != SECTION_APP:
            if SECTION_APP not in self._cp:
                self._cp[SECTION_APP] = {}
            # merge: canonical wins
            for k, v in self._cp[existing_app].items():
                if k not in self._cp[SECTION_APP]:
                    self._cp[SECTION_APP][k] = v
            self._cp.remove_section(existing_app)

        # Deduplicate profile sections that differ only by case/prefix casing
        groups: dict[str, list[str]] = {}
        for sec in list(self._cp.sections()):
            if sec.lower().startswith(PROFILE_PREFIX):
                prof = sec[len(PROFILE_PREFIX):].strip()
                key = prof.lower()
                groups.setdefault(key, []).append(sec)

        for _key, secs in groups.items():
            if len(secs) <= 1:
                continue
            # prefer canonical prefix 'profile:' if present
            primary = None
            for s in secs:
                if s.startswith(PROFILE_PREFIX):
                    primary = s
                    break
            if primary is None:
                primary = secs[0]

            for s in secs:
                if s == primary:
                    continue
                # merge: primary wins on conflicts
                for k, v in self._cp[s].items():
                    if k not in self._cp[primary]:
                        self._cp[primary][k] = v
                self._cp.remove_section(s)

    def _profile_section(self, name: str) -> str:
        return f"{PROFILE_PREFIX}{name}"

    def _get_profile_names(self) -> list[str]:
        # unique (case-insensitive), preserve first-seen casing
        by_lower: dict[str, str] = {}
        for sec in self._cp.sections():
            if sec.lower().startswith(PROFILE_PREFIX):
                raw = sec[len(PROFILE_PREFIX):].strip()
                if not raw:
                    continue
                key = raw.lower()
                by_lower.setdefault(key, raw)
        names = list(by_lower.values())
        names.sort(key=lambda x: x.lower())
        return names

    def _refresh_profile_combo(self, desired: Optional[str] = None) -> str:
        """Refresh combobox values and ensure a valid selected profile.

        Returns the selected (valid) profile name.
        """
        names = self._get_profile_names()
        if not names:
            names = ["Default"]
        self.cb_profiles["values"] = names

        cur = (desired if desired is not None else self.profile_name.get()).strip()
        if cur not in names:
            cur = names[0]

        # ensure displayed selection is consistent across platforms
        self.profile_name.set(cur)
        try:
            self.cb_profiles.current(names.index(cur))
        except Exception:
            # fallback
            self.cb_profiles.set(cur)
        # keep batch checklist in sync
        if hasattr(self, "batch_list_frame"):
            self._refresh_batch_profile_list(prefer_config=getattr(self, "_loading_config", False))

        return cur

    def _ensure_minimum_config(self) -> None:
        # app section may come from legacy casing; normalize_config() should fix, but be safe
        if SECTION_APP not in self._cp:
            alt = self._sec_ci(SECTION_APP)
            if alt and alt in self._cp:
                self._cp[SECTION_APP] = dict(self._cp[alt])
                self._cp.remove_section(alt)
            else:
                self._cp[SECTION_APP] = {}
        if "active_profile" not in self._cp[SECTION_APP]:
            self._cp[SECTION_APP]["active_profile"] = "Default"

        # se non esistono profili, creane uno Default
        if not self._get_profile_names():
            self._cp[self._profile_section("Default")] = {
                "project_dir": str(get_default_project_dir()),
                "output_file": "",
                "include_patterns": DEFAULT_INCLUDE,
                "exclude_dirs": DEFAULT_EXCLUDE_DIRS,
                "add_timestamp": "False",
                "skip_binary": "True",
                "header_full_path": "False",
                "watch_poll_ms": "1500",
                "watch_quiet_ms": "1200",
                "watch_export_on_start": "True",
            }

    # ---------- Batch selection persistence ----------
    def _has_saved_batch_selection(self) -> bool:
        try:
            return self._cp.has_option(SECTION_APP, APP_BATCH_SELECTED_KEY)
        except Exception:
            return False

    def _get_batch_selection_from_config(self) -> Set[str]:
        try:
            raw = self._cp.get(SECTION_APP, APP_BATCH_SELECTED_KEY, fallback="") or ""
        except Exception:
            raw = ""
        return {x.strip().lower() for x in raw.split(",") if x.strip()}

    def _store_batch_selection_to_config(self) -> None:
        # Only touch the app section; do NOT auto-save profiles here.
        if SECTION_APP not in self._cp:
            self._cp[SECTION_APP] = {}
        sel = self._get_selected_batch_profiles()
        self._cp[SECTION_APP][APP_BATCH_SELECTED_KEY] = ",".join(sel)

    def _on_batch_selection_changed(self) -> None:
        # Persist selection for next run (written to disk on close/export/save)
        self._store_batch_selection_to_config()
        if hasattr(self, "lbl_batch_status"):
            try:
                total = len(self._get_profile_names())
                sel = len(self._get_selected_batch_profiles())
                self.lbl_batch_status.configure(text=f"{total} profiles — selected {sel}")
            except Exception:
                pass

    def _apply_profile_to_ui(self, name: str) -> None:
        # section may exist with different casing
        sec = self._profile_section(name)
        sec_real = self._sec_ci(sec) or sec
        if sec_real not in self._cp:
            # fallback: crea dal default
            self._cp[sec_real] = {
                "project_dir": str(get_default_project_dir()),
                "output_file": "",
                "include_patterns": DEFAULT_INCLUDE,
                "exclude_dirs": DEFAULT_EXCLUDE_DIRS,
                "add_timestamp": "False",
                "skip_binary": "True",
                "header_full_path": "False",
                "watch_poll_ms": "1500",
                "watch_quiet_ms": "1200",
                "watch_export_on_start": "True",
            }

        s = self._cp[sec_real]
        self._loading_ui = True
        try:
            # NB: project_dir e output_file SONO parte del profilo
            self.project_dir.set(normalize_ui_path(s.get("project_dir", self.project_dir.get())))

            self.include_patterns.set(s.get("include_patterns", DEFAULT_INCLUDE))
            self.exclude_dirs.set(s.get("exclude_dirs", DEFAULT_EXCLUDE_DIRS))
            self.add_timestamp.set(s.getboolean("add_timestamp", fallback=False))
            self.skip_binary.set(s.getboolean("skip_binary", fallback=True))
            self.header_full_path.set(s.getboolean("header_full_path", fallback=False))

            self.output_file.set(normalize_ui_path(s.get("output_file", "")))
            self.watch_poll_ms.set(s.get("watch_poll_ms", "1500"))
            self.watch_quiet_ms.set(s.get("watch_quiet_ms", "1200"))
            self.watch_export_on_start.set(s.getboolean("watch_export_on_start", fallback=True))

            # Se il profilo non ha output_file, calcolane uno di default per quella project_dir
            self._ensure_output_default()
        finally:
            self._loading_ui = False

    def _write_ui_to_profile(self, name: str) -> None:
        sec = self._profile_section(name)
        sec_real = self._sec_ci(sec) or sec
        if sec_real not in self._cp:
            self._cp[sec_real] = {}

        # project/output per profilo
        self._cp[sec_real]["project_dir"] = normalize_ui_path(self.project_dir.get())
        self._cp[sec_real]["output_file"] = normalize_ui_path(self.output_file.get())

        self._cp[sec_real]["include_patterns"] = self.include_patterns.get()
        self._cp[sec_real]["exclude_dirs"] = self.exclude_dirs.get()
        self._cp[sec_real]["add_timestamp"] = str(self.add_timestamp.get())
        self._cp[sec_real]["skip_binary"] = str(self.skip_binary.get())
        self._cp[sec_real]["header_full_path"] = str(self.header_full_path.get())
        self._cp[sec_real]["watch_poll_ms"] = self.watch_poll_ms.get().strip()
        self._cp[sec_real]["watch_quiet_ms"] = self.watch_quiet_ms.get().strip()
        self._cp[sec_real]["watch_export_on_start"] = str(self.watch_export_on_start.get())

    def _load_config(self) -> None:
        # carica ini
        if self.config_path.exists():
            try:
                self._cp.read(self.config_path, encoding="utf-8")
            except Exception:
                self._cp = configparser.ConfigParser()

        # ripara config legacy (casing/duplicati)
        self._normalize_config()

        self._ensure_minimum_config()

        # active profile
        active = (self._cp[SECTION_APP].get("active_profile", "Default") or "Default").strip()

        # refresh + ensure selection is valid, then apply
        selected = self._refresh_profile_combo(desired=active)
        self._apply_profile_to_ui(selected)
        # failsafe: some Tk builds may render widgets after this point
        self.after_idle(lambda s=selected: (not self._loading_ui) and self._apply_profile_to_ui(s))
        self._active_profile = selected

        # After loading config and profiles, rebuild batch list preferring saved selection
        if hasattr(self, "batch_list_frame"):
            try:
                self._refresh_batch_profile_list(prefer_config=True)
            except Exception:
                pass

        self._log(f"Loaded config: {self.config_path}")

    def _save_config(self, silent: bool = False) -> None:
        try:
            self._ensure_minimum_config()
            # keep batch selection in sync with config on any save
            try:
                self._store_batch_selection_to_config()
            except Exception:
                pass
            current = self.profile_name.get().strip() or "Default"
            self._write_ui_to_profile(current)
            self._cp[SECTION_APP]["active_profile"] = current

            ensure_parent_dir(self.config_path)
            with self.config_path.open("w", encoding="utf-8") as f:
                self._cp.write(f)

            if not silent:
                self._log(f"Saved config: {self.config_path}")
                messagebox.showinfo("Saved", f"Profile saved:\n{current}\n\nConfig file:\n{self.config_path}")
        except Exception as e:
            if not silent:
                messagebox.showerror("Error", str(e))

    def _on_profile_selected(self, _evt=None) -> None:
        if self._loading_ui:
            return

        old = getattr(self, "_active_profile", "Default") or "Default"
        new = (self.profile_name.get() or "Default").strip() or "Default"

        # Applica in idle per evitare glitch di update su alcuni Tk/OS
        def _do_switch() -> None:
            if self._loading_ui:
                return

            # salva i valori della UI nel profilo *precedente* (non in quello appena selezionato)
            self._write_ui_to_profile(old)

            # passa al nuovo profilo
            self._cp[SECTION_APP]["active_profile"] = new
            self._apply_profile_to_ui(new)
            self._active_profile = new

            # persisti su disco
            self._save_config(silent=True)
            self._log(f"Switched profile: {new}")

        self.after_idle(_do_switch)

    def _profile_new(self) -> None:
        name = simpledialog.askstring("New profile", "Profile name:")
        name = sanitize_profile_name(name or "")
        if not name:
            return
        sec = self._profile_section(name)
        if (self._sec_ci(sec) or sec) in self._cp:
            messagebox.showerror("Error", f"Profile already exists: {name}")
            return

        # crea copiando i valori correnti (più comodo)
        base_name = self.profile_name.get().strip() or "Default"
        self._write_ui_to_profile(base_name)
        base_sec = self._sec_ci(self._profile_section(base_name)) or self._profile_section(base_name)
        if base_sec not in self._cp:
            self._cp[base_sec] = {}
        self._cp[sec] = dict(self._cp[base_sec])

        self.profile_name.set(name)
        self._cp[SECTION_APP]["active_profile"] = name
        self._active_profile = name
        self._refresh_profile_combo()
        self._apply_profile_to_ui(name)
        self._save_config(silent=True)
        self._log(f"Created profile: {name}")

    def _profile_rename(self) -> None:
        old = self.profile_name.get().strip()
        if not old:
            return
        new = simpledialog.askstring("Rename profile", f"New name for '{old}':")
        new = sanitize_profile_name(new or "")
        if not new or new == old:
            return

        old_sec = self._sec_ci(self._profile_section(old)) or self._profile_section(old)
        new_sec = self._profile_section(new)

        if (self._sec_ci(new_sec) or new_sec) in self._cp:
            messagebox.showerror("Error", f"Profile already exists: {new}")
            return
        if old_sec not in self._cp:
            messagebox.showerror("Error", f"Profile not found: {old}")
            return

        self._cp[new_sec] = dict(self._cp[old_sec])
        self._cp.remove_section(old_sec)

        self.profile_name.set(new)
        self._cp[SECTION_APP]["active_profile"] = new
        self._active_profile = new
        self._refresh_profile_combo()
        self._save_config(silent=True)
        self._log(f"Renamed profile: {old} -> {new}")

    def _profile_delete(self) -> None:
        name = self.profile_name.get().strip()
        if not name:
            return
        names = self._get_profile_names()
        if len(names) <= 1:
            messagebox.showerror("Error", "You cannot delete the last profile.")
            return

        if not messagebox.askyesno("Delete profile", f"Delete profile '{name}'?"):
            return

        sec = self._sec_ci(self._profile_section(name)) or self._profile_section(name)
        if sec in self._cp:
            self._cp.remove_section(sec)

        # scegli un altro profilo come active
        remaining = self._get_profile_names()
        new_active = remaining[0] if remaining else "Default"
        self.profile_name.set(new_active)
        self._cp[SECTION_APP]["active_profile"] = new_active
        self._active_profile = new_active
        self._refresh_profile_combo()
        self._apply_profile_to_ui(new_active)
        self._save_config(silent=True)
        self._log(f"Deleted profile: {name}")

    def _reset_defaults(self) -> None:
        # resetta SOLO i campi della UI (poi "Save profile" per salvarli nel profilo selezionato)
        self.include_patterns.set(DEFAULT_INCLUDE)
        self.exclude_dirs.set(DEFAULT_EXCLUDE_DIRS)
        self.add_timestamp.set(False)
        self.skip_binary.set(True)
        self.header_full_path.set(False)
        self.output_file.set("")
        self.watch_poll_ms.set("1500")
        self.watch_quiet_ms.set("1200")
        self.watch_export_on_start.set(True)
        self._ensure_output_default()
        self._log("Reset to defaults (not saved yet).")

    def _on_close(self) -> None:
        self._watch_stop(log=False)
        # persist batch selection
        try:
            self._store_batch_selection_to_config()
        except Exception:
            pass
        self._save_config(silent=True)
        self.destroy()


    def _build_watch_tab(self, parent: ttk.Frame, pad: dict) -> None:
        info = ttk.LabelFrame(parent, text="Continuous watch")
        info.pack(fill="both", expand=True, **pad)

        desc = ttk.Label(
            info,
            text=(
                "Select a profile in Export, then start monitoring. DumpIt watches matching files "
                "for that profile and automatically re-exports after a short quiet period."
            ),
            wraplength=760,
            justify="left",
        )
        desc.pack(fill="x", padx=8, pady=(8, 4))

        status = ttk.Frame(info)
        status.pack(fill="x", padx=8, pady=(0, 6))
        ttk.Label(status, text="Status:").pack(side="left")
        self.lbl_watch_status = ttk.Label(status, text="Stopped")
        self.lbl_watch_status.pack(side="left", padx=(6, 16))
        ttk.Label(status, text="Profile locked at start:").pack(side="left")
        self.lbl_watch_profile = ttk.Label(status, text="—")
        self.lbl_watch_profile.pack(side="left", padx=(6, 0))

        opts = ttk.LabelFrame(info, text="Watch options")
        opts.pack(fill="x", padx=8, pady=6)
        grid = ttk.Frame(opts)
        grid.pack(fill="x", padx=8, pady=8)

        ttk.Label(grid, text="Poll interval (ms)").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(grid, textvariable=self.watch_poll_ms, width=12).grid(row=0, column=1, sticky="w", padx=6, pady=4)
        ttk.Label(grid, text="Quiet time before export (ms)").grid(row=0, column=2, sticky="w", padx=6, pady=4)
        ttk.Entry(grid, textvariable=self.watch_quiet_ms, width=12).grid(row=0, column=3, sticky="w", padx=6, pady=4)

        ttk.Checkbutton(
            grid,
            text="Run one export immediately on Start",
            variable=self.watch_export_on_start,
        ).grid(row=1, column=0, columnspan=4, sticky="w", padx=6, pady=4)

        actions = ttk.Frame(info)
        actions.pack(fill="x", padx=8, pady=6)
        self.btn_watch_start = ttk.Button(actions, text="Start monitoring", command=self._watch_start)
        self.btn_watch_start.pack(side="left", padx=4)
        self.btn_watch_stop = ttk.Button(actions, text="Stop", command=self._watch_stop, state="disabled")
        self.btn_watch_stop.pack(side="left", padx=4)
        ttk.Button(actions, text="Export now", command=lambda: self._run_export(show_message=True)).pack(side="left", padx=12)

        details = ttk.LabelFrame(info, text="Activity")
        details.pack(fill="both", expand=True, padx=8, pady=(6, 10))

        self.lbl_watch_last_change = ttk.Label(details, text="No changes detected yet.", wraplength=760, justify="left")
        self.lbl_watch_last_change.pack(fill="x", padx=8, pady=(8, 4))

        self.lbl_watch_last_export = ttk.Label(details, text="No automatic export yet.", wraplength=760, justify="left")
        self.lbl_watch_last_export.pack(fill="x", padx=8, pady=(0, 8))

    def _set_watch_status(self, text: str) -> None:
        self.lbl_watch_status.configure(text=text)
        self.lbl_watch_profile.configure(text=(self._watch_profile_name or "—"))
        self.lbl_watch_last_change.configure(text=self._watch_last_change_summary)
        self.lbl_watch_last_export.configure(text=self._watch_last_export_summary)
        self.btn_watch_start.configure(state=("disabled" if self._watch_running else "normal"))
        self.btn_watch_stop.configure(state=("normal" if self._watch_running else "disabled"))

    def _watch_validate_ms(self, value: str, label: str, fallback: int, minimum: int = 100) -> int:
        raw = (value or "").strip()
        try:
            parsed = int(raw)
        except ValueError:
            raise ValueError(f"{label} must be an integer.")
        if parsed < minimum:
            raise ValueError(f"{label} must be at least {minimum} ms.")
        return parsed

    def _get_current_ui_export_settings(self) -> tuple[Path, Path, list[str], set[str], bool, bool]:
        root = Path(normalize_ui_path(self.project_dir.get())).resolve()
        if not root.exists():
            raise FileNotFoundError("Project folder does not exist.")

        patterns = normalize_patterns(parse_csv_list(self.include_patterns.get()))
        exclude_dirs = {x.lower() for x in parse_csv_list(self.exclude_dirs.get())}
        out = normalize_ui_path(self.output_file.get().strip())
        out_path = Path(out).resolve() if out else build_default_output(root, self.add_timestamp.get())
        return root, out_path, patterns, exclude_dirs, self.skip_binary.get(), self.header_full_path.get()

    def _file_digest(self, p: Path) -> str:
        h = hashlib.sha1()
        with p.open("rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    
    
    def _build_watch_snapshot(self) -> dict[str, tuple[int, int, str]]:
        if self._watch_root is None or self._watch_out_path is None:
            return {}
    
        exclude_files = {canon_path(self._watch_out_path)}
        files = collect_files(
            self._watch_root,
            self._watch_exclude_dirs,
            self._watch_patterns,
            self._watch_skip_binary,
            exclude_files=exclude_files,
        )
    
        snapshot: dict[str, tuple[int, int, str]] = {}
        for p in files:
            try:
                st = p.stat()
                digest = self._file_digest(p)
            except OSError:
                continue
            snapshot[canon_path(p)] = (st.st_mtime_ns, st.st_size, digest)
    
        return snapshot

    def _summarize_snapshot_changes(
        self,
        old_snapshot: dict[str, tuple[int, int, str]],
        new_snapshot: dict[str, tuple[int, int, str]],
    ) -> tuple[int, int, int]:
        added = len(set(new_snapshot) - set(old_snapshot))
        removed = len(set(old_snapshot) - set(new_snapshot))
        modified = 0
    
        for key in set(old_snapshot).intersection(new_snapshot):
            if old_snapshot[key] != new_snapshot[key]:
                modified += 1
    
        return added, modified, removed

    def _schedule_watch_tick(self) -> None:
        if not self._watch_running:
            return
        self._watch_after_id = self.after(self._watch_poll_interval_ms, self._watch_tick)

    def _schedule_watch_export(self) -> None:
        if not self._watch_running:
            return
        if self._watch_pending_export_id:
            try:
                self.after_cancel(self._watch_pending_export_id)
            except Exception:
                pass
        self._watch_pending_export_id = self.after(self._watch_quiet_period_ms, self._watch_export_now)

    def _watch_start(self) -> None:
        if self._watch_running:
            return
        try:
            poll_ms = self._watch_validate_ms(self.watch_poll_ms.get(), "Poll interval", 1500)
            quiet_ms = self._watch_validate_ms(self.watch_quiet_ms.get(), "Quiet time before export", 1200)
            root, out_path, patterns, exclude_dirs, skip_binary, header_full_path = self._get_current_ui_export_settings()
        except Exception as e:
            messagebox.showerror("Watch", str(e))
            return

        self.watch_poll_ms.set(str(poll_ms))
        self.watch_quiet_ms.set(str(quiet_ms))
        self._save_config(silent=True)

        self._watch_running = True
        self._watch_profile_name = (self.profile_name.get().strip() or "Default")
        self._watch_root = root
        self._watch_out_path = out_path
        self._watch_patterns = list(patterns)
        self._watch_exclude_dirs = set(exclude_dirs)
        self._watch_skip_binary = skip_binary
        self._watch_header_full_path = header_full_path
        self._watch_poll_interval_ms = poll_ms
        self._watch_quiet_period_ms = quiet_ms
        self._watch_snapshot = self._build_watch_snapshot()
        self._watch_last_change_summary = f"Monitoring {len(self._watch_snapshot)} matching files under: {root}"
        self._watch_last_export_summary = "No automatic export yet."
        self._set_watch_status("Monitoring")
        self._log(
            f"Watch started for profile '{self._watch_profile_name}' "
            f"(poll {poll_ms} ms, quiet {quiet_ms} ms, files {len(self._watch_snapshot)})"
        )

        if self.watch_export_on_start.get():
            self._watch_last_export_summary = "Automatic export requested at start..."
            self._set_watch_status("Exporting")
            self.after(10, self._watch_export_now)
        else:
            self._schedule_watch_tick()

    def _watch_stop(self, log: bool = True) -> None:
        if self._watch_after_id:
            try:
                self.after_cancel(self._watch_after_id)
            except Exception:
                pass
        self._watch_after_id = None

        if self._watch_pending_export_id:
            try:
                self.after_cancel(self._watch_pending_export_id)
            except Exception:
                pass
        self._watch_pending_export_id = None

        was_running = self._watch_running
        self._watch_running = False
        self._watch_export_in_progress = False
        self._watch_profile_name = ""
        self._watch_root = None
        self._watch_out_path = None
        self._watch_patterns = []
        self._watch_exclude_dirs = set()
        self._watch_snapshot = {}
        self._watch_poll_interval_ms = 1500
        self._watch_quiet_period_ms = 1200
        self._set_watch_status("Stopped")
        if was_running and log:
            self._log("Watch stopped.")

    def _watch_tick(self) -> None:
        self._watch_after_id = None
        if not self._watch_running:
            return

        try:
            if self._watch_root is None or not self._watch_root.exists():
                raise FileNotFoundError("Watched project folder no longer exists.")

            new_snapshot = self._build_watch_snapshot()
            added, modified, removed = self._summarize_snapshot_changes(self._watch_snapshot, new_snapshot)
            self._watch_snapshot = new_snapshot

            if added or modified or removed:
                self._watch_last_change_summary = (
                    f"Changes detected at {datetime.now().strftime('%H:%M:%S')} — "
                    f"added {added}, modified {modified}, removed {removed}."
                )
                self._set_watch_status("Waiting quiet period")
                self._log(
                    f"Watch change detected for '{self._watch_profile_name}': "
                    f"added {added}, modified {modified}, removed {removed}."
                )
                self._schedule_watch_export()
            elif not self._watch_pending_export_id and not self._watch_export_in_progress:
                self._set_watch_status("Monitoring")
        except Exception as e:
            self._watch_last_change_summary = f"Watch error: {e}"
            self._set_watch_status("Error")
            self._log(f"Watch error: {e}")
            self._watch_stop(log=False)
            messagebox.showerror("Watch", str(e))
            return

        self._schedule_watch_tick()

    def _watch_export_now(self) -> None:
        self._watch_pending_export_id = None
        if not self._watch_running or self._watch_export_in_progress:
            return

        self._watch_export_in_progress = True
        self._set_watch_status("Exporting")
        try:
            included, skipped, out_path = self._run_export(show_message=False)
            self._watch_last_export_summary = (
                f"Last automatic export at {datetime.now().strftime('%H:%M:%S')} — "
                f"included {included}, skipped read errors {skipped}, output {out_path}"
            )
            self._watch_snapshot = self._build_watch_snapshot()
            self._log(f"Watch auto-export completed for '{self._watch_profile_name}'.")
        except Exception as e:
            self._watch_last_export_summary = f"Automatic export failed: {e}"
            self._log(f"Watch auto-export failed: {e}")
            self._set_watch_status("Error")
            self._watch_export_in_progress = False
            self._watch_stop(log=False)
            messagebox.showerror("Watch", str(e))
            return

        self._watch_export_in_progress = False
        if self._watch_running:
            self._set_watch_status("Monitoring")
            if self._watch_after_id is None:
                self._schedule_watch_tick()

    def _run_export(self, show_message: bool = True) -> tuple[int, int, Path]:
        root = Path(normalize_ui_path(self.project_dir.get())).resolve()
        if not root.exists():
            raise FileNotFoundError("Project folder does not exist.")

        patterns = normalize_patterns(parse_csv_list(self.include_patterns.get()))
        exclude = {x.lower() for x in parse_csv_list(self.exclude_dirs.get())}

        out = normalize_ui_path(self.output_file.get().strip())
        out_path = Path(out).resolve() if out else build_default_output(root, self.add_timestamp.get())

        included, skipped = export_to_file(
            root=root,
            out_path=out_path,
            exclude_dirs=exclude,
            patterns=patterns,
            skip_binary=self.skip_binary.get(),
            header_full_path=self.header_full_path.get(),
            profile_name=(self.profile_name.get().strip() or "Default"),
        )

        self._save_config(silent=True)
        self._log(f"OK: exported {included} files -> {out_path} (skipped read errors: {skipped})")
        if show_message:
            messagebox.showinfo(
                "Done",
                f"Export completed.\nIncluded: {included}\nSkipped read errors: {skipped}\nOutput: {out_path}",
            )
        return included, skipped, out_path


    # ---------- Batch UI / Runner ----------
    def _build_batch_tab(self, parent: ttk.Frame, pad: dict) -> None:
        info = ttk.LabelFrame(parent, text="Batch")
        info.pack(fill="both", expand=True, **pad)

        top = ttk.Frame(info)
        top.pack(fill="x", padx=8, pady=(8, 4))

        ttk.Label(
            top,
            text="Select one or more profiles to run. (Batch uses the saved profile settings — click 'Save profile' if needed.)",
            wraplength=760,
            justify="left",
        ).pack(side="left", fill="x", expand=True)

        tools = ttk.Frame(info)
        tools.pack(fill="x", padx=8, pady=(0, 6))

        ttk.Button(tools, text="Select all", command=self._batch_select_all).pack(side="left", padx=4)
        ttk.Button(tools, text="Select none", command=self._batch_select_none).pack(side="left", padx=4)

        self.lbl_batch_status = ttk.Label(tools, text="")
        self.lbl_batch_status.pack(side="right")

        # Scrollable checklist
        container = ttk.Frame(info)
        container.pack(fill="both", expand=True, padx=8, pady=6)

        self.batch_canvas = tk.Canvas(container, highlightthickness=0)
        self.batch_scroll = ttk.Scrollbar(container, orient="vertical", command=self.batch_canvas.yview)
        self.batch_canvas.configure(yscrollcommand=self.batch_scroll.set)

        self.batch_scroll.pack(side="right", fill="y")
        self.batch_canvas.pack(side="left", fill="both", expand=True)

        self.batch_list_frame = ttk.Frame(self.batch_canvas)
        self.batch_canvas_window = self.batch_canvas.create_window((0, 0), window=self.batch_list_frame, anchor="nw")

        def _on_frame_configure(_evt=None):
            self.batch_canvas.configure(scrollregion=self.batch_canvas.bbox("all"))

        def _on_canvas_configure(evt):
            # make inner frame width follow canvas width
            try:
                self.batch_canvas.itemconfig(self.batch_canvas_window, width=evt.width)
            except Exception:
                pass

        self.batch_list_frame.bind("<Configure>", _on_frame_configure)
        self.batch_canvas.bind("<Configure>", _on_canvas_configure)

        # Run buttons
        run = ttk.Frame(info)
        run.pack(fill="x", padx=8, pady=(0, 10))

        self.btn_batch_preview = ttk.Button(run, text="Run batch preview", command=lambda: self._run_batch("preview"))
        self.btn_batch_preview.pack(side="left", padx=4)

        self.btn_batch_export = ttk.Button(run, text="Run batch export", command=lambda: self._run_batch("export"))
        self.btn_batch_export.pack(side="left", padx=4)

        # Runtime state
        self.batch_vars: dict[str, tk.BooleanVar] = {}
        self._batch_queue: list[str] = []
        self._batch_mode: str = ""
        self._batch_results: list[tuple[str, str]] = []

        # initial populate (real refresh happens after config load)
        self._refresh_batch_profile_list()

    def _refresh_batch_profile_list(self, prefer_config: bool = False) -> None:
        names = self._get_profile_names()
        if not names:
            names = ["Default"]

        # preserve selection (case-insensitive). During startup we may want to ignore runtime UI state
        # and prefer what was saved in config.
        old_sel = {} if prefer_config else {k.lower(): v.get() for k, v in getattr(self, "batch_vars", {}).items()}
        # if no runtime selection yet, try load from config (only if previously saved)
        cfg_sel: Set[str] = set()
        has_cfg_sel = self._has_saved_batch_selection()
        if not old_sel and has_cfg_sel:
            cfg_sel = self._get_batch_selection_from_config()

        # clear UI
        if hasattr(self, "batch_list_frame"):
            for w in self.batch_list_frame.winfo_children():
                w.destroy()

        self.batch_vars = {}
        any_checked = False
        active = (self._cp.get(SECTION_APP, "active_profile", fallback="Default") or "Default").strip()

        for name in names:
            initial = old_sel.get(name.lower(), (name.lower() in cfg_sel) if has_cfg_sel else False)
            var = tk.BooleanVar(value=initial)
            self.batch_vars[name] = var
            any_checked = any_checked or var.get()

            cb = ttk.Checkbutton(self.batch_list_frame, text=name, variable=var, command=self._on_batch_selection_changed)
            cb.pack(anchor="w", padx=6, pady=2)

        # if nothing selected and there was NO saved selection, default to active profile
        if names and not any_checked and not has_cfg_sel:
            for n in names:
                if n.lower() == active.lower():
                    self.batch_vars[n].set(True)
                    any_checked = True
                    break

        # keep config in sync with what's shown
        self._store_batch_selection_to_config()

        # status line
        if hasattr(self, "lbl_batch_status"):
            self.lbl_batch_status.configure(text=f"{len(names)} profiles — selected {len(self._get_selected_batch_profiles())}")

        # refresh scrollregion
        if hasattr(self, "batch_canvas"):
            try:
                self.batch_canvas.configure(scrollregion=self.batch_canvas.bbox("all"))
            except Exception:
                pass

    def _batch_select_all(self) -> None:
        for v in getattr(self, "batch_vars", {}).values():
            v.set(True)
        self._on_batch_selection_changed()

    def _batch_select_none(self) -> None:
        for v in getattr(self, "batch_vars", {}).values():
            v.set(False)
        self._on_batch_selection_changed()

    def _get_selected_batch_profiles(self) -> list[str]:
        out: list[str] = []
        for name, var in getattr(self, "batch_vars", {}).items():
            if var.get():
                out.append(name)
        out.sort(key=lambda x: x.lower())
        return out

    def _read_profile_settings(self, name: str):
        sec = self._profile_section(name)
        sec_real = self._sec_ci(sec) or sec
        if sec_real not in self._cp:
            raise ValueError(f"Profile not found: {name}")

        s = self._cp[sec_real]

        project_dir = normalize_ui_path(s.get("project_dir", str(get_default_project_dir())))
        root = Path(project_dir).resolve()

        include_patterns = normalize_patterns(parse_csv_list(s.get("include_patterns", DEFAULT_INCLUDE)))
        exclude_dirs = {x.lower() for x in parse_csv_list(s.get("exclude_dirs", DEFAULT_EXCLUDE_DIRS))}

        add_timestamp = s.getboolean("add_timestamp", fallback=False)
        skip_binary = s.getboolean("skip_binary", fallback=True)
        header_full_path = s.getboolean("header_full_path", fallback=False)

        out_str = normalize_ui_path(s.get("output_file", "").strip())
        out_path = Path(out_str).resolve() if out_str else build_default_output(root, add_timestamp)

        return root, out_path, include_patterns, exclude_dirs, skip_binary, header_full_path

    def _set_batch_running(self, running: bool) -> None:
        try:
            self.btn_batch_preview.configure(state=("disabled" if running else "normal"))
            self.btn_batch_export.configure(state=("disabled" if running else "normal"))
        except Exception:
            pass

    def _run_batch(self, mode: str) -> None:
        selected = self._get_selected_batch_profiles()
        if not selected:
            messagebox.showerror("Batch", "Select at least one profile.")
            return

        # Remember current batch selection for next run
        self._store_batch_selection_to_config()

        # Persist the current profile silently (so batch sees latest saved state for it)
        self._save_config(silent=True)

        self._batch_queue = list(selected)
        self._batch_mode = mode
        self._batch_results = []
        self._set_batch_running(True)
        self.lbl_batch_status.configure(text=f"Running {mode}: 0/{len(self._batch_queue)}")
        self._log(f"Batch start ({mode}): {', '.join(selected)}")

        self.after(10, self._batch_step)

    def _batch_step(self) -> None:
        total = len(self._batch_queue) + len(self._batch_results)

        if not self._batch_queue:
            # done
            ok = sum(1 for _, status in self._batch_results if status == "OK")
            err = sum(1 for _, status in self._batch_results if status != "OK")
            self._set_batch_running(False)
            self.lbl_batch_status.configure(text=f"Done: OK {ok}, Errors {err}")
            self._log(f"Batch done: OK {ok}, Errors {err}")
            messagebox.showinfo("Batch done", f"Completed.\nOK: {ok}\nErrors: {err}")
            return

        name = self._batch_queue.pop(0)
        done = len(self._batch_results) + 1
        self.lbl_batch_status.configure(text=f"Running {self._batch_mode}: {done}/{done + len(self._batch_queue)}")

        try:
            root, out_path, patterns, exclude_dirs, skip_binary, header_full_path = self._read_profile_settings(name)
            if not root.exists():
                raise FileNotFoundError(f"Project folder does not exist: {root}")

            if self._batch_mode == "preview":
                exclude_files = {canon_path(out_path)}
                files = collect_files(root, exclude_dirs, patterns, skip_binary, exclude_files=exclude_files)
                self._log(f"[{name}] Preview: {len(files)} files from: {root}")
            else:
                included, skipped = export_to_file(
                    root=root,
                    out_path=out_path,
                    exclude_dirs=exclude_dirs,
                    patterns=patterns,
                    skip_binary=skip_binary,
                    header_full_path=header_full_path,
                    profile_name=name,
                )
                self._log(f"[{name}] OK: exported {included} files -> {out_path} (skipped read errors: {skipped})")

            self._batch_results.append((name, "OK"))
        except Exception as e:
            self._batch_results.append((name, "ERR"))
            self._log(f"[{name}] ERROR: {e}")

        # keep UI responsive
        self.after(10, self._batch_step)


def _crash_log_path() -> Path:
    # log nel config folder (stesso posto del dumpit.ini)
    p = get_config_path()
    return p.with_suffix(".crash.log")

def main() -> None:
    try:
        app = DumpItApp()

        # cattura errori anche dentro callback Tkinter
        def _tk_report(exc, val, tb):
            import traceback
            _crash_log_path().write_text("".join(traceback.format_exception(exc, val, tb)), encoding="utf-8")
            messagebox.showerror("DumpIt crash", f"Error saved to:\n{_crash_log_path()}")

        app.report_callback_exception = _tk_report  # type: ignore
        app.mainloop()
    except Exception as e:
        import traceback
        _crash_log_path().write_text(traceback.format_exc(), encoding="utf-8")
        # su build -w non vedrai niente, ma il file log resta
        raise

if __name__ == "__main__":
    main()
