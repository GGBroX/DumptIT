#!/usr/bin/env python3
from __future__ import annotations

from typing import Optional, Set

import os
import sys
import platform
import fnmatch
import configparser
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


def export_to_file(root: Path, out_path: Path, exclude_dirs: set[str], patterns: list[str],
                   skip_binary: bool, header_full_path: bool) -> tuple[int, int]:
    exclude_files = {canon_path(out_path)}
    files = collect_files(root, exclude_dirs, patterns, skip_binary, exclude_files=exclude_files)
    skipped = 0

    parts: list[str] = []
    for p in files:
        header = str(p) if header_full_path else rel_posix(root, p)
        parts.append(f"===== FILE: {header} =====\n")
        try:
            parts.append(read_text_safely(p))
        except Exception:
            skipped += 1
            parts.append("[[ERROR reading file]]\n")
        if not parts[-1].endswith("\n"):
            parts.append("\n")
        parts.append("\n")

    ensure_parent_dir(out_path)
    out_path.write_text("".join(parts), encoding="utf-8")
    return (len(files) - skipped, skipped)


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
        self.geometry("860x560")
        self.minsize(860, 560)

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
        self._active_profile = "Default"  # profile currently applied to the UI

        self._build_ui()

        self._load_config()
        self._ensure_output_default()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- UI ----------
    def _build_ui(self) -> None:
        pad = {"padx": 10, "pady": 6}
        root = ttk.Frame(self)
        root.pack(fill="both", expand=True, **pad)

        # Profiles frame
        lf0 = ttk.LabelFrame(root, text="Profile")
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
        lf1 = ttk.LabelFrame(root, text="Project folder")
        lf1.pack(fill="x", **pad)
        ttk.Entry(lf1, textvariable=self.project_dir).pack(side="left", fill="x", expand=True, padx=8, pady=8)
        ttk.Button(lf1, text="Browse…", command=self._browse_project).pack(side="left", padx=8, pady=8)

        # Include patterns
        lf2 = ttk.LabelFrame(root, text="Include patterns (comma-separated, ex: *.al,app.json,*.gd)")
        lf2.pack(fill="x", **pad)
        ttk.Entry(lf2, textvariable=self.include_patterns).pack(fill="x", padx=8, pady=8)

        # Exclude dirs
        lf3 = ttk.LabelFrame(root, text="Exclude folders (comma-separated, match by folder name)")
        lf3.pack(fill="x", **pad)
        ttk.Entry(lf3, textvariable=self.exclude_dirs).pack(fill="x", padx=8, pady=8)

        # Output
        lf4 = ttk.LabelFrame(root, text="Output file")
        lf4.pack(fill="x", **pad)
        ttk.Entry(lf4, textvariable=self.output_file).pack(side="left", fill="x", expand=True, padx=8, pady=8)
        ttk.Button(lf4, text="Choose…", command=self._choose_output).pack(side="left", padx=8, pady=8)

        # Options
        lf5 = ttk.LabelFrame(root, text="Options")
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
        actions = ttk.Frame(root)
        actions.pack(fill="x", **pad)
        ttk.Button(actions, text="Preview", command=self._preview).pack(side="left", padx=4)
        ttk.Button(actions, text="Export", command=self._export).pack(side="left", padx=4)

        # Log
        self.log = tk.Text(root, height=10, wrap="word")
        self.log.pack(fill="both", expand=True, **pad)
        self.log.configure(state="disabled")

        # Footer
        footer = ttk.Frame(root)
        footer.pack(fill="x", **pad)
        self.lbl_cfg = ttk.Label(footer, text=f"Config: {self.config_path}")
        self.lbl_cfg.pack(side="left")

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
            }

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

        self._log(f"Loaded config: {self.config_path}")

    def _save_config(self, silent: bool = False) -> None:
        try:
            self._ensure_minimum_config()
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
        self._ensure_output_default()
        self._log("Reset to defaults (not saved yet).")

    def _on_close(self) -> None:
        self._save_config(silent=True)
        self.destroy()


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
