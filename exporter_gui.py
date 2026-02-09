#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import platform
import fnmatch
import configparser
from pathlib import Path
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox


APP_NAME = "DumpIt"
CONFIG_FILE_NAME = "dumpit.ini"

DEFAULT_INCLUDE = "*.al,app.json,*.gd,*.tscn,*.tres,*.cfg,*.ini,*.json,*.md,*.txt"
DEFAULT_EXCLUDE_DIRS = ".git,.vscode,.alpackages,bin,obj,node_modules,.idea,.vs,.devcontainer,.godot,.import"

def get_config_path() -> Path:
    system = platform.system().lower()
    if system.startswith("win"):
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / APP_NAME / CONFIG_FILE_NAME
    # Linux / others -> XDG
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else (Path.home() / ".config")
    return base / APP_NAME / CONFIG_FILE_NAME

def ensure_parent_dir(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)

def parse_csv_list(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]

def normalize_patterns(patterns: list[str]) -> list[str]:
    """
    Accetta:
    - "*.al"
    - ".al" (diventa "*.al")
    - "app.json" (match esatto)
    - "src/*.gd" (match su path relativo)
    """
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

def rel_posix(root: Path, file_path: Path) -> str:
    return file_path.relative_to(root).as_posix()

def should_skip_by_dir(rel_path: Path, exclude_dirs: set[str]) -> bool:
    return any(part in exclude_dirs for part in rel_path.parts)

def is_probably_binary(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            chunk = f.read(8192)
        return b"\x00" in chunk
    except Exception:
        return True

def read_text_safely(p: Path) -> str:
    # tenta utf-8 (con BOM), poi utf-8, poi fallback
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
        # se pattern contiene '/' o '\' lo matchiamo sul path relativo
        if ("/" in pat) or ("\\" in pat):
            if fnmatch.fnmatch(rp, pat.replace("\\", "/")):
                return True
        else:
            if fnmatch.fnmatch(nm, pat):
                return True
    return False

def collect_files(root: Path, exclude_dirs: set[str], patterns: list[str], skip_binary: bool) -> list[Path]:
    files: list[Path] = []
    for p in root.rglob("*"):
        if p.is_dir():
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
    """
    returns (included_files, skipped_files)
    """
    files = collect_files(root, exclude_dirs, patterns, skip_binary)
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

class DumpItApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("DumpIt — Source Exporter")
        self.geometry("820x520")
        self.minsize(820, 520)

        # State
        self.project_dir = tk.StringVar(value=str(Path.cwd()))
        self.include_patterns = tk.StringVar(value=DEFAULT_INCLUDE)
        self.exclude_dirs = tk.StringVar(value=DEFAULT_EXCLUDE_DIRS)
        self.add_timestamp = tk.BooleanVar(value=False)
        self.skip_binary = tk.BooleanVar(value=True)
        self.header_full_path = tk.BooleanVar(value=False)
        self.output_file = tk.StringVar(value="")

        self.config_path = get_config_path()

        self._build_ui()
        self._load_config()          # carica se esiste
        self._ensure_output_default() # imposta output se vuoto

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        pad = {"padx": 10, "pady": 6}
        root = ttk.Frame(self)
        root.pack(fill="both", expand=True, **pad)

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
        ttk.Button(actions, text="Save settings", command=self._save_config).pack(side="left", padx=16)
        ttk.Button(actions, text="Reset defaults", command=self._reset_defaults).pack(side="left", padx=4)

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

    def _browse_project(self) -> None:
        d = filedialog.askdirectory(title="Select project folder", initialdir=self.project_dir.get() or str(Path.cwd()))
        if d:
            self.project_dir.set(d)
            self._suggest_output_if_default()

    def _choose_output(self) -> None:
        root = Path(self.project_dir.get()).resolve()
        initial = build_default_output(root, self.add_timestamp.get())
        f = filedialog.asksaveasfilename(
            title="Choose output file",
            initialdir=str(root),
            initialfile=initial.name,
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")]
        )
        if f:
            self.output_file.set(f)

    def _ensure_output_default(self) -> None:
        if not self.output_file.get().strip():
            root = Path(self.project_dir.get()).resolve()
            self.output_file.set(str(build_default_output(root, self.add_timestamp.get())))

    def _suggest_output_if_default(self) -> None:
        """
        Se l'output attuale sembra quello "di default" (stessa cartella e nome che parte con root.name),
        allora lo rigeneriamo (utile quando cambi project dir o toggle timestamp).
        """
        try:
            root = Path(self.project_dir.get()).resolve()
            current = self.output_file.get().strip()
            if not current:
                self.output_file.set(str(build_default_output(root, self.add_timestamp.get())))
                return
            curp = Path(current).resolve()
            if curp.parent == root and curp.stem.startswith(root.name):
                self.output_file.set(str(build_default_output(root, self.add_timestamp.get())))
        except Exception:
            pass

    def _preview(self) -> None:
        try:
            root = Path(self.project_dir.get()).resolve()
            if not root.exists():
                messagebox.showerror("Error", "Project folder does not exist.")
                return

            patterns = normalize_patterns(parse_csv_list(self.include_patterns.get()))
            exclude = set(parse_csv_list(self.exclude_dirs.get()))
            files = collect_files(root, exclude, patterns, self.skip_binary.get())
            self._log(f"Preview: {len(files)} files will be included from: {root}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _export(self) -> None:
        try:
            root = Path(self.project_dir.get()).resolve()
            if not root.exists():
                messagebox.showerror("Error", "Project folder does not exist.")
                return

            patterns = normalize_patterns(parse_csv_list(self.include_patterns.get()))
            exclude = set(parse_csv_list(self.exclude_dirs.get()))

            out = self.output_file.get().strip()
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

    def _reset_defaults(self) -> None:
        self.include_patterns.set(DEFAULT_INCLUDE)
        self.exclude_dirs.set(DEFAULT_EXCLUDE_DIRS)
        self.add_timestamp.set(False)
        self.skip_binary.set(True)
        self.header_full_path.set(False)
        self.output_file.set("")
        self._ensure_output_default()
        self._log("Reset to defaults (not saved yet).")

    def _load_config(self) -> None:
        cp = configparser.ConfigParser()
        if not self.config_path.exists():
            return
        try:
            cp.read(self.config_path, encoding="utf-8")
            s = cp["settings"]

            self.project_dir.set(s.get("project_dir", self.project_dir.get()))
            self.include_patterns.set(s.get("include_patterns", self.include_patterns.get()))
            self.exclude_dirs.set(s.get("exclude_dirs", self.exclude_dirs.get()))
            self.add_timestamp.set(s.getboolean("add_timestamp", fallback=self.add_timestamp.get()))
            self.skip_binary.set(s.getboolean("skip_binary", fallback=self.skip_binary.get()))
            self.header_full_path.set(s.getboolean("header_full_path", fallback=self.header_full_path.get()))
            self.output_file.set(s.get("output_file", self.output_file.get()))
            self._log(f"Loaded config: {self.config_path}")
        except Exception:
            # config rotta? non blocchiamo l'app
            self._log("Warning: failed to load config, using defaults.")

    def _save_config(self, silent: bool = False) -> None:
        try:
            cp = configparser.ConfigParser()
            cp["settings"] = {
                "project_dir": self.project_dir.get(),
                "include_patterns": self.include_patterns.get(),
                "exclude_dirs": self.exclude_dirs.get(),
                "add_timestamp": str(self.add_timestamp.get()),
                "skip_binary": str(self.skip_binary.get()),
                "header_full_path": str(self.header_full_path.get()),
                "output_file": self.output_file.get(),
            }
            ensure_parent_dir(self.config_path)
            with self.config_path.open("w", encoding="utf-8") as f:
                cp.write(f)
            if not silent:
                self._log(f"Saved config: {self.config_path}")
                messagebox.showinfo("Saved", f"Settings saved to:\n{self.config_path}")
        except Exception as e:
            if not silent:
                messagebox.showerror("Error", str(e))

    def _on_close(self) -> None:
        # salva silenziosamente all'uscita
        self._save_config(silent=True)
        self.destroy()

if __name__ == "__main__":
    DumpItApp().mainloop()
