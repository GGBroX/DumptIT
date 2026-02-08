#!/usr/bin/env python3
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime
import fnmatch

DEFAULT_EXCLUDE_DIRS = [".git", ".vscode", ".alpackages", "bin", "obj", "node_modules", ".idea", ".vs"]
DEFAULT_PATTERNS = ["*.al", "app.json"]  # default AL

def should_skip(rel: Path, exclude_dirs: set[str]) -> bool:
    return any(part in exclude_dirs for part in rel.parts)

def read_text_safely(p: Path) -> str:
    for enc in ("utf-8-sig", "utf-8"):
        try:
            return p.read_text(encoding=enc)
        except UnicodeDecodeError:
            pass
    return p.read_text(encoding="utf-8", errors="replace")

def match_patterns(name: str, patterns: list[str]) -> bool:
    name_l = name.lower()
    return any(fnmatch.fnmatch(name_l, pat.lower()) for pat in patterns)

def collect_files(root: Path, exclude_dirs: set[str], patterns: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        rel = p.relative_to(root)
        if should_skip(rel, exclude_dirs):
            continue
        if match_patterns(p.name, patterns) or (p.suffix.lower() and match_patterns("*" + p.suffix.lower(), patterns)):
            files.append(p)
    files.sort(key=lambda x: str(x).lower())
    return files

def export(root: Path, out_path: Path, exclude_dirs: set[str], patterns: list[str]) -> int:
    files = collect_files(root, exclude_dirs, patterns)
    parts: list[str] = []
    for p in files:
        rel = p.relative_to(root).as_posix()
        parts.append(f"===== FILE: {rel} =====\n")
        parts.append(read_text_safely(p))
        if not parts[-1].endswith("\n"):
            parts.append("\n")
        parts.append("\n")
    out_path.write_text("".join(parts), encoding="utf-8")
    return len(files)

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Source Exporter (AL/Generic)")
        self.geometry("760x460")
        self.minsize(760, 460)

        self.project_dir = tk.StringVar(value=str(Path.cwd()))
        self.patterns = tk.StringVar(value=",".join(DEFAULT_PATTERNS))
        self.exclude_dirs = tk.StringVar(value=",".join(DEFAULT_EXCLUDE_DIRS))
        self.add_timestamp = tk.BooleanVar(value=False)
        self.output_file = tk.StringVar(value="")

        self._build()
        self._suggest_output()

    def _build(self) -> None:
        pad = {"padx": 10, "pady": 6}
        root = ttk.Frame(self)
        root.pack(fill="both", expand=True, **pad)

        lf1 = ttk.LabelFrame(root, text="Project folder")
        lf1.pack(fill="x", **pad)
        ttk.Entry(lf1, textvariable=self.project_dir).pack(side="left", fill="x", expand=True, padx=8, pady=8)
        ttk.Button(lf1, text="Browse…", command=self._browse).pack(side="left", padx=8, pady=8)

        lf2 = ttk.LabelFrame(root, text="Include patterns (comma-separated)")
        lf2.pack(fill="x", **pad)
        ttk.Entry(lf2, textvariable=self.patterns).pack(fill="x", padx=8, pady=8)

        lf3 = ttk.LabelFrame(root, text="Exclude folders (comma-separated)")
        lf3.pack(fill="x", **pad)
        ttk.Entry(lf3, textvariable=self.exclude_dirs).pack(fill="x", padx=8, pady=8)

        lf4 = ttk.LabelFrame(root, text="Output")
        lf4.pack(fill="x", **pad)
        ttk.Entry(lf4, textvariable=self.output_file).pack(side="left", fill="x", expand=True, padx=8, pady=8)
        ttk.Button(lf4, text="Choose…", command=self._choose_out).pack(side="left", padx=8, pady=8)

        opts = ttk.Frame(root)
        opts.pack(fill="x", **pad)
        ttk.Checkbutton(opts, text="Add timestamp to output name", variable=self.add_timestamp,
                        command=self._suggest_output).pack(side="left")

        actions = ttk.Frame(root)
        actions.pack(fill="x", **pad)
        ttk.Button(actions, text="Preview", command=self._preview).pack(side="left", padx=4)
        ttk.Button(actions, text="Export", command=self._export).pack(side="left", padx=4)

        self.log = tk.Text(root, height=10, wrap="word")
        self.log.pack(fill="both", expand=True, **pad)
        self.log.configure(state="disabled")

    def _log(self, s: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", s + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _browse(self) -> None:
        d = filedialog.askdirectory(title="Select project folder", initialdir=self.project_dir.get() or str(Path.cwd()))
        if d:
            self.project_dir.set(d)
            self._suggest_output()

    def _choose_out(self) -> None:
        root = Path(self.project_dir.get()).resolve()
        initial = self._suggested_path(root)
        f = filedialog.asksaveasfilename(
            title="Choose output file",
            initialdir=str(root),
            initialfile=initial.name,
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")]
        )
        if f:
            self.output_file.set(f)

    def _suggested_path(self, root: Path) -> Path:
        name = root.name
        if self.add_timestamp.get():
            name += "_" + datetime.now().strftime("%Y-%m-%d_%H%M%S")
        return root / f"{name}.txt"

    def _suggest_output(self) -> None:
        if not self.output_file.get().strip():
            root = Path(self.project_dir.get()).resolve()
            self.output_file.set(str(self._suggested_path(root)))

    def _preview(self) -> None:
        try:
            root = Path(self.project_dir.get()).resolve()
            exc = {x.strip() for x in self.exclude_dirs.get().split(",") if x.strip()}
            pats = [x.strip() for x in self.patterns.get().split(",") if x.strip()]
            files = collect_files(root, exc, pats)
            self._log(f"Preview: {len(files)} files from {root}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _export(self) -> None:
        try:
            root = Path(self.project_dir.get()).resolve()
            exc = {x.strip() for x in self.exclude_dirs.get().split(",") if x.strip()}
            pats = [x.strip() for x in self.patterns.get().split(",") if x.strip()]
            out = Path(self.output_file.get().strip() or str(self._suggested_path(root))).resolve()
            out.parent.mkdir(parents=True, exist_ok=True)

            n = export(root, out, exc, pats)
            self._log(f"OK: exported {n} files -> {out}")
            messagebox.showinfo("Done", f"Export completed.\nFiles: {n}\nOutput: {out}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    App().mainloop()
