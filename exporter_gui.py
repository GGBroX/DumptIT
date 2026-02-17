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


def rel_posix(root: Path, file_path: Path) -> str:
    return file_path.relative_to(root).as_posix()

def should_skip_by_dir(rel_path: Path, exclude_dirs: set[str]) -> bool:
    return any(part in exclude_dirs for part in rel_path.parts)

