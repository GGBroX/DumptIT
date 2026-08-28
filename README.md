# DumpIt — Complete Manual

**Source baseline:** `DumpIT_2026-08-28_225051.txt`  
**Dump baseline:** 2026-08-28 20:50:52 UTC  
**Main application source:** `exporter_gui.py` — 6137 lines in the baseline  
**Purpose:** operational and technical manual for the DumpIt application in the configuration represented by the specified baseline.

---

# 1. What DumpIt Is

DumpIt is a Tkinter desktop application for working with text snapshots of software projects.

Its main functions are:

```text
Export
    creates a text dump of a project

Import
    reconstructs files from a DumpIt dump

Watch
    monitors a project and automatically reruns export

Batch
    runs Preview or Export across multiple profiles

Diff
    compares two dumps and generates a visual, text, or .patch delta

Apply Patch
    validates, previews, applies, and reverses unified-diff patches
    through either the DumpIt engine or Git
```

DumpIt uses **persistent profiles** to associate each project with its own settings.

The interface contains a global profile bar, six functional tabs, and one shared log.

---

# 2. Startup and Build

## 2.1 Running from Source

The entry point is:

```text
exporter_gui.py
```

Run:

```bash
python exporter_gui.py
```

The source uses the Python standard library and Tkinter.

The project build pipeline uses Python 3.11.

On Ubuntu the pipeline installs:

```bash
sudo apt-get install -y tk tcl tk-dev tcl-dev
```

## 2.2 Building the Executable

The current pipeline uses PyInstaller:

```bash
python -m pip install pyinstaller
pyinstaller -F -w -n DumpIt exporter_gui.py
```

Result:

```text
dist/DumpIt...
```

The workflow produces artifacts for both Windows and Ubuntu.

## 2.3 Initial Directory

When DumpIt runs as a PyInstaller executable:

```text
default project folder = executable directory
```

When it runs from Python:

```text
default project folder = current working directory
```

---

# 3. General Interface

The main window is organized as follows:

```text
PROFILE BAR

[ Export ] [ Import ] [ Watch ] [ Batch ] [ Diff ] [ Apply Patch ]

SHARED LOG

Config: <dumpit.ini path>
```

Initial size:

```text
850 x 490
```

Initial minimum size:

```text
800 x 465
```

The UI automatically detects the operating-system light/dark theme on a best-effort basis.

The baseline does not provide a manual theme selector.

---

# 4. Profiles

The profile is global to the application.

The top bar contains:

```text
Profile: <profile>
New...
Rename...
Delete

Save
Reset
```

## 4.1 What a Profile Contains

Per-profile persisted settings include:

```text
project_dir
output_file

include_patterns
exclude_dirs
add_timestamp
timestamp_keep_old
skip_binary
header_full_path

import_dump_file
import_target_dir
import_overwrite
import_backup

watch_poll_ms
watch_quiet_ms
watch_export_on_start

patch_file
patch_target_dir
patch_strip_level
patch_reverse
patch_backup
patch_auto_detect
patch_engine
```

The active profile is stored in the application section of the INI file.

## 4.2 New

`New...` creates a new profile by copying the current values of the active profile.

The name is normalized:

```text
newline -> space
:       -> -
[       -> -
]       -> -
```

Two profiles cannot be created with the same existing name.

## 4.3 Rename

`Rename...` renames the current profile.

The new name cannot already exist.

## 4.4 Delete

`Delete` removes the current profile after confirmation.

The last remaining profile cannot be deleted.

After deletion, DumpIt selects another available profile.

## 4.5 Save

`Save`:

```text
writes the current UI values into the active profile
saves the active profile
saves the Batch selection
writes dumpit.ini
```

## 4.6 Reset

`Reset` restores default values **in the UI only**.

It does not automatically persist the reset.

To make it persistent:

```text
Reset
↓
verify values
↓
Save
```

---

# 5. Persistent Configuration

## 5.1 Windows

Default path:

```text
%APPDATA%\DumpIt\dumpit.ini
```

If `APPDATA` is unavailable:

```text
%USERPROFILE%\AppData\Roaming\DumpIt\dumpit.ini
```

## 5.2 macOS / Linux / Unix

If the following variable is defined:

```text
XDG_CONFIG_HOME
```

DumpIt uses:

```text
$XDG_CONFIG_HOME/DumpIt/dumpit.ini
```

otherwise:

```text
~/.config/DumpIt/dumpit.ini
```

## 5.3 Legacy Config Compatibility

At startup DumpIt normalizes older configuration layouts:

```text
App -> app
duplicate profile: sections differing only by letter case -> merge
```

If a conflict occurs during the merge, the primary/canonical section keeps its own value.

---

# 6. Default Values

Main defaults:

```text
Profile
    Default

Include patterns
    *.al,app.json,*.gd,*.tscn,*.tres,*.cfg,*.ini,*.json,*.md,*.txt

Exclude folders
    .git,.vscode,.alpackages,bin,obj,node_modules,.idea,.vs,.devcontainer,.godot,.import

Timestamp output
    OFF

Keep old
    10

Skip binary
    ON

Full path header
    OFF

Import overwrite
    ON

Import backup
    ON

Watch poll
    1500 ms

Watch quiet
    1200 ms

Watch export on start
    ON

Patch strip
    1

Patch reverse
    OFF

Patch backup
    ON

Patch auto-detect
    ON

Patch engine
    dumpit
```

Note: the Include list is only the **default**. A profile may include any other user-configured pattern, for example `*.py`, `*.js`, `*.css`, `*.yml`.

---

# 7. Export

The Export tab contains:

```text
Project folder
Include patterns
Exclude folders
Output file

Timestamp output
Keep old
Skip binary
Full path header

Preview
Export
```

---

# 8. Project Folder

`Project folder` is the root scanned recursively.

`Browse...` selects the directory.

The project must exist.

The path is saved in the profile.

When the root changes, DumpIt may update the output filename if the current one still matches a default output name.

---

# 9. Include Patterns

Patterns are comma-separated.

Example:

```text
*.py,*.js,*.css,*.md,pyproject.toml
```

Matching is case-insensitive.

Rules:

```text
pattern without / or \
    -> match against filename

pattern with / or \
    -> match against path relative to root
```

Examples:

```text
*.py
    include all Python files

README.md
    include files with that name at any depth

tests/*.py
    include relative paths compatible with the pattern
```

An abbreviated form such as:

```text
.py
```

is normalized to:

```text
*.py
```

when it contains no wildcard or path separator.

---

# 10. Exclude Folders

Excluded directories are also comma-separated.

Comparison is case-insensitive.

If any component of the relative path matches an excluded directory, the file is ignored.

Example:

```text
.git,node_modules,.venv,dist,build
```

A file under:

```text
project/node_modules/package/file.js
```

is excluded when `node_modules` is in the list.

---

# 11. Skip Binary

With `Skip binary` enabled, DumpIt performs a simple classification.

It reads up to:

```text
8192 bytes
```

If it finds a NUL byte:

```text
\x00
```

the file is considered probably binary and is excluded.

If the sample cannot be read, the file is treated as binary for filtering purposes.

This is not a complete MIME-recognition system; it is a practical safeguard for primarily text-based dumps.

---

# 12. Reading Text Files

For included files DumpIt attempts:

```text
UTF-8 with BOM / utf-8-sig
UTF-8
UTF-8 with errors=replace as fallback
```

Therefore a file that is not strictly UTF-8 may still be represented in the dump with replacement characters.

Read errors do not necessarily stop the entire export; they are counted as `skipped read errors`.

---

# 13. Output File

If not specified, the default output is:

```text
<project root>/<root name>.txt
```

Example:

```text
H:\DEV\MY_PROJECT
↓
H:\DEV\MY_PROJECT\MY_PROJECT.txt
```

DumpIt excludes the output itself from scanning to prevent self-inclusion.

When timestamping is enabled, it also excludes the associated family of timestamped exports.

---

# 14. Timestamp Output

With `Timestamp output` enabled:

```text
name.txt
```

becomes:

```text
name_YYYY-MM-DD_HHMMSS.txt
```

Example:

```text
TradingTool_2026-08-28_225051.txt
```

If the current filename already contains a DumpIt-format timestamp, the program first derives the base name and then applies the new timestamp.

---

# 15. Keep Old

`Keep old` controls retention of timestamped exports.

The value must be:

```text
integer >= 0
```

The implemented semantics are:

```text
keep the new export
+
keep N previous timestamped exports
```

Therefore:

```text
Keep old = 10
```

results in keeping at most:

```text
1 new + 10 previous
```

for that output family.

Older files are deleted after a successful timestamped export.

Deletion errors are logged.

---

# 16. Full Path Header

With `Full path header` disabled, file sections use relative paths:

```text
===== FILE: src/module.py | lines=123 | modified=... =====
```

With `Full path header` enabled:

```text
===== FILE: H:\DEV\PROJECT\src\module.py | lines=123 | modified=... =====
```

The `PROJECT TREE` remains based on relative paths.

For Diff and Import it is normally simpler to keep the same mode across the dumps being compared.

---

# 17. Export Preview

`Preview`:

```text
validates project folder
calculates filters
calculates excluded output
scans the project
counts included files
```

The result is written to the log:

```text
Preview: N files will be included from: <root>
```

The Export Preview in the baseline does not open a detailed file list.

It does not write the dump.

---

# 18. Export

`Export` performs:

```text
1. root validation
2. pattern parsing
3. output calculation
4. scanning
5. file reading
6. metadata construction
7. PROJECT TREE construction
8. dump rendering
9. UTF-8 write
10. optional timestamp cleanup
11. silent config save
12. log and final dialog
```

The result reports:

```text
Included
Skipped read errors
Output
optional timestamp cleanup
```

---

# 19. DumpIt Dump Format

Structure:

```text
===== DUMPIT EXPORT =====
timestamp_utc: ...
root: ...
output: ...
profile: ...
files_included: ...

===== PROJECT TREE =====
...

===== FILE: <path> | lines=<N> | modified=<timestamp> =====
<content>

===== FILE: ...
...
```

Minimal example:

```text
===== DUMPIT EXPORT =====
timestamp_utc: 2026-08-28 20:50:52 UTC
root: H:\DEV\PROJECT
output: H:\DUMPS\PROJECT.txt
profile: Project
files_included: 2

===== PROJECT TREE =====
README.md [lines: 20 | modified=2026-08-28 18:10:00]
src/
  main.py [lines: 50 | modified=2026-08-28 18:11:00]

===== FILE: README.md | lines=20 | modified=2026-08-28 18:10:00 =====
...

===== FILE: src/main.py | lines=50 | modified=2026-08-28 18:11:00 =====
...
```

The general dump timestamp is UTC.

The `modified` date comes from the file's filesystem metadata.

---

# 20. Project Tree

The Project Tree is built only from files actually included.

For each file it shows:

```text
name
line count
last modified time
```

Directories are sorted before files.

Sorting is case-insensitive.

---

# 21. Import

The Import tab contains:

```text
Dump file
Target folder
Current
Browse...

Overwrite existing files
Backup overwritten files to .dumpit_import_backup

Preview import
Import dump
```

Purpose:

```text
recreate under a target root
the relative tree represented in the dump
```

Import does not delete extra files already present in the target.

---

# 22. Dump Formats Accepted by Import

The parser recognizes sections of the form:

```text
===== FILE: <path> =====
```

and the current format:

```text
===== FILE: <path> | lines=N | modified=... =====
```

The parser treats the content between one `FILE` section and the next as that file's content.

If it finds no valid file sections:

```text
No DumpIt file sections found
```

and the import fails.

---

# 23. Dump Root and Absolute Paths

DumpIt reads, when available:

```text
root: <source root>
```

before the first file section.

If a file header is absolute, it is accepted only when it can be made relative to the root declared in the dump.

Example:

```text
root:
    C:\DEV\PROJECT

header:
    C:\DEV\PROJECT\src\x.py

result:
    src/x.py
```

An absolute path outside the declared root is rejected.

---

# 24. Import Path Safety

Import rejects or skips paths that are:

```text
empty
absolute and not reducible to the dump root
containing ..
containing NUL
containing : in a relative component
duplicates after normalization
pointing to an already-existing directory
```

Unsafe items are counted as:

```text
Skipped invalid/unsafe
```

Preview shows up to eight examples and then the number of additional items.

---

# 25. Import Preview

`Preview import` builds a plan without writing files.

It shows:

```text
Dump
Dump root
Target
Files in dump
Will create
Will overwrite
Will skip existing
Skipped invalid/unsafe
```

If the target does not exist, DumpIt asks whether it should be created.

---

# 26. Overwrite Existing Files

With:

```text
Overwrite existing files = ON
```

an existing file is planned as:

```text
overwrite
```

With the option disabled:

```text
skip_existing
```

Import does not semantically compare file contents; path existence determines the behavior.

---

# 27. Import Backup

With:

```text
Backup overwritten files to .dumpit_import_backup = ON
```

overwritten files are copied before writing into:

```text
<target>/.dumpit_import_backup/YYYYMMDD_HHMMSS/
```

while preserving relative structure.

The backup covers **overwritten** files, not newly created files.

---

# 28. Import Execution

`Import dump`:

```text
1. rebuilds the plan
2. shows counts
3. requests confirmation
4. performs create/overwrite/skip
5. backs up overwritten files when requested
6. saves config
7. shows the final result
```

Result:

```text
Created
Overwritten
Skipped existing
Skipped invalid/unsafe
Backed up
Backup path, if present
```

## 28.1 Import Transactional Limitation

Import writes items sequentially.

The baseline does not implement a global atomic commit for the entire plan.

Therefore, a filesystem error during execution can theoretically occur after some files have already been written.

For destructive operations, use backup and, when possible, version control.

---

# 29. Watch

The Watch tab implements continuous monitoring through polling.

Controls:

```text
Poll ms
Quiet ms
Run one export immediately on Start

Start monitoring
Stop
Export now
```

Displayed state:

```text
Status
Profile locked at start
Last change
Last automatic export
```

---

# 30. Poll ms

`Poll ms` is the filesystem polling interval.

Default:

```text
1500 ms
```

DumpIt validates that it is a positive integer.

---

# 31. Quiet ms

`Quiet ms` is the quiet period required after a change before automatic export.

Default:

```text
1200 ms
```

Purpose:

```text
avoid one export for every individual write in a burst
```

While changes continue arriving, export is postponed until the quiet period expires.

---

# 32. Change Detection

Watch builds a snapshot of files matching the profile filters.

For each file it records:

```text
mtime nanoseconds
size
content digest
```

It detects:

```text
added
modified
removed
```

The DumpIt output and the corresponding timestamped output family are excluded from monitoring.

---

# 33. Starting Watch

`Start monitoring`:

```text
validates Poll and Quiet
reads current Export settings
stores the active profile
builds the initial snapshot
locks the configuration used for monitoring
saves config
starts polling
```

If:

```text
Run one export immediately on Start = ON
```

an export is requested immediately.

---

# 34. Actual Watch Behavior to Know

The configuration used to **detect changes** is copied into Watch state at Start time.

Automatic export, however, calls the normal `_run_export()` in the baseline, which reads the current Export UI variables at execution time.

Therefore:

```text
monitoring snapshot
    uses values fixed at Start

automatic export
    uses current UI values
```

For predictable behavior:

```text
do not change profile or Export settings
while Watch is active
```

or stop Watch, change configuration, and start it again.

---

# 35. Stopping Watch

`Stop`:

```text
cancels the polling timer
cancels any pending export
resets Watch runtime state
sets Status = Stopped
```

Closing DumpIt automatically stops Watch.

---

# 36. Export Now in the Watch Tab

`Export now` invokes the normal current Export.

Watch does not need to be active.

It therefore uses:

```text
current profile/UI
```

---

# 37. Batch

Batch allows the same type of operation to run across multiple profiles.

Controls:

```text
Select all
Select none

profile list with checkboxes

Run batch preview
Run batch export
```

The profile selection is persisted in the application section of the INI file.

---

# 38. Fundamental Batch Rule

Batch uses the **saved profile settings**.

The UI itself states:

```text
Batch uses the saved profile settings — click 'Save' if needed.
```

When a batch starts, DumpIt silently saves the current profile and then reads profile sections from configuration.

---

# 39. Batch Preview

For each selected profile:

```text
validates root
applies include/exclude
applies skip binary
calculates output to exclude
counts files
writes result to log
```

It does not generate dumps.

---

# 40. Batch Export

For each selected profile:

```text
reads saved settings
performs export
performs timestamp retention if enabled
logs the result
continues with the next profile
```

An error in one profile is logged as `ERR` but does not necessarily stop processing of subsequent profiles.

Final result:

```text
OK N
Errors N
```

---

# 41. Diff

The Diff tab compares two DumpIt dumps.

Controls:

```text
Old dump
New dump

Delta file

Format:
    .patch
    .txt

Open visual diff
Save delta file
```

---

# 42. Diff Semantics

The parser transforms each dump into:

```text
path -> content
```

The comparison produces:

```text
added
removed
modified
unchanged
```

Rules:

```text
added
    path exists only in New

removed
    path exists only in Old

modified
    same path, different content

unchanged
    same path, identical content
```

Comparison is performed on the full content of each file section.

---

# 43. Path Consistency Across Dumps

Diff uses the path in the `FILE` header as identity.

Therefore it is important to compare dumps produced using consistent conventions.

Problematic example:

```text
Old:
    src/a.py

New:
    C:\PROJECT\src\a.py
```

Even if they refer to the same physical file, the parser sees two different keys.

For regular comparisons, keep the following option consistent:

```text
Full path header
```

across both dumps.

---

# 44. Visual Diff

`Open visual diff`:

```text
loads Old
loads New
calculates delta
generates local HTML
opens the default browser
```

Temporary HTML files are created under:

```text
<system temp>/DumpIt/
```

with names such as:

```text
dumpit_diff_<timestamp>.html
```

DumpIt cleans these temporary files:

```text
at startup
before opening new diffs
at shutdown
```

---

# 45. .txt Delta

The text format contains:

```text
===== DUMPIT DELTA =====

created_utc
old_dump
new_dump
added
removed
modified
unchanged
```

Then, when present:

```text
ADDED FILES
REMOVED FILES
MODIFIED FILES

full content of added files
full content of removed files
unified diff of modified files
```

---

# 46. .patch Delta

The `.patch` format is unified diff.

For removed files:

```diff
--- a/path
+++ /dev/null
```

For added files:

```diff
--- /dev/null
+++ b/path
```

For modified files:

```diff
--- a/path
+++ b/path
```

If there are no differences:

```text
# DumpIt delta: no differences found.
```

The `.patch` generated by Diff is therefore directly connected to the Apply Patch function.

---

# 47. Apply Patch

The current tab is labeled:

```text
Apply patch — v7
```

Controls:

```text
Patch file
Target folder
Current
Browse...

Engine:
    dumpit
    git

Strip (-p)
Reverse (-R)
Auto-detect target/-p (Reverse uses receipt)
Backup touched files

Requested / resolved mapping
Refresh

Preview
Dry run
Apply
Copy log
```

On Windows, drag & drop is also supported:

```text
.patch/.diff file
    -> Patch file

directory
    -> Target folder
```

---

# 48. Supported Patch Format

Normal format:

```diff
diff --git a/src/file.py b/src/file.py
--- a/src/file.py
+++ b/src/file.py
@@ -10,3 +10,3 @@
 context
-old
+new
 context
```

For new files:

```diff
diff --git a/src/new.py b/src/new.py
new file mode 100644
--- /dev/null
+++ b/src/new.py
@@ -0,0 +1 @@
+content
```

For deleted files:

```diff
diff --git a/src/old.py b/src/old.py
deleted file mode 100644
--- a/src/old.py
+++ /dev/null
@@ -1 +0,0 @@
-content
```

---

# 49. Strip (-p)

With a standard Git patch:

```text
a/src/file.py
b/src/file.py
```

the normal value is:

```text
-p1
```

to obtain:

```text
src/file.py
```

The value in the Strip field acts as:

```text
an effective constraint when Auto-detect is OFF

an initial preference when Auto-detect is ON
```

---

# 50. Auto-detect Target/-p

With Auto-detect enabled, DumpIt evaluates safe combinations of:

```text
cwd
--directory
-p
```

The resolver uses the selected target as the containment boundary.

Before considering a candidate valid, it performs a mapping preflight.

---

# 51. Requested vs Resolved

The UI shows:

```text
Requested:
    target
    strip

Resolved:
    cwd
    optional --directory
    strip

Patch SHA256
```

If the resolved mapping differs from the requested values:

```text
AUTO-DETECT OVERRIDE
```

The Apply dialog shows Requested and Resolved again before confirmation.

---

# 52. Resolution Cache

When a resolution has been calculated for the current selection, DumpIt retains it.

Preview, Dry run, and Apply reuse the same resolution as long as the patch-related UI state does not change.

The cache is invalidated if any relevant parameter changes, including:

```text
profile
patch
target
strip
reverse
auto-detect
backup
engine
```

Before the operation, DumpIt recalculates the mapping anyway and refuses the operation if it no longer matches the resolved mapping.

Conceptual message:

```text
Resolved patch mapping changed after resolution.
Operation refused; run Preview again.
```

---

# 53. Patch Mapping Safety

The full mapping is validated before Apply.

DumpIt rejects:

```text
paths that do not survive strip
paths escaping the resolved cwd
paths escaping the selected target
many-to-one collisions
patches without file paths
```

During auto-detect it also rejects a candidate where a create-file patch maps to an already-existing target.

Forbidden collision example:

```text
a/BRIDGES/README.md   --p2--> README.md
a/HOUSES/README.md    --p2--> README.md
a/WAREHOUSE/README.md --p2--> README.md
```

That candidate is invalid.

---

# 54. DumpIt Engine

`dumpit` is the internal text patch engine.

Properties:

```text
parses unified diff
builds a complete plan
validates every hunk
does not write if any hunk failed
supports controlled hunk relocation
detects already-applied hunks
preserves newline and existing-file encoding as implemented
supports text create / modify / delete
```

It is the default engine.

---

# 55. Git Engine

`git` invokes `git apply`.

Validation first uses:

```text
git apply --check
```

DumpIt auto-detection still selects the safe candidate mapping before invoking Git.

The Git engine requires `git` to be available on the system.

It is necessary when the patch semantics require capabilities not handled by the DumpIt text engine, for example Git binary patches.

---

# 56. Binary Patches

The DumpIt engine is text-only.

Do not use it for:

```text
GIT binary patch
Binary files ...
```

For binary patches use:

```text
Engine = git
```

with Git installed.

---

# 57. DumpIt Engine Hunk States

Applicable states:

```text
APPLICABLE_EXACT
APPLICABLE_EXACT_EOF_CONTEXT
APPLICABLE_EXACT_OFFSET
APPLICABLE_EXACT_OFFSET_EOF_CONTEXT
APPLICABLE_RELOCATED
APPLICABLE_RELOCATED_EOF_CONTEXT
```

Already-applied state:

```text
ALREADY_APPLIED
```

Errors:

```text
FAILED_NOT_FOUND
FAILED_AMBIGUOUS
FAILED_FILE_MISSING
```

Interpretation:

```text
FAILED_NOT_FOUND
    the old block was not found in an applicable way

FAILED_AMBIGUOUS
    multiple candidate positions make the hunk non-deterministic

FAILED_FILE_MISSING
    the file required by the modification does not exist
```

If the plan contains failed hunks:

```text
the DumpIt engine writes no files
```

---

# 58. Patch Preview

`Preview`:

```text
resolves mapping
writes it to the log
revalidates it
builds the plan
does not write the target
generates a before/after visual diff HTML
opens the browser
```

It shows counts for:

```text
Added
Removed
Modified
Unchanged
```

For the DumpIt engine, hunk states are also logged.

---

# 59. Patch Dry Run

`Dry run` executes the validation path for the operation without applying the final modifications.

It should be used before Apply when the patch changes important data.

---

# 60. Apply Patch

Recommended workflow:

```text
1. select patch
2. select target
3. select engine
4. set -p
5. use Auto-detect as needed
6. Backup ON
7. Preview
8. verify Requested / Resolved
9. verify file mapping
10. Dry run
11. Apply
12. run project tests
```

Before the real Apply, DumpIt asks for confirmation.

If auto-detect changed the requested mapping, the dialog shows an explicit warning.

---

# 61. Patch Backup

With:

```text
Backup touched files = ON
```

existing files touched by the patch are copied to:

```text
<resolved root>/.dumpit_patch_backup/YYYYMMDD_HHMMSS/
```

while preserving relative structure.

New files obviously have no previous version to save.

Backup does not replace version control or testing.

---

# 62. Apply Receipt

After a successful forward Apply, DumpIt saves a JSON receipt.

Directory:

```text
<config folder>/patch_receipts/
```

Receipt identity depends on:

```text
requested target
patch SHA256
engine
```

The receipt contains:

```text
version
apply_id
applied_at
patch_sha256
engine

requested_target
requested_strip

resolved_cwd
resolved_directory
resolved_strip

mapping:
    patch_path
    action
    relative_target
    absolute_target

pre_state
post_state
```

---

# 63. Reverse

To reverse a patch:

```text
Reverse (-R) = ON
```

## 63.1 Reverse with Auto-detect ON

DumpIt does not perform a new unrestricted auto-detect.

It looks for the forward Apply receipt and reuses:

```text
resolved cwd
resolved directory
resolved strip
mapping
```

Before Reverse it verifies:

```text
patch digest
mapping
current filesystem == recorded post_state
```

If the filesystem changed:

```text
Automatic Reverse refused
```

This prevents automatic reversal of a patch on a tree that drifted after Apply.

## 63.2 Reverse with Auto-detect OFF

The receipt is not used by the auto-detect path.

Mapping depends on the current explicit values.

For deterministic reversal of a forward operation performed with auto-detect, keep Auto-detect enabled.

---

# 64. Copy Log

`Copy log` in the Apply Patch tab copies a dedicated report containing at least:

```text
DumpIt Apply Patch log
copied_at
profile
patch
target
strip
reverse
auto_detect
engine

operation log
```

This is the format to provide when diagnosing a patch failure.

The application also has a shared log.

---

# 65. How to Generate Robust Patches for DumpIt

Primary rule:

```text
generate the patch against the latest source/dump available
```

Use standard unified diff with paths:

```text
a/<path relative to root>
b/<path relative to root>
```

and normally:

```text
-p1
```

Hunks must contain enough context to be unique.

Avoid:

```text
overly generic blocks
create patches for files that already exist
absolute paths
..
target collisions
unrelated refactoring in the same step
```

A patch should represent one coherent logical intervention.

---

# 66. Atomic Patches

Prefer:

```text
Project_STEP_A.patch
Project_STEP_B.patch
Project_STEP_C.patch
```

over one patch mixing independent interventions.

A patch may modify multiple files when they are all required by the same step.

When appropriate, include tests verifying the step in the same patch.

---

# 67. Patch Naming

Recommended format:

```text
<Project>_<Step>_<short_description>.patch
```

Examples:

```text
TradingTool_AR7E_vertex_materialization.patch
MediaCache_106BT_centered_cut_crossfade.patch
DumpIt_AP7_path_resolution_safety.patch
```

---

# 68. Diagnosing Failed Patches

When a patch fails, collect:

```text
Copy log
original patch
latest source/dump of the target
```

Common causes:

```text
stale baseline
file moved
file renamed
hunk context changed
patch already partially applied
wrong target
wrong strip
auto-detect resolved differently than expected
ambiguous hunk
Git unavailable
binary patch used with DumpIt engine
filesystem changed after forward Apply
```

Do not blindly change `-p` or line numbers just to force Apply.

---

# 69. Shared Log

The lower part of the window contains a shared log.

Main functions record information such as:

```text
config load/save
profile changes
preview/export
watch
batch
diff
import
patch resolution
patch apply
backup
operational errors
```

The source also contains a function for copying the full log to the clipboard.

---

# 70. Crash Log

Unhandled Tkinter exceptions are written to:

```text
<config path with .crash.log extension>
```

Windows example:

```text
%APPDATA%\DumpIt\dumpit.crash.log
```

The error is also shown through a message box when possible.

---

# 71. Operational Directories Created by DumpIt

Summary:

```text
Config
    <config folder>/dumpit.ini

Crash log
    <config folder>/dumpit.crash.log

Patch receipts
    <config folder>/patch_receipts/*.json

Patch backups
    <patch resolved root>/.dumpit_patch_backup/<timestamp>/

Import backups
    <import target>/.dumpit_import_backup/<timestamp>/

Temporary visual diffs
    <system temp>/DumpIt/dumpit_diff_*.html
```

---

# 72. Relationship Between Export, Diff, and Apply Patch

Complete workflow:

```text
EXPORT OLD
    ↓
project changes
    ↓
EXPORT NEW
    ↓
DIFF
    ↓
Save delta file .patch
    ↓
APPLY PATCH to a compatible target
```

This allows DumpIt to be used as a text-based pipeline:

```text
snapshot
compare
patch
apply
```

It does not replace Git as a version-control system, but it can also operate on projects or workflows where a text dump is the primary exchange artifact.

---

# 73. Relationship Between Export and Import

Workflow:

```text
PROJECT A
    ↓ Export
DUMP
    ↓ Import
TARGET B
```

Import reconstructs only files present in the dump.

It does not replicate:

```text
files excluded by the profile
binary files skipped
complete filesystem metadata
permissions
extra files to delete
empty directories not represented by files
```

Import is therefore a reconstruction of the **exported text content**, not a byte-perfect clone of the entire filesystem.

---

# 74. Structural Limitations of the DumpIt Format

The dump is designed for text sources.

It does not fully represent:

```text
POSIX permissions
ACLs
filesystem owner
symlink semantics
original timestamps as restorable metadata
reliable binary payloads
extended attributes
empty directories
```

`modified` in the Project Tree and file headers is informational.

Import writes contents as UTF-8 and does not restore the original encoding of an exported file.

---

# 75. Diff Limitations

Diff compares text extracted from dumps.

Therefore it:

```text
does not compare files absent from the dumps
does not compare filesystem metadata
does not reconstruct file-rename identity
```

A rename normally appears as:

```text
removed old/path
+
added new/path
```

---

# 76. Watch Limitations

Watch uses polling, not a native filesystem event watcher.

Implications:

```text
changes are observed at the next poll
cost increases with the number of monitored files
each snapshot also calculates file digests
```

The quiet period reduces repeated exports during bursts of changes.

---

# 77. Apply Patch Limitations

The DumpIt engine:

```text
is text-only
does not replace every git apply semantic
```

The Git engine:

```text
requires Git to be installed
```

A successful Apply guarantees that the patch was applied according to the selected engine; it does not guarantee that the project is functionally correct.

Always run the relevant tests after Apply.

---

# 78. Recommended Workflow — Manual Snapshot

```text
1. select profile
2. verify Project folder
3. verify Include patterns
4. verify Exclude folders
5. Preview
6. check file count
7. Export
8. retain the resulting dump
```

---

# 79. Recommended Workflow — Versioned Snapshots

```text
Timestamp output = ON
Keep old = N

Preview
↓
Export
↓
DumpIt generates:
    name_YYYY-MM-DD_HHMMSS.txt
↓
automatic cleanup of older snapshots
```

---

# 80. Recommended Workflow — Continuous Monitoring

```text
1. configure and Save the profile
2. start Watch
3. avoid profile/settings changes while Watch is active
4. inspect Last change
5. inspect Last automatic export
6. Stop before changing configuration
```

---

# 81. Recommended Workflow — Comparison

```text
Old dump = previous snapshot
New dump = current snapshot

Open visual diff
↓
verify changes

optional:
Save delta file
    .txt   for reading
    .patch for application
```

---

# 82. Recommended Workflow — Import

```text
1. select dump
2. select target
3. choose Overwrite
4. leave Backup ON if files already exist
5. Preview import
6. check create/overwrite/skip/unsafe
7. Import dump
8. verify result
```

---

# 83. Recommended Workflow — Apply Patch

```text
PATCH
↓
TARGET
↓
Engine = dumpit for normal text patches
-p1 as default for Git-style a/... b/... paths
Auto-detect ON
Backup ON
↓
Preview
↓
check Requested / Resolved / SHA256 / mapping
↓
Dry run
↓
Apply
↓
project tests
```

---

# 84. Recommended Workflow — Reverse

```text
same patch
same requested target
same engine
Reverse ON
Auto-detect ON
↓
DumpIt loads forward receipt
↓
verifies post-state
↓
Preview
↓
Dry run
↓
Apply
```

If the filesystem changed after the forward operation:

```text
do not force automatic reverse
```

Restore through version control or backup, or analyze the delta manually.

---

# 85. Quick Troubleshooting

## Project folder does not exist

Cause:

```text
invalid profile root
```

Action:

```text
Browse...
select the correct root
Save
```

## Export includes 0 files

Check:

```text
Include patterns
Exclude folders
Skip binary
correct root
```

## The dump includes a previous output

The baseline automatically excludes the current output and the associated timestamped family.

If an older dump with a different name appears, add it to excludes or change pattern/output settings.

## Import skips files

Check `Skipped invalid/unsafe`.

Causes:

```text
absolute path outside root
..
duplicate
target directory where a file is expected
:
NUL
```

## Import does not overwrite

Check:

```text
Overwrite existing files
```

## Watch does not export immediately

Check:

```text
Run one export immediately on Start
Quiet ms
Status
```

## Batch uses old values

Save the profile:

```text
Save
```

Batch uses persisted settings.

## Diff shows files as added/removed instead of modified

Probable file-header path mismatch.

Check that both dumps use either:

```text
Full path header OFF
```

or both use ON with a compatible root convention.

## Patch FAILED_NOT_FOUND

The target baseline does not match the old block.

Use an updated source/dump and regenerate the patch.

## Patch FAILED_AMBIGUOUS

The hunk context does not identify a single location.

Regenerate the patch with more context.

## Patch FAILED_FILE_MISSING

The expected file does not exist at the resolved mapping.

Check target, strip, and baseline.

## No safe cwd/-p candidate

No combination proposed by auto-detect passes the safety preflight.

Do not force it: inspect the patch structure and target root.

## Git apply unavailable

Install Git, or use the DumpIt engine if the patch is compatible with the text engine.

## Reverse refused

The post-state does not match the receipt.

The filesystem changed after the forward operation, or patch/target/engine do not correspond to the receipt.

---

# 86. Export Checklist

```text
[ ] correct profile
[ ] correct Project folder
[ ] correct Include patterns
[ ] correct Exclude folders
[ ] correct Output file
[ ] Timestamp appropriate for intended use
[ ] valid Keep old
[ ] Skip binary appropriate
[ ] Full path header consistent with Diff/Import use
[ ] Preview completed
[ ] plausible file count
[ ] Export completed
```

---

# 87. Import Checklist

```text
[ ] correct dump
[ ] correct target
[ ] Preview import completed
[ ] create count plausible
[ ] overwrite count plausible
[ ] skip existing understood
[ ] unsafe paths reviewed
[ ] Backup ON if required
[ ] confirm Import
[ ] verify final result
```

---

# 88. Diff Checklist

```text
[ ] correct Old
[ ] correct New
[ ] consistent path convention
[ ] visual diff reviewed
[ ] delta format selected
[ ] correct delta output
```

---

# 89. Apply Patch Checklist

```text
[ ] patch built against current baseline
[ ] correct target root
[ ] correct engine
[ ] correct requested strip
[ ] Auto-detect selected intentionally
[ ] Backup ON
[ ] Preview successful
[ ] Requested verified
[ ] Resolved verified
[ ] Patch SHA256 visible
[ ] mapping plausible and collision-free
[ ] Dry run successful
[ ] Apply confirmed
[ ] project tests executed
```

---

# 90. Patch Generation Checklist

```text
[ ] latest source/dump used as baseline
[ ] valid unified diff
[ ] paths relative to root
[ ] a/ and b/ prefixes for standard Git-style patch
[ ] -p1 normally expected
[ ] no absolute paths
[ ] no ..
[ ] no target collisions
[ ] sufficient hunk context
[ ] new files use /dev/null
[ ] deleted files use /dev/null
[ ] no binary diff with DumpIt engine
[ ] patch atomic with respect to the step
[ ] no unrelated changes
[ ] tests included when required
```

---

# 91. DumpIt Project Structure in the Baseline

```text
.github/
  workflows/
    build.yml

dumpit_tool/
  q0/
    __init__.py
    basics.py

  tests/
    test_dumpit_patch_engine.py
    test_dumpit_path_resolution_safety.py
    test_quota_imports.py

  __init__.py

exporter_gui.py
QUOTA_MANIFEST.md
```

The project is in an initial QUOTA migration.

`dumpit_tool/q0/basics.py` contains lower-level primitives, while `exporter_gui.py` remains the legacy composition/UI layer.

---

# 92. Q0 Technical Responsibilities

The baseline declares the following in Q0:

```text
constants / theme values
path normalization
safe text read
pattern matching
timestamped output helpers
patch path normalization
patch backup path collection
dump/import/diff value objects
```

The QUOTA manifest identifies the extraction of pure application functions toward Q1 as the next ideal step, for example:

```text
collect_files
collect_export_entries
render_export_text
parse_dump_text
build_dump_import_plan
compare_dump_snapshots
build_unified_patch
```

This section describes the current architectural state of the project, not a UI function.

---

# 93. Existing Patch Safety Tests

The baseline contains specific tests for:

```text
exact hunk
relocated hunk
already applied
ambiguous hunk
transactional failure
CRLF preservation

many-to-one path collision
auto-detect -p1 Treehouse scaffold
Git/DumpIt auto-detect consistency
forward/reverse path preservation
receipt reuse
filesystem drift refusal
root containment
```

These tests document the guarantees introduced after earlier path-resolution problems.

---

# 94. Final Operating Principles

For Export:

```text
Preview before Export.
```

For Import:

```text
Preview import before writing.
Backup when overwriting.
```

For Batch:

```text
Save before Batch.
```

For Watch:

```text
keep configuration stable during monitoring.
```

For Diff:

```text
use consistent path headers across Old and New.
```

For Patch:

```text
Preview mapping == applied mapping.
```

For Reverse:

```text
forward receipt + intact post-state.
```

For any filesystem modification:

```text
DumpIt validates structure;
project tests validate behavior.
```

---

# 95. Quick Reference

```text
PROFILE
    defines persistent settings

EXPORT
    project -> dump

IMPORT
    dump -> file tree

WATCH
    changes -> automatic export

BATCH
    saved profiles -> multi-profile preview/export

DIFF
    old dump + new dump -> visual / txt / patch

APPLY PATCH
    patch + target -> preview / dry-run / apply

REVERSE
    forward receipt + patch + target -> controlled reversal
```

---

# 96. Baseline and Manual Validity

This manual describes behavior supported by the source baseline:

```text
DumpIT_2026-08-28_225051.txt
```

The dump was produced on August 28, 2026.

The DumpIt application files included in the baseline were mainly modified on August 14, 2026; the August 28 dump nevertheless represents the most recent source reference provided for this manual.

If the DumpIt source changes, the areas that should be reverified first are:

```text
profile defaults
dump format
Import path rules
Watch behavior
Batch persistence
Diff format
Apply Patch resolver
receipt/reverse
backup locations
```
