# DumpIt — Complete Manual

**Original source baseline:** `DumpIT_2026-09-04_100252.txt`  
**Included extensions:** patches `LLM0` → `LLM5` + `_LLM` output naming patch  
**Manual revision:** 2026-09-05  
**Main application source:** `exporter_gui.py` — 6338 lines in the reconstructed baseline after the LLM patches  
**Purpose:** complete operational and technical manual for the current state of the DumpIt application, including the `llm` export mode.

---

# 1. What DumpIt Is

DumpIt is a Tkinter desktop application for working with textual snapshots of software projects.

Its main functions are:

```text
Export
    creates a textual dump of a project
    in standard or llm format

Import
    reconstructs files from a DumpIt dump

Watch
    monitors a project and automatically runs export again

Batch
    runs Preview or Export across multiple profiles

Diff
    compares two dumps and generates a visual, textual, or .patch delta

Apply Patch
    validates, previews, applies, and reverses unified-diff patches
    through the DumpIt or Git engine
```

DumpIt uses **persistent profiles** to associate each project with its own settings.

The interface contains a global profile bar, six functional tabs, and a shared log.

The `llm` mode does not compress or rewrite source. It adds deterministic metadata and a structural index around the textual content, which remains the authoritative payload of the dump.

---

# 2. Startup and Build

## 2.1 Running from source

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

## 2.2 Executable build

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

## 2.3 Initial directory

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

There is no manual theme selector in the baseline.

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

## 4.1 What a profile contains

Persisted settings for each profile include:

```text
project_dir
output_file

include_patterns
exclude_dirs
add_timestamp
timestamp_keep_old
skip_binary
header_full_path
export_format

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

The new name must not already exist.

## 4.4 Delete

`Delete` removes the current profile after confirmation.

The last remaining profile cannot be deleted.

After deletion, DumpIt selects another available profile.

## 4.5 Save

`Save`:

```text
writes the current UI values into the active profile
stores the active profile
stores the Batch selection
writes dumpit.ini
```

## 4.6 Reset

`Reset` restores default values **in the UI only**.

It does not automatically save the reset.

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

If defined:

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

## 5.3 Legacy config compatibility

At startup, DumpIt normalizes older configurations:

```text
App -> app
duplicate profile: sections differing only by casing -> merge
```

If a conflict occurs during merge, the primary/canonical section keeps its own value.

For `export_format`, compatibility is conservative:

```text
missing key        -> standard
standard value     -> standard
llm value          -> llm
unsupported value  -> standard while loading config
```

Internal APIs that explicitly receive an unsupported format instead use strict validation and raise an error.

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

Export format
    standard

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

`export_format=standard` preserves historical behavior. `export_format=llm` enables the indexed format described in the following sections.

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
Export format: standard | llm

Preview
Export
```

`Export format` is persisted in the profile.

Semantics:

```text
standard
    historical DumpIt format

llm
    lossless indexed format for LLM navigation and ingestion
```

The selected format changes rendering and, for `llm`, also changes the physical output name through the `_LLM` suffix.

---

# 8. Project Folder

`Project folder` is the root scanned recursively.

`Browse...` selects the directory.

The project must exist.

The path is stored in the profile.

When the root changes, DumpIt may update the output name if the current one still corresponds to a default output.

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
    -> match against file name

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

A shorthand form such as:

```text
.py
```

is normalized to:

```text
*.py
```

when it contains no wildcard or separator.

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

is excluded if `node_modules` is in the list.

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

it considers the file probably binary and excludes it.

If the sample cannot be read, the file is treated as binary for filtering purposes.

This is not a complete MIME-recognition system; it is a practical safeguard for primarily textual dumps.

---

# 12. Reading Text Files

For included files, DumpIt attempts:

```text
UTF-8 with BOM / utf-8-sig
UTF-8
UTF-8 with errors=replace as fallback
```

Therefore, a file that is not strictly UTF-8 can still be represented in the dump with replacement characters.

Read errors do not necessarily stop the entire export; they are counted as `skipped read errors`.

---

# 13. Output File

If not specified, the default base output is:

```text
<project root>/<root name>.txt
```

Example:

```text
H:\DEV\MY_PROJECT
↓
H:\DEV\MY_PROJECT\MY_PROJECT.txt
```

The path shown/stored in the profile represents the **base output**. The resolver then applies the selected format.

With `standard` format:

```text
MY_PROJECT.txt
```

With `llm` format:

```text
MY_PROJECT_LLM.txt
```

The `_LLM` suffix is automatically inserted before the extension. The operation is idempotent: a basename already ending in `_LLM` does not receive a second suffix.

DumpIt excludes from the scan:

```text
current output
current base output
standard variant of the same basename
_LLM variant of the same basename
```

With timestamps enabled, timestamped families of **both** variants are also excluded. This prevents an old dump of the other format from being included in a new dump when switching between Standard and LLM.

---

# 14. Timestamp Output

With `Timestamp output` enabled, the timestamp is applied to the basename already resolved for the format.

Standard:

```text
name.txt
↓
name_YYYY-MM-DD_HHMMSS.txt
```

LLM:

```text
name.txt
↓
name_LLM_YYYY-MM-DD_HHMMSS.txt
```

Examples:

```text
TradingTool_2026-09-05_113000.txt
TradingTool_LLM_2026-09-05_113000.txt
```

If the current name already contains a DumpIt-format timestamp, the program first derives the base name and then applies the new timestamp.

If a timestamped path is resolved in `llm` mode, `_LLM` is placed before the timestamp:

```text
DumpIt_2026-09-05_113000.txt
↓
DumpIt_LLM_2026-09-05_113000.txt
```

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

keeps at most:

```text
1 new + 10 previous
```

for the current output family.

Standard and LLM form separate families:

```text
Project_YYYY-...txt
Project_LLM_YYYY-...txt
```

Retention executed during an export operates on the family of the file actually generated. Scan exclusion, however, considers both families to prevent cross-format self-inclusion.

Older files are deleted after a successful timestamped export. Deletion errors are logged.

---

# 16. Full Path Header

With `Full path header` disabled, file sections use relative paths.

Standard:

```text
===== FILE: src/module.py | lines=123 | modified=... =====
```

LLM:

```text
===== FILE: src/module.py | lines=123 | id=F-... | bytes=... | sha256=... | modified=... =====
```

With `Full path header` enabled, the path in the `FILE` section becomes absolute:

```text
===== FILE: H:\DEV\PROJECT\src\module.py | ... =====
```

The `PROJECT TREE` always remains based on relative paths.

In LLM format, the `FILE INDEX` also always remains based on relative paths, regardless of `Full path header`.

For Diff and Import, it is normally simpler to keep the same `Full path header` mode consistent between compared dumps. Standard and LLM can still be compared if the `FILE` headers represent the same paths.

---

# 17. Export Preview

`Preview`:

```text
validates project folder
computes filters
normalizes Export format
resolves the effective output name
computes both output variants to exclude
scans the project
counts included files
```

The result is written to the log:

```text
Preview: N files will be included from: <root>
```

Export Preview does not open a detailed file list and does not write the dump.

Preview uses the same naming resolver as Export: when `llm` is selected, the effective output considered is the `_LLM` variant.

---

# 18. Export

`Export` performs:

```text
1. root validation
2. pattern parsing
3. export_format normalization
4. standard/LLM output resolution
5. calculation of output variants to exclude
6. scan
7. file reads
8. metadata construction for each entry
9. PROJECT TREE construction
10. optional FILE INDEX construction
11. standard or llm rendering
12. UTF-8 write
13. optional timestamp cleanup
14. silent config save
15. log and final dialog
```

The result reports:

```text
Included
Skipped read errors
Output
[optional timestamp cleanup]
```

File content is collected once into the `ExportFileEntry` structure; the selected renderer decides which metadata to add around the payload.

---

# 19. DumpIt Dump Format

DumpIt supports two export formats:

```text
standard
llm
```

Both contain `FILE` sections with the complete textual content of included files.

## 19.1 Standard Format

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

The Standard format remains compatible with historical behavior: introducing LLM mode does not add stable IDs, hashes, or a `FILE INDEX` to Standard rendering.

## 19.2 LLM Format

Structure:

```text
===== DUMPIT EXPORT =====
format_version: 2
export_format: llm
timestamp_utc: ...
root: ...
output: ...
profile: ...
files_included: ...

===== PROJECT TREE =====
...

===== FILE INDEX =====
F-... | relative/path.ext | ext=.ext | bytes=N | lines=N | sha256=...
...

===== FILE: <path> | lines=<N> | id=F-... | bytes=N | sha256=... | modified=<timestamp> =====
<content>

===== FILE: ...
...
```

The LLM format is **lossless with respect to the DumpIt textual payload**: it does not minify, compress, remove comments, renumber lines, or intentionally modify file content.

## 19.3 LLM Metadata per File

For each file, DumpIt computes:

```text
stable_id
extension
byte_count
content_sha256
line_count
modified_at
```

### stable_id

Format:

```text
F-<16 hex>
```

It is derived from SHA-256 of the normalized relative path, taking the first 16 hexadecimal characters and adding the `F-` prefix.

Normalization:

```text
\ -> /
leading ./ removed
```

Properties:

```text
same relative path, different content -> same stable_id
different relative path / rename      -> different stable_id
different repository root, same relpath -> same stable_id
```

The stable ID therefore represents the identity of the **relative path**, not the content.

### byte_count

`bytes` is the byte length of the UTF-8 encoding of the text actually exported:

```text
len(text.encode("utf-8"))
```

It is not necessarily equal to the original physical file size on the filesystem if the file underwent BOM/fallback decoding or replacement characters.

### content_sha256

This is the SHA-256 of the same UTF-8 payload used for `byte_count`.

It describes the textual content actually inserted into the dump.

### extension

This is the path suffix converted to lowercase, for example:

```text
.py
.js
.md
```

It may be empty for files without an extension.

## 19.4 Operational Compatibility

The Import/Diff parser continues to use `===== FILE:` headers as section boundaries. Additional LLM sections (`FILE INDEX`, global metadata) appear before file blocks and do not alter extracted content.

There is no `END FILE` marker: the next `FILE` header delimits the current block.

---

# 20. Project Tree

The Project Tree is built only from files actually included.

Directories are ordered before files and sorting is case-insensitive.

## 20.1 Standard Project Tree

For each file it shows:

```text
name
line count
last modification
```

Example:

```text
src/
  main.py [lines: 50 | modified: 2026-09-05 09:10:00]
```

## 20.2 LLM Project Tree

For each file it shows:

```text
name
stable_id
line count
byte_count
```

Example:

```text
src/
  main.py [F-a1b2c3d4e5f60718 | 50 lines | 1840 bytes]
```

`modified` is intentionally omitted from the LLM tree to reduce volatile metadata. It remains available in the header of the corresponding `FILE` section.

## 20.3 LLM FILE INDEX

LLM format adds a linear index after the Project Tree:

```text
===== FILE INDEX =====
F-... | src/main.py | ext=.py | bytes=1840 | lines=50 | sha256=...
```

The FILE INDEX always uses relative paths and preserves the same ordering as exported entries. It does not replace file content; it is a navigation index.

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

The parser recognizes file sections delimited by `===== FILE:` headers.

Legacy format:

```text
===== FILE: <path> =====
```

Current Standard format:

```text
===== FILE: <path> | lines=N | modified=... =====
```

LLM format:

```text
===== FILE: <path> | lines=N | id=F-... | bytes=N | sha256=... | modified=... =====
```

Path extraction truncates metadata starting at the ` | lines=` marker. This is why LLM headers remain backward-compatible with Import and Diff.

The parser treats the content between one `FILE` section and the next as the file payload.

Sections before the first `FILE`, including:

```text
PROJECT TREE
FILE INDEX
format_version
export_format
```

are not imported as files and do not alter the payload.

If no valid file sections are found:

```text
No DumpIt file sections found
```

and import fails.

---

# 23. Dump Root and Absolute Paths

DumpIt reads, when available:

```text
root: <source root>
```

before the first file section.

If a file header is absolute, it is accepted only if it can be made relative to the root declared in the dump.

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
contain ..
contain NUL
contain : in a relative component
duplicates after normalization
point to an already existing directory
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

If the target does not exist, DumpIt asks whether to create it.

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

Import does not semantically compare content; path existence determines behavior.

---

# 27. Import Backup

With:

```text
Backup overwritten files to .dumpit_import_backup = ON
```

files to be overwritten are copied before writing to:

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
4. executes create/overwrite/skip
5. backs up overwrites when requested
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

The baseline has no global atomic commit for the whole plan.

Therefore, a filesystem error during execution can theoretically occur after some files have already been written.

For destructive operations, use backup and, where possible, version control.

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

Displayed status:

```text
Status
Profile locked at start
Last change
Last automatic export
```

Watch supports both `export_format` values.

When the current format is `llm`, the resolver uses the `_LLM` output; when it is `standard`, it uses the normal output. In both cases, monitoring excludes from its scan both the Standard and LLM families of the same base output.

---

# 30. Poll ms

`Poll ms` is the filesystem polling interval.

Default:

```text
1500 ms
```

DumpIt validates that it is a positive integer value.

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

When changes keep arriving, export is postponed until the quiet period expires.

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

The resolver determines the effective output from `export_format`.

The following are excluded from the scan:

```text
current output
Standard base
LLM base
Standard timestamped family
LLM timestamped family
```

This prevents switching between `standard` and `llm` from generating false Watch events or self-including the dump from the other format.

---

# 33. Starting Watch

`Start monitoring`:

```text
validates Poll and Quiet
reads current Export settings
stores the active profile
prepares the initial snapshot
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

# 34. Effective Watch Behavior to Know

The configuration used to **detect changes** is copied into Watch runtime state at Start.

Automatic export calls the normal `_run_export()`, which reads the current Export UI variables at execution time.

Therefore:

```text
monitoring snapshot
    uses values fixed at Start

automatic export
    uses current UI values
    including export_format
```

For predictable behavior:

```text
do not change profile, filters, output, or Export format
while Watch is active
```

or stop Watch, change configuration, and start it again.

`_LLM` naming is resolved centrally, so Preview/Watch/Export use the same output rule.

---

# 35. Stop Watch

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

`Export now` invokes the current normal Export.

Watch does not need to be active.

It therefore uses:

```text
current profile/UI
```

---

# 37. Batch

Batch allows the same type of operation to be run across multiple profiles.

Controls:

```text
Select all
Select none

profile list with checkboxes

Run batch preview
Run batch export
```

Profile selection is persisted in the application section of the INI file.

Each profile may independently use:

```text
export_format = standard
```

or:

```text
export_format = llm
```

Therefore, a single Batch run may produce Standard output for some profiles and LLM output for others.

---

# 38. Fundamental Batch Rule

Batch uses the **saved profile settings**, including `export_format`.

The UI itself states:

```text
Batch uses the saved profile settings — click 'Save' if needed.
```

At the start of a batch, DumpIt silently saves the current profile, then reads profile sections from configuration.

For each profile, the resolver computes the effective output name:

```text
standard -> normal base
llm      -> base with _LLM
```

An unsaved format change may therefore not be used by Batch.

---

# 39. Batch Preview

For each selected profile:

```text
checks root
applies include/exclude
applies skip binary
reads saved export_format
resolves standard/LLM output
computes both output families to exclude
counts files
writes result to log
```

It does not generate dumps.

---

# 40. Batch Export

For each selected profile:

```text
reads saved settings
normalizes export_format
resolves standard/LLM output
exports with the correct renderer
runs timestamp retention if enabled
logs result
continues with the next profile
```

An error in one profile is logged as `ERR` but does not necessarily prevent processing of subsequent profiles.

Final result:

```text
OK N
Errors N
```

Batch uses the same `export_to_file()` as normal Export; there is no separate Batch renderer.

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

The parser converts each dump into:

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
    path present only in New

removed
    path present only in Old

modified
    same path, different content

unchanged
    same path, identical content
```

Comparison is based on the complete content of the file section.

LLM metadata outside the payload (`FILE INDEX`, stable ID, hash, byte count) is not compared as file content.

With the same files and the same `Full path header` convention:

```text
Standard dump
vs
LLM dump
```

produces the same `path -> content` snapshots; therefore Diff must report no file differences if the repository has not changed.

---

# 43. Path Consistency Across Dumps

Diff uses the path in the `FILE` header as identity.

Therefore, dumps should be compared using consistent path conventions.

Problematic example:

```text
Old:
    src/a.py

New:
    C:\PROJECT\src\a.py
```

Even if they represent the same physical file, the parser sees two different keys.

For regular comparisons, keep the option:

```text
Full path header
```

consistent between dumps.

The difference between `standard` and `llm` **does not** itself change file identity: the parser ignores additional metadata after `| lines=`.

In LLM format, the `FILE INDEX` always uses relative paths, but Diff continues to use the path from the `FILE` header, not the index.

---

# 44. Visual Diff

`Open visual diff`:

```text
loads Old
loads New
computes delta
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

DumpIt cleans up these temporary files:

```text
at startup
before opening new diffs
at shutdown
```

---

# 45. .txt Delta

The textual format contains:

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

complete content of added files
complete content of removed files
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

The value in the Strip field is:

```text
the effective constraint when Auto-detect is OFF

the initial preference when Auto-detect is ON
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

If the resolved mapping differs from requested values:

```text
AUTO-DETECT OVERRIDE
```

The Apply dialog shows Requested and Resolved again before confirmation.

---

# 52. Resolution Cache

Once a resolution has been computed for the current selection, DumpIt keeps it.

Preview, Dry run, and Apply reuse the same resolution as long as patch settings do not change.

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

Before the operation, DumpIt still recomputes the mapping and refuses the operation if it no longer matches the resolved mapping.

Conceptual message:

```text
Resolved patch mapping changed after resolution.
Operation refused; run Preview again.
```

---

# 53. Patch Mapping Safety

The complete mapping is validated before Apply.

DumpIt rejects:

```text
paths that do not survive strip
paths that escape the resolved cwd
paths that escape the selected target
many-to-one collisions
patches without file paths
```

During auto-detect, it also rejects a candidate where a create-file patch maps onto an already existing target.

Example of a forbidden collision:

```text
a/BRIDGES/README.md   --p2--> README.md
a/HOUSES/README.md    --p2--> README.md
a/WAREHOUSE/README.md --p2--> README.md
```

The candidate is invalid.

---

# 54. DumpIt Engine

`dumpit` is the internal text engine.

Properties:

```text
parses unified diff
builds a complete plan
validates all hunks
writes nothing if failed hunks exist
supports controlled hunk relocation
detects already-applied hunks
preserves newline and existing-file encoding as implemented
supports textual create / modify / delete
```

It is the default.

---

# 55. Git Engine

`git` invokes `git apply`.

Validation first uses:

```text
git apply --check
```

DumpIt auto-detect still determines a safe candidate mapping before invoking Git.

The Git engine requires `git` to be available on the system.

It is required when patch semantics need capabilities not handled by the DumpIt text engine, for example Git binary patches.

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
    multiple candidate locations make the hunk nondeterministic

FAILED_FILE_MISSING
    the file required for modification does not exist
```

If the plan contains failed hunks:

```text
no file is written by the DumpIt engine
```

---

# 58. Patch Preview

`Preview`:

```text
resolves mapping
records it in the log
revalidates it
builds the plan
does not write the target
generates a visual before/after HTML diff
opens the browser
```

It shows counts:

```text
Added
Removed
Modified
Unchanged
```

For the DumpIt engine, hunk states are also logged.

---

# 59. Patch Dry Run

`Dry run` executes the validation path of the operation without applying final changes.

It should be used before Apply when the patch modifies important data.

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

Backup does not replace version control or tests.

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

DumpIt does not run a new free auto-detect.

It looks for the receipt from the forward Apply and reuses:

```text
resolved cwd
resolved directory
resolved strip
mapping
```

Before Reverse it checks:

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
generate the patch against the most recent available source/dump
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

Hunks should contain enough context to be unique.

Avoid:

```text
overly generic blocks
create patches against already existing files
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

to one patch that mixes independent interventions.

A patch may modify multiple files if they are all required by the same step.

When appropriate, include in the same patch the tests that verify the step.

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
most recent source/dump of the target
```

Common causes:

```text
outdated baseline
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

Do not blindly change `-p` or line numbers to force Apply.

---
# 69. Shared Log

The lower part of the window contains a common log.

Main functions write to it:

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

The source also contains a function to copy the entire log to the clipboard.

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

The error is also shown in a message box when possible.

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
EXPORT OLD (standard or llm)
    ↓
project changes
    ↓
EXPORT NEW (standard or llm)
    ↓
DIFF
    ↓
Save delta file .patch
    ↓
APPLY PATCH to a compatible target
```

This allows DumpIt to be used as a textual pipeline:

```text
snapshot
compare
patch
apply
```

Standard and LLM are two representations of the same project payload. For Diff/patch, what matters is the content extracted from `FILE` sections, not the `FILE INDEX`.

This does not replace Git as a version-control system, but it can operate on projects or contexts where a textual dump is the primary exchange artifact.

---

# 73. Relationship Between Export and Import

Workflow:

```text
PROJECT A
    ↓ Export standard or llm
DUMP
    ↓ Import
TARGET B
```

Import reconstructs only files present in the dump's `FILE` sections.

In LLM format it does not import:

```text
FILE INDEX
stable_id
byte_count
content_sha256
format_version
export_format
```

as separate files; these elements are container metadata.

Import does not replicate:

```text
files excluded by the profile
skipped binary files
complete filesystem metadata
permissions
extra files to delete
empty directories not represented by files
```

Import is therefore a reconstruction of the **exported textual content**, not a byte-perfect clone of the entire filesystem.

---

# 74. Structural Limitations of the DumpIt Format

The dump is designed for textual source files.

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

`modified` in headers is informational.

In Standard format it also appears in the Project Tree; in LLM format it is omitted from the Project Tree but remains in the `FILE` header.

Import writes content as UTF-8 and does not restore the original encoding of the exported file.

In LLM format:

```text
bytes  = size of the exported UTF-8 payload
sha256 = hash of the exported UTF-8 payload
```

These fields do not claim byte-perfect identity with the original file if reading required decoding/fallback.

The `stable_id` is path-derived: it is not a content hash and must not be used as proof that two contents are identical.

---

# 75. Diff Limitations

Diff compares text extracted from the dump.

Therefore it:

```text
does not compare files not included in the dumps
does not compare filesystem metadata
does not reconstruct identity across file renames
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
cost grows with the number of monitored files
each snapshot also computes file digests
```

The quiet period reduces repeated exports during bursts of changes.

LLM mode does not change detection. It changes only rendering and output naming.

DumpIt excludes both Standard/LLM families from Watch, but other dumps with unrelated basenames may still be observed if they match Include patterns.

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

A successful Apply guarantees that the patch was applied according to the selected engine, not that the project is functionally correct.

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
8. keep the resulting dump
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
4. observe Last change
5. observe Last automatic export
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
4. leave Backup ON if files exist
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
-p1 as default for Git paths a/... b/...
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
checks post-state
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

## The dump includes the previous output

DumpIt automatically excludes:

```text
current output
Standard variant
LLM variant
related timestamped families
```

If an old dump with a **different basename** appears, add it to excludes or change patterns/output.

## The LLM name does not contain `_LLM`

Check that:

```text
Export format = llm
```

The resolver normally produces:

```text
name.txt -> name_LLM.txt
name_YYYY-...txt -> name_LLM_YYYY-...txt
```

If the basename already ends in `_LLM`, a second suffix is not added.

## The Standard name contains `_LLM`

`standard` mode does not forcibly remove an `_LLM` written manually in the Output file field. Set a base output without `_LLM` if conventional Standard naming is desired.

## Import skips files

Check `Skipped invalid/unsafe`.

Causes:

```text
absolute path outside root
..
duplicate
target directory instead of file
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

## Watch exports in the unexpected format

Automatic export reads current Export UI settings, including `export_format`. Avoid changing format while Watch is active, or restart Watch after the change.

## Batch uses old values

Save the profile:

```text
Save
```

Batch uses persisted settings, including `export_format`.

## Diff Standard vs LLM shows unexpected differences

With the same repository it should produce the same file/content snapshot.

Check:

```text
consistent Full path header
consistent Include/Exclude
same logical root
no changes between the two exports
```

The LLM `FILE INDEX` should not produce differences by itself.

## Diff shows files as added/removed instead of modified

Likely path-header mismatch.

Check that both dumps use:

```text
Full path header OFF
```

or both use ON with compatible roots.

## Patch FAILED_NOT_FOUND

The target baseline does not match the old block.

Use an updated source/dump and regenerate the patch.

## Patch FAILED_AMBIGUOUS

The hunk context does not identify exactly one location.

Regenerate the patch with more context.

## Patch FAILED_FILE_MISSING

The expected file does not exist in the resolved mapping.

Check target, strip, and baseline.

## No safe cwd/-p candidate

No combination proposed by auto-detect passes the safety preflight.

Do not force it: check patch structure and target root.

## Git apply unavailable

Install Git or use the DumpIt engine if the patch is compatible with the text engine.

## Reverse refused

The post-state does not match the receipt.

The filesystem changed after the forward operation, or patch/target/engine do not match the receipt.

---

# 86. Export Checklist

```text
[ ] correct profile
[ ] correct Project folder
[ ] correct Include patterns
[ ] correct Exclude folders
[ ] correct base Output file
[ ] correct Export format: standard | llm
[ ] if llm, expected effective output with _LLM
[ ] Timestamp appropriate for intended use
[ ] valid Keep old
[ ] appropriate Skip binary
[ ] Full path header consistent with Diff/Import
[ ] Preview run
[ ] plausible file count
[ ] Export run
[ ] if llm, indexed PROJECT TREE present
[ ] if llm, FILE INDEX present
[ ] if llm, FILE header with id/bytes/sha256
```

For Standard ↔ LLM verification of the same project:

```text
[ ] same filters
[ ] same Full path header convention
[ ] Diff = 0 differences in files/content
```

---

# 87. Import Checklist

```text
[ ] correct dump
[ ] correct target
[ ] Preview import run
[ ] plausible create count
[ ] plausible overwrite count
[ ] skip existing understood
[ ] unsafe paths reviewed
[ ] Backup ON if needed
[ ] Import confirmed
[ ] final result verified
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
[ ] Auto-detect chosen deliberately
[ ] Backup ON
[ ] Preview succeeded
[ ] Requested verified
[ ] Resolved verified
[ ] Patch SHA256 visible
[ ] plausible collision-free mapping
[ ] Dry run succeeded
[ ] Apply confirmed
[ ] project tests run
```

---

# 90. Patch Generation Checklist

```text
[ ] latest source/dump used as baseline
[ ] valid unified diff
[ ] paths relative to root
[ ] a/ and b/ prefixes for standard Git patch
[ ] -p1 normally expected
[ ] no absolute paths
[ ] no ..
[ ] no target collisions
[ ] sufficient hunk context
[ ] new files use /dev/null
[ ] deleted files use /dev/null
[ ] no binary diff with DumpIt engine
[ ] patch atomic relative to the step
[ ] no unrelated changes
[ ] tests included when needed
```

---

# 91. Technical Structure of the DumpIt Project in the Current Baseline

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

    test_dumpit_llm_export_contract.py
    test_dumpit_llm_export_metadata.py
    test_dumpit_llm_export_renderer.py
    test_dumpit_llm_project_tree.py
    test_dumpit_llm_profile_routing.py
    test_dumpit_llm_closure.py

  __init__.py

exporter_gui.py
QUOTA_MANIFEST.md
```

In the reconstructed baseline after LLM0–LLM5 + `_LLM` naming, `exporter_gui.py` contains 6338 lines.

The project remains in an early QUOTA migration.

`dumpit_tool/q0/basics.py` contains lower-level primitives, while `exporter_gui.py` remains the legacy composition/UI layer.

The LLM patches were deliberately implemented without coupling this feature to the QUOTA refactoring: LLM format is an Export feature, not an architectural change to the project.

---

# 92. Technical Responsibilities of Q0

The baseline declares in Q0:

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

The QUOTA manifest identifies extraction of pure application functions toward Q1 as the ideal next step, for example:

```text
collect_files
collect_export_entries
render_export_text
render_llm_export_text
parse_dump_text
build_dump_import_plan
compare_dump_snapshots
build_unified_patch
```

In the current state, LLM mode is implemented in the existing composition/UI layer alongside the Standard renderer.

This section describes the current architectural state of the project, not a UI function.

---

# 93. Existing Safety and Compatibility Tests

The baseline contains specific tests for the patch engine:

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

The LLM tranche adds dedicated tests for:

```text
unchanged Standard format
legacy dump parsing
metadata sections before FILE blocks
additional metadata in FILE headers
Import from LLM dump
Diff Standard ↔ LLM
path-derived stable ID
stable ID independent of repository root
rename -> different stable ID
content change -> same stable ID / different hash
UTF-8 byte_count
content SHA-256
deterministic FILE INDEX
deterministic LLM Project Tree
Full path header compatibility
profile/config export_format
legacy fallback -> standard
Export routing
Batch routing
Watch routing
idempotent _LLM naming
_LLM suffix before timestamp
mutual exclusion of Standard/LLM output families
```

These tests define the contract of LLM mode: add structure around the payload without changing Import/Diff semantics for the content.

---

# 94. Final Operational Principles

For Export:

```text
Preview before Export.
Explicitly choose standard or llm.
```

For LLM Export:

```text
The file payload remains authoritative and uncompressed.
FILE INDEX and hashes are navigation/verification metadata.
```

For Import:

```text
Preview import before writing.
Backup when overwriting.
```

For Batch:

```text
Save before Batch.
Format is part of the saved profile.
```

For Watch:

```text
keep configuration stable during monitoring,
including export_format.
```

For Diff:

```text
keep path headers consistent between Old and New.
Standard and LLM are comparable on payload.
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
    including export_format

STANDARD EXPORT
    project -> historical dump

LLM EXPORT
    project -> indexed lossless dump
    compact PROJECT TREE
    FILE INDEX
    stable ID / bytes / sha256
    output with _LLM suffix

IMPORT
    standard or llm dump -> file tree

WATCH
    changes -> automatic export
    standard or llm

BATCH
    saved profiles -> multiple preview/export
    each profile keeps its own format

DIFF
    old dump + new dump -> visual / txt / patch
    Standard and LLM compatible on FILE payload

APPLY PATCH
    patch + target -> preview / dry-run / apply

REVERSE
    forward receipt + patch + target -> controlled reversal
```

Key rule of LLM mode:

```text
DumpIt adds structure; it does not rewrite source.
```

---

# 96. Baseline and Manual Validity

This manual describes the supported behavior of the current state obtained from:

```text
DumpIT_2026-09-04_100252.txt
+
LLM0 — export contract guardrails
LLM1 — deterministic file metadata
LLM2 — LLM renderer + FILE INDEX
LLM3 — compact LLM PROJECT TREE
LLM4 — profile/UI/Batch/Watch routing
LLM5 — compatibility closure
+
LLM output name suffix patch
```

The documentation revision is dated:

```text
2026-09-05
```

LLM mode is deliberately language-agnostic. It does not introduce:

```text
symbol index
static dependency analysis
language-specific parser
semantic chunking
source compression
token estimation
ARCHIPELAGO awareness
```

If DumpIt source changes, the areas to revalidate first are:

```text
profile defaults
export_format and output naming
Standard format
LLM format
stable ID / byte_count / content_sha256
PROJECT TREE / FILE INDEX
Import parser compatibility
Watch output exclusion
Batch persistence/routing
Diff Standard ↔ LLM
Apply Patch resolver
receipt/reverse
backup locations
```

The manual treats Standard format as the backward-compatible baseline and LLM format as a lossless structural extension of the same textual snapshot.

---
