# disk-cleanup-advisor

A conservative Windows disk cleanup helper. It scans a drive or folder, writes
JSON/CSV/HTML reports, and tells you what looks safe to review before deletion.

这是一个用于 Windows 的扫盘小工具：默认扫描 `E:\`，输出报告，让你知道盘里主要是什么、哪些内容可能可以删除。默认只报告，不会删除任何东西。

## Features

- Pure Python 3.12 standard library, no extra packages required.
- Writes three report formats:
  - `scan.json`: machine-readable report and delete IDs.
  - `scan.csv`: spreadsheet-friendly file list.
  - `scan.html`: browser-friendly summary.
- Classifies files and top-level folders as:
  - `never_delete`: protected Windows/system paths.
  - `keep`: documents, source/work areas, app/game directories.
  - `review`: downloads, archives, installers, large old files, unknown content.
  - `delete_candidate`: cache, temporary, log, and recycle-bin-like content.
- Permanent deletion is available, but it is intentionally hard to trigger.

## Quick Start

From this repository:

```powershell
$env:PYTHONPATH = "src"
python -m disk_cleanup_advisor scan --path E:\ --out E:\CodexTasks\reports
```

Open:

```text
E:\CodexTasks\reports\scan.html
```

Print a summary later:

```powershell
$env:PYTHONPATH = "src"
python -m disk_cleanup_advisor summary --input E:\CodexTasks\reports\scan.json
```

Scan another path:

```powershell
$env:PYTHONPATH = "src"
python -m disk_cleanup_advisor scan --path D:\ --out E:\CodexTasks\reports
```

## Deletion Workflow

Deletion only works by file IDs from `scan.json`. The tool does not accept a
free-form path for deletion.

Dry run:

```powershell
$env:PYTHONPATH = "src"
python -m disk_cleanup_advisor delete --input E:\CodexTasks\reports\scan.json --ids f_example123456
```

Permanent deletion:

```powershell
$env:PYTHONPATH = "src"
python -m disk_cleanup_advisor delete --input E:\CodexTasks\reports\scan.json --ids f_example123456 --apply --confirm PERMANENT-DELETE
```

Safety gates:

- `scan` never deletes files.
- `delete` without `--apply` is a dry run.
- `--apply` requires `--confirm PERMANENT-DELETE`.
- Protected system paths are rejected.
- Files are rejected if their size or modified timestamp changed after scanning.
- This first version deletes files only, not whole directories.

## Reading The Report

If Windows shows much more used space than the report's total scanned size, check
the `Skipped Or Inaccessible Paths` section in `scan.html`. Permission-protected
backup folders, system storage, virtual disks, and recycle-bin accounts can hold
large amounts of data that a normal user process cannot enumerate.

## Privacy Notes

Real scan reports can expose private folder names and file paths. Do not commit
your real `E:\CodexTasks\reports` output to a public repository. The committed
files in `examples/` are synthetic and use fake paths only.

## Development

Run tests:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Install locally in editable mode if you want the `disk-cleanup-advisor` command:

```powershell
python -m pip install -e .
disk-cleanup-advisor scan --path E:\ --out E:\CodexTasks\reports
```
