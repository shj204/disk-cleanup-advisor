from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import os
import stat
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__


CONFIRM_TOKEN = "PERMANENT-DELETE"
DEFAULT_SCAN_ROOT = Path(r"E:\\" if os.name == "nt" else ".")
DEFAULT_REPORT_DIR = Path(r"E:\CodexTasks\reports" if os.name == "nt" else "reports")
DEFAULT_LOG_DIR = Path(r"E:\CodexTasks\trash_logs" if os.name == "nt" else "trash_logs")
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

PROTECTED_NAMES = {
    "$windows.~bt",
    "$windows.~ws",
    "$sysreset",
    "boot",
    "config.msi",
    "msocache",
    "program files",
    "program files (x86)",
    "programdata",
    "recovery",
    "system volume information",
    "windows",
    "windowsapps",
}

PROGRAM_OR_APP_NAMES = {
    "epic",
    "epic games",
    "legionzone",
    "node",
    "nodejs",
    "pcl",
    "steam",
    "steamapps",
    "wegame",
    "wegameapps",
}

DOWNLOAD_NAMES = {
    "baidunetdiskdownload",
    "downloads",
    "download",
    "thunder download",
    "browser downloads",
    "迅雷下载",
    "网盘下载",
    "浏览器下载",
    "下载",
}

CACHE_NAMES = {
    "$recycle.bin",
    ".cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "cache",
    "caches",
    "huancun",
    "log",
    "logs",
    "qycache",
    "temp",
    "tmp",
    "缓存",
    "临时",
}

REVIEW_REBUILDABLE_NAMES = {
    ".gradle",
    ".mypy_cache",
    ".tox",
    ".venv",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
}

KEEP_NAMES = {
    ".git",
    "documents",
    "src",
    "source",
    "user",
    "users",
    "work",
    "workspace",
    "文档",
    "项目",
}

TEMP_SUFFIXES = {
    ".bak",
    ".cache",
    ".dmp",
    ".etl",
    ".log",
    ".old",
    ".part",
    ".tmp",
}

REVIEW_SUFFIXES = {
    ".7z",
    ".apk",
    ".dmg",
    ".exe",
    ".iso",
    ".msi",
    ".rar",
    ".tar",
    ".tgz",
    ".zip",
}

DOCUMENT_SUFFIXES = {
    ".doc",
    ".docx",
    ".pdf",
    ".ppt",
    ".pptx",
    ".txt",
    ".xls",
    ".xlsx",
}


class AdvisorError(Exception):
    """Expected CLI error with a user-facing message."""


def now_local_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def normalize_name(value: str) -> str:
    return value.strip().lower()


def lower_parts(path: Path) -> list[str]:
    return [normalize_name(part) for part in path.parts if part and part not in {"\\", "/"}]


def contains_any_name(path: Path, names: set[str]) -> bool:
    parts = set(lower_parts(path))
    return bool(parts & names)


def is_reparse_point(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def is_protected_path(path: Path) -> bool:
    return contains_any_name(path, PROTECTED_NAMES)


def classify_path(path: Path, *, is_dir: bool, size: int, mtime: float) -> tuple[str, str, bool]:
    protected = is_protected_path(path)
    name = normalize_name(path.name)
    suffix = path.suffix.lower()
    age_days = max(0.0, (time.time() - mtime) / 86400) if mtime else 0.0

    if protected:
        return "never_delete", "protected Windows/system path", True

    if contains_any_name(path, CACHE_NAMES) or suffix in TEMP_SUFFIXES or name.endswith(".tmp"):
        return "delete_candidate", "cache, temporary, log, or recycle-bin-like content", False

    if contains_any_name(path, REVIEW_REBUILDABLE_NAMES):
        return "review", "rebuildable dependency or build output; confirm before deleting", False

    if contains_any_name(path, DOWNLOAD_NAMES):
        return "review", "download area; confirm whether the files are still needed", False

    if suffix in REVIEW_SUFFIXES:
        return "review", "installer/archive image; often removable after use", False

    if contains_any_name(path, PROGRAM_OR_APP_NAMES):
        return "keep", "application or game directory; uninstall through the app/store when possible", False

    if contains_any_name(path, KEEP_NAMES) or suffix in DOCUMENT_SUFFIXES:
        return "keep", "document, source, or work area", False

    if not is_dir and size >= 1024**3 and age_days >= 180:
        return "review", "large file older than 180 days", False

    return "review", "unknown content; inspect before deleting", False


def file_id(path: Path, size: int, modified_ns: int) -> str:
    material = f"{path.resolve(strict=False)}|{size}|{modified_ns}".encode("utf-8", "surrogatepass")
    return "f_" + hashlib.sha1(material).hexdigest()[:14]


def display_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def safe_relative_parts(path: Path, root: Path) -> tuple[str, ...]:
    try:
        rel = path.relative_to(root)
        return rel.parts
    except ValueError:
        return path.parts


def top_bucket(path: Path, root: Path) -> str:
    parts = safe_relative_parts(path, root)
    if len(parts) <= 1:
        return "<root files>"
    return parts[0]


def classification_path(path: Path, root: Path) -> Path:
    parts = safe_relative_parts(path, root)
    root_name = root.name
    if root_name:
        parts = (root_name, *parts)
    if not parts:
        return Path(str(root))
    return Path(*parts)


def bucket_path(root: Path, bucket: str) -> Path:
    return root if bucket == "<root files>" else root / bucket


def build_report(root: Path, *, min_size_mb: float = 1.0) -> dict[str, Any]:
    root = root.expanduser().resolve(strict=False)
    if not root.exists():
        raise AdvisorError(f"Scan path does not exist: {root}")
    if not root.is_dir():
        raise AdvisorError(f"Scan path must be a directory: {root}")

    started = time.time()
    min_size = int(max(0.0, min_size_mb) * 1024 * 1024)
    items: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    directory_totals: dict[str, dict[str, int]] = defaultdict(lambda: {"size": 0, "files": 0})
    extension_totals: dict[str, dict[str, int]] = defaultdict(lambda: {"size": 0, "files": 0})
    category_totals: dict[str, dict[str, int]] = defaultdict(lambda: {"size": 0, "files": 0})
    stack = [root]
    total_size = 0
    file_count = 0
    dir_count = 0

    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                entries = list(iterator)
        except OSError as exc:
            errors.append({"path": str(current), "error": str(exc)})
            continue

        for entry in entries:
            path = Path(entry.path)
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                errors.append({"path": str(path), "error": str(exc)})
                continue

            if is_reparse_point(st):
                errors.append({"path": str(path), "error": "skipped reparse point"})
                continue

            if stat.S_ISDIR(st.st_mode):
                dir_count += 1
                stack.append(path)
                continue

            if not stat.S_ISREG(st.st_mode):
                continue

            size = int(st.st_size)
            modified_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000)))
            category, reason, protected = classify_path(
                classification_path(path, root),
                is_dir=False,
                size=size,
                mtime=st.st_mtime,
            )
            bucket = top_bucket(path, root)
            extension = path.suffix.lower() or "[no extension]"

            file_count += 1
            total_size += size
            directory_totals[bucket]["size"] += size
            directory_totals[bucket]["files"] += 1
            extension_totals[extension]["size"] += size
            extension_totals[extension]["files"] += 1
            category_totals[category]["size"] += size
            category_totals[category]["files"] += 1

            if size >= min_size or category == "delete_candidate":
                items.append(
                    {
                        "id": file_id(path, size, modified_ns),
                        "path": str(path),
                        "size": size,
                        "size_human": display_size(size),
                        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                        "modified_ns": modified_ns,
                        "extension": extension,
                        "category": category,
                        "reason": reason,
                        "protected": protected,
                    }
                )

    directories = []
    for bucket, totals in directory_totals.items():
        path = bucket_path(root, bucket)
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0
        category, reason, protected = classify_path(
            classification_path(path, root),
            is_dir=True,
            size=totals["size"],
            mtime=mtime,
        )
        directories.append(
            {
                "path": str(path),
                "size": totals["size"],
                "size_human": display_size(totals["size"]),
                "files": totals["files"],
                "category": category,
                "reason": reason,
                "protected": protected,
            }
        )

    report = {
        "tool": "disk-cleanup-advisor",
        "version": __version__,
        "scan": {
            "root": str(root),
            "created_at": now_local_iso(),
            "duration_seconds": round(time.time() - started, 2),
            "min_reported_file_size_mb": min_size_mb,
            "total_size": total_size,
            "total_size_human": display_size(total_size),
            "file_count": file_count,
            "dir_count": dir_count,
            "reported_item_count": len(items),
            "error_count": len(errors),
        },
        "categories": sorted(
            (
                {
                    "category": category,
                    "size": totals["size"],
                    "size_human": display_size(totals["size"]),
                    "files": totals["files"],
                }
                for category, totals in category_totals.items()
            ),
            key=lambda row: row["size"],
            reverse=True,
        ),
        "directories": sorted(directories, key=lambda row: row["size"], reverse=True),
        "extensions": sorted(
            (
                {
                    "extension": extension,
                    "size": totals["size"],
                    "size_human": display_size(totals["size"]),
                    "files": totals["files"],
                }
                for extension, totals in extension_totals.items()
            ),
            key=lambda row: row["size"],
            reverse=True,
        ),
        "items": sorted(items, key=lambda row: row["size"], reverse=True),
        "errors": errors,
    }
    return report


def write_reports(report: dict[str, Any], output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "scan.json"
    csv_path = output_dir / "scan.csv"
    html_path = output_dir / "scan.html"

    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "id",
                "category",
                "size_human",
                "size",
                "modified",
                "extension",
                "protected",
                "reason",
                "path",
            ],
        )
        writer.writeheader()
        for item in report["items"]:
            writer.writerow({key: item.get(key, "") for key in writer.fieldnames})

    html_path.write_text(render_html(report), encoding="utf-8")
    return {"json": json_path, "csv": csv_path, "html": html_path}


def render_html(report: dict[str, Any]) -> str:
    scan = report["scan"]

    def esc(value: Any) -> str:
        return html.escape(str(value))

    def table(headers: list[str], rows: list[dict[str, Any]], limit: int = 100) -> str:
        head = "".join(f"<th>{esc(header)}</th>" for header in headers)
        body_rows = []
        for row in rows[:limit]:
            cells = "".join(f"<td>{esc(row.get(header, ''))}</td>" for header in headers)
            body_rows.append(f"<tr>{cells}</tr>")
        return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"

    category_rows = [
        {
            "category": row["category"],
            "size": row["size_human"],
            "files": row["files"],
        }
        for row in report["categories"]
    ]
    directory_rows = [
        {
            "category": row["category"],
            "size": row["size_human"],
            "files": row["files"],
            "reason": row["reason"],
            "path": row["path"],
        }
        for row in report["directories"]
    ]
    item_rows = [
        {
            "id": row["id"],
            "category": row["category"],
            "size": row["size_human"],
            "modified": row["modified"],
            "reason": row["reason"],
            "path": row["path"],
        }
        for row in report["items"]
    ]
    error_rows = [
        {
            "path": row.get("path", ""),
            "error": row.get("error", ""),
        }
        for row in report.get("errors", [])
    ]
    extension_rows = [
        {
            "extension": row["extension"],
            "size": row["size_human"],
            "files": row["files"],
        }
        for row in report["extensions"]
    ]

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Disk Cleanup Advisor Report</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #17202a; background: #f7f9fb; }}
    main {{ max-width: 1180px; margin: 0 auto; }}
    h1, h2 {{ margin: 0 0 12px; }}
    section {{ margin: 22px 0; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }}
    .card {{ background: #fff; border: 1px solid #d9e2ec; border-radius: 8px; padding: 14px; }}
    .value {{ font-size: 22px; font-weight: 700; }}
    .label {{ color: #52616b; font-size: 13px; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d9e2ec; }}
    th, td {{ padding: 9px 10px; border-bottom: 1px solid #e6edf3; text-align: left; font-size: 13px; vertical-align: top; }}
    th {{ background: #edf2f7; font-weight: 700; }}
    tr:nth-child(even) td {{ background: #fbfdff; }}
    code {{ background: #edf2f7; padding: 2px 4px; border-radius: 4px; }}
    .note {{ color: #52616b; line-height: 1.5; }}
  </style>
</head>
<body>
<main>
  <h1>Disk Cleanup Advisor Report</h1>
  <p class="note">Root: <code>{esc(scan["root"])}</code> | Created: {esc(scan["created_at"])}</p>
  <div class="cards">
    <div class="card"><div class="value">{esc(scan["total_size_human"])}</div><div class="label">Total scanned size</div></div>
    <div class="card"><div class="value">{esc(scan["file_count"])}</div><div class="label">Files scanned</div></div>
    <div class="card"><div class="value">{esc(scan["reported_item_count"])}</div><div class="label">Reported file items</div></div>
    <div class="card"><div class="value">{esc(scan["error_count"])}</div><div class="label">Skipped/error paths</div></div>
  </div>

  <section>
    <h2>Category Summary</h2>
    {table(["category", "size", "files"], category_rows)}
  </section>

  <section>
    <h2>Largest Top-Level Areas</h2>
    {table(["category", "size", "files", "reason", "path"], directory_rows)}
  </section>

  <section>
    <h2>Largest Extensions</h2>
    {table(["extension", "size", "files"], extension_rows, limit=50)}
  </section>

  <section>
    <h2>Largest Reported Files</h2>
    <p class="note">Only file IDs listed here can be passed to the delete command. Permanent deletion still requires <code>{CONFIRM_TOKEN}</code>.</p>
    {table(["id", "category", "size", "modified", "reason", "path"], item_rows)}
  </section>

  <section>
    <h2>Skipped Or Inaccessible Paths</h2>
    <p class="note">If Windows reports more used space than this scan totals, these paths and protected system storage are the first places to investigate.</p>
    {table(["path", "error"], error_rows, limit=100)}
  </section>
</main>
</body>
</html>
"""


def load_report(input_path: Path) -> dict[str, Any]:
    try:
        return json.loads(input_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AdvisorError(f"Report not found: {input_path}") from exc
    except json.JSONDecodeError as exc:
        raise AdvisorError(f"Invalid JSON report: {input_path}") from exc


def delete_items(
    report: dict[str, Any],
    ids: list[str],
    *,
    apply: bool = False,
    confirm: str | None = None,
    log_dir: Path | None = None,
) -> dict[str, Any]:
    if not ids:
        raise AdvisorError("No item IDs were supplied.")

    by_id = {item["id"]: item for item in report.get("items", [])}
    missing = [item_id for item_id in ids if item_id not in by_id]
    if missing:
        raise AdvisorError("IDs are not present in the scan report: " + ", ".join(missing))

    blockers: list[str] = []
    targets: list[dict[str, Any]] = []
    for item_id in ids:
        item = by_id[item_id]
        path = Path(item["path"])

        if item.get("protected") or item.get("category") == "never_delete" or is_protected_path(path):
            blockers.append(f"{item_id}: protected path {path}")
            continue

        if not path.exists():
            blockers.append(f"{item_id}: file no longer exists {path}")
            continue

        if not path.is_file():
            blockers.append(f"{item_id}: only files can be deleted by this tool {path}")
            continue

        try:
            st = path.stat()
        except OSError as exc:
            blockers.append(f"{item_id}: cannot stat {path}: {exc}")
            continue

        current_size = int(st.st_size)
        current_modified_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000)))
        if current_size != int(item.get("size", -1)) or current_modified_ns != int(item.get("modified_ns", -1)):
            blockers.append(f"{item_id}: file changed since scan {path}")
            continue

        targets.append(
            {
                "id": item_id,
                "path": str(path),
                "size": current_size,
                "size_human": display_size(current_size),
                "category": item.get("category", ""),
                "reason": item.get("reason", ""),
            }
        )

    if blockers:
        raise AdvisorError("Deletion blocked:\n" + "\n".join(blockers))

    total_size = sum(target["size"] for target in targets)
    result = {
        "apply": apply,
        "deleted": [],
        "targets": targets,
        "total_size": total_size,
        "total_size_human": display_size(total_size),
    }

    if not apply:
        return result

    if confirm != CONFIRM_TOKEN:
        raise AdvisorError(f"Permanent deletion requires --confirm {CONFIRM_TOKEN}")

    deleted: list[dict[str, Any]] = []
    for target in targets:
        path = Path(target["path"])
        path.unlink()
        deleted.append({**target, "deleted_at": now_local_iso()})

    result["deleted"] = deleted
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"delete-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        log_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        result["log_path"] = str(log_path)
    return result


def print_summary(report: dict[str, Any]) -> None:
    scan = report["scan"]
    print(f"Root: {scan['root']}")
    print(f"Created: {scan['created_at']}")
    print(f"Total: {scan['total_size_human']} across {scan['file_count']} files")
    print("")
    print("By category:")
    for row in report.get("categories", []):
        print(f"  {row['category']:<18} {row['size_human']:>10}  {row['files']} files")
    print("")
    print("Largest top-level areas:")
    for row in report.get("directories", [])[:15]:
        print(f"  {row['size_human']:>10}  {row['category']:<16}  {row['path']}")
    if report.get("errors"):
        print("")
        print("Skipped or inaccessible paths:")
        for row in report["errors"][:10]:
            print(f"  {row['path']} | {row['error']}")


def command_scan(args: argparse.Namespace) -> int:
    report = build_report(args.path, min_size_mb=args.min_size_mb)
    outputs = write_reports(report, args.out)
    print_summary(report)
    print("")
    print("Wrote reports:")
    for kind, path in outputs.items():
        print(f"  {kind}: {path}")
    return 0


def command_summary(args: argparse.Namespace) -> int:
    report = load_report(args.input)
    print_summary(report)
    return 0


def command_delete(args: argparse.Namespace) -> int:
    report = load_report(args.input)
    result = delete_items(
        report,
        args.ids,
        apply=args.apply,
        confirm=args.confirm,
        log_dir=args.log_dir if args.apply else None,
    )
    action = "Deleted" if args.apply else "Dry run"
    print(f"{action}: {len(result['targets'])} file(s), {result['total_size_human']}")
    for target in result["targets"]:
        print(f"  {target['id']}  {target['size_human']}  {target['path']}")
    if args.apply and result.get("log_path"):
        print(f"Deletion log: {result['log_path']}")
    if not args.apply:
        print(f"Nothing was deleted. Add --apply --confirm {CONFIRM_TOKEN} to permanently delete these files.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="disk-cleanup-advisor",
        description="Scan a disk, write cleanup reports, and gate permanent deletion behind explicit confirmation.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a directory and write JSON/CSV/HTML reports")
    scan.add_argument("--path", type=Path, default=DEFAULT_SCAN_ROOT, help=f"path to scan, default: {DEFAULT_SCAN_ROOT}")
    scan.add_argument("--out", type=Path, default=DEFAULT_REPORT_DIR, help=f"report directory, default: {DEFAULT_REPORT_DIR}")
    scan.add_argument(
        "--min-size-mb",
        type=float,
        default=1.0,
        help="minimum file size to list individually; directory totals still include every file",
    )
    scan.set_defaults(func=command_scan)

    summary = subparsers.add_parser("summary", help="print a summary from scan.json")
    summary.add_argument("--input", type=Path, required=True, help="path to scan.json")
    summary.set_defaults(func=command_summary)

    delete = subparsers.add_parser("delete", help="dry-run or permanently delete files by report item ID")
    delete.add_argument("--input", type=Path, required=True, help="path to scan.json")
    delete.add_argument("--ids", nargs="+", required=True, help="file IDs from the report")
    delete.add_argument("--apply", action="store_true", help="perform permanent deletion; without this, only previews")
    delete.add_argument("--confirm", help=f"must be exactly {CONFIRM_TOKEN} when --apply is used")
    delete.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR, help=f"deletion log directory, default: {DEFAULT_LOG_DIR}")
    delete.set_defaults(func=command_delete)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except AdvisorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
