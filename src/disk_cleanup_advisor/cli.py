from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import os
import shutil
import stat
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__


CONFIRM_TOKEN = "PERMANENT-DELETE"
DEFAULT_REPORT_DIR = Path(r"E:\CodexTasks\reports" if os.name == "nt" else "reports")
DEFAULT_LOG_DIR = Path(r"E:\CodexTasks\trash_logs" if os.name == "nt" else "trash_logs")
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

CATEGORY_LABELS = {
    "never_delete": "不要动",
    "keep": "建议保留",
    "review": "人工检查",
    "delete_candidate": "可删除候选",
}

REASON_TRANSLATIONS = {
    "protected Windows/system path": "Windows 或系统保护路径",
    "cache, temporary, log, or recycle-bin-like content": "缓存、临时文件、日志或类似回收站的内容",
    "rebuildable dependency or build output; confirm before deleting": "依赖目录或构建产物，删除前请确认可重新生成",
    "download area; confirm whether the files are still needed": "下载目录，请确认文件是否还需要",
    "installer/archive image; often removable after use": "安装包、压缩包或镜像文件，使用后通常可清理",
    "application or game directory; uninstall through the app/store when possible": "应用或游戏目录，建议通过软件或平台卸载",
    "document, source, or work area": "文档、源码或工作资料",
    "large file older than 180 days": "超过 180 天未修改的大文件",
    "unknown content; inspect before deleting": "未知内容，删除前请先查看",
}

CSV_COLUMNS = [
    ("id", "ID"),
    ("category_label", "分类"),
    ("category", "分类代码"),
    ("size_human", "大小"),
    ("size", "字节数"),
    ("modified", "修改时间"),
    ("extension", "扩展名"),
    ("protected_label", "受保护"),
    ("reason", "原因"),
    ("path", "路径"),
]

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


def configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


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
        return "never_delete", "Windows 或系统保护路径", True

    if contains_any_name(path, CACHE_NAMES) or suffix in TEMP_SUFFIXES or name.endswith(".tmp"):
        return "delete_candidate", "缓存、临时文件、日志或类似回收站的内容", False

    if contains_any_name(path, REVIEW_REBUILDABLE_NAMES):
        return "review", "依赖目录或构建产物，删除前请确认可重新生成", False

    if contains_any_name(path, DOWNLOAD_NAMES):
        return "review", "下载目录，请确认文件是否还需要", False

    if suffix in REVIEW_SUFFIXES:
        return "review", "安装包、压缩包或镜像文件，使用后通常可清理", False

    if contains_any_name(path, PROGRAM_OR_APP_NAMES):
        return "keep", "应用或游戏目录，建议通过软件或平台卸载", False

    if contains_any_name(path, KEEP_NAMES) or suffix in DOCUMENT_SUFFIXES:
        return "keep", "文档、源码或工作资料", False

    if not is_dir and size >= 1024**3 and age_days >= 180:
        return "review", "超过 180 天未修改的大文件", False

    return "review", "未知内容，删除前请先查看", False


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


def category_label(category: str) -> str:
    return CATEGORY_LABELS.get(category, category)


def bool_label(value: bool) -> str:
    return "是" if value else "否"


def display_reason(reason: str) -> str:
    return REASON_TRANSLATIONS.get(reason, reason)


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


def available_drive_roots() -> list[Path]:
    if os.name != "nt":
        return [Path(".").resolve()]
    drives: list[Path] = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = Path(f"{letter}:\\")
        if root.exists():
            drives.append(root)
    return drives


def choose_scan_root() -> Path:
    drives = available_drive_roots()
    if not drives:
        return Path(".").resolve()

    if not sys.stdin.isatty():
        preferred = Path("E:\\")
        return preferred if preferred.exists() else drives[0]

    print("请选择要扫描的盘符：")
    for index, drive in enumerate(drives, start=1):
        try:
            usage = shutil.disk_usage(drive)
        except OSError:
            usage = None
        detail = ""
        if usage is not None:
            detail = f" 可用 {display_size(usage.free)} / 总计 {display_size(usage.total)}"
        print(f"  {index}. {drive}{detail}")

    default_index = next((i for i, drive in enumerate(drives, start=1) if str(drive).upper().startswith("E:\\")), 1)
    raw = input(f"输入编号或盘符，直接回车默认 {drives[default_index - 1]}：").strip()
    if not raw:
        return drives[default_index - 1]

    if raw.isdigit():
        selected = int(raw)
        if 1 <= selected <= len(drives):
            return drives[selected - 1]
        raise AdvisorError(f"无效编号：{raw}")

    candidate = raw.upper().rstrip("\\/")
    if len(candidate) == 1 and candidate.isalpha():
        candidate = f"{candidate}:"
    root = Path(candidate + "\\" if candidate.endswith(":") else candidate)
    if not root.exists():
        raise AdvisorError(f"盘符或路径不存在：{root}")
    return root


def build_report(root: Path, *, min_size_mb: float = 1.0) -> dict[str, Any]:
    root = root.expanduser().resolve(strict=False)
    if not root.exists():
        raise AdvisorError(f"扫描路径不存在：{root}")
    if not root.is_dir():
        raise AdvisorError(f"扫描路径必须是目录：{root}")

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
        writer = csv.DictWriter(handle, fieldnames=[label for _, label in CSV_COLUMNS])
        writer.writeheader()
        for item in report["items"]:
            row = dict(item)
            row["category_label"] = category_label(str(item.get("category", "")))
            row["protected_label"] = bool_label(bool(item.get("protected", False)))
            row["reason"] = display_reason(str(item.get("reason", "")))
            writer.writerow({label: row.get(key, "") for key, label in CSV_COLUMNS})

    html_path.write_text(render_html(report), encoding="utf-8")
    return {"json": json_path, "csv": csv_path, "html": html_path}


def render_html(report: dict[str, Any]) -> str:
    scan = report["scan"]

    def esc(value: Any) -> str:
        return html.escape(str(value))

    def table(columns: list[tuple[str, str]], rows: list[dict[str, Any]], limit: int = 100) -> str:
        head = "".join(f"<th>{esc(label)}</th>" for _, label in columns)
        body_rows = []
        for row in rows[:limit]:
            cells = "".join(f"<td>{esc(row.get(key, ''))}</td>" for key, _ in columns)
            body_rows.append(f"<tr>{cells}</tr>")
        return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"

    category_rows = [
        {
            "label": category_label(row["category"]),
            "category": row["category"],
            "size": row["size_human"],
            "files": row["files"],
        }
        for row in report["categories"]
    ]
    directory_rows = [
        {
            "category": category_label(row["category"]),
            "size": row["size_human"],
            "files": row["files"],
            "reason": display_reason(row["reason"]),
            "path": row["path"],
        }
        for row in report["directories"]
    ]
    item_rows = [
        {
            "id": row["id"],
            "category": category_label(row["category"]),
            "size": row["size_human"],
            "modified": row["modified"],
            "reason": display_reason(row["reason"]),
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
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>磁盘清理建议报告</title>
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
  <h1>磁盘清理建议报告</h1>
  <p class="note">扫描位置：<code>{esc(scan["root"])}</code> | 生成时间：{esc(scan["created_at"])}</p>
  <div class="cards">
    <div class="card"><div class="value">{esc(scan["total_size_human"])}</div><div class="label">已扫描文件总量</div></div>
    <div class="card"><div class="value">{esc(scan["file_count"])}</div><div class="label">已扫描文件数</div></div>
    <div class="card"><div class="value">{esc(scan["reported_item_count"])}</div><div class="label">报告列出的文件数</div></div>
    <div class="card"><div class="value">{esc(scan["error_count"])}</div><div class="label">跳过或无法访问路径</div></div>
  </div>

  <section>
    <h2>分类汇总</h2>
    {table([("label", "分类"), ("category", "分类代码"), ("size", "大小"), ("files", "文件数")], category_rows)}
  </section>

  <section>
    <h2>最大顶层目录</h2>
    {table([("category", "分类"), ("size", "大小"), ("files", "文件数"), ("reason", "原因"), ("path", "路径")], directory_rows)}
  </section>

  <section>
    <h2>最大文件类型</h2>
    {table([("extension", "扩展名"), ("size", "大小"), ("files", "文件数")], extension_rows, limit=50)}
  </section>

  <section>
    <h2>报告列出的大文件</h2>
    <p class="note">只有这里列出的文件 ID 可以传给删除命令。永久删除仍然必须输入确认词 <code>{CONFIRM_TOKEN}</code>。</p>
    {table([("id", "ID"), ("category", "分类"), ("size", "大小"), ("modified", "修改时间"), ("reason", "原因"), ("path", "路径")], item_rows)}
  </section>

  <section>
    <h2>跳过或无法访问的路径</h2>
    <p class="note">如果 Windows 显示的已用空间明显大于本报告扫描到的总量，优先检查这些路径、权限受限目录和系统保护存储。</p>
    {table([("path", "路径"), ("error", "错误")], error_rows, limit=100)}
  </section>
</main>
</body>
</html>
"""


def load_report(input_path: Path) -> dict[str, Any]:
    try:
        return json.loads(input_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AdvisorError(f"找不到报告：{input_path}") from exc
    except json.JSONDecodeError as exc:
        raise AdvisorError(f"JSON 报告无效：{input_path}") from exc


def delete_items(
    report: dict[str, Any],
    ids: list[str],
    *,
    apply: bool = False,
    confirm: str | None = None,
    log_dir: Path | None = None,
) -> dict[str, Any]:
    if not ids:
        raise AdvisorError("没有提供文件 ID。")

    by_id = {item["id"]: item for item in report.get("items", [])}
    missing = [item_id for item_id in ids if item_id not in by_id]
    if missing:
        raise AdvisorError("这些 ID 不在扫描报告中：" + ", ".join(missing))

    blockers: list[str] = []
    targets: list[dict[str, Any]] = []
    for item_id in ids:
        item = by_id[item_id]
        path = Path(item["path"])

        if item.get("protected") or item.get("category") == "never_delete" or is_protected_path(path):
            blockers.append(f"{item_id}: 受保护路径 {path}")
            continue

        if not path.exists():
            blockers.append(f"{item_id}: 文件已经不存在 {path}")
            continue

        if not path.is_file():
            blockers.append(f"{item_id}: 当前工具只删除文件，不删除目录 {path}")
            continue

        try:
            st = path.stat()
        except OSError as exc:
            blockers.append(f"{item_id}: 无法读取文件状态 {path}: {exc}")
            continue

        current_size = int(st.st_size)
        current_modified_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000)))
        if current_size != int(item.get("size", -1)) or current_modified_ns != int(item.get("modified_ns", -1)):
            blockers.append(f"{item_id}: 文件在扫描后发生变化 {path}")
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
        raise AdvisorError("删除已阻止：\n" + "\n".join(blockers))

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
        raise AdvisorError(f"永久删除需要 --confirm {CONFIRM_TOKEN}")

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
    print(f"扫描位置：{scan['root']}")
    print(f"生成时间：{scan['created_at']}")
    print(f"总计：{scan['total_size_human']}，共 {scan['file_count']} 个文件")
    print("")
    print("按分类：")
    for row in report.get("categories", []):
        label = category_label(row["category"])
        print(f"  {label:<10} {row['size_human']:>10}  {row['files']} 个文件")
    print("")
    print("最大顶层目录：")
    for row in report.get("directories", [])[:15]:
        print(f"  {row['size_human']:>10}  {category_label(row['category']):<10}  {row['path']}")
    if report.get("errors"):
        print("")
        print("跳过或无法访问的路径：")
        for row in report["errors"][:10]:
            print(f"  {row['path']} | {row['error']}")


def command_scan(args: argparse.Namespace) -> int:
    scan_path = args.path if args.path is not None else choose_scan_root()
    report = build_report(scan_path, min_size_mb=args.min_size_mb)
    outputs = write_reports(report, args.out)
    print_summary(report)
    print("")
    print("已写入报告：")
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
    action = "已永久删除" if args.apply else "删除预演"
    print(f"{action}：{len(result['targets'])} 个文件，{result['total_size_human']}")
    for target in result["targets"]:
        print(f"  {target['id']}  {target['size_human']}  {target['path']}")
    if args.apply and result.get("log_path"):
        print(f"删除日志：{result['log_path']}")
    if not args.apply:
        print(f"没有删除任何文件。若确认永久删除，请追加 --apply --confirm {CONFIRM_TOKEN}。")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="disk-cleanup-advisor",
        description="扫描磁盘、生成清理建议报告，并把永久删除放在显式确认之后。",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="扫描目录并写入 JSON/CSV/HTML 报告")
    scan.add_argument("--path", type=Path, help="要扫描的路径；不传时会让你选择盘符")
    scan.add_argument("--out", type=Path, default=DEFAULT_REPORT_DIR, help=f"报告目录，默认：{DEFAULT_REPORT_DIR}")
    scan.add_argument(
        "--min-size-mb",
        type=float,
        default=1.0,
        help="单独列入报告的最小文件大小，目录汇总仍包含所有文件",
    )
    scan.set_defaults(func=command_scan)

    summary = subparsers.add_parser("summary", help="从 scan.json 打印中文摘要")
    summary.add_argument("--input", type=Path, required=True, help="scan.json 路径")
    summary.set_defaults(func=command_summary)

    delete = subparsers.add_parser("delete", help="按报告 ID 预演或永久删除文件")
    delete.add_argument("--input", type=Path, required=True, help="scan.json 路径")
    delete.add_argument("--ids", nargs="+", required=True, help="报告里的文件 ID")
    delete.add_argument("--apply", action="store_true", help="执行永久删除；不传时只预演")
    delete.add_argument("--confirm", help=f"使用 --apply 时必须精确输入 {CONFIRM_TOKEN}")
    delete.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR, help=f"删除日志目录，默认：{DEFAULT_LOG_DIR}")
    delete.set_defaults(func=command_delete)
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except AdvisorError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("已中断。", file=sys.stderr)
        return 130
