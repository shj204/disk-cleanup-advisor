# disk-cleanup-advisor

一个偏保守的 Windows 扫盘和清理建议工具。它会扫描盘符或目录，生成
JSON/CSV/HTML 报告，告诉你空间主要被什么占用，以及哪些内容适合人工检查后删除。

默认只报告，不会删除任何东西。

## 功能

- 只使用 Python 3.12 标准库，不需要额外安装依赖。
- 不传 `--path` 时默认列出本机盘符，让你选择要扫描哪个盘。
- 输出三种报告：
  - `scan.json`：机器可读报告，包含删除命令需要的文件 ID。
  - `scan.csv`：中文表头，适合用表格软件查看。
  - `scan.html`：中文浏览器报告，适合快速看大目录和建议分类。
- 分类：
  - `never_delete` / 不要动：Windows 或系统保护路径。
  - `keep` / 建议保留：文档、源码、工作区、应用或游戏目录。
  - `review` / 人工检查：下载、压缩包、安装包、大文件、未知内容。
  - `delete_candidate` / 可删除候选：缓存、临时文件、日志、类似回收站内容。
- 支持永久删除，但必须走显式确认。

## 快速开始

在仓库目录下：

```powershell
$env:PYTHONPATH = "src"
python -m disk_cleanup_advisor scan --out E:\CodexTasks\reports
```

运行后会让你选择盘符。也可以直接指定路径：

```powershell
$env:PYTHONPATH = "src"
python -m disk_cleanup_advisor scan --path E:\ --out E:\CodexTasks\reports
```

打开中文 HTML 报告：

```text
E:\CodexTasks\reports\scan.html
```

之后打印中文摘要：

```powershell
$env:PYTHONPATH = "src"
python -m disk_cleanup_advisor summary --input E:\CodexTasks\reports\scan.json
```

扫描其他路径：

```powershell
$env:PYTHONPATH = "src"
python -m disk_cleanup_advisor scan --path D:\ --out E:\CodexTasks\reports
```

## 删除流程

删除只接受 `scan.json` 里的文件 ID，不接受随便输入路径。

预演删除：

```powershell
$env:PYTHONPATH = "src"
python -m disk_cleanup_advisor delete --input E:\CodexTasks\reports\scan.json --ids f_example123456
```

永久删除：

```powershell
$env:PYTHONPATH = "src"
python -m disk_cleanup_advisor delete --input E:\CodexTasks\reports\scan.json --ids f_example123456 --apply --confirm PERMANENT-DELETE
```

安全规则：

- `scan` 永远不删除文件。
- `delete` 不带 `--apply` 时只是预演。
- `--apply` 必须搭配 `--confirm PERMANENT-DELETE`。
- 系统保护路径会被拒绝。
- 如果文件大小或修改时间和扫描时不同，会拒绝删除。
- 第一版只删除文件，不删除整个目录。

## 阅读报告

如果 Windows 显示的已用空间明显大于报告里的扫描总量，请查看 `scan.html`
里的“跳过或无法访问的路径”。权限受限备份目录、系统保护存储、虚拟磁盘和部分
回收站账户可能占用大量空间，但普通用户进程无法枚举。

## 隐私提醒

真实扫描报告会暴露你的文件夹名和文件路径。不要把真实的
`E:\CodexTasks\reports` 输出提交到公开仓库。`examples/` 里的示例是虚构路径。

## 开发

运行测试：

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

如果想直接使用 `disk-cleanup-advisor` 命令，可以本地安装：

```powershell
python -m pip install -e .
disk-cleanup-advisor scan --path E:\ --out E:\CodexTasks\reports
```
