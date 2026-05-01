import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from disk_cleanup_advisor.cli import AdvisorError, build_report, delete_items, load_report, write_reports


class DiskCleanupAdvisorTests(unittest.TestCase):
    def make_fixture(self, root: Path) -> dict[str, Path]:
        downloads = root / "Downloads"
        cache = root / "cache"
        docs = root / "文档"
        protected = root / "System Volume Information"
        for folder in (downloads, cache, docs, protected):
            folder.mkdir(parents=True, exist_ok=True)

        files = {
            "installer": downloads / "old-installer.iso",
            "cache": cache / "render-cache.tmp",
            "doc": docs / "budget.xlsx",
            "protected": protected / "index.dat",
        }
        files["installer"].write_bytes(b"a" * 1024)
        files["cache"].write_bytes(b"b" * 512)
        files["doc"].write_bytes(b"c" * 256)
        files["protected"].write_bytes(b"d" * 128)
        return files

    def test_scan_classifies_common_paths_and_writes_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = self.make_fixture(root)

            report = build_report(root, min_size_mb=0)
            by_path = {Path(item["path"]).name: item for item in report["items"]}

            self.assertEqual(by_path[files["installer"].name]["category"], "review")
            self.assertEqual(by_path[files["cache"].name]["category"], "delete_candidate")
            self.assertEqual(by_path[files["doc"].name]["category"], "keep")
            self.assertEqual(by_path[files["protected"].name]["category"], "never_delete")
            self.assertTrue(by_path[files["protected"].name]["protected"])

            out = root / "out"
            outputs = write_reports(report, out)
            self.assertTrue(outputs["json"].exists())
            self.assertTrue(outputs["csv"].exists())
            self.assertTrue(outputs["html"].exists())

            loaded = load_report(outputs["json"])
            self.assertEqual(loaded["scan"]["file_count"], 4)
            self.assertTrue(files["cache"].exists(), "scan/report generation must not delete files")

    def test_delete_is_dry_run_by_default_and_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = self.make_fixture(root)
            report = build_report(root, min_size_mb=0)
            cache_item = next(item for item in report["items"] if Path(item["path"]).name == files["cache"].name)

            dry_run = delete_items(report, [cache_item["id"]], apply=False)
            self.assertEqual(len(dry_run["targets"]), 1)
            self.assertTrue(files["cache"].exists())

            with self.assertRaises(AdvisorError):
                delete_items(report, [cache_item["id"]], apply=True, confirm="WRONG")
            self.assertTrue(files["cache"].exists())

            applied = delete_items(report, [cache_item["id"]], apply=True, confirm="PERMANENT-DELETE", log_dir=root / "logs")
            self.assertEqual(len(applied["deleted"]), 1)
            self.assertFalse(files["cache"].exists())
            self.assertTrue(Path(applied["log_path"]).exists())

    def test_delete_rejects_protected_and_unknown_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = self.make_fixture(root)
            report = build_report(root, min_size_mb=0)
            protected_item = next(item for item in report["items"] if Path(item["path"]).name == files["protected"].name)

            with self.assertRaises(AdvisorError):
                delete_items(report, [protected_item["id"]], apply=True, confirm="PERMANENT-DELETE")
            self.assertTrue(files["protected"].exists())

            with self.assertRaises(AdvisorError):
                delete_items(report, ["f_doesnotexist"], apply=False)

    def test_report_json_contains_no_private_paths_when_using_sample(self):
        sample = PROJECT_ROOT / "examples" / "sample_scan.json"
        data = json.loads(sample.read_text(encoding="utf-8"))
        serialized = json.dumps(data, ensure_ascii=False)
        self.assertEqual(data["scan"]["root"], "E:\\ExampleDrive")
        self.assertNotIn("CodexTasks", serialized)
        self.assertNotIn("Users\\21332", serialized)


if __name__ == "__main__":
    unittest.main()
