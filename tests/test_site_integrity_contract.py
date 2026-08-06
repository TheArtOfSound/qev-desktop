import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "sign_site_content.py"
SPEC = importlib.util.spec_from_file_location("sign_site_content", MODULE_PATH)
assert SPEC and SPEC.loader
signer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signer)


class SiteIntegrityContractTests(unittest.TestCase):
    def test_python_canonicalization_matches_browser_contract(self):
        value = {
            "z": "Qira ✓",
            "a": {"two": 2, "one": 1},
            "list": [{"b": True, "a": None}],
        }
        expected = (
            '{"a":{"one":1,"two":2},'
            '"list":[{"a":null,"b":true}],'
            '"z":"Qira ✓"}'
        ).encode("utf-8")
        self.assertEqual(signer.canonical_manifest_bytes(value), expected)

    def test_browser_verifier_uses_same_compact_sorted_contract(self):
        verifier = (
            Path(__file__).resolve().parents[1]
            / "landing"
            / "site-verify.js"
        ).read_text(encoding="utf-8")
        self.assertIn("JSON.stringify(deepSortKeys(obj))", verifier)
        self.assertNotIn("JSON.stringify(deepSortKeys(obj), null, 2)", verifier)

    def test_new_launcher_assets_are_discovered_automatically(self):
        with tempfile.TemporaryDirectory() as temporary:
            landing = Path(temporary)
            (landing / "index.html").write_text("ok", encoding="utf-8")
            (landing / "qira-apps").mkdir()
            (landing / "qira-apps" / "launcher.js").write_text(
                "customElements.define('qira-product-launcher', class {});",
                encoding="utf-8",
            )
            (landing / "site-integrity.json").write_text("{}", encoding="utf-8")
            (landing / ".DS_Store").write_bytes(b"ignored")
            (landing / "draft.tmp").write_text("ignored", encoding="utf-8")

            with patch.object(signer, "LANDING_DIR", landing):
                self.assertEqual(
                    signer.discover_site_files(),
                    ["index.html", "qira-apps/launcher.js"],
                )

    def test_manifest_file_count_matches_discovered_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            landing = Path(temporary)
            (landing / "a.txt").write_text("a", encoding="utf-8")
            (landing / "nested").mkdir()
            (landing / "nested" / "b.txt").write_text("b", encoding="utf-8")

            with patch.object(signer, "LANDING_DIR", landing):
                files = signer.discover_site_files()
                manifest = signer.build_manifest(files, "00" * 32)

            self.assertEqual(manifest["file_count"], 2)
            self.assertEqual(sorted(manifest["files"]), ["a.txt", "nested/b.txt"])


if __name__ == "__main__":
    unittest.main()
