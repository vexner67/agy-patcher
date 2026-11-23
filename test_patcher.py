import importlib.util
import json
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("agy_patcher", HERE / "agy_patcher.py")
p = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p
spec.loader.exec_module(p)

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.data = bytearray(range(128))
        self.data[:8] = bytes.fromhex("cffaedfe0c000001")
        self.data = bytes(self.data)
        self.edit = p.Edit(48, self.data[48:52], b"\x01\x02\x03\x04",
                           self.data[32:68], "fixture")
        self.profile = p.Profile("cli", "fixture", len(self.data),
                                 p.digest(self.data), 8, 128, (self.edit,))

    def test_exact_changes_only(self):
        actual = p.patch_bytes(self.data, self.profile)
        self.assertEqual(actual[:48], self.data[:48])
        self.assertEqual(actual[48:52], self.edit.after)
        self.assertEqual(actual[52:], self.data[52:])

    def test_unknown_and_already_patched_rejected(self):
        for bad in (self.data[:-1] + b"x", p.patch_bytes(self.data, self.profile)):
            with self.subTest(data_hash=p.digest(bad)), self.assertRaises(p.Refused):
                p.patch_bytes(bad, self.profile)

    def test_context_checked_independently(self):
        bad = replace(self.profile, edits=(replace(self.edit, context=b"x" * 36),))
        with self.assertRaises(p.Refused):
            p.patch_bytes(self.data, bad)

    def test_signing_cannot_change_text(self):
        raw = p.patch_bytes(self.data, self.profile)
        p.verify_signed_copy(raw, raw, self.profile)
        altered = bytearray(raw)
        altered[80] ^= 1
        with self.assertRaises(p.Refused):
            p.verify_signed_copy(raw, bytes(altered), self.profile)
        with self.assertRaises(p.Refused):
            p.verify_signed_copy(raw, raw[:64], self.profile)

    def test_no_overwrite_or_source_nested_output(self):
        with tempfile.TemporaryDirectory(dir=HERE, prefix=".patcher-test-") as temp:
            root = Path(temp)
            app = root / "Source.app"
            app.mkdir()
            with self.assertRaises(p.Refused):
                p.output_location(app, app)
            with self.assertRaises(p.Refused):
                p.output_location(app / "nested", app)

    def test_source_symlink_rejected(self):
        with tempfile.TemporaryDirectory(dir=HERE, prefix=".patcher-test-") as temp:
            root = Path(temp)
            source = root / "source"
            source.write_bytes(self.data)
            link = root / "link"
            link.symlink_to(source)
            with self.assertRaises(OSError):
                p.read_source(link, self.profile)

    def test_external_bundle_link_rejected(self):
        with tempfile.TemporaryDirectory(dir=HERE, prefix=".patcher-test-") as temp:
            root = Path(temp)
            (root / "escape").symlink_to(HERE)
            with self.assertRaises(p.Refused):
                p.tree_inventory(root)

@unittest.skipUnless(sys.platform == "darwin", "macOS integration")
class InstalledBuildTests(unittest.TestCase):
    def test_cli_copy(self):
        source = Path.home() / ".local/bin/agy"
        data = p.read_source(source, p.CLI)
        with tempfile.TemporaryDirectory(dir=HERE, prefix=".patcher-test-") as temp:
            output = p.build(source, data, Path(temp) / "cli", p.CLI)
            self.assertEqual(p.file_digest(output / "agy.original"), p.CLI.sha256)
            self.assertEqual(p.file_digest(source), p.CLI.sha256)
            process = subprocess.run([str(output / "agy"), "--version"],
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn(p.CLI.version, process.stdout + process.stderr)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(p.file_digest(output / "agy"), manifest["patched_sha256"])
            with self.assertRaises(p.Refused):
                p.build(source, data, output, p.CLI)

    def test_app_copy(self):
        source = Path("/Applications/Antigravity.app")
        p.check_app(source)
        original = p.tree_inventory(source)
        data = p.read_source(source / p.APP_BINARY, p.APP)
        with tempfile.TemporaryDirectory(dir=HERE, prefix=".patcher-test-") as temp:
            output = p.build(source, data, Path(temp) / "app", p.APP)
            copy = output / "Antigravity.app"
            p.run_checked(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(copy)])
            self.assertEqual(p.file_digest(output / "language_server.original"), p.APP.sha256)
            self.assertEqual(p.tree_inventory(source), original)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["bundle_source_inventory"], original)
            self.assertEqual(p.file_digest(copy / p.APP_BINARY), manifest["patched_sha256"])
            for resource in ["Contents/Info.plist", "Contents/Resources/app.asar"]:
                self.assertEqual(p.file_digest(copy / resource), p.file_digest(source / resource))
            self.assertEqual(manifest["bundle_output_inventory"], p.tree_inventory(copy))
            self.assertTrue(manifest["electron_loader_smoke"].startswith("electron-loader-ok:"))
            self.assertIn("Contents/MacOS/Antigravity", manifest["library_validation_exceptions"])
            original_entitlements = p.macho_metadata(source / "Contents/MacOS/Antigravity")["entitlements"]
            copied_entitlements = p.macho_metadata(copy / "Contents/MacOS/Antigravity")["entitlements"]
            self.assertTrue(copied_entitlements[p.LIBRARY_VALIDATION_EXCEPTION])
            for key, value in original_entitlements.items():
                self.assertEqual(copied_entitlements[key], value)
            print("\nApp changed paths:", len(manifest["bundle_changed_paths"]))

if __name__ == "__main__":
    unittest.main(verbosity=2)
