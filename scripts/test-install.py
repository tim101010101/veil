#!/usr/bin/env python3
import hashlib
import io
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import unittest

INSTALLER = Path(__file__).with_name("install.sh").resolve()


@unittest.skipUnless(sys.platform.startswith("linux"), "managed installer is Linux-only")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="veil-installer-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.fixture = self.root / "fixture"
        self.fixture.mkdir()
        self.env = {**os.environ, "PATH": f"{self.tools}:{os.environ['PATH']}",
                    "HOME": str(self.root),
                    "FIXTURE": str(self.fixture), "VEIL_VERSION": ""}
        self.tool("curl", """for arg do url=$arg; done
case "$url" in
  */SHA256SUMS) cat "$FIXTURE/SHA256SUMS" ;;
  *.tar.gz) cat "$FIXTURE/archive.tar.gz" ;;
  *) exit 99 ;;
esac
""")
        self.archive()

    def tool(self, name, content):
        path = self.tools / name
        path.write_text("#!/bin/sh\n" + content)
        path.chmod(0o755)

    def archive(self, member="veil", checksum=True):
        path = self.fixture / "archive.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            body = b"#!/bin/sh\necho fixture-build\n"
            header = tarfile.TarInfo(member)
            header.mode = 0o755
            header.size = len(body)
            archive.addfile(header, io.BytesIO(body))
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if checksum else "0" * 64
        arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(platform.machine(), platform.machine())
        (self.fixture / "SHA256SUMS").write_text(f"{digest}  veil-0.3.0-linux-{arch}.tar.gz\n")

    def install(self, *args):
        return subprocess.run(["sh", str(INSTALLER), "--version", "0.3.0", "--dir", str(self.bin), *args],
                              env=self.env, capture_output=True, text=True, timeout=10)

    def test_install_creates_managed_receipt_without_shell_changes(self):
        profile = self.root / ".profile"
        profile.write_text("original")
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.bin / "veil").is_symlink())
        executable = (self.bin / "veil").resolve()
        self.assertIn(hashlib.sha256(executable.read_bytes()).hexdigest(), executable.with_name("install.toml").read_text())
        self.assertEqual(profile.read_text(), "original")
        self.assertFalse((self.bin / ".veil/upgrade.lock").exists())

    def test_direct_install_requires_explicit_adoption_and_retains_previous(self):
        (self.bin / "veil").write_bytes(b"old binary")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--adopt", result.stderr)
        self.assertEqual((self.bin / "veil").read_bytes(), b"old binary")
        result = self.install("--adopt")
        self.assertEqual(result.returncode, 0, result.stderr)
        previous = list((self.bin / ".veil").glob("legacy-*/veil"))
        self.assertEqual([path.read_bytes() for path in previous], [b"old binary"])

    def test_changed_managed_binary_is_not_overwritten(self):
        self.assertEqual(self.install().returncode, 0)
        (self.bin / "veil").write_bytes(b"external replacement")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.bin / "veil").read_bytes(), b"external replacement")

    def test_invalid_downloads_leave_old_binary_intact(self):
        (self.bin / "veil").write_bytes(b"old binary")
        for member, checksum in [("veil", False), ("../outside", True)]:
            with self.subTest(member=member, checksum=checksum):
                self.archive(member, checksum)
                result = self.install("--adopt")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.bin / "veil").read_bytes(), b"old binary")
                self.assertFalse((self.root / "outside").exists())
                self.assertFalse((self.bin / ".veil/upgrade.lock").exists())

    def test_failed_activation_preserves_the_previous_launcher(self):
        (self.bin / "veil").write_bytes(b"old binary")
        self.tool("mv", "exit 1\n")
        result = self.install("--adopt")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.bin / "veil").read_bytes(), b"old binary")
        self.assertFalse(list((self.bin / ".veil").glob("0.3.0-*")))

    def test_interruption_after_activation_does_not_remove_the_selected_binary(self):
        (self.bin / "veil").write_bytes(b"old binary")
        self.tool("mv", '/bin/mv "$@" || exit\nkill -TERM "$PPID"\nsleep 0.1\n')
        result = self.install("--adopt")
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assertTrue((self.bin / "veil").is_file())
        self.assertIn(b"fixture-build", (self.bin / "veil").read_bytes())
        self.assertEqual(next((self.bin / ".veil").glob("legacy-*/veil")).read_bytes(), b"old binary")

    def test_existing_lock_is_not_removed(self):
        (self.bin / ".veil").mkdir()
        lock = self.bin / ".veil/upgrade.lock"
        lock.write_text("other updater")
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(lock.read_text(), "other updater")


if __name__ == "__main__":
    unittest.main()
