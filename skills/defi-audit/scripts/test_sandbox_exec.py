"""The analyzer launcher must block sibling files, application env, and TCP."""

from __future__ import annotations

import ctypes
import ctypes.util
import importlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


LAUNCHER = Path(__file__).with_name("sandbox_exec.py")


@unittest.skipUnless(sys.platform == "linux" and platform.machine() in {"x86_64", "aarch64"},
                     "Landlock requires Linux")
class SandboxExecTests(unittest.TestCase):
    def setUp(self) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.syscall(444, None, 0, 1) < 4 or not ctypes.util.find_library("seccomp"):
            self.skipTest("Landlock ABI 4 and libseccomp are required")

    def test_project_can_run_without_reading_sibling_or_app_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "skill" / "defi-audit" / "scripts"
            scripts.mkdir(parents=True)
            launcher = scripts / "sandbox_exec.py"
            shutil.copyfile(LAUNCHER, launcher)
            probe = scripts / "probe.py"
            probe.write_text("""
import ctypes, json, os, socket, subprocess, sys
from pathlib import Path
project = Path.cwd()
output = Path(os.environ['ARTEX_SANDBOX_OUTPUT'])
private = Path(sys.argv[1])
def attempt(fn):
    try:
        fn()
        return 'allowed'
    except OSError as exc:
        return exc.errno
def tcp():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect(('127.0.0.1', 9))
def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM):
        pass
def child_read():
    return subprocess.run([sys.executable, '-c',
                           'import sys; open(sys.argv[1]).read()', str(private)],
                          capture_output=True).returncode
libc = ctypes.CDLL(None, use_errno=True)
memory_result = libc.process_vm_readv(os.getpid(), None, 0, None, 0, 0)
memory_errno = ctypes.get_errno() if memory_result < 0 else 0
(output / 'result.txt').write_text('written')
marker = Path(os.environ['HOME']) / 'prior-run'
prior_state = marker.exists()
marker.write_text('created')
print(json.dumps({
    'source': (project / 'Vault.sol').read_text(),
    'private': attempt(lambda: private.read_text()),
    'proc': attempt(lambda: Path('/proc/1/environ').read_bytes()),
    'tcp': attempt(tcp),
    'udp': attempt(udp),
    'child_private_exit': child_read(),
    'memory_errno': memory_errno,
    'secret_env': os.environ.get('ARTEX_PG_DSN'),
    'prior_state': prior_state,
}))
""")
            project = root / "project"
            project.mkdir()
            (project / "Vault.sol").write_text("contract Vault {}")
            output = root / "output"
            output.mkdir()
            private = root / "private.txt"
            private.write_text("secret")
            env = dict(os.environ, ARTEX_PG_DSN="postgres://secret")
            completed = subprocess.run(
                [sys.executable, str(launcher), "--project", str(project),
                 "--output-dir", str(output), "--script", str(probe),
                 "--", str(private)],
                text=True, capture_output=True, timeout=15, env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["source"], "contract Vault {}")
            self.assertNotEqual(result["private"], "allowed")
            self.assertNotEqual(result["proc"], "allowed")
            self.assertNotIn(result["tcp"], ("allowed", 111))  # ECONNREFUSED means connect was allowed
            self.assertNotEqual(result["udp"], "allowed")
            self.assertNotEqual(result["child_private_exit"], 0)
            self.assertEqual(result["memory_errno"], 1)
            self.assertIsNone(result["secret_env"])
            self.assertFalse(result["prior_state"])
            self.assertEqual((output / "result.txt").read_text(), "written")
            again = subprocess.run(
                [sys.executable, str(launcher), "--project", str(project),
                 "--output-dir", str(output), "--script", str(probe),
                 "--", str(private)],
                text=True, capture_output=True, timeout=15, env=env,
            )
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertFalse(json.loads(again.stdout)["prior_state"])


class CompilerWrapperTests(unittest.TestCase):
    """The arm64 solc wrapper needs qemu, not Landlock, so test it separately."""

    def test_arm64_solc_wrapper_uses_native_qemu(self) -> None:
        if platform.machine() not in {"aarch64", "arm64"}:
            self.skipTest("wrapper is only needed on arm64")
        if shutil.which("qemu-x86_64") is None:
            self.skipTest("qemu-x86_64 is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "tool" / ".solc-select" / "artifacts" / "solc-0.8.35"
            artifacts.mkdir(parents=True)
            # A minimal little-endian ELF64 header with e_machine=x86_64; the
            # wrapper is inspected, not executed.
            binary = artifacts / "solc-0.8.35"
            binary.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 32)
            binary.chmod(0o755)
            home = root / "sandbox-home"
            home.mkdir()
            launcher = importlib.import_module("sandbox_exec")
            launcher.link_installed_compilers(root / "tool", home)
            target = home / ".svm" / "0.8.35" / "solc-0.8.35"
            self.assertTrue(target.is_file())
            self.assertFalse(target.is_symlink())
            wrapper = target.read_text()
            self.assertIn("qemu-x86_64", wrapper)
            self.assertIn(str(binary.resolve()), wrapper)


if __name__ == "__main__":
    unittest.main()
