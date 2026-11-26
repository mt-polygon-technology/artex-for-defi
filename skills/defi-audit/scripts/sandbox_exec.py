#!/usr/bin/env python3
"""Run a fixed DeFi analyzer with confined files and no IP sockets.

This is a defense for fixed analysis actions, not a container boundary. It fails
closed when Linux Landlock with network rules is unavailable.
The deployment must still isolate arbitrary worker Bash commands and provide
CPU/memory limits for untrusted projects.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import os
import platform
import re
import shutil
import socket
import sys
import uuid
from pathlib import Path


LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
PR_SET_NO_NEW_PRIVS = 38

FS_EXECUTE = 1 << 0
FS_WRITE_FILE = 1 << 1
FS_READ_FILE = 1 << 2
FS_READ_DIR = 1 << 3
FS_REMOVE_DIR = 1 << 4
FS_REMOVE_FILE = 1 << 5
FS_MAKE_CHAR = 1 << 6
FS_MAKE_DIR = 1 << 7
FS_MAKE_REG = 1 << 8
FS_MAKE_SOCK = 1 << 9
FS_MAKE_FIFO = 1 << 10
FS_MAKE_BLOCK = 1 << 11
FS_MAKE_SYM = 1 << 12
FS_REFER = 1 << 13
FS_TRUNCATE = 1 << 14
NET_BIND_TCP = 1 << 0
NET_CONNECT_TCP = 1 << 1

READ_DIR_RIGHTS = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR
WRITE_DIR_RIGHTS = (
    READ_DIR_RIGHTS | FS_WRITE_FILE | FS_REMOVE_DIR | FS_REMOVE_FILE |
    FS_MAKE_DIR | FS_MAKE_REG | FS_MAKE_SOCK | FS_MAKE_FIFO | FS_MAKE_SYM |
    FS_REFER | FS_TRUNCATE
)


class RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64),
                ("handled_access_net", ctypes.c_uint64)]


class PathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64),
                ("parent_fd", ctypes.c_int32),
                ("reserved", ctypes.c_uint32)]


class SeccompArgCompare(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint32), ("op", ctypes.c_int),
                ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]


def _check(result: int, label: str) -> int:
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, f"{label}: {os.strerror(error)}")
    return result


def block_ip_sockets() -> None:
    library = ctypes.util.find_library("seccomp")
    if not library:
        raise RuntimeError("libseccomp is required for DeFi analyzer network isolation")
    seccomp = ctypes.CDLL(library)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                               ctypes.c_int, ctypes.c_uint32,
                                               ctypes.POINTER(SeccompArgCompare)]
    seccomp.seccomp_rule_add_array.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    context = seccomp.seccomp_init(0x7FFF0000) # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError("could not initialize seccomp filter")
    try:
        syscall = seccomp.seccomp_syscall_resolve_name(b"socket")
        if syscall < 0:
            raise RuntimeError("socket syscall is unavailable")
        deny = 0x00050000 | 1 # SCMP_ACT_ERRNO(EPERM)
        for family in (socket.AF_INET, socket.AF_INET6,
                       getattr(socket, "AF_PACKET", 17), getattr(socket, "AF_NETLINK", 16)):
            comparison = SeccompArgCompare(0, 4, int(family), 0) # SCMP_CMP_EQ
            result = seccomp.seccomp_rule_add_array(context, deny, syscall, 1,
                                                    ctypes.byref(comparison))
            if result < 0:
                raise OSError(-result, "could not add seccomp socket rule")
        # A fixed repository analysis must not inspect or modify the
        # credentialed ARTEX process through cross-process memory syscalls.
        for name in (b"ptrace", b"process_vm_readv", b"process_vm_writev", b"pidfd_getfd"):
            syscall = seccomp.seccomp_syscall_resolve_name(name)
            if syscall < 0:
                continue  # syscall absent on this architecture/kernel
            result = seccomp.seccomp_rule_add_array(context, deny, syscall, 0, None)
            if result < 0:
                raise OSError(-result, "could not add seccomp process rule")
        result = seccomp.seccomp_load(context)
        if result < 0:
            raise OSError(-result, "could not enforce seccomp socket filter")
    finally:
        seccomp.seccomp_release(context)


def _add_path_rule(libc: ctypes.CDLL, ruleset_fd: int, path: Path,
                   directory_rights: int, file_rights: int) -> None:
    if not path.exists():
        return
    real = path.resolve(strict=True)
    is_dir = real.is_dir()
    flags = os.O_PATH | os.O_CLOEXEC
    fd = os.open(real, flags)
    try:
        rights = directory_rights if is_dir else file_rights
        attr = PathBeneathAttr(rights, fd, 0)
        _check(libc.syscall(445, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                            ctypes.byref(attr), 0), f"allow {real}")
    finally:
        os.close(fd)


def _is_x86_64_elf(path: Path) -> bool:
    """Return True for an x86_64 ELF executable without relying on `file`."""
    try:
        with path.open("rb") as stream:
            header = stream.read(20)
    except OSError:
        return False
    return (len(header) == 20 and header[:4] == b"\x7fELF"
            and header[4] == 2 and header[5] == 1
            and int.from_bytes(header[18:20], "little") == 62)


def link_installed_compilers(tool_home: Path, sandbox_home: Path) -> None:
    """Expose only already-installed solc binaries to Foundry's offline SVM.

    On arm64 the Solidity project publishes only x86_64 Linux binaries. Foundry
    invokes ``~/.svm/<version>/solc-<version>`` directly, which would otherwise
    go through the host's binfmt/Rosetta handler. That handler needs
    ``/proc/self/exe``, which Landlock intentionally does not grant. Install a
    tiny native wrapper that execs qemu-x86_64 instead, so the compiler works
    inside the confined process tree.
    """
    svm = sandbox_home / ".svm"
    sources = []
    for directory in (tool_home / ".svm", tool_home / ".solc-select" / "artifacts"):
        if directory.is_dir():
            sources.extend(directory.iterdir())
    qemu = shutil.which("qemu-x86_64")
    for directory in sources:
        if not directory.is_dir():
            continue
        version = directory.name.removeprefix("solc-")
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
            continue
        binary = directory / f"solc-{version}"
        if not binary.is_file() or not os.access(binary, os.X_OK):
            continue
        target = svm / version / f"solc-{version}"
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            continue
        resolved = binary.resolve(strict=True)
        if qemu and _is_x86_64_elf(resolved):
            target.write_text("#!/bin/sh\nexec " + qemu + " " + str(resolved) + " \"$@\"\n", encoding="utf-8")
            target.chmod(0o755)
        else:
            target.symlink_to(resolved)


def restrict(project: Path, output: Path, script: Path, tool_home: Path) -> None:
    if sys.platform != "linux" or platform.machine() not in {"x86_64", "aarch64"}:
        raise RuntimeError("DeFi analyzer requires a Linux Landlock sandbox")
    libc = ctypes.CDLL(None, use_errno=True)
    abi = _check(libc.syscall(444, None, 0, LANDLOCK_CREATE_RULESET_VERSION),
                 "query Landlock ABI")
    if abi < 4:
        raise RuntimeError("DeFi analyzer requires Landlock ABI 4 or newer")

    # Handle device-node creation everywhere without granting it in any rule.
    handled_fs = WRITE_DIR_RIGHTS | FS_MAKE_CHAR | FS_MAKE_BLOCK
    attr = RulesetAttr(handled_fs, NET_BIND_TCP | NET_CONNECT_TCP)
    ruleset_fd = _check(libc.syscall(444, ctypes.byref(attr), ctypes.sizeof(attr), 0),
                        "create Landlock ruleset")
    try:
        # These paths contain executable/runtime code only. In the Docker image,
        # Foundry and solc-select are installed under root's toolchain folders.
        runtime = [Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64"),
                   Path("/sbin"), Path(sys.prefix), Path(sys.base_prefix),
                   Path(sys.executable).parent, script.parent.parent]
        for path in runtime:
            _add_path_rule(libc, ruleset_fd, path, READ_DIR_RIGHTS,
                           FS_EXECUTE | FS_READ_FILE)
        for path in (tool_home / ".foundry", tool_home / ".solc-select",
                     tool_home / ".svm"):
            _add_path_rule(libc, ruleset_fd, path, READ_DIR_RIGHTS,
                           FS_EXECUTE | FS_READ_FILE)
        for path in (Path("/etc/ld.so.cache"), Path("/etc/passwd"),
                     Path("/etc/group"), Path("/etc/localtime")):
            _add_path_rule(libc, ruleset_fd, path, READ_DIR_RIGHTS, FS_READ_FILE)
        for path in (Path("/dev/null"), Path("/dev/zero"), Path("/dev/urandom")):
            _add_path_rule(libc, ruleset_fd, path, READ_DIR_RIGHTS,
                           FS_READ_FILE | FS_WRITE_FILE)
        for path in (project, output):
            _add_path_rule(libc, ruleset_fd, path, WRITE_DIR_RIGHTS,
                           FS_EXECUTE | FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE)
        _check(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
               "set no_new_privs")
        block_ip_sockets()
        _check(libc.syscall(446, ruleset_fd, 0), "enforce Landlock ruleset")
    finally:
        os.close(ruleset_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--trusted-scripts", type=Path,
                        help="trusted adapter script directory when launched from an in-memory copy")
    parser.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        project = args.project.resolve(strict=True)
        output = args.output_dir.resolve(strict=True)
        script = args.script.resolve(strict=True)
        trusted_scripts = (args.trusted_scripts.resolve(strict=True) if args.trusted_scripts
                           else Path(__file__).resolve().parent)
        if not project.is_dir() or not output.is_dir() or not script.is_file():
            raise ValueError("project, output, and script must exist")
        if (script.parent != trusted_scripts or
                script.parent.name != "scripts" or script.parent.parent.name != "defi-audit"):
            raise ValueError("script is outside the trusted DeFi adapter")
        os.umask(0o077)
        sandbox_state = output / ".sandbox" / uuid.uuid4().hex
        home = sandbox_state / "home"
        temp = sandbox_state / "tmp"
        home.mkdir(parents=True, mode=0o700)
        temp.mkdir(mode=0o700)
        tool_home = Path(os.environ.get("HOME", "/root")).resolve()
        link_installed_compilers(tool_home, home)
        allowed_env = {"PATH", "USER", "LANG", "LC_ALL", "FOUNDRY_PROFILE",
                       "FOUNDRY_SOLC", "SOLC_VERSION", "SOLC_BIN"}
        env = {key: value for key, value in os.environ.items() if key in allowed_env}
        env.update({"HOME": str(home), "TMPDIR": str(temp),
                    "XDG_CACHE_HOME": str(home / ".cache"),
                    "XDG_CONFIG_HOME": str(home / ".config"),
                    "ARTEX_SANDBOX_OUTPUT": str(output),
                    "FOUNDRY_OFFLINE": "true", "NO_COLOR": "1",
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"})
        os.environ.clear()
        os.environ.update(env)
        os.chdir(project)
        restrict(project, output, script, tool_home)
        script_args = args.args[1:] if args.args[:1] == ["--"] else args.args
        os.execv(sys.executable, [sys.executable, str(script), *script_args])
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"DeFi analyzer sandbox unavailable: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
