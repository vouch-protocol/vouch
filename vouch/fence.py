"""Fenced launcher: run an agent where it can only reach the files it was given.

The Identity Sidecar pattern keeps private keys out of the model's context: the
agent asks a separate process to sign. That separation is a promise the
operating system has to keep, because the agent runs code as the same user.

``run_fenced`` keeps it on Linux by starting the agent inside a Landlock
ruleset. Landlock is a kernel security module that a process applies to itself,
with no administrator rights. Once applied, the kernel refuses every file access
outside the listed paths, for the agent and for every process it starts, for as
long as they live.

    from vouch.fence import FencePolicy, run_fenced

    exit_code = run_fenced(
        ["python", "agent.py"],
        FencePolicy(workspace="./project", read_only=("/data/catalog",)),
    )

What the agent gets:

  - the workspace: read, write, create, delete, rename, execute
  - system runtime folders (``/usr``, ``/lib`` and friends): read and execute
  - a private temporary folder, removed when the agent exits
  - any extra path the caller lists, with the access the caller chose

The Vouch Protocol key store is always outside the fence. A policy that would
expose it is refused before anything runs. Secret-bearing ``VOUCH_*``
environment variables are removed from the agent's environment, and file
descriptors the launcher inherited are closed before the agent starts.

Scope: file access. The launcher refuses to start the agent when the kernel
cannot enforce the fence, unless the caller passes ``allow_unfenced=True``.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import platform
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, NoReturn, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)

__all__ = [
    "EXIT_CANNOT_START",
    "EXIT_LAUNCHER_ERROR",
    "EXIT_NOT_FOUND",
    "FenceCommandNotFoundError",
    "FenceError",
    "FencePlan",
    "FencePolicy",
    "FenceStartError",
    "FenceUnavailableError",
    "Grant",
    "MAX_LANDLOCK_ABI",
    "landlock_abi",
    "plan_fence",
    "run_fenced",
]

# Exit codes for launcher failures, following env(1) and timeout(1).
EXIT_LAUNCHER_ERROR = 125
EXIT_CANNOT_START = 126
EXIT_NOT_FOUND = 127

# Landlock file-system access rights (include/uapi/linux/landlock.h).
_FS_EXECUTE = 1 << 0
_FS_WRITE_FILE = 1 << 1
_FS_READ_FILE = 1 << 2
_FS_READ_DIR = 1 << 3
_FS_REMOVE_DIR = 1 << 4
_FS_REMOVE_FILE = 1 << 5
_FS_MAKE_CHAR = 1 << 6
_FS_MAKE_DIR = 1 << 7
_FS_MAKE_REG = 1 << 8
_FS_MAKE_SOCK = 1 << 9
_FS_MAKE_FIFO = 1 << 10
_FS_MAKE_BLOCK = 1 << 11
_FS_MAKE_SYM = 1 << 12
_FS_REFER = 1 << 13  # Landlock ABI 2
_FS_TRUNCATE = 1 << 14  # Landlock ABI 3

# The newest Landlock ABI whose file-system rights this module applies. A newer
# kernel is fenced with exactly this set.
MAX_LANDLOCK_ABI = 3

_ABI1_RIGHTS = (1 << 13) - 1

_READ = _FS_READ_FILE | _FS_READ_DIR
_READ_EXECUTE = _READ | _FS_EXECUTE
_READ_WRITE = (
    _READ
    | _FS_WRITE_FILE
    | _FS_REMOVE_DIR
    | _FS_REMOVE_FILE
    | _FS_MAKE_DIR
    | _FS_MAKE_REG
    | _FS_MAKE_SOCK
    | _FS_MAKE_FIFO
    | _FS_MAKE_SYM
    | _FS_REFER
    | _FS_TRUNCATE
)
# Rights the kernel accepts on a rule for a single file (anything else is EINVAL).
_FILE_RIGHTS = _FS_EXECUTE | _FS_WRITE_FILE | _FS_READ_FILE | _FS_TRUNCATE

KIND_WORKSPACE = "workspace"
KIND_READ_WRITE = "read-write"
KIND_READ_EXECUTE = "read-execute"
KIND_READ_ONLY = "read-only"
KIND_TEMP = "temp"
KIND_DEVICE = "device"

_KIND_ACCESS: Dict[str, int] = {
    KIND_WORKSPACE: _READ_WRITE | _FS_EXECUTE,
    KIND_READ_WRITE: _READ_WRITE,
    KIND_READ_EXECUTE: _READ_EXECUTE,
    KIND_READ_ONLY: _READ,
    KIND_TEMP: _READ_WRITE,
    KIND_DEVICE: _FS_READ_FILE | _FS_WRITE_FILE,
}
_WRITABLE_KINDS = frozenset({KIND_WORKSPACE, KIND_READ_WRITE, KIND_TEMP, KIND_DEVICE})

# What an ordinary dynamically linked program needs in order to start.
_SYSTEM_READ_EXECUTE = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")
_SYSTEM_READ_ONLY = (
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/alternatives",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/pki",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
)
_SYSTEM_DEVICES = ("/dev/null", "/dev/tty")

# Environment variables named VOUCH_* that carry one of these words hold key
# material or a shared secret, and never reach the fenced process.
_SECRET_MARKERS = ("PRIVATE", "SEED", "SECRET", "TOKEN", "PASSWORD", "PASSPHRASE")

# Landlock system calls share one number on every architecture that uses the
# generic system call table. Other machines are treated as "cannot enforce".
_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446
_GENERIC_SYSCALL_MACHINES = frozenset(
    {
        "x86_64",
        "amd64",
        "i386",
        "i486",
        "i586",
        "i686",
        "aarch64",
        "arm64",
        "armv6l",
        "armv7l",
        "armv8l",
        "riscv32",
        "riscv64",
        "ppc",
        "ppc64",
        "ppc64le",
        "s390x",
        "loongarch64",
    }
)
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_PDEATHSIG = 1

_libc_handle: Optional[ctypes.CDLL] = None


class FenceError(Exception):
    """The fence could not be built, or the policy was refused."""


class FenceUnavailableError(FenceError):
    """This machine cannot enforce the fence."""


class FenceCommandNotFoundError(FenceError):
    """The command to run does not exist."""


class FenceStartError(FenceError):
    """The fenced process could not start the command."""


@dataclass(frozen=True)
class FencePolicy:
    """What a fenced process may reach.

    Attributes:
        workspace: Folder the agent works in. Full access, and the agent's
            starting directory.
        read_only: Extra paths the agent may read.
        read_execute: Extra paths the agent may read and execute, for example
            an interpreter installed outside the system folders.
        read_write: Extra paths the agent may read and change.
        protect: Extra paths that must stay outside the fence. The Vouch
            Protocol key store is always protected.
        drop_env: Extra environment variable names to remove from the agent's
            environment.
        system_paths: Grant read and execute on the system runtime folders.
    """

    workspace: str = "."
    read_only: Tuple[str, ...] = ()
    read_execute: Tuple[str, ...] = ()
    read_write: Tuple[str, ...] = ()
    protect: Tuple[str, ...] = ()
    drop_env: Tuple[str, ...] = ()
    system_paths: bool = True


@dataclass(frozen=True)
class Grant:
    """One path inside the fence.

    Attributes:
        path: The real path, with symbolic links resolved.
        kind: One of the ``KIND_*`` names.
        is_dir: Whether the path is a directory.
        access: The Landlock access mask applied to it (0 when not fenced).
    """

    path: str
    kind: str
    is_dir: bool
    access: int


@dataclass(frozen=True)
class FencePlan:
    """The fence that a run applies, resolved against this machine."""

    fenced: bool
    landlock_abi_kernel: int
    landlock_abi_used: int
    workspace: str
    grants: Tuple[Grant, ...]
    protected: Tuple[str, ...]
    executable: str
    executable_sha256: str
    argument_count: int
    dropped_env: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        """Return the plan as a JSON-ready report."""
        return {
            "type": "FenceReport",
            "version": 1,
            "fenced": self.fenced,
            "mechanism": "landlock" if self.fenced else "none",
            "covers": ["filesystem"] if self.fenced else [],
            "landlockAbi": {"kernel": self.landlock_abi_kernel, "used": self.landlock_abi_used},
            "noNewPrivileges": self.fenced,
            "workspace": self.workspace,
            "paths": [
                {"path": grant.path, "access": grant.kind, "directory": grant.is_dir}
                for grant in self.grants
            ],
            "protected": list(self.protected),
            "droppedEnvironment": list(self.dropped_env),
            "executable": {"path": self.executable, "sha256": self.executable_sha256},
            "argumentCount": self.argument_count,
            "host": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
            },
        }


@dataclass
class _Prepared:
    """A grant plus the open handle the kernel rule is bound to."""

    grant: Grant
    fd: Optional[int]


# --------------------------------------------------------------------------
# Kernel interface
# --------------------------------------------------------------------------


def _libc() -> ctypes.CDLL:
    global _libc_handle
    if _libc_handle is None:
        handle = ctypes.CDLL(None, use_errno=True)
        handle.syscall.restype = ctypes.c_long
        _libc_handle = handle
    return _libc_handle


def _syscall(number: int, *args: Any) -> int:
    """Make a raw system call and raise ``OSError`` on failure."""
    libc = _libc()
    ctypes.set_errno(0)
    result = libc.syscall(ctypes.c_long(number), *args)
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return int(result)


def _platform_can_fence() -> bool:
    return sys.platform.startswith("linux") and platform.machine() in _GENERIC_SYSCALL_MACHINES


def landlock_abi() -> int:
    """Return the kernel's Landlock ABI version, or 0 when it cannot be used.

    Every failure to ask the kernel counts as "cannot be used", which makes
    ``run_fenced`` refuse to start the agent by default.
    """
    if not _platform_can_fence():
        return 0
    try:
        return _syscall(
            _SYS_LANDLOCK_CREATE_RULESET,
            ctypes.c_void_p(None),
            ctypes.c_size_t(0),
            ctypes.c_uint(_LANDLOCK_CREATE_RULESET_VERSION),
        )
    except OSError:
        return 0


def _handled_access(abi: int) -> int:
    """Return every file-system right the fence governs at this ABI."""
    if abi <= 0:
        return 0
    handled = _ABI1_RIGHTS
    if abi >= 2:
        handled |= _FS_REFER
    if abi >= 3:
        handled |= _FS_TRUNCATE
    return handled


def _grant_access(kind: str, is_dir: bool, abi: int) -> int:
    """Return the access mask for one grant, limited to what the kernel accepts."""
    access = _KIND_ACCESS[kind] & _handled_access(abi)
    if not is_dir:
        access &= _FILE_RIGHTS
    return access


def _build_ruleset(prepared: Sequence[_Prepared], abi: int) -> int:
    """Create a Landlock ruleset holding every grant and return its handle."""
    attr = struct.pack("=Q", _handled_access(abi))
    attr_buf = ctypes.create_string_buffer(attr, len(attr))
    try:
        ruleset_fd = _syscall(
            _SYS_LANDLOCK_CREATE_RULESET,
            ctypes.cast(attr_buf, ctypes.c_void_p),
            ctypes.c_size_t(len(attr)),
            ctypes.c_uint(0),
        )
    except OSError as exc:
        raise FenceError("the kernel refused to create the fence: %s" % exc.strerror)
    try:
        for item in prepared:
            if item.fd is None or item.grant.access == 0:
                continue
            rule = struct.pack("=Qi", item.grant.access, item.fd)
            rule_buf = ctypes.create_string_buffer(rule, len(rule))
            try:
                _syscall(
                    _SYS_LANDLOCK_ADD_RULE,
                    ctypes.c_int(ruleset_fd),
                    ctypes.c_uint(_LANDLOCK_RULE_PATH_BENEATH),
                    ctypes.cast(rule_buf, ctypes.c_void_p),
                    ctypes.c_uint(0),
                )
            except OSError as exc:
                raise FenceError(
                    "the kernel refused the rule for %r: %s" % (item.grant.path, exc.strerror)
                )
    except BaseException:
        os.close(ruleset_fd)
        raise
    return ruleset_fd


def _restrict_self(ruleset_fd: int) -> None:
    """Apply the ruleset to the calling process. There is no way back."""
    libc = _libc()
    ctypes.set_errno(0)
    result = libc.prctl(
        ctypes.c_int(_PR_SET_NO_NEW_PRIVS),
        ctypes.c_ulong(1),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    )
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    _syscall(_SYS_LANDLOCK_RESTRICT_SELF, ctypes.c_int(ruleset_fd), ctypes.c_uint(0))


# --------------------------------------------------------------------------
# Policy resolution
# --------------------------------------------------------------------------


def _is_within(child: str, parent: str) -> bool:
    """True when ``child`` is ``parent`` or sits beneath it."""
    if child == parent:
        return True
    prefix = parent if parent.endswith(os.sep) else parent + os.sep
    return child.startswith(prefix)


def _overlaps(first: str, second: str) -> bool:
    return _is_within(first, second) or _is_within(second, first)


def _protected_paths(policy: FencePolicy) -> Tuple[str, ...]:
    """Return the real paths that must stay outside the fence."""
    home = os.path.expanduser("~")
    candidates = [
        # Keep in step with vouch.keys.VOUCH_DIR and vouch.cli.PRIVATE_KEY_PATH.
        os.path.join(home, ".vouch"),
        os.path.join(home, ".ssh", "vouch_signing"),
    ]
    candidates.extend(policy.protect)
    resolved: List[str] = []
    for candidate in candidates:
        real = os.path.realpath(os.path.abspath(os.path.expanduser(candidate)))
        if real not in resolved:
            resolved.append(real)
    return tuple(resolved)


def _fd_real_path(fd: int, fallback: str) -> str:
    """Return the real path of an open handle, as the kernel sees it."""
    try:
        return os.readlink("/proc/self/fd/%d" % fd)
    except OSError:
        return os.path.realpath(fallback)


def _open_grant(path: str, kind: str, required: bool, abi: int) -> Optional[_Prepared]:
    """Resolve one requested path into a grant bound to an open handle.

    The handle is what the kernel rule attaches to, and the protected-path
    check runs on that same handle's real path, so the path checked and the
    path granted are the same object.
    """
    fd: Optional[int] = None
    try:
        expanded = os.path.abspath(os.path.expanduser(path))
        o_path = getattr(os, "O_PATH", None)
        if o_path is not None:
            fd = os.open(expanded, o_path | os.O_CLOEXEC)
            mode = os.fstat(fd).st_mode
            real = _fd_real_path(fd, expanded)
        else:
            mode = os.stat(expanded).st_mode
            real = os.path.realpath(expanded)
    except (OSError, ValueError) as exc:
        if fd is not None:
            os.close(fd)
        if not required:
            return None
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
        raise FenceError("cannot use path %r: %s" % (path, reason))
    is_dir = stat.S_ISDIR(mode)
    grant = Grant(path=real, kind=kind, is_dir=is_dir, access=_grant_access(kind, is_dir, abi))
    return _Prepared(grant=grant, fd=fd)


def _close_prepared(prepared: Sequence[_Prepared]) -> None:
    for item in prepared:
        if item.fd is not None:
            os.close(item.fd)
            item.fd = None


def _prepare(policy: FencePolicy, abi: int, temp_dir: Optional[str]) -> List[_Prepared]:
    """Resolve the policy into grants, refusing any that expose a protected path."""
    requests: List[Tuple[str, str, bool]] = [(policy.workspace, KIND_WORKSPACE, True)]
    if temp_dir is not None:
        requests.append((temp_dir, KIND_TEMP, True))
    requests.extend((path, KIND_READ_WRITE, True) for path in policy.read_write)
    requests.extend((path, KIND_READ_EXECUTE, True) for path in policy.read_execute)
    requests.extend((path, KIND_READ_ONLY, True) for path in policy.read_only)
    if policy.system_paths:
        requests.extend((path, KIND_READ_EXECUTE, False) for path in _SYSTEM_READ_EXECUTE)
        requests.extend((path, KIND_READ_ONLY, False) for path in _SYSTEM_READ_ONLY)
        requests.extend((path, KIND_DEVICE, False) for path in _SYSTEM_DEVICES)

    protected = _protected_paths(policy)
    prepared: List[_Prepared] = []
    try:
        for path, kind, required in requests:
            item = _open_grant(path, kind, required, abi)
            if item is None:
                continue
            prepared.append(item)
            for secret in protected:
                if _overlaps(item.grant.path, secret):
                    raise FenceError(
                        "path %r would put %s inside the fence; choose a narrower path"
                        % (path, secret)
                    )
            if kind == KIND_WORKSPACE and not item.grant.is_dir:
                raise FenceError("workspace %r is not a directory" % path)
    except BaseException:
        _close_prepared(prepared)
        raise
    return prepared


def _is_vouch_secret(name: str) -> bool:
    upper = name.upper()
    return upper.startswith("VOUCH_") and any(marker in upper for marker in _SECRET_MARKERS)


def _child_environment(
    environ: Mapping[str, str], drop: Sequence[str], temp_dir: Optional[str]
) -> Tuple[Dict[str, str], Tuple[str, ...]]:
    """Return the agent's environment and the names that were removed from it."""
    extra = set(drop)
    dropped = sorted(name for name in environ if name in extra or _is_vouch_secret(name))
    child_env = {name: value for name, value in environ.items() if name not in dropped}
    if temp_dir is not None:
        for name in ("TMPDIR", "TMP", "TEMP"):
            child_env[name] = temp_dir
    return child_env, tuple(dropped)


def _resolve_executable(name: str, launch_cwd: str, search_path: Optional[str]) -> str:
    """Find the program to run, the way a shell would."""
    if not name:
        raise FenceCommandNotFoundError("no command given")
    if os.sep in name:
        candidate = os.path.normpath(os.path.join(launch_cwd, os.path.expanduser(name)))
        if not os.path.isfile(candidate):
            raise FenceCommandNotFoundError("command not found: %s" % name)
        return candidate
    found = shutil.which(name, path=search_path)
    if found is None:
        raise FenceCommandNotFoundError("command not found: %s" % name)
    return os.path.abspath(found)


def _require_executable_inside(executable: str, prepared: Sequence[_Prepared]) -> None:
    """Refuse early, with advice, when the program itself is outside the fence."""
    real = os.path.realpath(executable)
    for item in prepared:
        grant = item.grant
        if not grant.access & _FS_EXECUTE:
            continue
        if _is_within(real, grant.path) if grant.is_dir else real == grant.path:
            return
    folder = os.path.dirname(real)
    if os.path.basename(folder) in ("bin", "sbin"):
        folder = os.path.dirname(folder)
    raise FenceError(
        "%s is outside the fence, so it cannot run; allow its folder with "
        "read and execute access (--rx %s)" % (real, folder)
    )


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _checked_report_path(
    report_path: Optional[str], prepared: Sequence[_Prepared]
) -> Optional[str]:
    """Return where to write the report, refusing a place the agent can change."""
    if report_path is None:
        return None
    target = os.path.abspath(os.path.expanduser(report_path))
    real = os.path.join(os.path.realpath(os.path.dirname(target)), os.path.basename(target))
    for item in prepared:
        grant = item.grant
        if grant.kind not in _WRITABLE_KINDS:
            continue
        if _is_within(real, grant.path) if grant.is_dir else real == grant.path:
            raise FenceError(
                "the report %r sits where the fenced process can write; "
                "choose a path outside the fence" % report_path
            )
    return real


def _write_report(path: str, report: Mapping[str, Any]) -> None:
    scratch = "%s.%d.tmp" % (path, os.getpid())
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(scratch, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(scratch, path)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_plan(
    prepared: Sequence[_Prepared],
    policy: FencePolicy,
    argv: Sequence[str],
    environ: Mapping[str, str],
    abi_kernel: int,
    abi_used: int,
    launch_cwd: str,
    temp_dir: Optional[str],
) -> Tuple[FencePlan, Dict[str, str]]:
    executable = _resolve_executable(argv[0], launch_cwd, environ.get("PATH"))
    if abi_used:
        _require_executable_inside(executable, prepared)
    child_env, dropped = _child_environment(environ, policy.drop_env, temp_dir)
    plan = FencePlan(
        fenced=abi_used > 0,
        landlock_abi_kernel=abi_kernel,
        landlock_abi_used=abi_used,
        workspace=prepared[0].grant.path,
        grants=tuple(item.grant for item in prepared),
        protected=_protected_paths(policy),
        executable=executable,
        executable_sha256=_sha256_file(executable),
        argument_count=len(argv) - 1,
        dropped_env=dropped,
    )
    return plan, child_env


# --------------------------------------------------------------------------
# Launching
# --------------------------------------------------------------------------


def _close_other_fds(keep: Set[int]) -> None:
    """Close every descriptor except ``keep`` (runs in the child, before the fence)."""
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        names = []
    if names:
        for name in names:
            fd = int(name)
            if fd in keep:
                continue
            try:
                os.close(fd)
            except OSError:
                # The handle used to list the directory is already gone.
                continue
        return
    try:
        limit = min(int(os.sysconf("SC_OPEN_MAX")), 65536)
    except (OSError, ValueError):
        limit = 4096
    start = 0
    for kept in sorted(keep):
        if kept > start:
            os.closerange(start, kept)
        start = kept + 1
    os.closerange(start, limit)


def _child(
    error_read: int,
    error_fd: int,
    ruleset_fd: Optional[int],
    signal_mask: Optional[Set[Any]],
    parent_pid: int,
    workspace: str,
    executable: str,
    argv: Sequence[str],
    env: Mapping[str, str],
) -> NoReturn:
    """Become the agent: fence this process, then replace it with the command."""
    try:
        os.close(error_read)
        if signal_mask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, signal_mask)
        # A session of its own: the agent has no controlling terminal, so it
        # cannot push keystrokes into the terminal the launcher was started from.
        os.setsid()
        if sys.platform.startswith("linux"):
            _end_with_parent(parent_pid)
        keep = {0, 1, 2, error_fd}
        if ruleset_fd is not None:
            keep.add(ruleset_fd)
        _close_other_fds(keep)
        os.chdir(workspace)
        if ruleset_fd is not None:
            _restrict_self(ruleset_fd)
            os.close(ruleset_fd)
        os.execve(executable, list(argv), dict(env))
    except BaseException as exc:  # nothing may escape the child
        message = "%s: %s" % (type(exc).__name__, exc)
        os.write(error_fd, message.encode("utf-8", "replace")[:4096])
    finally:
        # Reached only when the command did not start. Leave at once, without
        # running the launcher's own cleanup a second time.
        os._exit(EXIT_CANNOT_START)


def _end_with_parent(parent_pid: int) -> None:
    """Ask the kernel to end this process if the launcher goes away."""
    libc = _libc()
    ctypes.set_errno(0)
    result = libc.prctl(
        ctypes.c_int(_PR_SET_PDEATHSIG),
        ctypes.c_ulong(int(signal.SIGKILL)),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    )
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    if os.getppid() != parent_pid:
        raise ProcessLookupError("the launcher exited before the command started")


def _forwarded_signals() -> Set[Any]:
    """Signals the launcher passes on to the agent."""
    names = ("SIGINT", "SIGQUIT", "SIGTERM", "SIGHUP", "SIGWINCH")
    return {getattr(signal, name) for name in names if hasattr(signal, name)}


def _supervise_signals(pid: int) -> Callable[[], None]:
    """Pass stop requests on to the agent while the launcher waits for it.

    The agent runs in its own session, so a terminal's interrupt reaches only
    the launcher, which hands it on.
    """

    def forward(signum: int, _frame: Any) -> None:
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            return

    previous: Dict[Any, Any] = {}
    for signum in _forwarded_signals():
        previous[signum] = signal.signal(signum, forward)

    def restore() -> None:
        for signum, handler in previous.items():
            signal.signal(signum, signal.SIG_DFL if handler is None else handler)

    return restore


def _spawn_and_wait(
    ruleset_fd: Optional[int],
    workspace: str,
    executable: str,
    argv: Sequence[str],
    env: Mapping[str, str],
) -> int:
    """Start the agent in a child process and return its exit code."""
    if not hasattr(os, "fork"):
        return subprocess.call(list(argv), executable=executable, cwd=workspace, env=dict(env))

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):
            continue
    # Signal handlers can only be installed from the main thread. There, stop
    # requests are held back across the fork so none is lost before the
    # launcher is ready to pass it on.
    supervising = threading.current_thread() is threading.main_thread()
    signal_mask: Optional[Set[Any]] = None
    if supervising:
        signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, _forwarded_signals())
    parent_pid = os.getpid()
    error_read, error_write = os.pipe()
    restore: Callable[[], None] = lambda: None  # noqa: E731
    try:
        try:
            pid = os.fork()
        except OSError as exc:
            os.close(error_read)
            os.close(error_write)
            raise FenceStartError("could not start a process: %s" % exc.strerror)
        if pid == 0:
            _child(
                error_read,
                error_write,
                ruleset_fd,
                signal_mask,
                parent_pid,
                workspace,
                executable,
                argv,
                env,
            )
        os.close(error_write)
        if supervising:
            restore = _supervise_signals(pid)
    finally:
        if signal_mask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, signal_mask)
    try:
        with os.fdopen(error_read, "rb") as pipe:
            failure = pipe.read()
        _, status = os.waitpid(pid, 0)
    finally:
        restore()
    if failure:
        raise FenceStartError(failure.decode("utf-8", "replace"))
    code = os.waitstatus_to_exitcode(status)
    return 128 - code if code < 0 else code


def plan_fence(
    command: Sequence[str],
    policy: Optional[FencePolicy] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
) -> FencePlan:
    """Resolve the fence a run would apply, without running anything.

    Args:
        command: The program and its arguments.
        policy: What the agent may reach. Defaults to the current folder.
        env: Environment to plan against. Defaults to this process's.

    Returns:
        The resolved plan. ``plan.fenced`` is False when this machine cannot
        enforce the fence.

    Raises:
        FenceError: The policy was refused or a path cannot be used.
        FenceCommandNotFoundError: The command does not exist.
    """
    policy = policy if policy is not None else FencePolicy()
    argv = [str(part) for part in command]
    if not argv:
        raise FenceCommandNotFoundError("no command given")
    environ = dict(os.environ if env is None else env)
    abi_kernel = landlock_abi()
    abi_used = min(abi_kernel, MAX_LANDLOCK_ABI)
    prepared = _prepare(policy, abi_used, None)
    try:
        plan, _ = _make_plan(
            prepared, policy, argv, environ, abi_kernel, abi_used, os.getcwd(), None
        )
    finally:
        _close_prepared(prepared)
    return plan


def run_fenced(
    command: Sequence[str],
    policy: Optional[FencePolicy] = None,
    *,
    allow_unfenced: bool = False,
    report_path: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> int:
    """Run a command inside the fence and return its exit code.

    The calling process stays outside the fence and waits. The command runs in
    a child process that fences itself and then becomes the command, so the
    fence is in place before the command's first instruction.

    Args:
        command: The program and its arguments. The program is looked up on
            ``PATH`` the way a shell would.
        policy: What the agent may reach. Defaults to the current folder.
        allow_unfenced: Run the command even when this machine cannot enforce
            the fence. The report then says ``"fenced": false``.
        report_path: Where to write a JSON record of the fence that was
            applied. Must be outside every path the agent can write.
        env: Environment for the agent. Defaults to this process's.

    Returns:
        The command's exit code, or 128 plus the signal number when a signal
        ended it.

    Raises:
        FenceUnavailableError: The fence cannot be enforced here and
            ``allow_unfenced`` is False.
        FenceError: The policy was refused or a path cannot be used.
        FenceCommandNotFoundError: The command does not exist.
        FenceStartError: The fenced process could not start the command.
    """
    policy = policy if policy is not None else FencePolicy()
    argv = [str(part) for part in command]
    if not argv:
        raise FenceCommandNotFoundError("no command given")
    environ = dict(os.environ if env is None else env)

    abi_kernel = landlock_abi()
    abi_used = min(abi_kernel, MAX_LANDLOCK_ABI)
    if abi_used == 0:
        if not allow_unfenced:
            raise FenceUnavailableError(
                "this machine cannot enforce the fence (it needs Linux 5.13 or newer "
                "with Landlock enabled)"
            )
        logger.warning("running without a fence: this machine cannot enforce one")

    launch_cwd = os.getcwd()
    temp_dir = tempfile.mkdtemp(prefix="vouch-run-")
    ruleset_fd: Optional[int] = None
    try:
        prepared = _prepare(policy, abi_used, temp_dir)
        try:
            plan, child_env = _make_plan(
                prepared, policy, argv, environ, abi_kernel, abi_used, launch_cwd, temp_dir
            )
            report_file = _checked_report_path(report_path, prepared)
            if abi_used:
                ruleset_fd = _build_ruleset(prepared, abi_used)
        finally:
            _close_prepared(prepared)

        report = plan.to_dict()
        report["startedAt"] = _now()
        if report_file is not None:
            _write_report(report_file, report)

        exit_code = _spawn_and_wait(ruleset_fd, plan.workspace, plan.executable, argv, child_env)

        if report_file is not None:
            report["endedAt"] = _now()
            report["exitCode"] = exit_code
            _write_report(report_file, report)
        return exit_code
    finally:
        if ruleset_fd is not None:
            os.close(ruleset_fd)
        shutil.rmtree(temp_dir, ignore_errors=True)
