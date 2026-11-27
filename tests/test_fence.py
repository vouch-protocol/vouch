"""Tests for the fenced launcher (``vouch run``).

The adversary is the agent itself: code running as the same user inside the
fence, trying to reach files, keys, and secrets it was never given. Tests that
need the kernel to enforce the fence are skipped where it cannot.
"""

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from vouch import cli, fence

requires_fence = pytest.mark.skipif(
    fence.landlock_abi() == 0, reason="needs Linux with Landlock enabled"
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Where this Python lives, so the fenced interpreter can start.
PYTHON_PATHS = tuple(
    sorted(
        {
            os.path.realpath(sys.prefix),
            os.path.realpath(sys.base_prefix),
            os.path.dirname(os.path.dirname(os.path.realpath(sys.executable))),
        }
    )
)

AGENT_HEADER = """
import json, os, sys

results = {}


def probe(name, fn):
    try:
        results[name] = ["ok", fn()]
    except BaseException as exc:
        results[name] = ["error", type(exc).__name__, getattr(exc, "errno", None)]


def read(path):
    with open(path) as handle:
        return handle.read()


def write(path, text="x"):
    with open(path, "w") as handle:
        handle.write(text)
    return "written"
"""

AGENT_FOOTER = """
with open("result.json", "w") as handle:
    json.dump(results, handle, default=str)
"""


@pytest.fixture
def layout(tmp_path, monkeypatch):
    """A fake home with a key store, a workspace, and a folder outside both."""
    root = tmp_path.resolve()
    real_home = os.environ.get("HOME", "")
    home = root / "home"
    (home / ".vouch" / "keys").mkdir(parents=True)
    (home / ".vouch" / "keys" / "agent.key").write_text("PRIVATE-KEY-MATERIAL")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "vouch_signing").write_text("SSH-SIGNING-KEY")
    workspace = root / "workspace"
    workspace.mkdir()
    (workspace / "notes.txt").write_text("inside")
    outside = root / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("OUTSIDE-SECRET")
    monkeypatch.setenv("HOME", str(home))
    return SimpleNamespace(
        root=root, home=home, workspace=workspace, outside=outside, real_home=real_home
    )


def run_agent(layout, body, *, env=None, argv=(), **policy_fields):
    """Run ``body`` as a fenced agent and return (exit code, probe results)."""
    script = layout.workspace / "agent.py"
    script.write_text(AGENT_HEADER + body + AGENT_FOOTER)
    policy_fields.setdefault("workspace", str(layout.workspace))
    policy_fields["read_execute"] = tuple(policy_fields.get("read_execute", ())) + PYTHON_PATHS
    policy = fence.FencePolicy(**policy_fields)
    code = fence.run_fenced([sys.executable, "agent.py", *argv], policy, env=env)
    result_file = layout.workspace / "result.json"
    results = json.loads(result_file.read_text()) if result_file.exists() else {}
    return code, results


def denied(results, name):
    outcome = results[name]
    return outcome[0] == "error" and outcome[1] == "PermissionError"


# --------------------------------------------------------------------------
# Rule building (no kernel needed)
# --------------------------------------------------------------------------


def test_handled_rights_grow_with_the_abi_and_stop_at_the_supported_one():
    assert fence._handled_access(0) == 0
    abi1 = fence._handled_access(1)
    assert abi1 == (1 << 13) - 1
    assert fence._handled_access(2) == abi1 | fence._FS_REFER
    assert fence._handled_access(3) == abi1 | fence._FS_REFER | fence._FS_TRUNCATE
    assert fence._handled_access(9) == fence._handled_access(fence.MAX_LANDLOCK_ABI)


def test_a_single_file_only_carries_file_rights():
    for kind in fence._KIND_ACCESS:
        access = fence._grant_access(kind, False, fence.MAX_LANDLOCK_ABI)
        assert access & ~fence._FILE_RIGHTS == 0


def test_no_grant_ever_allows_device_nodes():
    for kind in fence._KIND_ACCESS:
        access = fence._grant_access(kind, True, fence.MAX_LANDLOCK_ABI)
        assert not access & (fence._FS_MAKE_CHAR | fence._FS_MAKE_BLOCK)


def test_only_the_workspace_and_read_execute_paths_can_execute():
    executable = {
        kind
        for kind in fence._KIND_ACCESS
        if fence._grant_access(kind, True, fence.MAX_LANDLOCK_ABI) & fence._FS_EXECUTE
    }
    assert executable == {fence.KIND_WORKSPACE, fence.KIND_READ_EXECUTE}


def test_read_only_paths_carry_no_write_rights():
    access = fence._grant_access(fence.KIND_READ_ONLY, True, fence.MAX_LANDLOCK_ABI)
    assert access == fence._FS_READ_FILE | fence._FS_READ_DIR


@pytest.mark.parametrize(
    "name",
    [
        "VOUCH_PRIVATE_KEY",
        "VOUCH_ED25519_SEED",
        "VOUCH_BRIDGE_SECRET",
        "VOUCH_API_TOKEN",
        "VOUCH_KEY_PASSWORD",
        "vouch_private_key",
    ],
)
def test_secret_bearing_variables_are_recognised(name):
    assert fence._is_vouch_secret(name)


@pytest.mark.parametrize(
    "name", ["VOUCH_PUBLIC_KEY", "VOUCH_DID", "PATH", "AWS_SECRET_ACCESS_KEY", "MY_VOUCH_SEED"]
)
def test_other_variables_are_left_alone(name):
    assert not fence._is_vouch_secret(name)


def test_a_sibling_folder_with_a_shared_prefix_is_not_inside():
    assert fence._is_within("/home/a/.vouch/keys", "/home/a/.vouch")
    assert fence._is_within("/home/a/.vouch", "/home/a/.vouch")
    assert not fence._is_within("/home/a/.vouch-backup", "/home/a/.vouch")
    assert not fence._is_within("/home/a", "/home/a/.vouch")


def test_protected_paths_cover_where_the_keys_really_live():
    from vouch.keys import VOUCH_DIR

    protected = fence._protected_paths(fence.FencePolicy())
    assert os.path.realpath(VOUCH_DIR) in protected
    assert os.path.realpath(str(cli.PRIVATE_KEY_PATH)) in protected


# --------------------------------------------------------------------------
# Refusals before anything runs
# --------------------------------------------------------------------------


def test_refuses_to_run_when_the_fence_cannot_be_enforced(layout, monkeypatch):
    monkeypatch.setattr(fence, "landlock_abi", lambda: 0)
    marker = layout.workspace / "ran"
    with pytest.raises(fence.FenceUnavailableError):
        fence.run_fenced(
            [sys.executable, "-c", "open('ran', 'w').close()"],
            fence.FencePolicy(workspace=str(layout.workspace)),
        )
    assert not marker.exists()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs a POSIX system")
def test_runs_unfenced_only_when_asked_and_says_so_in_the_report(layout, monkeypatch):
    monkeypatch.setattr(fence, "landlock_abi", lambda: 0)
    report = layout.outside / "report.json"
    code = fence.run_fenced(
        [sys.executable, "-c", "open('ran', 'w').close()"],
        fence.FencePolicy(workspace=str(layout.workspace)),
        allow_unfenced=True,
        report_path=str(report),
    )
    assert code == 0
    assert (layout.workspace / "ran").exists()
    record = json.loads(report.read_text())
    assert record["fenced"] is False
    assert record["mechanism"] == "none"
    assert record["covers"] == []


def test_an_empty_command_is_refused(layout):
    with pytest.raises(fence.FenceCommandNotFoundError):
        fence.run_fenced([], fence.FencePolicy(workspace=str(layout.workspace)))


def test_a_missing_command_is_refused(layout):
    with pytest.raises(fence.FenceCommandNotFoundError):
        fence.plan_fence(
            ["no-such-program-anywhere"], fence.FencePolicy(workspace=str(layout.workspace))
        )


def test_a_workspace_holding_the_key_store_is_refused(layout):
    with pytest.raises(fence.FenceError, match="inside the fence"):
        fence.plan_fence([sys.executable], fence.FencePolicy(workspace=str(layout.home)))


@pytest.mark.parametrize("relative", [".vouch", ".vouch/keys", ".vouch/keys/agent.key", ".ssh"])
def test_any_grant_touching_the_key_store_is_refused(layout, relative):
    policy = fence.FencePolicy(
        workspace=str(layout.workspace), read_only=(str(layout.home / relative),)
    )
    with pytest.raises(fence.FenceError, match="inside the fence"):
        fence.plan_fence([sys.executable], policy)


def test_a_symlink_that_leads_to_the_key_store_is_refused(layout):
    link = layout.outside / "looks-harmless"
    link.symlink_to(layout.home / ".vouch")
    policy = fence.FencePolicy(workspace=str(layout.workspace), read_write=(str(link),))
    with pytest.raises(fence.FenceError, match="inside the fence"):
        fence.plan_fence([sys.executable], policy)


def test_a_workspace_that_is_a_symlink_to_home_is_refused(layout):
    link = layout.root / "ws-link"
    link.symlink_to(layout.home)
    with pytest.raises(fence.FenceError, match="inside the fence"):
        fence.plan_fence([sys.executable], fence.FencePolicy(workspace=str(link)))


def test_a_folder_that_only_shares_a_name_prefix_with_the_key_store_is_fine(layout):
    backup = layout.home / ".vouch-backup"
    backup.mkdir()
    policy = fence.FencePolicy(
        workspace=str(layout.workspace),
        read_only=(str(backup),),
        read_execute=PYTHON_PATHS,
    )
    plan = fence.plan_fence([sys.executable], policy)
    assert str(backup) in [grant.path for grant in plan.grants]


def test_extra_protected_paths_are_honoured(layout):
    policy = fence.FencePolicy(
        workspace=str(layout.workspace),
        read_only=(str(layout.outside),),
        protect=(str(layout.outside / "secret.txt"),),
    )
    with pytest.raises(fence.FenceError, match="inside the fence"):
        fence.plan_fence([sys.executable], policy)


def test_a_path_that_does_not_exist_is_refused(layout):
    policy = fence.FencePolicy(
        workspace=str(layout.workspace), read_only=(str(layout.outside / "nope"),)
    )
    with pytest.raises(fence.FenceError, match="cannot use path"):
        fence.plan_fence([sys.executable], policy)


def test_a_path_with_a_null_byte_is_refused(layout):
    policy = fence.FencePolicy(workspace=str(layout.workspace), read_only=("/tmp/a\x00b",))
    with pytest.raises(fence.FenceError, match="cannot use path"):
        fence.plan_fence([sys.executable], policy)


def test_a_workspace_that_is_a_file_is_refused(layout):
    policy = fence.FencePolicy(workspace=str(layout.workspace / "notes.txt"))
    with pytest.raises(fence.FenceError, match="not a directory"):
        fence.plan_fence([sys.executable], policy)


def test_a_report_the_agent_could_rewrite_is_refused(layout):
    policy = fence.FencePolicy(workspace=str(layout.workspace), read_execute=PYTHON_PATHS)
    with pytest.raises(fence.FenceError, match="outside the fence"):
        fence.run_fenced(
            [sys.executable, "-c", "open('ran', 'w').close()"],
            policy,
            allow_unfenced=True,
            report_path=str(layout.workspace / "report.json"),
        )
    assert not (layout.workspace / "ran").exists()


@requires_fence
def test_a_program_outside_the_fence_is_refused_with_advice(layout):
    tool = layout.outside / "bin" / "tool"
    tool.parent.mkdir()
    tool.write_text("#!/bin/sh\necho hello\n")
    tool.chmod(0o755)
    with pytest.raises(fence.FenceError, match="--rx %s" % layout.outside):
        fence.plan_fence([str(tool)], fence.FencePolicy(workspace=str(layout.workspace)))


def test_the_plan_lists_the_fence_without_running_anything(layout):
    policy = fence.FencePolicy(
        workspace=str(layout.workspace),
        read_only=(str(layout.outside),),
        read_execute=PYTHON_PATHS,
    )
    plan = fence.plan_fence([sys.executable, "-c", "open('ran', 'w').close()"], policy)
    record = plan.to_dict()
    assert not (layout.workspace / "ran").exists()
    assert record["workspace"] == str(layout.workspace)
    assert record["argumentCount"] == 2
    assert (
        record["executable"]["sha256"]
        == hashlib.sha256(open(sys.executable, "rb").read()).hexdigest()
    )
    by_path = {entry["path"]: entry["access"] for entry in record["paths"]}
    assert by_path[str(layout.workspace)] == fence.KIND_WORKSPACE
    assert by_path[str(layout.outside)] == fence.KIND_READ_ONLY
    assert str(layout.home / ".vouch") in record["protected"]
    # The arguments can hold secrets, so the record keeps only their count.
    assert "open('ran'" not in json.dumps(record)


# --------------------------------------------------------------------------
# The fence, enforced by the kernel
# --------------------------------------------------------------------------


@requires_fence
def test_reads_outside_the_workspace_are_refused(layout):
    code, results = run_agent(
        layout,
        f"""
probe("inside", lambda: read("notes.txt"))
probe("outside", lambda: read({str(layout.outside / "secret.txt")!r}))
probe("outside_listing", lambda: os.listdir({str(layout.outside)!r}))
probe("system_file", lambda: read("/etc/passwd"))
probe("parent_traversal", lambda: read("../outside/secret.txt"))
""",
    )
    assert code == 0
    assert results["inside"] == ["ok", "inside"]
    for name in ("outside", "outside_listing", "system_file", "parent_traversal"):
        assert denied(results, name), name


@requires_fence
def test_changes_outside_the_workspace_are_refused(layout):
    target = layout.outside / "secret.txt"
    code, results = run_agent(
        layout,
        f"""
probe("write_inside", lambda: write("made.txt"))
probe("mkdir_inside", lambda: os.mkdir("sub"))
probe("rename_inside", lambda: os.rename("made.txt", "sub/moved.txt"))
probe("delete_inside", lambda: os.remove("sub/moved.txt"))
probe("overwrite", lambda: write({str(target)!r}))
probe("append", lambda: open({str(target)!r}, "a").write("x"))
probe("truncate", lambda: os.truncate({str(target)!r}, 0))
probe("create", lambda: write({str(layout.outside / "new.txt")!r}))
probe("mkdir", lambda: os.mkdir({str(layout.outside / "newdir")!r}))
probe("delete", lambda: os.remove({str(target)!r}))
probe("global_tmp", lambda: write("/tmp/vouch-fence-escape-test"))
""",
    )
    assert code == 0
    for name in ("write_inside", "mkdir_inside", "rename_inside", "delete_inside"):
        assert results[name][0] == "ok", name
    for name in ("overwrite", "append", "truncate", "create", "mkdir", "delete", "global_tmp"):
        assert denied(results, name), name
    assert target.read_text() == "OUTSIDE-SECRET"
    assert not (layout.outside / "new.txt").exists()
    assert not os.path.exists("/tmp/vouch-fence-escape-test")


@requires_fence
def test_a_read_only_path_can_be_read_and_nothing_else(layout):
    target = layout.outside / "secret.txt"
    code, results = run_agent(
        layout,
        f"""
probe("read", lambda: read({str(target)!r}))
probe("write", lambda: write({str(target)!r}))
probe("create", lambda: write({str(layout.outside / "new.txt")!r}))
probe("delete", lambda: os.remove({str(target)!r}))
""",
        read_only=(str(layout.outside),),
    )
    assert code == 0
    assert results["read"] == ["ok", "OUTSIDE-SECRET"]
    for name in ("write", "create", "delete"):
        assert denied(results, name), name
    assert target.read_text() == "OUTSIDE-SECRET"


@requires_fence
def test_a_read_write_path_cannot_run_programs_but_the_workspace_can(layout):
    code, results = run_agent(
        layout,
        f"""
import shutil, subprocess

def build(folder):
    path = os.path.join(folder, "tool.sh")
    with open(path, "w") as handle:
        handle.write("#!/bin/sh\\necho ran\\n")
    os.chmod(path, 0o755)
    return path

probe("in_read_write", lambda: subprocess.run([build({str(layout.outside)!r})], capture_output=True, text=True).stdout)
probe("in_workspace", lambda: subprocess.run([build(".")], capture_output=True, text=True).stdout)
""",
        read_write=(str(layout.outside),),
    )
    assert code == 0
    assert denied(results, "in_read_write")
    assert results["in_workspace"] == ["ok", "ran\n"]


@requires_fence
def test_symlinks_do_not_lead_out_of_the_fence(layout):
    planted = layout.workspace / "planted"
    planted.symlink_to(layout.outside / "secret.txt")
    code, results = run_agent(
        layout,
        f"""
probe("planted_before_the_run", lambda: read("planted"))

def own_link():
    os.symlink({str(layout.home / ".vouch" / "keys" / "agent.key")!r}, "mine")
    return read("mine")

probe("made_by_the_agent", own_link)
""",
    )
    assert code == 0
    assert denied(results, "planted_before_the_run")
    assert denied(results, "made_by_the_agent")


@requires_fence
def test_outside_files_cannot_be_linked_or_moved_into_the_workspace(layout):
    target = layout.outside / "secret.txt"
    code, results = run_agent(
        layout,
        f"""
probe("hardlink", lambda: os.link({str(target)!r}, "linked"))
probe("move_in", lambda: os.rename({str(target)!r}, "moved"))
probe("read_linked", lambda: read("linked"))
probe("read_moved", lambda: read("moved"))
""",
    )
    assert code == 0
    for name in ("hardlink", "move_in", "read_linked", "read_moved"):
        assert results[name][0] == "error", name
    assert target.read_text() == "OUTSIDE-SECRET"
    assert not (layout.workspace / "linked").exists()
    assert not (layout.workspace / "moved").exists()


@requires_fence
def test_processes_the_agent_starts_inherit_the_fence(layout):
    target = str(layout.outside / "secret.txt")
    code, results = run_agent(
        layout,
        f"""
import subprocess

def child():
    done = subprocess.run(
        [sys.executable, "-c", "print(open({target!r}).read())"],
        capture_output=True, text=True,
    )
    return [done.returncode, "PermissionError" in done.stderr, done.stdout]

def grandchild():
    done = subprocess.run(
        ["/bin/sh", "-c", "cat {target}"], capture_output=True, text=True,
    )
    return [done.returncode, done.stdout]

probe("child", child)
probe("shell_child", grandchild)
""",
    )
    assert code == 0
    assert results["child"] == ["ok", [1, True, ""]]
    assert results["shell_child"][0] == "ok"
    assert results["shell_child"][1][0] != 0
    assert "OUTSIDE-SECRET" not in results["shell_child"][1][1]


@requires_fence
def test_the_agent_cannot_widen_its_own_fence(layout):
    code, results = run_agent(
        layout,
        f"""
import ctypes, struct

def widen():
    libc = ctypes.CDLL(None, use_errno=True)
    everything = (1 << 15) - 1
    attr = struct.pack("=Q", everything)
    ruleset = libc.syscall(444, attr, len(attr), 0)
    root = os.open("/", os.O_PATH)
    libc.syscall(445, ruleset, 1, struct.pack("=Qi", everything, root), 0)
    return libc.syscall(446, ruleset, 0)

probe("widen", widen)
probe("outside_after", lambda: read({str(layout.outside / "secret.txt")!r}))
probe("keys_after", lambda: read({str(layout.home / ".vouch" / "keys" / "agent.key")!r}))
""",
    )
    assert code == 0
    assert denied(results, "outside_after")
    assert denied(results, "keys_after")


@requires_fence
def test_the_key_store_is_out_of_reach(layout):
    code, results = run_agent(
        layout,
        """
home = os.path.expanduser("~")
probe("key_file", lambda: read(os.path.join(home, ".vouch", "keys", "agent.key")))
probe("key_folder", lambda: os.listdir(os.path.join(home, ".vouch")))
probe("signing_key", lambda: read(os.path.join(home, ".ssh", "vouch_signing")))
probe("home_listing", lambda: os.listdir(home))
probe("plant_key", lambda: write(os.path.join(home, ".vouch", "keys", "evil.key")))
""",
    )
    assert code == 0
    for name in ("key_file", "key_folder", "signing_key", "home_listing", "plant_key"):
        assert denied(results, name), name
    assert not (layout.home / ".vouch" / "keys" / "evil.key").exists()


@requires_fence
def test_secret_variables_never_reach_the_agent(layout):
    env = dict(
        os.environ,
        VOUCH_PRIVATE_KEY="jwk-private",
        VOUCH_ED25519_SEED="00" * 32,
        VOUCH_BRIDGE_SECRET="shared",
        VOUCH_DID="did:web:agent.example",
        UPSTREAM_API_KEY="other",
        KEEP_ME="yes",
    )
    code, results = run_agent(
        layout,
        """
names = ["VOUCH_PRIVATE_KEY", "VOUCH_ED25519_SEED", "VOUCH_BRIDGE_SECRET",
         "VOUCH_DID", "UPSTREAM_API_KEY", "KEEP_ME"]
probe("env", lambda: {name: os.environ.get(name) for name in names})
""",
        env=env,
        drop_env=("UPSTREAM_API_KEY",),
    )
    assert code == 0
    assert results["env"][1] == {
        "VOUCH_PRIVATE_KEY": None,
        "VOUCH_ED25519_SEED": None,
        "VOUCH_BRIDGE_SECRET": None,
        "VOUCH_DID": "did:web:agent.example",
        "UPSTREAM_API_KEY": None,
        "KEEP_ME": "yes",
    }


@requires_fence
def test_descriptors_the_launcher_inherited_are_closed(layout):
    leaked = os.open(str(layout.outside / "secret.txt"), os.O_RDONLY)
    os.set_inheritable(leaked, True)
    try:
        code, results = run_agent(
            layout,
            """
probe("leaked", lambda: os.read(int(sys.argv[1]), 64).decode())
""",
            argv=(str(leaked),),
        )
    finally:
        os.close(leaked)
    assert code == 0
    assert results["leaked"][0] == "error"
    assert results["leaked"][1] == "OSError"


@requires_fence
def test_another_process_cannot_be_read_through_proc(layout):
    env = dict(os.environ, SIDECAR_ONLY_SECRET="seed-material")
    sidecar = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        env=env,
        stdout=subprocess.DEVNULL,
    )
    try:
        environ_path = "/proc/%d/environ" % sidecar.pid
        deadline = time.time() + 5
        visible = b""
        while time.time() < deadline and b"SIDECAR_ONLY_SECRET" not in visible:
            with open(environ_path, "rb") as handle:
                visible = handle.read()
            time.sleep(0.05)
        if b"SIDECAR_ONLY_SECRET" not in visible:
            pytest.skip("this system already hides other processes from the same user")
        code, results = run_agent(
            layout,
            f"""
probe("environ", lambda: open({environ_path!r}, "rb").read().decode("latin-1"))
probe("memory", lambda: open("/proc/{sidecar.pid}/mem", "rb").read(1))
probe("own_status", lambda: "Name" in read("/proc/self/status"))
""",
            read_only=("/proc",),
        )
    finally:
        sidecar.kill()
        sidecar.wait()
    assert code == 0
    assert results["own_status"] == ["ok", True]
    assert results["environ"][0] == "error"
    assert results["memory"][0] == "error"


@requires_fence
def test_the_agent_gets_a_private_temp_folder_that_is_removed(layout):
    code, results = run_agent(
        layout,
        """
import tempfile

def use_temp():
    handle, path = tempfile.mkstemp()
    os.write(handle, b"scratch")
    os.close(handle)
    return [os.environ["TMPDIR"], os.path.dirname(path)]

probe("temp", use_temp)
""",
    )
    assert code == 0
    assert results["temp"][0] == "ok"
    temp_dir, used_dir = results["temp"][1]
    assert temp_dir == used_dir
    assert os.path.basename(temp_dir).startswith("vouch-run-")
    assert not os.path.exists(temp_dir)


@requires_fence
def test_the_agent_cannot_gain_privileges(layout):
    code, results = run_agent(
        layout,
        """
import ctypes

probe("no_new_privs", lambda: ctypes.CDLL(None).prctl(39, 0, 0, 0, 0))
""",
    )
    assert code == 0
    assert results["no_new_privs"] == ["ok", 1]


@requires_fence
def test_the_exit_code_is_passed_through(layout):
    policy = fence.FencePolicy(workspace=str(layout.workspace), read_execute=PYTHON_PATHS)
    assert fence.run_fenced([sys.executable, "-c", "raise SystemExit(7)"], policy) == 7
    killed = "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"
    assert fence.run_fenced([sys.executable, "-c", killed], policy) == 128 + signal.SIGKILL


@requires_fence
def test_the_report_records_the_fence_and_the_agent_cannot_touch_it(layout):
    report = layout.outside / "report.json"
    script = layout.workspace / "agent.py"
    script.write_text(
        f"""
import sys
try:
    open({str(report)!r}, "w").write("{{}}")
except PermissionError:
    sys.exit(3)
"""
    )
    policy = fence.FencePolicy(workspace=str(layout.workspace), read_execute=PYTHON_PATHS)
    code = fence.run_fenced([sys.executable, "agent.py"], policy, report_path=str(report))
    assert code == 3
    record = json.loads(report.read_text())
    assert record["type"] == "FenceReport"
    assert record["fenced"] is True
    assert record["mechanism"] == "landlock"
    assert record["covers"] == ["filesystem"]
    assert record["noNewPrivileges"] is True
    assert record["landlockAbi"]["used"] == min(fence.landlock_abi(), fence.MAX_LANDLOCK_ABI)
    assert record["exitCode"] == 3
    assert record["startedAt"] <= record["endedAt"]
    assert record["executable"]["path"] == sys.executable
    assert stat_mode(report) == 0o600


def stat_mode(path):
    return os.stat(str(path)).st_mode & 0o777


@requires_fence
def test_a_script_whose_interpreter_is_outside_the_fence_fails_to_start(layout):
    interpreter = layout.outside / "sh"
    interpreter.write_bytes(open("/bin/sh", "rb").read())
    interpreter.chmod(0o755)
    script = layout.workspace / "tool"
    script.write_text("#!%s\necho should-not-run\n" % interpreter)
    script.chmod(0o755)
    policy = fence.FencePolicy(workspace=str(layout.workspace))
    with pytest.raises(fence.FenceStartError, match="Permission"):
        fence.run_fenced([str(script)], policy)


# --------------------------------------------------------------------------
# The command line
# --------------------------------------------------------------------------


def cli_run(layout, *extra, command):
    argv = ["run", "--workspace", str(layout.workspace)]
    for path in PYTHON_PATHS:
        argv += ["--rx", path]
    return cli.main([*argv, *extra, "--", *command])


@requires_fence
def test_cli_runs_the_command_fenced_and_returns_its_exit_code(layout):
    target = str(layout.outside / "secret.txt")
    blocked = f"import sys\ntry:\n    open({target!r})\nexcept PermissionError:\n    sys.exit(42)"
    assert cli_run(layout, command=[sys.executable, "-c", blocked]) == 42


@requires_fence
def test_cli_extra_paths_and_report(layout):
    report = layout.root / "report.json"
    target = str(layout.outside / "secret.txt")
    code = cli_run(
        layout,
        "--ro",
        str(layout.outside),
        "--report",
        str(report),
        command=[sys.executable, "-c", f"assert open({target!r}).read() == 'OUTSIDE-SECRET'"],
    )
    assert code == 0
    assert json.loads(report.read_text())["exitCode"] == 0


def test_cli_plan_prints_the_fence(layout, capsys):
    assert cli_run(layout, "--plan", command=[sys.executable, "-c", "pass"]) == 0
    record = json.loads(capsys.readouterr().out)
    assert record["type"] == "FenceReport"
    assert record["workspace"] == str(layout.workspace)


def test_cli_exit_codes_for_launcher_failures(layout, capsys):
    assert cli.main(["run", "--workspace", str(layout.workspace)]) == fence.EXIT_LAUNCHER_ERROR
    assert (
        cli.main(["run", "--workspace", str(layout.workspace), "--", "no-such-program-anywhere"])
        == fence.EXIT_NOT_FOUND
    )
    assert (
        cli.main(["run", "--workspace", str(layout.home), "--", sys.executable])
        == fence.EXIT_LAUNCHER_ERROR
    )
    assert "inside the fence" in capsys.readouterr().err


def test_cli_refuses_without_a_fence_unless_told_otherwise(layout, monkeypatch, capsys):
    monkeypatch.setattr(fence, "landlock_abi", lambda: 0)
    code = cli_run(layout, command=[sys.executable, "-c", "open('ran', 'w').close()"])
    assert code == fence.EXIT_LAUNCHER_ERROR
    assert not (layout.workspace / "ran").exists()
    assert "--allow-unfenced" in capsys.readouterr().err


def start_launcher(layout, agent, **popen_fields):
    """Start ``vouch run`` as its own process, the way a shell would."""
    argv = [sys.executable, "-m", "vouch.cli", "run", "--workspace", str(layout.workspace)]
    for path in PYTHON_PATHS:
        argv += ["--rx", path]
    # The launcher is a fresh interpreter, so it needs the real home to find
    # packages installed for this user.
    env = dict(os.environ, PYTHONPATH=REPO_ROOT, HOME=layout.real_home)
    return subprocess.Popen(
        [*argv, "--", sys.executable, "-c", agent], env=env, cwd=REPO_ROOT, **popen_fields
    )


def wait_for(path, seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline and not path.exists():
        time.sleep(0.05)
    assert path.exists(), "the agent never wrote %s" % path.name


def stop(process):
    if process.poll() is None:
        process.kill()
        process.wait()


@requires_fence
@pytest.mark.parametrize("stop_signal", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_a_stop_request_to_the_launcher_reaches_the_agent(layout, stop_signal):
    agent = "import time; open('ready', 'w').close(); time.sleep(60)"
    launcher = start_launcher(layout, agent)
    try:
        wait_for(layout.workspace / "ready")
        launcher.send_signal(stop_signal)
        assert launcher.wait(timeout=15) == 128 + stop_signal
    finally:
        stop(launcher)


@requires_fence
def test_the_agent_does_not_outlive_its_launcher(layout):
    agent = (
        "import os, time\n"
        "open('tmpdir', 'w').write(os.environ['TMPDIR'])\n"
        "open('pid.part', 'w').write(str(os.getpid()))\n"
        "os.rename('pid.part', 'pid')\n"
        "time.sleep(60)\n"
    )
    launcher = start_launcher(layout, agent)
    agent_pid = None
    try:
        wait_for(layout.workspace / "pid")
        agent_pid = int((layout.workspace / "pid").read_text())
        launcher.kill()
        launcher.wait()
        deadline = time.time() + 15
        while time.time() < deadline and process_is_running(agent_pid):
            time.sleep(0.05)
        assert not process_is_running(agent_pid)
    finally:
        stop(launcher)
        if agent_pid is not None and process_is_running(agent_pid):
            os.kill(agent_pid, signal.SIGKILL)
        # A launcher that was killed cannot tidy up, so the test does.
        leftover = layout.workspace / "tmpdir"
        if leftover.exists() and os.path.basename(leftover.read_text()).startswith("vouch-run-"):
            shutil.rmtree(leftover.read_text(), ignore_errors=True)


def process_is_running(pid):
    try:
        with open("/proc/%d/stat" % pid) as handle:
            state = handle.read().rsplit(")", 1)[1].split()[0]
    except OSError:
        return False
    return state != "Z"


@requires_fence
def test_the_agent_starts_in_its_own_session_with_ordinary_signal_handling(layout):
    code, results = run_agent(
        layout,
        """
import signal

probe("session_leader", lambda: os.getsid(0) == os.getpid())
probe("launcher_session", lambda: os.getsid(os.getppid()) != os.getsid(0))
probe("blocked", lambda: sorted(int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK, [])))
probe("terminate", lambda: signal.getsignal(signal.SIGTERM) == signal.SIG_DFL)
probe("hangup", lambda: signal.getsignal(signal.SIGHUP) == signal.SIG_DFL)
probe("interrupt", lambda: signal.getsignal(signal.SIGINT) is signal.default_int_handler)
""",
    )
    assert code == 0
    assert results["session_leader"] == ["ok", True]
    assert results["launcher_session"] == ["ok", True]
    assert results["blocked"] == ["ok", []]
    for name in ("terminate", "hangup", "interrupt"):
        assert results[name] == ["ok", True], name


@requires_fence
def test_the_agent_cannot_type_into_the_terminal_it_was_started_from(layout):
    import fcntl
    import pty
    import termios

    terminal, terminal_side = pty.openpty()
    agent = """
import fcntl, termios
try:
    for byte in b"id\\n":
        fcntl.ioctl(0, termios.TIOCSTI, bytes([byte]))
    outcome = "typed"
except OSError as exc:
    outcome = "refused %d" % exc.errno
open("typing", "w").write(outcome)
"""

    def take_the_terminal():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    launcher = start_launcher(
        layout,
        agent,
        stdin=terminal_side,
        stdout=terminal_side,
        stderr=terminal_side,
        preexec_fn=take_the_terminal,
    )
    try:
        assert launcher.wait(timeout=60) == 0
        assert (layout.workspace / "typing").read_text().startswith("refused")
        # Nothing was left waiting in the terminal for a shell to run.
        os.set_blocking(terminal_side, False)
        with pytest.raises(BlockingIOError):
            os.read(terminal_side, 16)
    finally:
        stop(launcher)
        os.close(terminal_side)
        os.close(terminal)
