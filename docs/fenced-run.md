# Fenced runs: `vouch run`

**Applies to:** `vouch.fence`, the `vouch run` command
**Needs:** Linux 5.13 or newer with Landlock enabled

## 1. What it does

An agent runs code as you. Left alone, it can read anything you can read,
including the private keys that sign on its behalf.

`vouch run` starts the agent inside a fence. The Linux kernel then lets it reach
its workspace, the system folders a program needs to start, and the paths you
list. Every other file access is refused by the kernel, for the agent and for
every process it starts, for as long as they live.

The Vouch Protocol key store is always outside the fence. That is the Identity
Sidecar idea held in place by the operating system: the agent reasons and asks,
a separate process holds the key and signs.

No administrator rights are needed, and nothing has to be installed.

## 2. Quick start

```bash
cd my-agent-project
vouch run -- python agent.py
```

Everything after `--` is the command to run. The current folder becomes the
workspace. Inside the agent:

```python
open("notes.txt").read()                    # fine, it is in the workspace
open("/etc/passwd").read()                  # PermissionError
open("/home/you/.vouch/keys/agent.key")     # PermissionError
```

To see the fence without running anything:

```bash
vouch run --plan -- python agent.py
```

## 3. What the agent can reach

| Path | Access |
|---|---|
| The workspace (`--workspace`, default: current folder) | read, write, create, delete, rename, execute |
| System runtime folders (`/usr`, `/bin`, `/lib` and friends) | read, execute |
| A few system files (`/etc/ssl`, `/etc/resolv.conf`, `/etc/hosts`, `/dev/null` and similar) | what a program needs to start and resolve names |
| A private temporary folder, set as `TMPDIR` | read, write. Removed when the agent exits |
| Paths you add with `--ro`, `--rx`, `--rw` | the access you chose |

Two more things happen before the agent starts:

- Environment variables named `VOUCH_*` that carry key material or a shared
  secret (for example `VOUCH_PRIVATE_KEY`) are removed from its environment.
- File descriptors the launcher inherited are closed, so an open handle cannot
  carry a file across the fence.

## 4. Options

| Option | Meaning |
|---|---|
| `--workspace DIR` | Folder the agent works in. Default: the current folder |
| `--ro PATH` | Extra path the agent may read |
| `--rx PATH` | Extra path the agent may read and execute |
| `--rw PATH` | Extra path the agent may read and change |
| `--protect PATH` | Extra path that must stay outside the fence |
| `--drop-env NAME` | Extra environment variable to remove |
| `--no-system-paths` | Leave the system runtime folders out |
| `--report FILE` | Write a JSON record of the fence that was applied |
| `--plan` | Print the fence and exit |
| `--allow-unfenced` | Run the command on a machine that cannot enforce the fence |

`--ro`, `--rx`, `--rw`, `--protect` and `--drop-env` can be repeated.

### Interpreters installed in your home folder

If Python, Node or another toolchain lives outside the system folders, give it
read and execute access:

```bash
vouch run --rx ~/miniconda3 -- python agent.py
vouch run --rx ~/.nvm -- node agent.js
```

When the program is outside the fence, `vouch run` stops before starting it and
names the folder to add.

### The key store stays out

A fence that would contain the key store is refused. This stops with an error,
because your home folder holds `~/.vouch`:

```bash
vouch run --workspace ~ -- python agent.py
```

Pick the project folder as the workspace. Use `--protect` for other folders
that hold secrets you want the same guarantee for.

## 5. The fence report

`--report FILE` writes a record of the fence when the agent starts, and adds the
exit code when it ends. The file has to sit outside every path the agent can
write, so the agent cannot change its own record.

```bash
vouch run --report ~/fence-reports/run-1.json -- python agent.py
```

The record has this shape:

```json
{
  "type": "FenceReport",
  "version": 1,
  "fenced": true,
  "mechanism": "landlock",
  "covers": ["filesystem"],
  "landlockAbi": {"kernel": 3, "used": 3},
  "noNewPrivileges": true,
  "workspace": "/home/alice/project",
  "paths": [
    {"path": "/home/alice/project", "access": "workspace", "directory": true},
    {"path": "/usr", "access": "read-execute", "directory": true}
  ],
  "protected": ["/home/alice/.vouch", "/home/alice/.ssh/vouch_signing"],
  "droppedEnvironment": ["VOUCH_PRIVATE_KEY"],
  "executable": {"path": "/usr/bin/python3", "sha256": "<SHA-256 of the program file>"},
  "argumentCount": 1,
  "startedAt": "2026-11-27T08:30:00Z",
  "endedAt": "2026-11-27T08:30:04Z",
  "exitCode": 0
}
```

The record keeps the program's path and digest and the number of arguments.
Argument values stay out, since they can hold secrets.

## 6. From Python

```python
from vouch.fence import FencePolicy, run_fenced

exit_code = run_fenced(
    ["python", "agent.py"],
    FencePolicy(
        workspace="./project",
        read_only=("/data/catalog",),
        read_execute=("/opt/toolchain",),
    ),
    report_path="/var/log/agents/run-1.json",
)
```

`plan_fence(command, policy)` returns the resolved fence without running
anything. `landlock_abi()` returns the kernel's Landlock version, or 0 when the
fence cannot be enforced on this machine.

## 7. How it works

The fence uses Landlock, a security module built into Linux. A process hands the
kernel a list of paths with the access allowed on each, then asks the kernel to
apply that list to itself. From then on the kernel checks every file access
against the list. The list can be tightened later and never loosened, and every
child process inherits it.

`vouch run` splits into two processes:

1. The launcher resolves the paths, checks that none of them reaches the key
   store, and builds the list in the kernel.
2. A child process applies the list to itself, gives up the ability to gain
   privileges, and then becomes your command. The fence is in place before the
   command's first instruction.

The launcher stays outside the fence, waits, and returns the agent's exit code.

The agent runs in a session of its own, with no controlling terminal, so it
cannot type into the terminal you started it from. The launcher passes
interrupt, quit, terminate, hang-up and window-size signals on to it, so Ctrl-C
still stops the agent. If the launcher itself goes away, the kernel ends the
agent.

## 8. Other systems

On a machine that cannot enforce the fence, `vouch run` stops with a message and
exit code 125. With `--allow-unfenced` it runs the command and the report says
`"fenced": false`, so anything that reads the report can tell the two apart.

## 9. Exit codes

| Code | Meaning |
|---|---|
| the command's own code | The command ran |
| 128 + N | The command was ended by signal N |
| 125 | The launcher refused the policy or cannot enforce the fence |
| 126 | The command was found but could not be started |
| 127 | The command was not found |
