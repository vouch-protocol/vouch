# Argument-aware Shield + Vouch-protected MCP servers - design

Status: **accepted and implemented.** Decisions recorded in Section 9.

Two changes that together make Vouch's pre-execution enforcement *binding* over
MCP rather than advisory:

1. **Shield v2** - rules match on `action` / `target` / `resource`, the same
   three fields a Vouch credential already binds, with glob matching on
   `resource`. Replaces the per-DID capability-level model that never sees
   arguments.
2. **`vouch.mcp.FastMCP`** - a drop-in replacement for the MCP SDK's `FastMCP`
   in which every registered tool is protected by default, plus two example
   servers that are its first users.

Shield is policy; the credential is evidence. This changes policy only. The
credential format, cryptosuite, and every existing test vector stay untouched.

---

## 1. What was there before this change

### 1.1 Shield

`vouch/shield/shield.py` and `vouch/shield/permissions.py` (the latter now removed; see Section 6).

```python
Shield.intercept(tool, args, token=None, did=None) -> InterceptResult
PermissionManager.check_permission(did, tool) -> (bool, reason)
```

`intercept` does four things: signature check, trust status, permission check,
allow. The permission check is the part being replaced. Its model is per-DID
capability *levels*:

```python
Capabilities(filesystem=none|read|write|full, network=..., shell=..., custom={})
```

plus a module-global `TOOL_REQUIREMENTS` mapping tool name to required levels.
`intercept` receives `args` and passes them to the flight recorder, but
`check_permission` never sees them. There is no way to express "`path` must be
under `reports/`".

Call sites of `check_permission` (all of them):

| Site | What it does |
|---|---|
| `vouch/shield/shield.py:153` | Inside `Shield.intercept` |
| `vouch/integrations/mcp/server.py:663` | The `check_action` MCP tool |
| `examples/mcp_trust_lifecycle.py:82` | Example |
| `vouch/shield/permissions.py:105` | Docstring |
| `integrations/aat/aat_to_shield.py` | Reads `TOOL_REQUIREMENTS`, does not call `check_permission` |

Small enough to replace cleanly, which is what Section 6 records.

### 1.2 vouch-mcp

`vouch/integrations/mcp/server.py`. **Note:** the brief refers to
`sign_action`; that name does not exist in this repo. The MCP tool is `sign`:

```python
@mcp.tool()
def sign(action: str, target: str, resource: str | None = None,
         post_quantum: bool = False) -> str
```

It already takes exactly the three fields Shield v2 will match on, so wiring
Shield into it is direct. `resource` defaults to `target` when omitted.

`check_action(tool, capabilities_json, requirements_json)` is the advisory
Shield tool. `check_action_aat` (added by the AAT work) sources rules from a
verified AAT leaf. Both return `ALLOW`/`DENY` strings and neither executes
anything.

### 1.3 The AAT adapter

`integrations/aat/aat_to_shield.py` maps only *tool scope* to Shield rules and
leaves argument constraints to Tenuo's evaluator, because flattening a
`reports/*` constraint into `filesystem: read` would have widened authority to
every filesystem read. Its `DESIGN.md` §5.1 row 1 records this as the primary
lossy row. Shield v2 is what closes it.

### 1.4 Verification primitives available

`Verifier.check_vouch_credential(credential) -> (bool, CredentialPassport)`
is the right receiving-side primitive. It resolves the issuer key from trusted
roots, from `did:key` offline, or via `did:web` resolution, then runs
`Verifier.verify`, which checks the Data Integrity proof, binds the proof to
the issuer, enforces `proofPurpose == assertionMethod`, validates the temporal
window, and requires `intent.resource`.

Revocation is separate: `status_list.verify_status` plus
`status_list_fetcher.StatusListFetcher` to fetch the list credential.

---

## 2. Shield v2 rule schema

YAML and JSON both accepted. Same shape either way.

```yaml
version: 2
rules:
  - did: did:web:agent.example.com
    allow:
      - id: reports-read                      # optional; auto-assigned if absent
        action: read_file
        target: filesystem
        resource: "reports/**"
      - action: search
        target: web
        resource: "**"
deny_default: true
```

Field rules:

- `version: 2` is REQUIRED. A file without it is treated as v1 (Section 6).
- `did` is matched exactly. No globbing on DIDs, deliberately: a wildcard DID
  is an authority-wide grant and should be spelled out, not pattern-matched.
- `action` and `target` are matched **exactly** (case-sensitive, no globs).
  They are short controlled vocabularies, not paths.
- `resource` is glob-matched (Section 3).
- `deny_default: true` is the only supported value in v2. It is written
  explicitly so the file states its own posture. `false` is rejected at load
  with a clear error rather than honoured.
- Unknown keys inside a rule are rejected at load time, not ignored. A typo
  like `resourse:` must not silently become an allow-anything rule.

Empty `rules`, a missing file, or a malformed file all mean deny-all
(Section 5).

### 2.1 The check API

```python
@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str                 # stable, greppable
    rule_id: str | None = None

Shield.check(did: str, action: str, target: str, resource: str) -> Decision
```

Stable reason strings, which the demo narrates verbatim:

| Reason | When |
|---|---|
| `"allowed"` | A rule matched. `rule_id` names it. |
| `"unknown did"` | No rule block for this DID. |
| `"no matching rule"` | The DID has rules, but none matched `action`+`target`. |
| `"resource outside scope"` | A rule matched `action`+`target` but its `resource` glob did not match. |
| `"invalid resource"` | Normalisation rejected the resource (Section 3.2). |
| `"malformed rules"` | The rules file did not load. |

The split between `"no matching rule"` and `"resource outside scope"` is the
one that earns its keep: it is the difference between "you may not do this at
all" and "you may do this, but not *there*", and Scene 2b turns on saying the
second one out loud.

---

## 3. Glob and normalisation

### 3.1 Glob semantics

Matching runs against the **normalised** resource (Section 3.2), on
`/`-separated segments, **case-sensitive**.

| Pattern | Meaning |
|---|---|
| `*` | exactly one segment; never matches `/` |
| `**` | zero or more segments |
| any other char | literal, including `.` and `?` |

`**` is only meaningful as a whole segment. `a/**/b` is valid; `a/**b` is
rejected at load as malformed.

A trailing `/**` also matches the bare prefix, so `reports/**` matches
`reports`, `reports/q3.txt`, and `reports/2026/q3.txt`. Without this, a rule
for a directory would fail to authorise the directory itself, which surprises
people writing `list_dir`.

Worked examples:

| Pattern | Matches | Does not match |
|---|---|---|
| `reports/**` | `reports`, `reports/q3.txt`, `reports/2026/q3.txt` | `secrets/keys.txt`, `reportsX/a` |
| `reports/*` | `reports/q3.txt` | `reports/2026/q3.txt`, `reports` |
| `**` | everything that normalises | nothing |
| `public.*` | `public.customers` | `public.a.b` (`.` is literal; `*` spans one *segment*, and there are no `/` here, so `*` covers the rest) |

That last row needs care. For non-path resources such as SQL table names there
are no `/` separators, so the whole string is one segment and `*` matches any
run of characters within it. This is what makes `public.*` work for the SQLite
example. It is a consequence of the segment rule, not a special case.

### 3.2 Normalisation, applied before matching

In order:

1. Reject if the resource contains a NUL or any C0/C1 control character →
   `"invalid resource"`.
2. Collapse repeated `/` (`reports//x` → `reports/x`).
3. Resolve `.` and `..` segments lexically (no filesystem access, no symlink
   resolution - this is a policy string, not a path on disk).
4. Strip leading `/` (`/reports/x` → `reports/x`).
5. Strip a single trailing `/`.
6. Reject if the result still begins with `..`, i.e. it escaped the root →
   `"invalid resource"`.

So `reports/../etc/passwd` normalises to `etc/passwd` and does **not** match
`reports/**`. That is the traversal case, and it is tested explicitly.

Normalisation is applied to **both** the rule pattern and the resource under
test, so a rule written `/reports/**` behaves identically to `reports/**`.

**Scope note.** This is string policy, not filesystem safety. A server that
maps a resource to a real path must *also* confine it to its root
(`os.path.realpath` under `VOUCH_FS_ROOT`), because symlinks live outside what
lexical normalisation can see. The example server does both, and says so.

---

## 4. Where the credential travels

Two options, per Step 0.4.

**(a) A `credential: str` argument on every protected tool.** Chosen for the
default. The wrapper adds it to the tool's JSON schema and strips it before
calling the user's function. Verified working against the installed SDK: the
parameter appears as `required` in `inputSchema`, and the tool body never sees
it.

**(b) Request metadata / `_meta`.** Cleaner, keeps the tool's own schema
honest, and is the right production pattern.

Going with **(a)** because the demo has to *show* the credential arriving, and
because it degrades well: a client that knows nothing about Vouch sees a
required argument it cannot fill and fails loudly, rather than silently
omitting metadata and getting a refusal it cannot explain. (b) is documented in
the README as the production pattern and is a clean follow-up - the wrapper's
credential-locating step is one function, so adding a `transport="meta"` option
later does not disturb anything else.

---

## 5. Fail-closed matrix

Every one of these denies, and every one logs:

| Condition | Result |
|---|---|
| No rules file configured | Refuse to start (Section 7) |
| Rules file missing at load | `"malformed rules"`, deny all |
| Rules file malformed / unknown keys / `version != 2` | `"malformed rules"`, deny all |
| Empty `rules` list | deny all, `"unknown did"` |
| No rule for the DID | `"unknown did"` |
| Rule matched action+target, resource glob did not | `"resource outside scope"` |
| Nothing matched | `"no matching rule"` |
| Resource fails normalisation | `"invalid resource"` |
| Credential missing or unparseable | `"no credential"` |
| Verification fails | verifier's reason |
| Credential intent ≠ the actual request | `"credential does not match request"` |

There is no path where a failure produces an allow, and no fallback that is
laxer than the configured policy.

---

## 6. Backward compatibility: none, by decision

The v1 format was per-DID capability levels at `~/.vouch/capabilities.json`.
Two options were put to the maintainer: migrate v1 files automatically with a
deprecation warning, or break hard with a `vouch shield migrate` command.

The answer was neither, on the grounds that there is no adoption today and
backward compatibility is not worth carrying for it. So the capability-level
model is **removed outright**: no shim, no auto-migration, no
`check_permission`. `Capabilities`, `PermissionManager`, `TOOL_REQUIREMENTS`,
and `vouch/shield/permissions.py` are gone, and every call site moved to
`Shield.check`.

That is also the more honest outcome. Auto-migration would have been
authority-preserving rather than authority-reducing: a v1 grant of
`filesystem: read` really did mean "any file", so every migrated rule would have
read `resource: "**"`. Everyone would have kept exactly the authority they had
while a new, finer-grained schema implied they had scoped it.

A file without `version: 2` now fails to load and denies everything, with an
error naming the file and pointing at this document.

### 6.1 A conflict in the brief, now moot

The brief specified `*` = one path segment **and** that migrated rules get
`resource: "*"`. Those disagree: `resource: "*"` matches `q3.txt` but not
`reports/q3.txt`, so migration under the precise semantics would have silently
*narrowed* every existing deployment.

With no migration, nothing is ever assigned `resource: "*"` and the conflict
never arises. The strict rule stands with no special case: `*` is exactly one
segment, `**` is any number.

## 7. `vouch.mcp.FastMCP`

```python
from vouch.mcp import FastMCP          # replaces: from mcp.server.fastmcp import FastMCP
mcp = FastMCP("crm-tools")

@mcp.tool()
def run_query(table: str, where: str) -> list[dict]: ...   # protected

@mcp.tool(unprotected=True)
def health() -> str: ...                                    # opt-out, warns
```

A thin subclass. `__init__` passes everything through. `tool()` keeps the SDK's
full signature and adds two kwargs:

- `unprotected: bool = False` - skip protection. Logs a WARNING at registration
  and at every call.
- `resource: Callable[[dict], str] | None = None` - override the resource
  binding (Section 7.2).

Everything else is delegated to `super().tool(...)`. The subclass does not
reimplement registration, schema generation, or dispatch. If the SDK's
`FastMCP.tool` changes shape, the call fails loudly at import/registration
rather than drifting.

### 7.1 Per-call order

1. Locate the credential (the `credential` argument; missing → `"no credential"`).
2. `Verifier.check_vouch_credential` - proof, issuer binding, purpose, temporal
   window. Plus revocation when `credentialStatus` is present.
3. Issuer ∈ `VOUCH_TRUSTED_ISSUERS` → else `"untrusted issuer"`.
4. Intent matches request: `intent.action == tool name`, `intent.target ==`
   configured target, `intent.resource ==` the resource computed from the
   *actual* arguments. Mismatch → `"credential does not match request"`.
5. `Shield.check(did, action, target, resource)`.
6. Only now call the user's function.

Any failure returns a structured refusal. No exception reaches the tool body.

### 7.2 Resource binding: strict by default

Default `intent.resource` for a protected tool is the **JCS canonicalisation of
the full argument dict** with `credential` removed. So a credential authorises
exactly one call with exactly those arguments. `run_query(table="a", where="x")`
does not authorise `run_query(table="a", where="y")`.

Opt-in loosening per tool:

```python
@mcp.tool(resource=lambda args: args["table"])
def run_query(table: str, where: str): ...
```

Then `intent.resource` is that value and rules can glob it (`public.*`). This
is a policy decision the tool author is making, documented with the same
seriousness as `unprotected=True`.

JCS (RFC 8785) is already in the repo (`vouch/jcs.py::canonicalize_str`) and is
what the credential's own proof uses, so the same bytes mean the same thing on
both sides.

### 7.3 Config

From env, read at construction:

| Var | Required | Meaning |
|---|---|---|
| `VOUCH_RULES` | yes | Path to the Shield v2 rules file |
| `VOUCH_TRUSTED_ISSUERS` | yes | Comma-separated DIDs whose credentials are accepted |
| `VOUCH_TARGET` | no | `intent.target` to require. Default: the server name |

Missing required config → **refuse to start**, with a message naming the
variable. Never "start unprotected".

### 7.4 `vouch.mcp.protect(server)`

Secondary API for people on the low-level `Server`: wraps its tool dispatch
with the same five steps. Same semantics, no schema injection (the low-level
server owns its own schemas), so the credential is read from arguments if
present.

**Naming note.** `vouch.protect` already exists in `vouch/autosign.py` and is
the *sending* side (sign-wraps outbound tools). `vouch.mcp.protect` is the
*receiving* side. Same word, opposite direction, different namespace. Worth a
sentence in both docstrings so nobody wires up the wrong one.

---

## 8. AAT follow-through

With Shield v2, the primary lossy row closes for path-shaped constraints.

Tenuo constraint forms and what they map to:

| Tenuo form | Shield v2 `resource` | Status |
|---|---|---|
| `Pattern("reports/*")` | `reports/*` | **exact** - same segment semantics |
| `Pattern("reports/**")` | `reports/**` | **exact** |
| `Exact("reports/q3.txt")` | `reports/q3.txt` (literal) | **exact** |
| `OneOf([...])` of paths | one rule per value | **exact** |
| `Subpath`, `Path` | glob over the prefix | exact where the prefix is literal |
| `Range`, numeric | none | still Tenuo-only |
| `Regex`, `CEL`, `Cmd`, `Shlex`, `Cidr`, `Url*` | none | still Tenuo-only |
| `Not`, `NotOneOf` | none (no negation in v2) | still Tenuo-only |

So: path-shaped constraints move from "lossy" to "exact"; everything else stays
with Tenuo. The **"both must allow" structure does not change.** The Shield
mapping never *replaces* Tenuo's evaluator for a constraint Shield cannot
express - it adds a second, independent refusal point for the ones it can.

New test: `test_aat_path_constraint_enforced_by_shield`, proving
`read_file /etc/passwd` is denied by **Shield** (with Tenuo's evaluator removed
from the path) when the leaf is `reports/*`.

---

## 9. Decisions taken

All three were put to the maintainer before any code was written.

**1. Migration: neither A nor B. Clean replacement.** The maintainer's answer was
that there is no adoption today, so backward compatibility is not worth carrying.
The capability-level model is removed outright: no shim, no auto-migration, no
`check_permission`. That is simpler and more honest than Option A, which would
have left everyone running `resource: "**"` rules while believing they were
scoped.

**2. The `*` versus `**` conflict in §6.1 dissolved with that answer.** With no
v1 files to migrate, nothing is ever assigned `resource: "*"`, so the
inconsistency never arises. The strict rule stands with no special case: `*` is
exactly one segment, `**` is any number.

**3. Credential transport: (a) confirmed** - a `credential` argument the wrapper
adds to the schema and strips before the tool body. `_meta` is documented as the
production pattern and remains a clean follow-up.

**4. Demo guide: written fresh**, at `docs/Vouch-MCP-Demo-Guide.md`, since the
maintainer's copy is not in this repo or on this machine. Every command in it has
been run as written.

### 9.1 What changed during implementation

Two things worth recording, because they differ from what this document
originally proposed.

**Refusals are raised as MCP `ToolError`, not returned as values.** Returning a
refusal dict broke the SDK's output validation for any tool with a declared
return type, and, more importantly, left a refusal looking like a result that a
model could read straight past. An error cannot be mistaken for data. The tool
body still never sees an exception, because it is never entered.

**Tenuo's glob and Shield's glob are not the same language.** Tenuo's `*`
crosses `/`; Shield's does not. Copying a pattern string across would have made
Shield wrongly deny `reports/2026/q3.txt` under a `reports/*` leaf. The adapter
translates instead - `reports/*` becomes `reports/*/**` - and a differential test
asserts the Shield rule is never wider than the Tenuo constraint it came from.
Patterns with no faithful translation fall back to `**` and stay with Tenuo's
evaluator alone.

## 10. Two things found while reading

- **Version numbers disagree.** `pyproject.toml` says `2.1.0`;
  `vouch/__init__.py::__version__` says `2.0.2`. Docs referencing `1.6.2` are in
  `README.md`, `docs/specs/*`, and `claude-skill/README.md`. I will fix the
  `1.6.2` references as the brief asks, but I am not going to silently change
  either version constant - that is a release decision. Flagging it.
- **`sign_action` does not exist**; the tool is `sign`. Noted in §1.2 so the
  brief and the code can be reconciled.
