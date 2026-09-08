# Vouch Shield decision vectors

The cross-language contract for Shield rules. Every implementation loads
`rules.yaml`, runs the calls in `cases.json`, and must produce the same verdict,
the same reason string, and the same rule id.

| File | What it is |
|---|---|
| `rules.yaml` | The shared rule set. Actions are named after the glob behaviour they exercise, so a failing case names its own cause. |
| `cases.json` | 77 calls with their expected decisions. |

## Running them

| Language | Command |
|---|---|
| Python | `pytest tests/test_shield_vectors.py` |
| TypeScript | `cd packages/sdk-ts && npm test` |

Both run in CI wherever the other shared vectors run.

## The shape of a case

```json
{
  "name": "deep: two segments below",
  "action": "deep",
  "target": "files",
  "resource": "reports/2026/q3.txt",
  "expect": { "allow": true, "reason": "allowed", "rule_id": "deep" }
}
```

`did` defaults to the top-level `did` in the file and is stated per case only
when a case is about a different one. `rule_id` is checked only when the case
states it, so a case can assert a verdict without pinning which rule produced
it. A case carrying its own `rules` object uses that document instead of
`rules.yaml`, which is how load-time behaviour is covered without a file per
case.

## What the cases cover

- **Glob depth.** `*` is exactly one segment and never crosses a `/`; `**` is
  any number including zero; a trailing `/**` also matches the bare prefix.
- **Non-path resources.** A string with no `/` is a single segment, so
  `public.*` matches `public.customers` and `public.a.b`. `.` is literal.
- **Normalisation.** Leading slash, duplicate slashes, `.` segments, trailing
  slash, and interior `..` all resolve before matching.
- **Traversal.** `reports/../etc/passwd` normalises to `etc/passwd` and falls
  outside a `reports/**` rule. A resource that climbs above its own root is
  refused outright rather than clamped, and reports `invalid resource` rather
  than `resource outside scope`.
- **Unusable resources.** Empty, slashes only, dot segments only, NUL, a C0
  control character, a newline, and a C1 control character.
- **Exact matching.** Action, target, and DID are compared exactly and are case
  sensitive. A DID is never matched by prefix.
- **Load failures.** A missing or wrong `version`, `deny_default: false`, an
  unknown key on a rule or a block, a missing or empty required field, a
  malformed resource pattern. Each denies everything with `malformed rules`
  rather than admitting anything.
- **Empty authority.** No rules, no `rules` key, or a DID with an empty allow
  list all permit nothing.

All six reason strings appear at least once, so no implementation can pass by
stubbing one out. A test asserts that, and that the allow and deny cases are
both well represented, so a port cannot pass by being uniformly strict or
uniformly permissive.

## Precedence when a case surprises you

The order of checks is observable and is part of the contract. A resource that
cannot be normalised reports `invalid resource` even when the DID is unknown,
because the resource is checked first. A rule that matches action and target but
not the resource reports `resource outside scope`, while no action and target
match at all reports `no matching rule`. That distinction is the difference
between "you may not do this" and "you may do this, but not there".

## Changing these

These are a contract between implementations, so a change to an expectation is
a change to Shield's behaviour and needs the same scrutiny as a change to the
code. Adding cases is cheap and welcome. Editing an expectation to make a
failing implementation pass is the wrong direction; work out which side is
wrong first.
