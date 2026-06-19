# Ways of Working: parallel development without the rebase tax

Several contributors (and AI assistants) work this repository at once. Conflicts
are not caused by working in parallel; they are caused by a few avoidable patterns.
This document is the agreement that keeps parallel work cheap.

## The three rules

1. **One surface, one owner at a time.** Two branches only conflict when they edit
   the same files. Pick disjoint surfaces (see the table below) and you get
   parallel speed with no conflicts, by construction.
2. **Small PRs, merged within a day.** A branch that lives four hours cannot drift
   far from `main`. Slice a "phase" into several small PRs instead of one large
   one. Rebase onto `main` at the **start** of work and once mid-way, never only
   at the end. Three five-minute rebases beat one two-hour rebase.
3. **Shared interfaces and shared files change in their own small PR first.** If
   two features need the same API or the same data file, land that change as one
   tiny PR, let everyone pull it, then build on top in parallel. Do not change a
   shared API underneath someone else's in-flight branch.

## Surface ownership

Claim a surface here before starting. Keep changes inside your surface; if you
need a change in someone else's surface, ask the owner to make it (rule 3).

| Surface | Paths | Owner |
|---|---|---|
| Robotics | `vouch/robotics/`, `tests/test_robot_*`, `docs/robotics.md`, robotics PADs, `/robotics` page, robotics KB | Instance A (robotics is its forte) |
| Core protocol + phase modules | `vouch/` (signer, verifier, validator, trifecta, audit, budget, federation, advanced_crypto, storage, etc.), Rust `core/` | Instance B (one module at a time) |
| Website | `website/` (pages, components, FAQ/Help data) | Website owner (single editor) |
| Assistant knowledge + skill | `*/knowledge/`, `claude-skill/` | Same owner as the change it documents |
| Disclosures index | `docs/disclosures/README.md` table | Whoever adds the PAD, appended in number order |

> Adjust the owners as the team changes. The rule that matters is *one owner per
> surface at a time*, not who specifically.

## Hot shared files (edit only if you own the surface)

These attract conflicts because everyone appends to them. Only the surface owner
edits them; others request the change:

- `website/src/app/faq/faq-data.ts`, `website/src/app/help/help-data.ts`
- `*/knowledge/*.md` (these are already per-topic files, keep it that way)
- `docs/disclosures/README.md` (the PAD index table)
- `vouch/signer.py`, `vouch/data_integrity.py` and other core primitives

If a hot file ever genuinely needs many parallel editors, split it into per-item
files combined at build time. Until then, single ownership is simpler and safer.

## Every PR must pass CI on the first try

- **DCO sign-off**: commit with `git commit --signoff` so it carries
  `Signed-off-by: <author name> <author email>` matching the author.
- **Ruff**: run `ruff format vouch/ tests/ examples/` before pushing (CI runs
  `ruff format --check`).
- **Tests**: `pytest` on Python 3.9 to 3.12.
- Stage explicit paths, not `git add -A` (it sweeps in untracked build artifacts).

## Signing idiom

Custom (non-intent) credentials are signed with the low-level primitive, not a
helper on `Signer`:

```python
credential["proof"] = data_integrity.build_proof(
    credential, _raw_priv(signer), signer.verification_method_id()
)
```

`Signer.sign_credential(intent)` is the high-level intent path.

## Never

- Rewrite shared history (`push --force` to `main` or a branch others build on).
  If a one-time rewrite is unavoidable, announce it, have everyone re-sync
  immediately, then never again.
- Let a feature branch live more than about a day without merging or rebasing.
