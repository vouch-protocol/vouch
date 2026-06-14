# Vouch attribution for Claude Code

Separate who wrote which line. When Claude Code and a human both edit a file,
git blame credits every line to the human who committed it. This hook records
the assistant's edits as they happen, so the AI's lines can be attributed to
the AI's own key and the human's lines to the human's key. When a line later
causes an incident, you can prove which of you wrote it.

This is the reference implementation of the per-region authorship attribution
described in [PAD-061](../../../docs/disclosures/README.md).

## Why this is legitimate and not just labelling

Two properties make the attribution trustworthy:

1. **Capture from the real edit channel.** The hook fires on the assistant's
   actual `Edit` / `Write` / `MultiEdit` operations. AI lines come only from
   edits the assistant truly made, not from a label anyone chose afterward.
2. **A separate AI-session key.** Recorded edits are attested with an
   AI-session key (`.vouch/attribution/<session>/ai-session.json`, written
   0600) that is distinct from the key you sign commits with. The human signs
   the final manifest with the human key. Neither party can mint the other's
   attribution.

The human's lines are the residual: anything that changed on disk that did not
arrive through the assistant's edit channel. Unchanged lines are marked
preexisting. Every region is bound to the exact bytes by a SHA-256 hash and a
JCS Data Integrity proof, so a region cannot be moved and the bytes cannot be
altered without breaking verification.

## Setup

```bash
pip install vouch-protocol
vouch git init          # configures your human signing identity
```

Merge the `hooks` block from [`settings.hooks.json`](settings.hooks.json) into
your `.claude/settings.json` (project) or `~/.claude/settings.json` (global).

That is all. From now on, every assistant edit is recorded automatically.

## Using it

```bash
# After a session of mixed editing, before or at commit time:
vouch attribute finalize

# See who wrote what:
vouch attribute blame src/app.py

# Verify the manifest (signatures, region completeness, byte hashes):
vouch attribute verify --check-files
```

`finalize` writes a signed manifest to
`.vouch/attribution/<session>/manifest.json`. Commit it alongside your code if
you want the attribution to travel with the repository.

## Honest degradation

Run `finalize` without the hook ever having recorded anything and the manifest
simply attributes everything to the human committer. The tool never invents AI
attribution it did not observe.
