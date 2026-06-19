---
description: Continue implementing OpenSSF badge compliance (Issues #4-#11)
---

# OpenSSF Badge Compliance Workflow

## Current Status

Check open issues:
```bash
cd /home/rampy/vouch-protocol && gh issue list --label "security,documentation,ci"
```

## Issues to Implement

| Issue | Title | Priority |
|-------|-------|----------|
| #13 | DCO enforcement (bot) | **HIGH - DO FIRST** |
| #6 | CHANGELOG.md | Medium |
| #7 | Issue templates | Medium |
| #8 | PR template | Medium |
| #9 | Dependabot | Medium |
| #10 | Static analysis (ruff) | Low |
| #11 | Code coverage | Low |

## Workflow for Each Issue

// turbo
1. Check which issues are still open:
```bash
cd /home/rampy/vouch-protocol && gh issue list
```

2. For each open issue, follow this process:
   - Create branch: `git checkout -b feature/issue-N-description`
   - Implement changes
   - Commit: `git commit -m "type: description (#N)"`
   - Push: `git push -u origin feature/issue-N-description`
   - Create PR: `gh pr create --base main`
   - Merge: `gh pr merge --squash --delete-branch`

3. Space out implementations for natural timing (at least 30 min between merges)

## Quick Start

To continue from where we left off:
```bash
cd /home/rampy/vouch-protocol && gh issue list
```

Then tell Claude: "Implement issue #N for OpenSSF compliance"
