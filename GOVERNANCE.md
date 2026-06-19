# Vouch Protocol Governance

## Governance Model
This project operates under a **Lazy Consensus** model. This means that consensus is assumed on all changes unless a valid objection is raised.

- **Decision Making**: Proposals are made via GitHub Issues or Discussions. If no objections are raised within 72 hours, the proposal is considered accepted.
- **Code Changes**: All code changes require at least one approval from a Maintainer.
- **Major Changes**: Significant architectural changes or changes to the protocol specification require explicit approval from the Project Lead.

## Roles & Responsibilities

### Project Lead (@rampyg)
- Sets overall technical direction and roadmap
- Final arbiter in case of unresolvable disagreements
- Manages signing keys and sensitive infrastructure
- Access to all project assets (domains, cloud accounts)

### Maintainers
- Review and merge Pull Requests
- Triage Issues and Disputes
- Maintain documentation and examples
- Have write access to the repository

### Contributors
- Submit Pull Requests
- Report bugs and suggest features
- Participate in discussions

## Contributor Ladder

Contributors grow into greater ownership as they earn trust. The rungs are
visible on purpose: people climb ladders they can see. Each rung adds
recognition and responsibility.

| Rung | How you get here | What you can do | Recognition |
|------|------------------|-----------------|-------------|
| **Newcomer** | Open your first issue or PR | Pick up a `good first issue`; ask questions in Discord | Welcomed by the bot |
| **Contributor** | One merged PR | Keep contributing; claim issues | Listed via all-contributors; receive a signed **Vouch Verified Contributor** credential |
| **Area Owner / Committer** | 2-3 solid PRs in one area, consistent participation | Added to `CODEOWNERS` for that area; auto-requested for review; can approve PRs (merge by a Maintainer) | Named in `MAINTAINERS.md` as a Committer |
| **Maintainer** | Sustained expertise over 3+ months; nominated by a Maintainer; approved by the Lead | Write access to specific modules; merge PRs in their area; mentor newcomers; join the release process | Listed as a Maintainer |
| **Project Lead** | Founding / appointed | Sets direction; final arbiter; manages signing keys and infrastructure | Listed as Project Lead |

How to climb:
1. **Ship**: multiple accepted PRs in an area (quality over quantity).
2. **Stay**: consistent participation in issues, reviews, and Discord.
3. **Be invited**: an existing Maintainer nominates you; the Lead approves.

Maintainers should actively point strong contributors at the next rung: when
someone lands a clean PR, reply with one specific `good second issue` or
`help wanted` task that builds on what they just did.

## Access Continuity (Bus Factor)
To ensure the project can continue if the project lead is incapacitated:

1.  **Repository Access**: Administrative access is maintained by the Project Lead. Emergency access is available via secure backup credentials stored in a diligent manner (e.g., physical security key or digital inheritance vault).
2.  **Infrastructure**: Credentials for critical infrastructure (Cloudflare, PyPI) are stored in a secure password manager.
3.  **Documentation**: All deployment and release processes are documented in `CONTRIBUTING.md` and the `scripts/` directory to allow a successor or fork to ship releases.
4.  **License**: The project is open source (Apache 2.0), ensuring that the community can fork and continue the project if necessary.