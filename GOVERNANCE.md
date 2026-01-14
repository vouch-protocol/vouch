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

## Access Continuity (Bus Factor)
To ensure the project can continue if key individuals are incapacitated:

1.  **Repository Access**: Multiple administrators have full access to the GitHub organization.
2.  **Infrastructure**: Credentials for critical infrastructure (Cloudflare, PyPI) are stored in a secure, shared password vault (e.g., 1Password for Teams) accessible by core maintainers.
3.  **Documentation**: All deployment and release processes are documented in `CONTRIBUTING.md` and the `scripts/` directory to allow any maintainer to ship releases.
4.  **License**: The project is open source (Apache 2.0), ensuring that the community can fork and continue the project if necessary.