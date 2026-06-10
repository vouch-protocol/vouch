# Agent Trust Index

The Agent Trust Index looks at AI agents that are already public and checks one
simple thing for each: can the agent prove who it is?

Most agents cannot. They run, they call tools, they spend money and take actions,
but there is no way to verify which agent acted or who stands behind it. The
Index measures that. Each agent gets a Trust Score from 0 to 100 and a letter
grade, based on whether it publishes a verifiable identity that anyone can check.

Nobody has to sign up. The Index finds agents on its own from public sources and
scores them. An agent that publishes a real verifiable identity stands out. The
rest show the size of the gap.

## How the score works (MVP)

For this first version we use one source, the public Model Context Protocol
registry, and we check for a resolvable decentralized identity:

- Resolvable DID: the agent publishes a did:web document at its own domain. (60)
- Valid verification key: that document carries a usable public key. (40)

Grades: A is 90 or above, B is 75, C is 60, D is 40, and F is below 40.

The scoring is open on purpose. You can read exactly how a number is reached, and
you can see the per-item breakdown for every agent in `data/results.json`.

## What comes next

- More sources: agent cards, A2A directories, and on-chain identity.
- Stronger signals: signed agent cards and verifiable credentials, a human or
  organization an agent is accountable to, a revocation method, and post-quantum
  keys.
- A public web page anyone can visit, with an embeddable badge so a verified
  agent can show its grade.

## Run it

```
python run.py 50
```

It writes `data/results.json` and prints a summary. It reuses the Vouch Protocol
did:web resolver to do the checking, so the Index is also a live test of Vouch
verification at internet scale.
