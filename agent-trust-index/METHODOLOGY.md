# How the Agent Trust Index measured this

This is the full account of how the numbers were produced, written so anyone can
check our work or reproduce it. The whole point of the Index is that the method is
open. No black box.

## The question we set out to answer

There are a lot of AI agents running in the world now. They call tools, move data,
and increasingly spend money. We wanted to answer one plain question for as many of
them as we could find: can this agent prove who it is?

"Prove who it is" has a precise meaning here. It means the agent publishes a
verifiable identity that anyone can check independently, without asking the agent's
owner to vouch for themselves. In practice today that means a decentralized
identifier (a did:web) that resolves to a document carrying a real public key.

## Why we score on adoption, not on a registry field

A fair early objection: surely a directory of agents already knows which are
trustworthy? It does not. Public directories list agents so people can find and
use them. They do not assign identities, and they carry no proof of who is behind
an agent. An agent only has a verifiable identity if its own operator chose to
publish one. So the honest way to measure trust is to go agent by agent and check
whether each one actually publishes verifiable identity, not to read a field off a
list. Almost none do, which is the finding.

## The steps, in order

1. We picked one large, public, current source to start: the Model Context
   Protocol registry, the closest thing the agent world has to a phone book.

2. We learned its shape by reading its API directly. Each entry gives an agent a
   name, a title, a description, and the network addresses it serves from.

3. For every agent we pulled out the domains it actually serves from, because a
   did:web identity has to live at the agent's own domain. The serving domain is
   where a real identity would be published, so that is where we look.

4. For each domain we tried to resolve a did:web identity, meaning we fetched the
   standard identity document the domain would publish if it had one, using the
   Vouch Protocol's own resolver. We do not only check the standard location. If
   that one is empty, we read the agent's published card and resolve any identity it
   declares there, including a did:web served from a path rather than the root, or a
   self-contained did:key. That way an agent that publishes identity in a less common
   but still valid place is counted rather than missed. The Index is therefore also a
   live test that Vouch verification works at internet scale.

5. We scored each agent out of 100. Sixty points for publishing a resolvable
   identity at all. Forty more for that identity document carrying a usable public
   key (in either common key format). Ninety or above is an A, then B, C, D, and F
   below forty. An agent with nothing scores zero, an F.

6. We checked our own work before trusting any number. We confirmed the scorer
   gives a perfect A to a domain that genuinely publishes an identity (we tested it
   against real ones in the wild), so the board is not just stuck on F because of a
   bug. That check caught a real mistake: our first version only recognised one of
   the two common key formats and would have under-scored a genuine agent. We fixed
   it and re-checked.

7. We then scanned the whole registry, not a sample. To make that feasible we
   resolved each unique domain once rather than once per agent, and ran the checks
   in parallel.

8. Finally we deduped to unique agents. The registry lists multiple versions of the
   same agent, so we collapsed those to one entry per agent and kept its best
   result, so an agent counts as verifiable if any of its versions is. This keeps
   the headline number honest rather than inflated by version rows.

## What we found

Of the 11,680 unique agents in the registry, 157 (about 1.34 percent) publish a
resolvable identity, which means 98.66 percent cannot prove who they are at all. Of
the 157, only 69 also carry a usable public key (a full A grade); the other 88
publish an identity that resolves but has no key anyone can verify a signature
against (a C grade). The small group that can prove themselves are mostly finance and
oracle agents, which fits: the agents that handle money are the first to bother
proving identity.

## What this measures, and what it does not

We are honest about the edges:

- This is one source and one main signal. We check the standard did:web location,
  path-based did:web, and DIDs declared in agent cards, so the undercount is small,
  but an agent could still publish identity somewhere we did not look (a different DID
  method, an on-chain identity, a directory we have not added yet), in which case we
  undercount. So treat the number as a floor, not a ceiling. As we add sources
  (agent-to-agent directories, on-chain identity) and stronger signals (verifiable
  credentials, a named human or organization behind the agent, a revocation method,
  post-quantum keys), the score gets richer.
- A high score means an agent can prove who it is, not that it is good or safe.
  Identity is the floor, not the ceiling. You cannot hold an agent accountable for
  anything if you cannot first tell which agent it was.

## Reproduce it

The code is small and open. Run it yourself and you will get the same kind of
result a few minutes later. The number moves on its own as agents adopt verifiable
identity, and the day it ticks down because more agents can prove who they are is a
day worth noting.
