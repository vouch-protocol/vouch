import Link from 'next/link';
import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Methodology - Agent Trust Index - Vouch Protocol',
    description:
        'The full, open account of how the Agent Trust Index measured how many public agents can prove who they are. No black box.',
};

export default function MethodologyPage() {
    return (
        <main className="min-h-screen bg-parchment text-ink">
            <div className="container-wide py-20 md:py-28">
                <Link href="/agent-trust-index/" className="font-mono uppercase text-[0.65rem] tracking-[0.14em] text-burgundy no-underline border-b border-transparent hover:border-burgundy">
                    Back to the Index
                </Link>
                <p className="eyebrow text-burgundy mt-6 mb-3">Open methodology</p>
                <h1 className="font-serif font-semibold text-[clamp(2rem,4.5vw,3.2rem)] leading-[1.08] tracking-tight mb-6 max-w-[820px]">
                    How the Agent Trust Index measured this
                </h1>

                <div className="max-w-prose text-ink-soft leading-relaxed space-y-5 text-[1.05rem]">
                    <p>
                        This is the full account of how the numbers were produced, written so anyone can
                        check our work or reproduce it. The whole point of the Index is that the method
                        is open. No black box.
                    </p>

                    <h2 className="font-serif font-semibold text-[1.4rem] text-ink tracking-tight pt-4">The question we set out to answer</h2>
                    <p>
                        There are a lot of AI agents running in the world now. They call tools, move
                        data, and increasingly spend money. We wanted to answer one plain question for as
                        many of them as we could find: can this agent prove who it is?
                    </p>
                    <p>
                        &quot;Prove who it is&quot; has a precise meaning here. It means the agent publishes a
                        verifiable identity that anyone can check independently, without asking the
                        agent&apos;s owner to vouch for themselves. In practice today that means a
                        decentralized identifier (a did:web) that resolves to a document carrying a real
                        public key.
                    </p>

                    <h2 className="font-serif font-semibold text-[1.4rem] text-ink tracking-tight pt-4">Why we score on adoption, not on a registry field</h2>
                    <p>
                        A fair early objection: surely a directory of agents already knows which are
                        trustworthy? It does not. Public directories list agents so people can find and
                        use them. They do not assign identities, and they carry no proof of who is behind
                        an agent. An agent only has a verifiable identity if its own operator chose to
                        publish one. So the honest way to measure trust is to go agent by agent and check
                        whether each one actually publishes verifiable identity, not to read a field off
                        a list. Almost none do, which is the finding.
                    </p>

                    <h2 className="font-serif font-semibold text-[1.4rem] text-ink tracking-tight pt-4">The steps, in order</h2>
                    <ol className="list-decimal pl-6 space-y-3">
                        <li>We picked one large, public, current source to start: the Model Context Protocol registry, the closest thing the agent world has to a phone book.</li>
                        <li>We learned its shape by reading its API directly. Each entry gives an agent a name, a title, a description, and the network addresses it serves from.</li>
                        <li>For every agent we pulled out the domains it actually serves from, because a did:web identity has to live at the agent&apos;s own domain. The serving domain is where a real identity would be published, so that is where we look.</li>
                        <li>For each domain we tried to resolve a did:web identity, meaning we fetched the standard identity document the domain would publish if it had one, using the Vouch Protocol&apos;s own resolver. We do not only check the standard location. If it is empty, we read the agent&apos;s published card and resolve any identity it declares there, including a did:web served from a path rather than the root, or a self-contained did:key, so an agent that publishes identity in a less common but still valid place is counted rather than missed. The Index is therefore also a live test that Vouch verification works at internet scale.</li>
                        <li>We scored each agent out of 100. Sixty points for publishing a resolvable identity at all. Forty more for that identity document carrying a usable public key (in either common key format). Ninety or above is an A, then B, C, D, and F below forty. An agent with nothing scores zero, an F.</li>
                        <li>We checked our own work before trusting any number. We confirmed the scorer gives a perfect A to a domain that genuinely publishes an identity (we tested it against real ones in the wild), so the board is not just stuck on F because of a bug. That check caught a real mistake: our first version only recognised one of the two common key formats and would have under-scored a genuine agent. We fixed it and re-checked.</li>
                        <li>We then scanned the whole registry, not a sample. To make that feasible we resolved each unique domain once rather than once per agent, and ran the checks in parallel.</li>
                        <li>Finally we deduped to unique agents. The registry lists multiple versions of the same agent, so we collapsed those to one entry per agent and kept its best result, so an agent counts as verifiable if any of its versions is. This keeps the headline number honest rather than inflated by version rows.</li>
                    </ol>

                    <h2 className="font-serif font-semibold text-[1.4rem] text-ink tracking-tight pt-4">What we found</h2>
                    <p>
                        Of the 11,680 unique agents in the registry, 157 (about 1.34 percent) publish a
                        resolvable identity, which means 98.66 percent cannot prove who they are at all. Of
                        the 157, only 69 also carry a usable public key (a full A grade); the other 88
                        publish an identity that resolves but has no key anyone can verify against (a C
                        grade). The small group that can prove themselves are mostly finance and oracle
                        agents, which fits: the agents that handle money are the first to bother proving
                        identity.
                    </p>

                    <h2 className="font-serif font-semibold text-[1.4rem] text-ink tracking-tight pt-4">What this measures, and what it does not</h2>
                    <p>We are honest about the edges:</p>
                    <ul className="list-disc pl-6 space-y-3">
                        <li>This is one source and one main signal. We check the standard did:web location, path-based did:web, and DIDs declared in agent cards, so the undercount is small, but an agent could still publish identity somewhere we did not look (a different DID method, an on-chain identity, a directory we have not added yet), in which case we undercount. So treat the number as a floor, not a ceiling. As we add sources (agent-to-agent directories, on-chain identity) and stronger signals (verifiable credentials, a named human or organization behind the agent, a revocation method, post-quantum keys), the score gets richer.</li>
                        <li>A high score means an agent can prove who it is, not that it is good or safe. Identity is the floor, not the ceiling. You cannot hold an agent accountable for anything if you cannot first tell which agent it was.</li>
                    </ul>

                    <h2 className="font-serif font-semibold text-[1.4rem] text-ink tracking-tight pt-4">Reproduce it</h2>
                    <p>
                        The code is small and open. Run it yourself and you will get the same kind of
                        result a few minutes later. The number moves on its own as agents adopt verifiable
                        identity, and the day it ticks down because more agents can prove who they are is a
                        day worth noting.
                    </p>
                </div>

                <div className="mt-10 flex flex-wrap gap-3">
                    <Link href="/agent-trust-index/" className="btn-primary">Back to the Index</Link>
                    <a href="https://github.com/vouch-protocol/vouch" target="_blank" rel="noopener noreferrer" className="btn-secondary">Source on GitHub</a>
                </div>
            </div>
        </main>
    );
}
