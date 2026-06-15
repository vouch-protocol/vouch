import Link from 'next/link';
import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Robotics — Vouch Protocol',
    description:
        'A robot is an agent with a body. Vouch gives it a did:vouch:agent identity, delegation chains for who authorized it, continuous trust, and a hardware root of trust that binds identity to the physical device.',
};

type Block = { eyebrow: string; title: string; body: string[] };

const BLOCKS: Block[] = [
    {
        eyebrow: 'Why it matters more, not less',
        title: 'A robot is an agent with a body',
        body: [
            'Identity, accountability, and continuous trust matter more, not less, when an agent can act in the physical world and cause physical harm.',
            'The same Vouch primitives apply, unchanged: a cryptographic identity for the robot, a record of who authorized it and within what limits, and a live signal of whether it is still behaving.',
        ],
    },
    {
        eyebrow: 'The same primitives',
        title: 'Identity, delegation, continuous trust',
        body: [
            'A did:vouch:agent identity gives the robot a key it generates and controls, not a string handed to it.',
            'Delegation chains record who authorized the robot and the bounds of that authority, so a single action can be traced back to an accountable human.',
            'The heartbeat runtime keeps trust a live signal that must be renewed. If a robot goes silent or starts misbehaving, its authority lapses on its own.',
        ],
    },
    {
        eyebrow: 'The robot-specific piece',
        title: 'A hardware root of trust',
        body: [
            'The robot-specific open profile anchors identity in hardware. The robot’s secure element, a TPM, a secure enclave, or an on-board AI module’s enclave, holds the DID and signs its heartbeats.',
            'Identity is bound to the physical device rather than a config file, so a cloned controller or a swapped board cannot impersonate the robot.',
            'The open did:vouch:agent profile defines the agent identity scheme; the embodied profile extends it for hardware attestation. Richer robot-lifecycle tooling builds on this open layer.',
        ],
    },
];

export default function RoboticsPage() {
    return (
        <main className="min-h-screen bg-parchment text-ink">
            <div className="max-w-prose-wide mx-auto px-6 py-16 md:py-24">
                <header className="mb-12">
                    <p className="eyebrow text-burgundy mb-3">Embodied agents</p>
                    <h1 className="font-serif text-[2.2rem] md:text-[2.8rem] leading-tight tracking-tight mb-4">
                        Identity for agents<br />with a body
                    </h1>
                    <p className="font-serif italic text-ink-soft text-[1.1rem] max-w-prose leading-relaxed">
                        Vouch Protocol&trade; extends the same open identity layer to robots: a key the
                        machine controls, a chain back to the human who authorized it, and a hardware
                        root of trust that binds the identity to the device itself.
                    </p>
                </header>

                <section className="space-y-12">
                    {BLOCKS.map((b) => (
                        <article key={b.title} className="border border-rule p-8 md:p-10">
                            <p className="eyebrow text-burgundy mb-2">{b.eyebrow}</p>
                            <h2 className="font-serif text-[1.5rem] md:text-[1.7rem] font-semibold tracking-tight mb-5">
                                {b.title}
                            </h2>
                            <div className="space-y-4 max-w-prose">
                                {b.body.map((p) => (
                                    <p key={p} className="text-ink leading-relaxed">{p}</p>
                                ))}
                            </div>
                        </article>
                    ))}
                </section>

                <footer className="mt-16 border-t border-rule pt-8 flex flex-col md:flex-row gap-4 md:justify-between text-[0.92rem]">
                    <Link
                        href="https://github.com/vouch-protocol/vouch/tree/main/docs/specs"
                        className="font-mono uppercase tracking-[0.14em] text-[0.7rem] text-ink border-b border-ink no-underline hover:bg-ink hover:text-parchment px-1 py-0.5 transition-colors w-fit"
                    >
                        The did:vouch:agent profile &rarr;
                    </Link>
                    <Link
                        href="/faq/"
                        className="font-mono uppercase tracking-[0.14em] text-[0.7rem] text-ink-soft border-b border-rule no-underline hover:text-ink px-1 py-0.5 transition-colors w-fit"
                    >
                        Robots in the FAQ &rarr;
                    </Link>
                </footer>
            </div>
        </main>
    );
}
