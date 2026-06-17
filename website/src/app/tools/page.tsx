import Link from 'next/link';
import type { Metadata } from 'next';
import CodeBlock from '@/components/CodeBlock';

export const metadata: Metadata = {
    title: 'Tools - Vouch Protocol',
    description:
        'Everything Vouch gives you: a command line, a standalone MCP server, SDKs in every major language, packages for your AI tools, trust primitives for robots and embodied agents, media provenance, a GitHub gatekeeper, and the Agent Trust Index.',
};

type Tool = {
    name: string;
    blurb: string;
    start?: string;
    href?: string;
    hrefLabel?: string;
    tag?: string;
};

type Group = {
    eyebrow: string;
    title: string;
    intro: string;
    tools: Tool[];
};

const GROUPS: Group[] = [
    {
        eyebrow: 'Command line',
        title: 'Things you can run today',
        intro: 'Install once with pip install vouch-protocol, then use any of these.',
        tools: [
            {
                name: 'vouch git',
                blurb: 'Sign every git commit cryptographically. One command sets it up, then it is automatic, and your repo gets a verified badge.',
                start: 'vouch git init',
            },
            {
                name: 'vouch scan',
                blurb: 'Find leaked Vouch key material in your code before it ships: a private key in a file, a seed in an env var, a DID document carrying a private key.',
                start: 'vouch scan .',
            },
            {
                name: 'vouch sign and verify',
                blurb: 'Sign any payload and verify it from the command line.',
                start: 'vouch sign "hello"',
            },
            {
                name: 'vouch media',
                blurb: 'Sign images so their origin can be verified, with C2PA support.',
                start: 'vouch media sign photo.jpg',
            },
            {
                name: 'vouch attribute',
                blurb: 'Separate who wrote which line. When an AI assistant and a human both edit a file, it records the lines the AI wrote under the AI key and the lines you wrote under yours, so when a line causes an incident you can prove which of you wrote it.',
                start: 'vouch attribute blame app.py',
            },
            {
                name: 'The Rogue Agent demo',
                blurb: 'A sixty-second demo: a real agent is accepted, an impersonator is rejected, a tampered credential is rejected. All local, no setup.',
                start: 'python examples/00_the_rogue_agent.py',
            },
        ],
    },
    {
        eyebrow: 'For your agents',
        title: 'Give an agent an identity and keep it honest',
        intro: 'The runtime pieces that let an agent prove who it is and stay within its bounds.',
        tools: [
            {
                name: 'MCP server',
                blurb: 'A standalone Model Context Protocol server. Any MCP client (Claude Desktop, Cursor, any agent) can create an identity, sign and verify credentials, scan for leaked keys, and decode DIDs, with no extra setup.',
                start: 'vouch-mcp',
            },
            {
                name: 'Bridge server',
                blurb: 'A standalone HTTP service (vouch-bridge) for media: C2PA image signing, QR badge overlay, and audio watermarking, behind a simple sign and verify API.',
                start: 'vouch-bridge',
            },
            {
                name: 'Identity Sidecar',
                blurb: 'Holds signing keys outside the model context, so a prompt injection cannot read or misuse them.',
            },
            {
                name: 'Vouch Shield',
                blurb: 'A runtime check that inspects every tool call against your rules, like a customs officer at the door.',
            },
            {
                name: 'Continuous trust',
                blurb: 'Heartbeats and session vouchers, so trust is a live signal that has to be renewed, not a badge issued once and trusted forever.',
            },
        ],
    },
    {
        eyebrow: 'Robots and embodied agents',
        title: 'Trust that reaches into the physical world',
        intro: 'The same Verifiable Credentials, extended to robots: a hardware-rooted identity, signed model and safety provenance, and physical limits enforced as capability. Built, tested, and shipped in vouch.robotics.',
        tools: [
            {
                name: 'Hardware-rooted identity',
                blurb: "A robot's signing key bound to a TPM or secure element, in a credential carrying make, model, and serial, so an identity cannot be cloned onto other hardware.",
                href: '/robotics/',
                hrefLabel: 'The robotics page →',
            },
            {
                name: 'Model and safety provenance',
                blurb: 'A signed record of the model, weights hash, and safety policy a robot runs, re-signed on every over-the-air update, so you can prove what was running at any past moment.',
            },
            {
                name: 'Physical capability scope',
                blurb: 'Limits enforced as cryptographic capability: max force, max speed, a lower speed near people, and allowed zones, checked before each actuation. A delegated scope can only narrow its parent.',
            },
            {
                name: 'Robot-to-robot handshake',
                blurb: 'Two robots from different fleets authenticate and agree a bounded-trust session over three signed messages, cooperating only within the intersection of what each offers.',
            },
            {
                name: 'Black box and kill switch',
                blurb: 'An encrypted, tamper-evident flight recorder, plus a kill-switch credential that proves who issued the emergency stop and lets only an attested authority trigger it.',
            },
            {
                name: 'Scannable robot passport',
                blurb: "A signed passport in a QR or NFC tag, so anyone can check a robot's owner, authorized actions, and standing offline, with no network call.",
                start: 'python examples/robotics_demo.py',
            },
        ],
    },
    {
        eyebrow: 'Framework integrations',
        title: 'Drop Vouch into the framework you already use',
        intro: 'Standalone packages that issue a verifiable credential for each tool call, with optional delegation back to a human principal. New in v1.6.2.',
        tools: [
            { name: 'vouch-langchain', blurb: 'A LangChain tool that signs each tool call before it leaves the agent.', start: 'pip install vouch-langchain', tag: 'New' },
            { name: 'vouch-crewai', blurb: 'A CrewAI tool, with supervisor-to-worker delegation that can only narrow authority, never widen it.', start: 'pip install vouch-crewai', tag: 'New' },
            { name: 'vouch-a2a', blurb: 'Binds an A2A (Agent2Agent) Agent Card to a Vouch identity, so two agents can verify each other before they collaborate.', start: 'pip install vouch-a2a', tag: 'New' },
            { name: 'vouch-mlflow', blurb: 'Signs an MLflow model artifact at registration time, bound to a content digest so any change to the weights breaks the signature.', start: 'pip install vouch-mlflow', tag: 'New' },
            { name: 'vouch-safetensors', blurb: 'Embeds a credential in a .safetensors header, complementary to OpenSSF Model Signing, so a model carries who produced it.', start: 'pip install vouch-safetensors', tag: 'New' },
        ],
    },
    {
        eyebrow: 'SDKs',
        title: 'The language you already use',
        intro: 'One shared crypto core, so every language produces byte-identical output, checked against shared test vectors.',
        tools: [
            { name: 'Python', blurb: 'The full reference implementation.', start: 'pip install vouch-protocol' },
            { name: 'TypeScript', blurb: 'For the browser and Node.', start: 'npm i @vouch-protocol-official/sdk' },
            { name: 'Go', blurb: 'A high-throughput signing sidecar.', start: 'go install github.com/vouch-protocol/vouch/go-sidecar/cmd/vouch-sidecar@latest' },
            { name: 'Rust', blurb: 'The shared core that every wrapper is built on.', start: 'cargo add vouch-core' },
            { name: 'Java and Kotlin', blurb: 'On the JVM.', start: 'com.vouchprotocol:vouch-core' },
            { name: '.NET', blurb: 'For C#.', start: 'VouchProtocol.Core', tag: 'Preview' },
            { name: 'Swift', blurb: 'For iOS and macOS.', start: 'VouchCore', tag: 'Preview' },
            { name: 'C and WebAssembly', blurb: 'For native, embedded, browser, and edge.', tag: 'Preview' },
        ],
    },
    {
        eyebrow: 'Inside your AI tools',
        title: 'Add Vouch from where you already work',
        intro: 'Packages that teach your AI assistant how to wire Vouch into your code, running on your own subscription.',
        tools: [
            {
                name: 'Claude Skill',
                blurb: 'Install it as a Claude Code plugin from the Vouch marketplace, then Claude knows how to add Vouch to your repo. It loads automatically when you mention Vouch.',
                start: '/plugin marketplace add vouch-protocol/vouch\n/plugin install vouch-protocol@vouch',
                href: '/help/#claude-skill-install',
                hrefLabel: 'Install guide →',
            },
            {
                name: 'OpenAI Custom GPT',
                blurb: 'The same knowledge inside ChatGPT. Open the shared GPT and ask it to wire Vouch into your code.',
                href: '/help/#openai-gpt-build',
                hrefLabel: 'How to use →',
            },
            {
                name: 'Gemini Gem',
                blurb: 'The same knowledge inside Gemini. Open the shared Gem and ask it to wire Vouch into your code.',
                href: '/help/#gemini-gem-create',
                hrefLabel: 'How to use →',
            },
            {
                name: 'VS Code extension',
                blurb: 'Sign and verify from inside the editor, scaffold an agent identity, and open the Vouch Assistant without leaving VS Code.',
                href: 'https://github.com/vouch-protocol/vouch/tree/main/vscode-vouch',
                hrefLabel: 'On GitHub →',
            },
        ],
    },
    {
        eyebrow: 'Media and the web',
        title: 'Prove where content came from',
        intro: 'Provenance for images, audio, and the open web.',
        tools: [
            { name: 'C2PA Content Credentials', blurb: 'Sign images so their origin and edits can be verified.' },
            { name: 'Vouch Sonic', blurb: 'An audio watermark that carries provenance through sound itself.' },
            { name: 'Browser extension', blurb: 'Sign and verify content on the page, for Chrome and Edge.' },
            { name: 'Mobile capture app', blurb: 'Capture-time signing on a phone, with device-level attestation from the secure enclave, plus Vouch Sonic.' },
        ],
    },
    {
        eyebrow: 'For your repositories',
        title: 'Guard the code itself',
        intro: 'Catch problems at the pull request, before they merge.',
        tools: [
            {
                name: 'Gatekeeper GitHub App',
                blurb: 'Verifies commit signatures on every pull request and blocks leaked Vouch keys before they land.',
                href: 'https://github.com/vouch-protocol/vouch/tree/main/github-app',
                hrefLabel: 'On GitHub →',
            },
        ],
    },
    {
        eyebrow: 'For the ecosystem',
        title: 'See the whole picture',
        intro: 'An open benchmark of how trustworthy the agent world actually is.',
        tools: [
            {
                name: 'Agent Trust Index',
                blurb: 'Scans agents in the wild and measures how many can actually prove who they are. In the first sweep of 11,680 public agents, just 1.3% could.',
                href: '/agent-trust-index/',
                hrefLabel: 'View the Index →',
            },
        ],
    },
];

function Start({ cmd }: { cmd: string }) {
    // Copyable command. A fixed height makes every card's code block identical, so a
    // row of cards lines up at the top. A long command scrolls horizontally within
    // that height (scrollbar sits at the bottom) instead of growing the box upward.
    // The copy button always carries the full command. Vertical padding is trimmed so
    // the line plus the scrollbar fit inside the fixed height.
    return <CodeBlock code={cmd} className="text-[0.8rem] !py-3 h-[4rem]" />;
}

export default function ToolsPage() {
    return (
        <main className="min-h-screen bg-parchment text-ink">
            <div className="container-wide py-16 md:py-24">
                <header className="mb-12">
                    <p className="eyebrow text-burgundy mb-3">What we have built</p>
                    <h1 className="font-serif text-[2.2rem] md:text-[2.8rem] leading-tight tracking-tight mb-4">
                        Vouch Protocol&trade; is not one tool.<br />
                        It is a whole set of them.
                    </h1>
                    <p className="font-serif italic text-ink-soft text-[1.1rem] max-w-prose leading-relaxed">
                        A command line, a standalone server your agents can call, SDKs in every major
                        language, packages for your AI tools, trust primitives for robots, media
                        provenance, a guard for your repositories, and an open benchmark of the whole
                        agent ecosystem. Everything here is open source and free.
                    </p>
                </header>

                <div className="space-y-16">
                    {GROUPS.map((group) => (
                        <section key={group.eyebrow}>
                            <div className="mb-6 pb-3 border-b border-rule">
                                <p className="eyebrow text-burgundy mb-1">{group.eyebrow}</p>
                                <h2 className="font-serif text-[1.6rem] font-semibold tracking-tight">{group.title}</h2>
                                <p className="text-ink-soft italic mt-1 leading-relaxed">{group.intro}</p>
                            </div>

                            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                                {group.tools.map((tool) => (
                                    <article key={tool.name} className="bg-parchment-warm border border-rule p-6 flex flex-col">
                                        <div className="flex items-baseline justify-between gap-3">
                                            <h3 className="font-serif text-[1.2rem] font-semibold tracking-tight">{tool.name}</h3>
                                            {tool.tag && (
                                                <span className="font-mono uppercase text-[0.58rem] tracking-[0.16em] border border-ink-faint text-ink-faint px-1.5 py-0.5">
                                                    {tool.tag}
                                                </span>
                                            )}
                                        </div>
                                        <p className="text-ink leading-relaxed mt-2 text-[0.96rem]">{tool.blurb}</p>
                                        {/* mt-auto pins the command (and link) to the bottom of the card
                                            so every card's code block aligns on the same baseline. */}
                                        <div className="mt-auto">
                                            {tool.start && <Start cmd={tool.start} />}
                                            {tool.href && (
                                                <Link
                                                    href={tool.href}
                                                    className="font-mono uppercase text-[0.65rem] tracking-[0.14em] text-ink border-b border-ink no-underline hover:text-burgundy hover:border-burgundy w-fit mt-3 transition-colors block"
                                                >
                                                    {tool.hrefLabel || 'Learn more →'}
                                                </Link>
                                            )}
                                        </div>
                                    </article>
                                ))}
                            </div>
                        </section>
                    ))}
                </div>

                <footer className="mt-16 border-t border-rule pt-8 flex flex-col md:flex-row gap-4 md:justify-between text-[0.92rem]">
                    <Link
                        href="/onboard/"
                        className="font-mono uppercase tracking-[0.14em] text-[0.7rem] text-ink border-b border-ink no-underline hover:bg-ink hover:text-parchment px-1 py-0.5 transition-colors w-fit"
                    >
                        Get started →
                    </Link>
                    <Link
                        href="https://github.com/vouch-protocol/vouch"
                        className="font-mono uppercase tracking-[0.14em] text-[0.7rem] text-ink-soft border-b border-rule no-underline hover:text-ink px-1 py-0.5 transition-colors w-fit"
                    >
                        Source on GitHub →
                    </Link>
                </footer>
            </div>
        </main>
    );
}
