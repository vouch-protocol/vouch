import type { Metadata } from 'next';
import Link from 'next/link';

export const metadata: Metadata = {
    title: 'Robotics - Vouch Protocol',
    description:
        'Open, vendor-neutral trust and accountability for robots and embodied agents: hardware-rooted identity, model and config provenance, cryptographically enforced physical limits, a robot-to-robot handshake, an encrypted black box, a verifiable kill switch, a scannable passport, a living-trust heartbeat, credential revocation, an accountable safety record, signed sensor perception provenance, an offline delegation lease, and a physical quorum for high-consequence actions.',
};

const CAPABILITIES = [
    {
        num: 'i.',
        title: 'Hardware-rooted identity',
        body: 'A robot gets an identity bound to a TPM or secure element. The make, model, serial, and lifecycle history are signed, and the binding cannot be cloned to other hardware. The open alternative to closed or state-run robot-ID schemes.',
        module: 'vouch.robotics.identity',
    },
    {
        num: 'ii.',
        title: 'Model & config provenance',
        body: 'A signed record of the model, weights hash, safety policy, and config a robot is running. It is re-signed on every over-the-air update, so you can always prove what software was running, even after the fact.',
        module: 'vouch.robotics.provenance',
    },
    {
        num: 'iii.',
        title: 'Physical capability scope',
        body: 'Max force, a slower speed near people, allowed zones, and shift windows, carried in a signed credential and checked before the actuator moves. A delegated scope can only narrow, never widen, its parent.',
        module: 'vouch.robotics.capability',
    },
    {
        num: 'iv.',
        title: 'Robot-to-robot handshake',
        body: 'Two robots from different trust domains authenticate and agree a cooperation session before acting together. The session scope is the intersection of what each robot offers, gated by a domain trust policy.',
        module: 'vouch.robotics.handshake',
    },
    {
        num: 'v.',
        title: 'Black box & kill switch',
        body: 'An encrypted, tamper-evident flight recorder: the chain proves nothing was changed, and only the key opens the payloads. Plus a verifiable emergency stop that proves who issued it, and that only an attested authority can trigger it.',
        module: 'vouch.robotics.blackbox',
    },
    {
        num: 'vi.',
        title: 'Scannable passport',
        body: 'A compact passport in a QR or NFC tag, so anyone can check a robot\'s owner, authorized actions, certification, and standing offline, with no network call.',
        module: 'vouch.robotics.passport',
    },
    {
        num: 'vii.',
        title: 'Living trust heartbeat',
        body: 'A robot heartbeats with a signed summary of what it physically did each interval (peak force, peak speed, speed near people, zone breaches) and whether it stayed inside its envelope. It is trusted only while a fresh, in-envelope heartbeat keeps arriving, so trust is earned continuously rather than granted once at the factory.',
        module: 'vouch.robotics.liveness',
    },
    {
        num: 'viii.',
        title: 'Credential revocation',
        body: 'Retire a single capability, provenance, or identity credential through a status list, or kill a whole robot identity at the DID level when a key is compromised or a robot is captured. The same two-level revocation the rest of Vouch uses, applied to robots.',
        module: 'vouch.robotics.revocation',
    },
    {
        num: 'ix.',
        title: 'Accountable safety record',
        body: 'A tamper-evident, append-only ledger of incidents, near-misses, overrides, and kill-switch events, summarized into a portable signed record of a robot\'s safety standing that travels with it across owners, insurers, and regulators.',
        module: 'vouch.robotics.safety_record',
    },
    {
        num: 'x.',
        title: 'Perception provenance',
        body: 'A robot signs the provenance of each captured sensor frame at capture: the frame hash, the sensor, the modality, and the time, hash-linked into a tamper-evident log. It can prove what its cameras and lidar actually saw, and a substituted frame is detectable.',
        module: 'vouch.robotics.perception',
    },
    {
        num: 'xi.',
        title: 'Offline delegation lease',
        body: 'A short-lived, scope-bounded grant a disconnected robot can verify and act on with no network call. Leases nest, each sub-grant only narrowing the one above, so a vendor can lease to an integrator, the integrator to an operator, and the operator to the robot, all verifiable.',
        module: 'vouch.robotics.lease',
    },
    {
        num: 'xii.',
        title: 'Physical quorum',
        body: 'A cryptographic two-person rule for high-consequence actions. Applying large force near a person, or an irreversible move, can require M of N attested approvers to each sign off before the robot is authorized to act.',
        module: 'vouch.robotics.physical_quorum',
    },
];

export default function RoboticsPage() {
    return (
        <>
            {/* Hero */}
            <section className="border-b border-rule">
                <div className="container-wide py-16 md:py-24">
                    <div className="eyebrow mb-5">Robotics</div>
                    <h1 className="font-serif font-semibold text-ink leading-[1.08] tracking-tight mb-6 max-w-[860px] text-[clamp(2.2rem,4.6vw,3.4rem)]">
                        Identity and accountability for robots.
                    </h1>
                    <p className="text-ink-soft text-[1.15rem] leading-snug max-w-prose mb-4">
                        As robots and embodied agents act in the physical world, they raise the same
                        questions a software agent does, and a few new ones. Who is this robot? What
                        software is it running? What is it allowed to do, and how fast near a person? Who
                        can stop it? Vouch answers all of these with open, vendor-neutral credentials.
                    </p>
                    <p className="text-ink-soft text-[1rem] leading-relaxed max-w-prose">
                        Every piece below is built on the same Verifiable Credentials as the rest of
                        Vouch, so it verifies with the Python, Rust, TypeScript, and Go SDKs. These are
                        open formats and reference implementations; hosted black-box storage and
                        fleet-scale infrastructure are left to whoever deploys them.
                    </p>
                </div>
            </section>

            {/* Capabilities */}
            <section className="border-b border-rule">
                <div className="container-wide py-16">
                    <div className="section-heading mb-8">
                        <span className="num">§ I</span>
                        <h2>What Vouch handles in robotics</h2>
                    </div>
                    <div className="grid md:grid-cols-2 gap-10">
                        {CAPABILITIES.map((cap) => (
                            <div key={cap.title} className="border-t-2 border-ink pt-5">
                                <div className="eyebrow-faint mb-2">{cap.num}</div>
                                <h3 className="font-serif font-semibold text-[1.3rem] tracking-tight mb-3">
                                    {cap.title}
                                </h3>
                                <p className="text-ink-soft leading-relaxed mb-4">{cap.body}</p>
                                <span className="font-mono text-burgundy text-[0.72rem] tracking-wider">
                                    {cap.module}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* Guides and FAQ */}
            <section className="border-b border-rule">
                <div className="container-wide py-16">
                    <div className="section-heading mb-6">
                        <span className="num">§ II</span>
                        <h2>Guides and questions</h2>
                    </div>
                    <p className="text-ink-soft leading-relaxed max-w-prose mb-6">
                        Build and verify each capability with the robotics guide, or browse the
                        robotics questions. Both live alongside the rest of Vouch&apos;s guides and
                        FAQ, filtered to embodied agents.
                    </p>
                    <div className="flex flex-wrap gap-3">
                        <Link href="/help/#robotics" className="btn-primary">
                            Robotics guide
                        </Link>
                        <Link href="/faq/#robotics" className="btn-secondary">
                            Robotics FAQ
                        </Link>
                    </div>
                </div>
            </section>

            {/* Standards + links */}
            <section className="border-b border-rule">
                <div className="container-wide py-16">
                    <div className="section-heading mb-6">
                        <span className="num">§ III</span>
                        <h2>Open, and headed for the standards bodies</h2>
                    </div>
                    <p className="text-ink-soft leading-relaxed max-w-prose mb-6">
                        The robot identity, provenance, and passport are Verifiable Credential profiles,
                        a natural fit to incubate alongside the existing W3C Credentials work. The
                        physical-safety and emergency-stop pieces are positioned for IEEE and ISO/TC 299
                        (Robotics). The methods are published as open defensive disclosures so they stay
                        free for everyone to implement.
                    </p>
                    <div className="flex flex-wrap gap-3">
                        <a
                            href="https://github.com/vouch-protocol/vouch/blob/main/docs/robotics.md"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn-primary"
                        >
                            Robotics documentation
                        </a>
                        <a
                            href="https://github.com/vouch-protocol/vouch/tree/main/vouch/robotics"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn-secondary"
                        >
                            Source on GitHub
                        </a>
                        <Link href="/tools/" className="btn-secondary">
                            All tools
                        </Link>
                    </div>
                </div>
            </section>
        </>
    );
}
