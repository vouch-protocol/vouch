import Link from 'next/link';
import { BLOG_POSTS } from './blog-data';

export const metadata = {
    title: 'Blog',
    description: 'Insights on AI agent security, cryptographic identity, and the agentic web from the Vouch Protocol team.',
};

export default function BlogIndex() {
    return (
        <>
            <section className="border-b border-rule">
                <div className="container-wide py-20 md:py-24">
                    <div className="eyebrow mb-6">Field notes</div>
                    <h1 className="font-serif font-semibold text-ink leading-[1.05] tracking-tight mb-6 max-w-[820px] text-[clamp(2.25rem,4.5vw,3.25rem)]">
                        Blog
                    </h1>
                    <p className="text-[1.1rem] leading-snug text-ink-soft max-w-prose">
                        Short essays on AI agent identity, cryptographic accountability, and the
                        engineering choices behind the protocol.
                    </p>
                </div>
            </section>

            <section>
                <div className="container-wide py-16">
                    <ul className="grid sm:grid-cols-2 lg:grid-cols-3 gap-10">
                        {[...BLOG_POSTS].sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()).map((post) => (
                            <li key={post.slug} className="feature-card">
                                <div className="eyebrow-faint mb-3">{post.date}{post.readingTime ? ` · ${post.readingTime}` : ''}</div>
                                <h2 className="font-serif font-semibold text-[1.2rem] mb-3 leading-snug">
                                    <Link href={`/blog/${post.slug}/`} className="no-underline text-ink hover:text-burgundy transition-colors">
                                        {post.title}
                                    </Link>
                                </h2>
                                <p className="text-ink-soft text-[0.95rem] leading-relaxed mb-3">
                                    {post.description}
                                </p>
                                <Link href={`/blog/${post.slug}/`} className="font-mono text-burgundy text-[0.7rem] uppercase tracking-wider no-underline border-b border-transparent hover:border-burgundy">
                                    Read more →
                                </Link>
                            </li>
                        ))}
                    </ul>
                </div>
            </section>
        </>
    );
}
