import Link from 'next/link';
import { notFound } from 'next/navigation';
import { BLOG_POSTS } from '../blog-data';

type Params = { slug: string };

export function generateStaticParams(): Params[] {
    return BLOG_POSTS.map((p) => ({ slug: p.slug }));
}

export async function generateMetadata({ params }: { params: Promise<Params> }) {
    const { slug } = await params;
    const post = BLOG_POSTS.find((p) => p.slug === slug);
    if (!post) return { title: 'Not found' };
    return { title: post.title, description: post.description };
}

export default async function BlogPostPage({ params }: { params: Promise<Params> }) {
    const { slug } = await params;
    const post = BLOG_POSTS.find((p) => p.slug === slug);
    if (!post) notFound();

    const idx = BLOG_POSTS.findIndex((p) => p.slug === slug);
    const prev = idx > 0 ? BLOG_POSTS[idx - 1] : null;
    const next = idx >= 0 && idx < BLOG_POSTS.length - 1 ? BLOG_POSTS[idx + 1] : null;

    return (
        <article>
            <section className="border-b border-rule">
                <div className="container-wide py-20 md:py-24">
                    <Link href="/blog/" className="font-mono text-burgundy text-[0.7rem] uppercase tracking-wider no-underline hover:underline">
                        ← Back to blog
                    </Link>
                    <div className="eyebrow-faint mt-6 mb-5">
                        {post.date}{post.readingTime ? ` · ${post.readingTime}` : ''}
                    </div>
                    <h1 className="font-serif font-semibold text-ink leading-[1.05] tracking-tight mb-6 max-w-[820px] text-[clamp(2rem,4vw,2.8rem)]">
                        {post.title}
                    </h1>
                    {post.description && (
                        <p className="text-[1.1rem] leading-snug text-ink-soft max-w-prose">
                            {post.description}
                        </p>
                    )}
                </div>
            </section>

            <section>
                <div className="container-wide py-16">
                    <div
                        className="vouch-blog-body max-w-prose-wide mx-auto"
                        dangerouslySetInnerHTML={{ __html: post.body }}
                    />
                </div>
            </section>

            <section className="border-t border-rule">
                <div className="container-wide py-12 grid sm:grid-cols-2 gap-6">
                    {prev ? (
                        <Link href={`/blog/${prev.slug}/`} className="block no-underline text-ink hover:text-burgundy">
                            <div className="eyebrow-faint mb-2">← Previous</div>
                            <div className="font-serif text-[1.05rem]">{prev.title}</div>
                        </Link>
                    ) : <span />}
                    {next ? (
                        <Link href={`/blog/${next.slug}/`} className="block no-underline text-ink hover:text-burgundy sm:text-right">
                            <div className="eyebrow-faint mb-2">Next →</div>
                            <div className="font-serif text-[1.05rem]">{next.title}</div>
                        </Link>
                    ) : <span />}
                </div>
            </section>
        </article>
    );
}
