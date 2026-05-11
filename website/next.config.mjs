/** @type {import('next').NextConfig} */
const nextConfig = {
  // Static export for GitHub Pages deployment
  output: 'export',
  images: {
    unoptimized: true,
  },
  // Trailing slashes give GH Pages cleaner URLs (/faq/ instead of /faq)
  trailingSlash: true,
  reactStrictMode: true,
  // The Vouch site is served at the root of vouch-protocol.com via the docs/ folder
  // No basePath needed; assets resolve relative to root
};

export default nextConfig;
