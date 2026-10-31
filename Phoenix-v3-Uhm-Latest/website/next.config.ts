import type { NextConfig } from 'next';

import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.dirname(fileURLToPath(import.meta.url));
const nextConfig: NextConfig = {
  reactStrictMode: true,
  productionBrowserSourceMaps: false,
  devIndicators: false,
  poweredByHeader: false,
  outputFileTracingRoot: projectRoot,
  turbopack: {
    root: projectRoot,
  },
  async headers() {
    const noStore = {
      key: 'Cache-Control',
      value: 'no-store, no-cache, must-revalidate, max-age=0',
    };
    return [
      { source: '/dashboard', headers: [noStore] },
      { source: '/dashboard/:path*', headers: [noStore] },
      { source: '/api/:path*', headers: [noStore] },
    ];
  },
};

export default nextConfig;
