import type { NextConfig } from "next";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;

function realtimeOrigin(url: string | undefined): string {
  if (!url) return "https://*.supabase.co wss://*.supabase.co";
  try {
    const parsed = new URL(url);
    const ws = parsed.protocol === "https:" ? "wss:" : "ws:";
    return `${parsed.origin} ${ws}//${parsed.host}`;
  } catch {
    return "https://*.supabase.co wss://*.supabase.co";
  }
}

const contentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "style-src 'self' 'unsafe-inline'",
  // The theme bootstrap script in app/layout.tsx is inline, so scripts must
  // allow inline execution until it is moved behind a nonce/hash.
  "script-src 'self' 'unsafe-inline'",
  `connect-src 'self' ${realtimeOrigin(supabaseUrl)}`,
  "upgrade-insecure-requests",
].join("; ");

const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
];

// CSP and HSTS are production-only: they would interfere with the dev server's
// HMR/eval and with plain-HTTP localhost.
if (process.env.NODE_ENV === "production") {
  securityHeaders.push(
    {
      key: "Strict-Transport-Security",
      value: "max-age=63072000; includeSubDomains; preload",
    },
    { key: "Content-Security-Policy", value: contentSecurityPolicy }
  );
}

const nextConfig: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
