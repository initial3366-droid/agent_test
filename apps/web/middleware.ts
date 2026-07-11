import { NextRequest, NextResponse } from "next/server";

function agentOrigin(): string {
  try {
    const candidate = new URL(
      process.env.NEXT_PUBLIC_AGENT_URL ?? "http://127.0.0.1:47621",
    );
    if (candidate.protocol === "http:" && candidate.hostname === "127.0.0.1") {
      return candidate.origin;
    }
  } catch {
    // Invalid values fail closed to the default loopback endpoint.
  }
  return "http://127.0.0.1:47621";
}

export function middleware(request: NextRequest) {
  const nonce = crypto.randomUUID().replaceAll("-", "");
  const localAgentOrigin = agentOrigin();
  const localAgentWebSocketOrigin = localAgentOrigin.replace(/^http:/, "ws:");
  const policy = [
    "default-src 'self'",
    "base-uri 'self'",
    `connect-src 'self' ${localAgentOrigin} ${localAgentWebSocketOrigin}`,
    "font-src 'self' data:",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "img-src 'self' data:",
    "object-src 'none'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    `style-src 'self' 'nonce-${nonce}'`,
    "worker-src 'self' blob:",
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("content-security-policy", policy);
  requestHeaders.set("x-nonce", nonce);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("content-security-policy", policy);
  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api/|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
