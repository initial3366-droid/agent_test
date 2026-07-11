import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const MAX_BODY_BYTES = 256 * 1024;
const SESSION_COOKIE = "forge_session";

function secureSessionCookie(): boolean {
  return process.env.NODE_ENV === "production" && process.env.ALLOW_INSECURE_PUBLIC_ORIGIN !== "true";
}

type RouteContext = { params: Promise<{ path: string[] }> };

function cloudOrigin(): URL {
  const value = process.env.API_URL ?? process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:4000";
  const url = new URL(value);
  if (!(["http:", "https:"] as const).includes(url.protocol as "http:" | "https:") || url.username || url.password) {
    throw new Error("Invalid API_URL");
  }
  const allowInternalHttp = process.env.ALLOW_INSECURE_INTERNAL_API === "true";
  if (process.env.NODE_ENV === "production" && url.protocol !== "https:" && !allowInternalHttp && !["127.0.0.1", "localhost", "::1"].includes(url.hostname)) {
    throw new Error("Production API_URL must use HTTPS unless it is loopback");
  }
  return url;
}

function isAllowed(method: string, path: string): boolean {
  const exact = new Set([
    "POST /auth/request-code",
    "POST /auth/verify",
    "POST /auth/logout",
    "GET /me",
    "GET /devices",
    "POST /devices",
    "GET /models",
    "POST /models",
    "GET /tasks",
    "POST /usage/events",
    "POST /audit",
    "GET /admin/overview",
    "GET /admin/tasks",
    "GET /admin/users",
    "GET /admin/audits",
  ]);
  if (exact.has(`${method} ${path}`)) return true;
  if (method === "PATCH" && /^\/admin\/users\/[0-9a-f-]{36}$/.test(path)) return true;
  return method === "PUT" && /^\/admin\/settings\/(registration_open|minimum_client_version|usage_limit)$/.test(path);
}

function securityHeaders(headers: Headers): Headers {
  headers.set("cache-control", "no-store, max-age=0");
  headers.set("pragma", "no-cache");
  headers.set("x-content-type-options", "nosniff");
  return headers;
}

async function readLimitedBody(request: NextRequest): Promise<string> {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel("request_too_large");
        throw new Error("request_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(joined);
}

async function proxy(request: NextRequest, context: RouteContext): Promise<NextResponse> {
  const { path: pathParts } = await context.params;
  const path = `/${pathParts.join("/")}`;
  const method = request.method.toUpperCase();

  if (!isAllowed(method, path)) {
    return NextResponse.json({ error: "not_found" }, { status: 404 });
  }

  if (method !== "GET") {
    const expectedOrigin = process.env.WEB_ORIGIN ?? request.nextUrl.origin;
    if (
      request.headers.get("origin") !== expectedOrigin ||
      request.headers.get("x-forge-client") !== "web"
    ) {
      return NextResponse.json({ error: "request_forbidden" }, { status: 403 });
    }
  }

  if (path === "/auth/logout") {
    const response = NextResponse.json({ loggedOut: true });
    response.cookies.set(SESSION_COOKIE, "", {
      expires: new Date(0),
      httpOnly: true,
      path: "/api/cloud",
      sameSite: "strict",
      secure: secureSessionCookie(),
    });
    securityHeaders(response.headers);
    return response;
  }

  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > MAX_BODY_BYTES) {
    return NextResponse.json({ error: "request_too_large" }, { status: 413 });
  }

  let body: string | undefined;
  if (method !== "GET" && method !== "HEAD") {
    if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
      return NextResponse.json({ error: "content_type_required" }, { status: 415 });
    }
    try {
      body = await readLimitedBody(request);
    } catch {
      return NextResponse.json({ error: "request_too_large" }, { status: 413 });
    }
  }

  const headers = new Headers({ accept: "application/json" });
  if (body !== undefined) headers.set("content-type", "application/json");
  if (method === "POST" && path === "/usage/events") {
    const idempotencyKey = request.headers.get("idempotency-key");
    if (idempotencyKey) {
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(idempotencyKey)) {
        return NextResponse.json({ error: "invalid_idempotency_key" }, { status: 400 });
      }
      headers.set("idempotency-key", idempotencyKey);
    }
  }
  const token = request.cookies.get(SESSION_COOKIE)?.value;
  if (token && !path.startsWith("/auth/")) headers.set("authorization", `Bearer ${token}`);

  let upstream: Response;
  try {
    const target = new URL(path, cloudOrigin());
    target.search = request.nextUrl.search;
    upstream = await fetch(target, {
      method,
      body,
      cache: "no-store",
      headers,
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    return NextResponse.json({ error: "cloud_unavailable" }, { status: 503 });
  }

  const responseText = await upstream.text();
  const responseHeaders = securityHeaders(new Headers({ "content-type": "application/json; charset=utf-8" }));

  if (path === "/auth/verify" && upstream.ok) {
    let login: { token?: unknown; user?: unknown };
    try {
      login = JSON.parse(responseText) as { token?: unknown; user?: unknown };
    } catch {
      return NextResponse.json({ error: "invalid_server_response" }, { status: 502 });
    }
    if (typeof login.token !== "string" || !login.user) {
      return NextResponse.json({ error: "invalid_server_response" }, { status: 502 });
    }

    const response = NextResponse.json({ user: login.user }, { headers: responseHeaders });
    response.cookies.set(SESSION_COOKIE, login.token, {
      httpOnly: true,
      maxAge: 12 * 60 * 60,
      path: "/api/cloud",
      sameSite: "strict",
      secure: secureSessionCookie(),
    });
    return response;
  }

  return new NextResponse(responseText || null, {
    status: upstream.status,
    headers: responseHeaders,
  });
}

export const GET = proxy;
export const POST = proxy;
export const PATCH = proxy;
export const PUT = proxy;
