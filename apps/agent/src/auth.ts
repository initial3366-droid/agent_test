import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";

export const FORGE_CLIENT_HEADER = "forge-web";
export const DEFAULT_SESSION_TTL_MS = 10 * 60 * 1000;

export type AgentSession = {
  id: string;
  deviceId: string;
  origin: string;
  expiresAt: number;
};

function constantTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export function bearerToken(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const match = /^Bearer ([A-Za-z0-9_-]{32,512})$/.exec(header);
  return match?.[1];
}

export function generateBootstrapToken(): string {
  return randomBytes(32).toString("base64url");
}

export function validateBootstrapToken(value: string): string {
  if (!/^[A-Za-z0-9_-]{32,512}$/.test(value)) throw new Error("invalid_bootstrap_token");
  return value;
}

export class SessionManager {
  private readonly sessions = new Map<string, AgentSession>();

  constructor(
    private readonly bootstrapToken: string,
    private readonly ttlMs = DEFAULT_SESSION_TTL_MS,
    private readonly maxSessions = 32
  ) {
    validateBootstrapToken(bootstrapToken);
  }

  issue(candidateBootstrapToken: string | undefined, deviceId: string, origin: string): { token: string; session: AgentSession } {
    if (!candidateBootstrapToken || !constantTimeEqual(candidateBootstrapToken, this.bootstrapToken)) {
      throw new Error("auth_invalid");
    }
    this.cleanup();
    while (this.sessions.size >= this.maxSessions) {
      const oldest = this.sessions.keys().next().value as string | undefined;
      if (!oldest) break;
      this.sessions.delete(oldest);
    }
    const token = randomBytes(32).toString("base64url");
    const session = { id: randomUUID(), deviceId, origin, expiresAt: Date.now() + this.ttlMs };
    this.sessions.set(token, session);
    return { token, session };
  }

  verify(candidate: string | undefined, origin: string): AgentSession {
    if (!candidate) throw new Error("auth_required");
    const session = this.sessions.get(candidate);
    if (!session) throw new Error("auth_invalid");
    if (session.expiresAt <= Date.now()) {
      this.sessions.delete(candidate);
      throw new Error("auth_expired");
    }
    if (session.origin !== origin) throw new Error("origin_forbidden");
    return session;
  }

  revokeSession(sessionId: string): void {
    for (const [token, session] of this.sessions) {
      if (session.id === sessionId) this.sessions.delete(token);
    }
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [token, session] of this.sessions) {
      if (session.expiresAt <= now) this.sessions.delete(token);
    }
  }
}
