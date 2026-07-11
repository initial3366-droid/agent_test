import { createHmac, timingSafeEqual } from "node:crypto";

export const LOGIN_CODE_TTL_MS = 10 * 60_000;
export const LOGIN_CODE_MAX_ATTEMPTS = 5;

export function keyedHash(secret: string, purpose: string, value: string): string {
  return createHmac("sha256", secret).update(`${purpose}\0${value}`, "utf8").digest("hex");
}

export function loginCodeHash(secret: string, email: string, code: string): string {
  return keyedHash(secret, "login-code", `${email}\0${code}`);
}

export function matchesHash(actualHex: string, expectedHex: string): boolean {
  if (!/^[a-f0-9]{64}$/i.test(actualHex) || !/^[a-f0-9]{64}$/i.test(expectedHex)) return false;
  return timingSafeEqual(Buffer.from(actualHex, "hex"), Buffer.from(expectedHex, "hex"));
}

type Bucket = { count: number; resetAt: number };

/** A bounded, per-process guard that supplements the database-backed OTP limits. */
export class FixedWindowRateLimiter {
  readonly #buckets = new Map<string, Bucket>();

  constructor(
    readonly limit: number,
    readonly windowMs: number,
    readonly maxBuckets = 10_000
  ) {}

  take(key: string, now = Date.now()): { allowed: boolean; retryAfterSeconds: number } {
    const current = this.#buckets.get(key);
    if (!current || current.resetAt <= now) {
      if (this.#buckets.size >= this.maxBuckets) this.prune(now);
      this.#buckets.set(key, { count: 1, resetAt: now + this.windowMs });
      return { allowed: true, retryAfterSeconds: 0 };
    }

    current.count += 1;
    return {
      allowed: current.count <= this.limit,
      retryAfterSeconds: Math.max(1, Math.ceil((current.resetAt - now) / 1000))
    };
  }

  private prune(now: number) {
    for (const [key, bucket] of this.#buckets) {
      if (bucket.resetAt <= now) this.#buckets.delete(key);
    }
    while (this.#buckets.size >= this.maxBuckets) {
      const oldest = this.#buckets.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.#buckets.delete(oldest);
    }
  }
}
