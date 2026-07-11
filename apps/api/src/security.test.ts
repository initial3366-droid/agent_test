import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { FixedWindowRateLimiter, loginCodeHash, matchesHash } from "./security.js";

describe("login code security", () => {
  it("binds hashes to both email and code", () => {
    const secret = "s".repeat(32);
    const digest = loginCodeHash(secret, "a@example.com", "123456");
    expect(matchesHash(digest, loginCodeHash(secret, "a@example.com", "123456"))).toBe(true);
    expect(matchesHash(digest, loginCodeHash(secret, "b@example.com", "123456"))).toBe(false);
  });

  it("enforces fixed-window limits", () => {
    const limiter = new FixedWindowRateLimiter(2, 1_000);
    expect(limiter.take("ip", 0).allowed).toBe(true);
    expect(limiter.take("ip", 1).allowed).toBe(true);
    expect(limiter.take("ip", 2).allowed).toBe(false);
    expect(limiter.take("ip", 1_001).allowed).toBe(true);
  });
});

describe("production configuration", () => {
  it("fails closed without explicit secrets", () => {
    expect(() => loadConfig({ NODE_ENV: "production", WEB_ORIGIN: "https://forge.example" })).toThrow();
  });

  it("rejects development origins in production", () => {
    expect(() => loadConfig({
      NODE_ENV: "production",
      DATABASE_URL: "postgres://db/forge",
      JWT_SECRET: "aB3!dE6@gH9#jK2$mN5%pQ8&rS1*tU4+",
      OTP_SECRET: "zY7!xW4@vU1#tS8$rQ5%pN2&mL9*kJ6+",
      BOOTSTRAP_ADMIN_EMAIL: "admin@example.com",
      RESEND_API_KEY: "re_production_test_key",
      RESEND_FROM_EMAIL: "auth@example.com",
      WEB_ORIGIN: "http://localhost:3000"
    })).toThrow("HTTPS");
  });

  it("allows an explicit insecure origin only with the test-only override", () => {
    const config = loadConfig({
      NODE_ENV: "production",
      DATABASE_URL: "postgres://db/forge",
      JWT_SECRET: "aB3!dE6@gH9#jK2$mN5%pQ8&rS1*tU4+",
      OTP_SECRET: "zY7!xW4@vU1#tS8$rQ5%pN2&mL9*kJ6+",
      BOOTSTRAP_ADMIN_EMAIL: "admin@example.com",
      RESEND_API_KEY: "re_production_test_key",
      RESEND_FROM_EMAIL: "auth@example.com",
      WEB_ORIGIN: "http://124.221.91.212:1205",
      ALLOW_INSECURE_PUBLIC_ORIGIN: "true"
    });
    expect(config.allowedOrigins).toEqual(["http://124.221.91.212:1205"]);
    expect(config.allowInsecurePublicOrigin).toBe(true);
  });
});
