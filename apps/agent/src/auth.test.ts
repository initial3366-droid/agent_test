import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SessionManager } from "./auth.js";

describe("SessionManager", () => {
  it("requires the bootstrap token and binds sessions to the origin", () => {
    const manager = new SessionManager("a".repeat(32));
    expect(() => manager.issue("b".repeat(32), randomUUID(), "http://localhost:3000")).toThrow("auth_invalid");
    const issued = manager.issue("a".repeat(32), randomUUID(), "http://localhost:3000");
    expect(manager.verify(issued.token, "http://localhost:3000").id).toBe(issued.session.id);
    expect(() => manager.verify(issued.token, "https://evil.example")).toThrow("origin_forbidden");
  });
});
