import { describe, expect, it } from "vitest";
import { ApprovalStore, requestHash } from "./approvals.js";
import { isPrivateAddress } from "./network.js";
import { isCommandAllowed } from "./server.js";

describe("security policy", () => {
  it("makes approvals one-use and request-bound", () => {
    const approvals = new ApprovalStore();
    const payload = { command: "npm test" };
    const challenge = approvals.create({sessionId:"s",workspaceId:"w",risk:"command",requestHash:requestHash(payload),summary:"npm test"});
    approvals.consume(challenge.id,{sessionId:"s",workspaceId:"w",risk:"command",requestHash:requestHash(payload)});
    expect(() => approvals.consume(challenge.id,{sessionId:"s",workspaceId:"w",risk:"command",requestHash:requestHash(payload)})).toThrow("approval_invalid");
  });

  it("denies destructive commands and classifies local addresses", () => {
    expect(isCommandAllowed("rm -rf /")).toBe(false);
    expect(isCommandAllowed("git reset --hard")).toBe(false);
    expect(isCommandAllowed("npm test")).toBe(true);
    expect(isPrivateAddress("127.0.0.1")).toBe(true);
    expect(isPrivateAddress("10.0.0.1")).toBe(true);
    expect(isPrivateAddress("8.8.8.8")).toBe(false);
  });
});
