import { describe, expect, it } from "vitest";
import { auditEventSchema, fileMutationSchema, providerSchema } from "./index.js";
describe("providerSchema", () => { it("rejects unsafe incomplete configuration", () => { expect(providerSchema.safeParse({name:"x"}).success).toBe(false); }); });
describe("providerSchema cloud boundary", () => {
  it("rejects an API key in cloud metadata", () => {
    expect(providerSchema.safeParse({
      name: "OpenAI", kind: "openai", baseUrl: "https://api.openai.com/v1", model: "gpt-5",
      contextWindow: 200_000, deviceId: crypto.randomUUID(), apiKey: "must-not-leave-device"
    }).success).toBe(false);
  });
});
describe("auditEventSchema", () => {
  it("rejects reserved actions and sensitive metadata", () => {
    expect(auditEventSchema.safeParse({
      action: "admin.setting_changed", resourceType: "client", metadata: { command: "cat ~/.ssh/id_rsa" }
    }).success).toBe(false);
  });
});
describe("fileMutationSchema", () => {
  it("bounds paths, content and hashes", () => {
    expect(fileMutationSchema.safeParse({operation:"write",workspaceId:crypto.randomUUID(),path:"a.ts",content:"x"}).success).toBe(true);
    expect(fileMutationSchema.safeParse({operation:"delete",workspaceId:crypto.randomUUID(),path:"a.ts",expectedHash:"bad"}).success).toBe(false);
    expect(fileMutationSchema.safeParse({operation:"write",workspaceId:crypto.randomUUID(),path:"a\0.ts",content:"x"}).success).toBe(false);
  });
});
