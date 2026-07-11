import { describe, expect, it } from "vitest";
import { modelMetadata, type ModelForm } from "./model";

describe("modelMetadata", () => {
  it("never includes the API key in cloud metadata", () => {
    const form: ModelForm = {
      configId: "b27c5fe2-930a-49a5-a028-1a2721465381",
      name: "Work",
      kind: "openai",
      baseUrl: "https://api.openai.com/v1",
      model: "gpt-5",
      contextWindow: 200_000,
      deviceId: "90fb9da0-6e62-4530-82bf-f7f25a896c7e",
      apiKey: "super-secret-value",
      isDefault: true,
    };

    const result = modelMetadata(form, {
      keyLastFour: "alue",
      keyFingerprint: "sha256",
    });

    expect(result).not.toHaveProperty("apiKey");
    expect(result.id).toBe(form.configId);
    expect(JSON.stringify(result)).not.toContain(form.apiKey);
  });
});
