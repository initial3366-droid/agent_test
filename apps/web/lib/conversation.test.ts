import { describe, expect, it } from "vitest";
import { buildContextPrompt, modelChoices } from "./conversation";

describe("conversation context", () => {
  it("keeps prior turns when the user sends a short confirmation", () => {
    const prompt = buildContextPrompt([{ user: "删除旧文件吗？", assistant: "是否继续删除？" }], "是");
    expect(prompt).toContain("是否继续删除");
    expect(prompt).toContain("Current user message:\n是");
  });

  it("extracts explicit model options", () => {
    expect(modelChoices("请选择：\n1. 保守方案\n2. 完整方案")).toEqual(["保守方案", "完整方案"]);
  });

  it("keeps the prompt inside the server byte budget", () => {
    const prompt = buildContextPrompt([{ user: "问", assistant: "中".repeat(100_000) }], "继续");
    expect(Buffer.byteLength(prompt)).toBeLessThanOrEqual(96_000);
    expect(prompt).toContain("Current user message:\n继续");
  });
});
