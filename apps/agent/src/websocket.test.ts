import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { textFrame, websocketAccept, websocketProtocols } from "./websocket.js";

describe("websocket boundary", () => {
  it("validates RFC6455 keys and encodes bounded server frames", () => {
    const key = randomBytes(16).toString("base64");
    expect(websocketAccept(key)).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(() => websocketAccept("invalid")).toThrow("invalid_websocket_key");
    expect(textFrame("ok")[0]).toBe(0x81);
    expect(() => textFrame("x".repeat(2 * 1024 * 1024 + 1))).toThrow("websocket_frame_too_large");
  });

  it("extracts only bounded bootstrap-safe protocol tokens", () => {
    const token = "a".repeat(43);
    expect(websocketProtocols(`forge-events, forge-token.${token}`)).toEqual({ eventProtocol: true, token });
    expect(websocketProtocols("forge-events, forge-token.bad").token).toBeUndefined();
  });
});
