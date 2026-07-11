import { createHash } from "node:crypto";

const WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

export function websocketAccept(key: string): string {
  const decoded = Buffer.from(key, "base64");
  if (!/^[A-Za-z0-9+/]{22}==$/.test(key) || decoded.length !== 16) {
    throw new Error("invalid_websocket_key");
  }
  return createHash("sha1").update(`${key}${WEBSOCKET_GUID}`).digest("base64");
}

export function textFrame(value: string): Buffer {
  const payload = Buffer.from(value, "utf8");
  if (payload.length > 2 * 1024 * 1024) throw new Error("websocket_frame_too_large");
  if (payload.length < 126) {
    return Buffer.concat([Buffer.from([0x81, payload.length]), payload]);
  }
  if (payload.length <= 0xffff) {
    const header = Buffer.allocUnsafe(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
    return Buffer.concat([header, payload]);
  }
  const header = Buffer.allocUnsafe(10);
  header[0] = 0x81;
  header[1] = 127;
  header.writeBigUInt64BE(BigInt(payload.length), 2);
  return Buffer.concat([header, payload]);
}

export function closeFrame(code = 1000): Buffer {
  const frame = Buffer.allocUnsafe(4);
  frame[0] = 0x88;
  frame[1] = 2;
  frame.writeUInt16BE(code, 2);
  return frame;
}

export function websocketProtocols(value: string | undefined): { eventProtocol: boolean; token?: string } {
  const protocols = (value ?? "").split(",").map(item => item.trim()).filter(Boolean);
  const tokenProtocol = protocols.find(item => item.startsWith("forge-token."));
  const token = tokenProtocol?.slice("forge-token.".length);
  return {
    eventProtocol: protocols.includes("forge-events"),
    token: token && /^[A-Za-z0-9_-]{32,512}$/.test(token) ? token : undefined
  };
}
