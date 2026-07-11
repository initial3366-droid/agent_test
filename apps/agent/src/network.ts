import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { isIP, type LookupFunction } from "node:net";

export type EndpointAssessment = {
  base: URL;
  target: URL;
  address: string;
  family: 4 | 6;
  addresses: Array<{ address: string; family: 4 | 6 }>;
  privateNetwork: boolean;
  trustedProviderEndpoint: boolean;
};

function privateIpv4(address: string): boolean {
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some(value => !Number.isInteger(value) || value < 0 || value > 255)) return true;
  const [a, b, c] = octets as [number, number, number, number];
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113);
}

export function isPrivateAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return privateIpv4(address);
  if (family !== 6) return true;
  const normalized = address.toLowerCase();
  if (normalized.startsWith("::ffff:")) {
    const mapped = normalized.slice(7);
    return isIP(mapped) === 4 ? privateIpv4(mapped) : true;
  }
  if (normalized === "::1" || normalized === "::") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd") || /^fe[89ab]/.test(normalized) || normalized.startsWith("ff")) return true;
  if (normalized.startsWith("2001:db8")) return true;
  return !/^[23]/.test(normalized);
}

function trustedEndpoint(kind: "openai" | "anthropic" | "openai-compatible", target: URL): boolean {
  if (target.protocol !== "https:") return false;
  const origin = target.origin.toLowerCase();
  return (kind === "openai" && origin === "https://api.openai.com") ||
    (kind === "anthropic" && origin === "https://api.anthropic.com");
}

async function lookupWithTimeout(hostname: string): Promise<Array<{ address: string; family: number }>> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      lookup(hostname, { all: true, verbatim: true }),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("model_dns_timeout")), 5_000);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function assessEndpoint(
  baseUrl: string,
  kind: "openai" | "anthropic" | "openai-compatible"
): Promise<EndpointAssessment> {
  const parsed = new URL(baseUrl);
  if (parsed.username || parsed.password || parsed.hash || parsed.search) throw new Error("invalid_model_url");
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new Error("invalid_model_protocol");
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
  const directFamily = isIP(hostname);
  const addresses = directFamily
    ? [{ address: hostname, family: directFamily as 4 | 6 }]
    : await lookupWithTimeout(hostname);
  if (addresses.length === 0) throw new Error("model_host_unresolved");
  if (addresses.some(result => /^(?:0\.|169\.254\.)/.test(result.address) || /^fe[89ab]/i.test(result.address))) {
    throw new Error("model_endpoint_denied");
  }
  const privateNetwork = addresses.some(result => isPrivateAddress(result.address));
  if (parsed.protocol === "http:" && !privateNetwork) throw new Error("insecure_model_transport");

  const eligibleAddresses = addresses
    .filter(result => isPrivateAddress(result.address) === privateNetwork)
    .map(result => ({ address: result.address, family: result.family as 4 | 6 }));
  const selected = eligibleAddresses[0]!;
  const normalizedBase = new URL(parsed.toString());
  if (!normalizedBase.pathname.endsWith("/")) normalizedBase.pathname = `${normalizedBase.pathname}/`;
  const target = new URL("models", normalizedBase);
  return {
    base: normalizedBase,
    target,
    address: selected.address,
    family: selected.family,
    addresses: eligibleAddresses,
    privateNetwork,
    trustedProviderEndpoint: trustedEndpoint(kind, parsed)
  };
}

function pinnedLookup(assessment: EndpointAssessment): LookupFunction {
  return (_hostname, options, callback) => {
    const requestedFamily = typeof options.family === "number" && options.family !== 0 ? options.family : undefined;
    const candidates = requestedFamily
      ? assessment.addresses.filter(candidate => candidate.family === requestedFamily)
      : assessment.addresses;
    const selected = candidates.length ? candidates : assessment.addresses;
    if (options.all) {
      callback(null, selected);
      return;
    }
    const first = selected[0]!;
    callback(null, first.address, first.family);
  };
}

function networkErrorCode(error: unknown, timedOut = false): string {
  if (timedOut) return "model_timeout";
  const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
  if (code === "ECONNREFUSED") return "model_connection_refused";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return "model_host_unresolved";
  if (
    code.startsWith("ERR_TLS_") || code.startsWith("CERT_") ||
    ["DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE"].includes(code)
  ) return "model_tls_failed";
  return "model_connection_failed";
}

export async function postModelJson(
  assessment: EndpointAssessment,
  path: string,
  headers: Record<string, string>,
  body: unknown,
  signal: AbortSignal,
  timeoutMs = 60_000,
  maximumResponseBytes = 4 * 1024 * 1024
): Promise<unknown> {
  if (!/^[a-z][a-z0-9/-]*$/i.test(path) || path.includes("..")) throw new Error("invalid_model_path");
  const target = new URL(path, assessment.base);
  if (target.origin !== assessment.base.origin) throw new Error("model_origin_changed");
  const encoded = Buffer.from(JSON.stringify(body), "utf8");
  if (encoded.length > 4 * 1024 * 1024) throw new Error("model_request_too_large");
  const lookup = pinnedLookup(assessment);
  return new Promise((resolve, reject) => {
    const options = {
      method: "POST",
      headers: { ...headers, "content-type": "application/json", "content-length": String(encoded.length), accept: "application/json" },
      lookup,
      autoSelectFamily: assessment.addresses.length > 1,
      autoSelectFamilyAttemptTimeout: 500
    };
    const onResponse = (response: http.IncomingMessage) => {
      const chunks: Buffer[] = [];
      let received = 0;
      response.on("data", chunk => {
        const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        received += value.length;
        if (received > maximumResponseBytes) {
          response.destroy(new Error("model_response_too_large"));
          return;
        }
        chunks.push(value);
      });
      response.once("error", error => reject(new Error(error.message === "model_response_too_large" ? error.message : "model_connection_failed")));
      response.once("end", () => {
        const status = response.statusCode ?? 500;
        if (status < 200 || status >= 300) return reject(new Error(`model_http_${status}`));
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch { reject(new Error("invalid_model_response")); }
      });
    };
    const request = target.protocol === "https:"
      ? https.request(target, { ...options, servername: target.hostname }, onResponse)
      : http.request(target, options, onResponse);
    const abort = () => request.destroy(new Error("model_cancelled"));
    request.once("error", error => reject(new Error(
      ["model_cancelled", "model_response_too_large", "model_timeout"].includes(error.message)
        ? error.message
        : networkErrorCode(error)
    )));
    request.once("close", () => signal.removeEventListener("abort", abort));
    request.setTimeout(timeoutMs, () => request.destroy(new Error("model_timeout")));
    if (signal.aborted) {
      abort();
      return;
    }
    signal.addEventListener("abort", abort, { once: true });
    request.end(encoded);
  });
}

export async function probeModelEndpoint(
  assessment: EndpointAssessment,
  kind: "openai" | "anthropic" | "openai-compatible",
  apiKey: string,
  timeoutMs = 15_000
): Promise<{ ok: boolean; status: number }> {
  if (/[\0\r\n]/.test(apiKey)) throw new Error("invalid_api_key");
  const headers: Record<string, string> = { accept: "application/json" };
  if (kind === "anthropic") {
    headers["x-api-key"] = apiKey;
    headers["anthropic-version"] = "2023-06-01";
  } else {
    headers.authorization = `Bearer ${apiKey}`;
  }
  const lookup = pinnedLookup(assessment);
  return new Promise((resolve, reject) => {
    const options = {
      method: "GET",
      headers,
      lookup,
      autoSelectFamily: assessment.addresses.length > 1,
      autoSelectFamilyAttemptTimeout: 500
    };
    const onResponse = (response: http.IncomingMessage) => {
      resolve({ ok: (response.statusCode ?? 500) >= 200 && (response.statusCode ?? 500) < 300, status: response.statusCode ?? 500 });
      response.destroy();
    };
    const request = assessment.target.protocol === "https:"
      ? https.request(assessment.target, { ...options, servername: assessment.target.hostname }, onResponse)
      : http.request(assessment.target, options, onResponse);
    let timedOut = false;
    request.once("error", error => reject(new Error(networkErrorCode(error, timedOut))));
    request.setTimeout(timeoutMs, () => {
      timedOut = true;
      request.destroy();
    });
    request.end();
  });
}
