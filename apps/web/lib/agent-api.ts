import { ApiError } from "./api";

const DEFAULT_AGENT_ORIGIN = "http://127.0.0.1:47621";
const CLIENT_HEADER = "forge-web";
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,512}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type AgentSession = { token: string; expiresAt: string; deviceId: string };

declare global {
  interface Window {
    __FORGE_AGENT_BOOTSTRAP_TOKEN__?: string;
  }
}

function configuredAgentOrigin(): string {
  const configured = process.env.NEXT_PUBLIC_AGENT_URL ?? DEFAULT_AGENT_ORIGIN;

  try {
    const url = new URL(configured);
    if (
      url.protocol !== "http:" ||
      url.hostname !== "127.0.0.1" ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) {
      return DEFAULT_AGENT_ORIGIN;
    }
    return url.origin;
  } catch {
    return DEFAULT_AGENT_ORIGIN;
  }
}

export const AGENT_ORIGIN = configuredAgentOrigin();

const sessions = new Map<string, AgentSession>();
let bootstrapToken: string | null = null;
let configuredDeviceId = "";
const sessionRequests = new Map<string, Promise<AgentSession>>();

function takeBootstrapToken(): string | null {
  if (bootstrapToken) return bootstrapToken;

  if (typeof window !== "undefined" && window.location.hash.length > 2048) {
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  } else if (typeof window !== "undefined" && window.location.hash.length > 1) {
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const tokenFromFragment =
      fragment.get("forge_agent_token") ?? fragment.get("forge-agent-token");
    if (tokenFromFragment) {
      fragment.delete("forge_agent_token");
      fragment.delete("forge-agent-token");
      const remainingFragment = fragment.toString();
      window.history.replaceState(
        null,
        "",
        `${window.location.pathname}${window.location.search}${remainingFragment ? `#${remainingFragment}` : ""}`,
      );
      if (TOKEN_PATTERN.test(tokenFromFragment)) {
        bootstrapToken = tokenFromFragment;
        return bootstrapToken;
      }
    }
  }

  if (typeof window !== "undefined" && window.__FORGE_AGENT_BOOTSTRAP_TOKEN__) {
    const injected = window.__FORGE_AGENT_BOOTSTRAP_TOKEN__;
    delete window.__FORGE_AGENT_BOOTSTRAP_TOKEN__;
    if (TOKEN_PATTERN.test(injected)) {
      bootstrapToken = injected;
      return bootstrapToken;
    }
  }

  // Development fallback only. Production desktop builds must inject the
  // one-time bootstrap token in memory instead of compiling it into the web app.
  const developmentToken = process.env.NODE_ENV === "production"
    ? null
    : process.env.NEXT_PUBLIC_FORGE_AGENT_TOKEN ?? process.env.NEXT_PUBLIC_AGENT_TOKEN ?? null;
  bootstrapToken = developmentToken && TOKEN_PATTERN.test(developmentToken) ? developmentToken : null;
  return bootstrapToken;
}

// Capture and erase a desktop-provided URL fragment as soon as the client
// module is evaluated, before any authenticated Agent request is made.
if (typeof window !== "undefined") takeBootstrapToken();

async function parseAgentResponse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ApiError(response.status, "invalid_agent_response");
  }
}

async function exchangeSession(deviceId: string): Promise<AgentSession> {
  const bootstrap = takeBootstrapToken();
  if (!bootstrap || !TOKEN_PATTERN.test(bootstrap) || !UUID_PATTERN.test(deviceId)) {
    throw new ApiError(401, "agent_pairing_required");
  }

  let response: Response;
  try {
    response = await fetch(`${AGENT_ORIGIN}/session`, {
      method: "POST",
      cache: "no-store",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${bootstrap}`,
        "content-type": "application/json",
        "x-forge-client": CLIENT_HEADER,
      },
      body: JSON.stringify({ deviceId }),
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    throw new ApiError(503, "agent_unavailable");
  }
  const payload = (await parseAgentResponse(response)) as Partial<AgentSession> & {
    error?: string;
  };

  if (!response.ok) {
    throw new ApiError(response.status, payload?.error ?? "agent_auth_failed");
  }
  if (
    typeof payload?.token !== "string" ||
    payload.token.length < 32 ||
    typeof payload.expiresAt !== "string" ||
    !Number.isFinite(Date.parse(payload.expiresAt)) ||
    payload.deviceId !== deviceId
  ) {
    throw new ApiError(502, "invalid_agent_session");
  }

  const nextSession = { token: payload.token, expiresAt: payload.expiresAt, deviceId };
  sessions.set(deviceId, nextSession);
  return nextSession;
}

async function getSession(deviceId: string): Promise<AgentSession> {
  const session = sessions.get(deviceId);
  if (
    session &&
    Date.parse(session.expiresAt) > Date.now() + 5_000
  ) {
    return session;
  }
  sessions.delete(deviceId);

  let request = sessionRequests.get(deviceId);
  if (!request) {
    request = exchangeSession(deviceId).finally(() => {
      sessionRequests.delete(deviceId);
    });
    sessionRequests.set(deviceId, request);
  }
  return request;
}

async function request<T>(
  path: string,
  init: RequestInit,
  deviceId: string,
  canRetry: boolean,
): Promise<T> {
  if (!path.startsWith("/")) throw new Error("Agent paths must start with a slash");
  const currentSession = await getSession(deviceId);
  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");
  headers.set("authorization", `Bearer ${currentSession.token}`);
  headers.set("x-forge-client", CLIENT_HEADER);
  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(`${AGENT_ORIGIN}${path}`, {
      ...init,
      cache: "no-store",
      headers,
      signal: init.signal ?? AbortSignal.timeout(30_000),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "TimeoutError") {
      throw new ApiError(408, "agent_timeout");
    }
    throw new ApiError(503, "agent_unavailable");
  }

  const payload = await parseAgentResponse(response);
  if (response.status === 401 && canRetry) {
    sessions.delete(deviceId);
    return request<T>(path, init, deviceId, false);
  }
  if (!response.ok) {
    const body = payload as { error?: unknown } | null;
    throw new ApiError(
      response.status,
      typeof body?.error === "string" ? body.error : `agent_http_${response.status}`,
      payload,
    );
  }
  return payload as T;
}

export function configureAgentDevice(deviceId: string): void {
  if (!UUID_PATTERN.test(deviceId)) throw new Error("Invalid device id");
  configuredDeviceId = deviceId;
}

export function agentApi<T>(path: string, init: RequestInit = {}, deviceId = configuredDeviceId): Promise<T> {
  return request<T>(path, init, deviceId, true);
}

export async function agentEventSocket(taskId: string, deviceId: string, after: number): Promise<WebSocket> {
  if (!UUID_PATTERN.test(taskId) || !UUID_PATTERN.test(deviceId) || !Number.isSafeInteger(after) || after < -1) {
    throw new ApiError(400, "invalid_event_subscription");
  }
  const currentSession = await getSession(deviceId);
  const url = new URL(`${AGENT_ORIGIN}/tasks/${taskId}/events/ws`);
  url.protocol = "ws:";
  url.searchParams.set("deviceId", deviceId);
  url.searchParams.set("after", String(after));
  try {
    return new WebSocket(url.toString(), ["forge-events", `forge-token.${currentSession.token}`]);
  } catch {
    throw new ApiError(503, "agent_websocket_unavailable");
  }
}

export async function agentApiWithApproval<T>(
  path: string,
  body: Record<string, unknown>,
  deviceId: string,
): Promise<T> {
  const approvalId = (value: unknown): string | null => {
    if (!value || typeof value !== "object") return null;
    const challenge = value as { error?: unknown; approvalId?: unknown };
    return challenge.error === "approval_required" && typeof challenge.approvalId === "string" && UUID_PATTERN.test(challenge.approvalId)
      ? challenge.approvalId
      : null;
  };
  try {
    const result = await agentApi<T | { error: string; approvalId: string }>(
      path,
      { method: "POST", body: JSON.stringify(body) },
      deviceId,
    );
    const challengeId = approvalId(result);
    if (!challengeId) return result as T;
    return agentApi<T>(
      path,
      { method: "POST", body: JSON.stringify({ ...body, approvalId: challengeId }) },
      deviceId,
    );
  } catch (error) {
    if (!(error instanceof ApiError) || error.code !== "approval_required") throw error;
    const challenge = error.issues as { approvalId?: unknown } | undefined;
    if (typeof challenge?.approvalId !== "string" || !UUID_PATTERN.test(challenge.approvalId)) {
      throw new ApiError(502, "invalid_approval_challenge");
    }
    return agentApi<T>(
      path,
      { method: "POST", body: JSON.stringify({ ...body, approvalId: challenge.approvalId }) },
      deviceId,
    );
  }
}

export type AgentHealth = { status: "ok"; platform: string; version: string };

export async function getAgentHealth(signal?: AbortSignal): Promise<AgentHealth | null> {
  try {
    const response = await fetch(`${AGENT_ORIGIN}/health`, {
      cache: "no-store",
      signal: signal ?? AbortSignal.timeout(3_000),
    });
    if (!response.ok) return null;
    const payload = (await parseAgentResponse(response)) as Partial<AgentHealth>;
    if (payload?.status !== "ok" || typeof payload.platform !== "string" || typeof payload.version !== "string") return null;
    return { status: "ok", platform: payload.platform, version: payload.version };
  } catch {
    return null;
  }
}

export async function agentHealth(signal?: AbortSignal): Promise<boolean> {
  return Boolean(await getAgentHealth(signal));
}

export function agentErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) return "本地客户端请求失败";
  if (error.code.startsWith("model_http_")) return "模型服务拒绝了连接测试";
  const messages: Record<string, string> = {
    agent_auth_failed: "本地客户端配对失败，请重新启动客户端",
    agent_pairing_required: "本地客户端尚未与此页面配对",
    agent_timeout: "本地客户端响应超时",
    agent_unavailable: "无法连接本地客户端",
    agent_websocket_unavailable: "实时事件连接不可用，已切换为恢复轮询",
    approval_denied: "已在本机拒绝该操作",
    approval_expired: "本机审批已过期，请重试",
    auth_expired: "本地会话已过期，请重新连接",
    auth_invalid: "本地会话无效，请重新连接",
    auth_required: "本地客户端需要重新认证",
    device_mismatch: "本地会话与所选设备不匹配",
    fetch_forbidden: "本地客户端拒绝了该页面的请求",
    key_not_found: "所选模型尚未在当前设备保存 API Key",
    model_connection_failed: "无法连接模型服务",
    model_connection_refused: "模型服务拒绝连接，请检查 API Base URL 和端口",
    model_host_unresolved: "无法解析模型服务域名",
    model_tls_failed: "模型服务的 HTTPS 证书校验失败",
    model_timeout: "模型服务响应超时",
    origin_forbidden: "当前页面来源未获本地客户端授权",
    task_limit_reached: "本地并发任务已达到上限",
    user_cancelled: "已取消选择文件夹",
  };
  return messages[error.code] ?? "本地客户端请求失败";
}
