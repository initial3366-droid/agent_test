export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly issues?: unknown,
  ) {
    super(code);
    this.name = "ApiError";
  }
}

async function readResponse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;

  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ApiError(response.status, "invalid_server_response");
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  if (!path.startsWith("/")) throw new Error("API paths must start with a slash");

  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");
  headers.set("x-forge-client", "web");
  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }

  const response = await fetch(`/api/cloud${path}`, {
    ...init,
    cache: "no-store",
    credentials: "same-origin",
    headers,
  });
  const payload = await readResponse(response);

  if (!response.ok) {
    const error = payload as { error?: unknown; issues?: unknown } | null;
    throw new ApiError(
      response.status,
      typeof error?.error === "string" ? error.error : `http_${response.status}`,
      error?.issues,
    );
  }

  return payload as T;
}

export function errorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) return "请求失败，请稍后重试";

  const messages: Record<string, string> = {
    account_disabled: "该账号已被停用",
    admin_required: "当前账号没有管理员权限",
    invalid_code: "验证码无效或已过期",
    registration_closed: "当前暂未开放注册",
    unauthorized: "登录已过期，请重新登录",
    validation_error: "提交内容格式不正确",
    cloud_unavailable: "云端服务暂时不可用",
    client_update_required: "本地客户端版本过低，请先更新",
    device_limit_reached: "账号绑定的设备数量已达到上限",
    platform_not_supported: "首版仅支持 Windows 与 macOS",
    request_too_large: "提交内容超过大小限制",
  };
  return messages[error.code] ?? "请求失败，请稍后重试";
}
