"use client";

import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  ChevronRight,
  CircleStop,
  Cpu,
  FileDiff,
  FileCode2,
  FolderOpen,
  Gauge,
  KeyRound,
  LayoutDashboard,
  LoaderCircle,
  LogOut,
  Monitor,
  Play,
  Plus,
  Search,
  ShieldCheck,
  TerminalSquare,
  Users,
  Wrench,
  X,
  type LucideIcon,
} from "lucide-react";
import {
  type FormEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import {
  agentApi,
  agentApiWithApproval,
  agentErrorMessage,
  agentEventSocket,
  agentHealth,
  configureAgentDevice,
  getAgentHealth,
} from "../lib/agent-api";
import { ApiError, api, errorMessage } from "../lib/api";
import { buildContextPrompt, modelChoices, type ConversationTurn } from "../lib/conversation";
import {
  type KeyMetadata,
  type ModelForm,
  type ModelKind,
  modelMetadata,
} from "../lib/model";

type View = "tasks" | "models" | "devices" | "admin";
type Role = "user" | "admin";

type User = {
  id: string;
  email: string;
  role: Role;
};

type Device = {
  id: string;
  name: string;
  platform: "windows" | "macos";
  version: string;
  keyConfigured: boolean;
  lastSeenAt: string;
};

type Model = {
  id: string;
  name: string;
  kind: ModelKind;
  baseUrl: string;
  model: string;
  contextWindow: number;
  isDefault: boolean;
  deviceId: string;
};

type WorkspaceRecord = {
  id: string;
  name: string;
  gitBranch: string | null;
  lastOpenedAt: string;
};

type FileEntry = { path: string };

type AdminOverview = {
  users: number;
  tasks: number;
  inputTokens: number;
  outputTokens: number;
};

type AdminUser = {
  id: string;
  email: string;
  role: Role;
  status: "active" | "disabled";
  deviceCount: number;
  lastLoginAt: string | null;
};

type AuditRecord = {
  id: string;
  action: string;
  resourceType: string;
  createdAt: string;
};

type AdminTaskRecord = {
  id: string;
  userEmail: string;
  workspaceName: string;
  status: "running" | "completed" | "failed" | "cancelled";
  model: string;
  inputTokens: number;
  outputTokens: number;
  durationMs: number | null;
  errorCode: string | null;
  createdAt: string;
};

function isUnauthorized(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401;
}

export default function App() {
  const [auth, setAuth] = useState<
    | { status: "loading" }
    | { status: "anonymous" }
    | { status: "authenticated"; user: User }
  >({ status: "loading" });

  useEffect(() => {
    // Remove credentials left by versions that stored bearer tokens in localStorage.
    window.localStorage.removeItem("forge_token");
    let active = true;
    api<User>("/me")
      .then((user) => active && setAuth({ status: "authenticated", user }))
      .catch(() => active && setAuth({ status: "anonymous" }));
    return () => {
      active = false;
    };
  }, []);

  const logout = useCallback(async () => {
    try {
      await api<{ loggedOut: boolean }>("/auth/logout", { method: "POST", body: "{}" });
    } finally {
      setAuth({ status: "anonymous" });
    }
  }, []);

  if (auth.status === "loading") {
    return (
      <main className="login" aria-busy="true">
        <LoaderCircle className="spin" size={26} aria-label="正在恢复会话" />
      </main>
    );
  }
  if (auth.status === "anonymous") {
    return <Login onLogin={(user) => setAuth({ status: "authenticated", user })} />;
  }
  return <Workspace me={auth.user} onLogout={logout} />;
}

function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [developmentCode, setDevelopmentCode] = useState("");
  const [error, setError] = useState("");
  const [requesting, setRequesting] = useState(false);
  const [verifying, setVerifying] = useState(false);

  async function requestCode() {
    if (!email.trim()) {
      setError("请输入邮箱地址");
      return;
    }
    setError("");
    setDevelopmentCode("");
    setRequesting(true);
    try {
      const response = await api<{ sent: boolean; developmentCode?: string }>(
        "/auth/request-code",
        { method: "POST", body: JSON.stringify({ email: email.trim() }) },
      );
      if (response.developmentCode) setDevelopmentCode(response.developmentCode);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setRequesting(false);
    }
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setVerifying(true);
    try {
      const response = await api<{ user: User }>("/auth/verify", {
        method: "POST",
        body: JSON.stringify({ email: email.trim(), code }),
      });
      onLogin(response.user);
    } catch (verifyError) {
      setError(errorMessage(verifyError));
    } finally {
      setVerifying(false);
    }
  }

  return (
    <main className="login">
      <form className="login-panel" onSubmit={verify}>
        <div className="brand-mark"><TerminalSquare size={22} /></div>
        <h1>Forge Agent</h1>
        <p>登录你的本地开发工作台</p>
        <label>
          邮箱地址
          <input
            type="email"
            autoComplete="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="name@company.com"
            required
          />
        </label>
        <button className="secondary" type="button" onClick={requestCode} disabled={requesting}>
          {requesting ? <LoaderCircle className="spin" size={16} /> : <KeyRound size={16} />}
          获取验证码
        </button>
        {developmentCode && (
          <div className="dev-code">开发验证码：<b>{developmentCode}</b></div>
        )}
        <label>
          验证码
          <input
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            value={code}
            onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))}
            maxLength={6}
            placeholder="6 位验证码"
            required
          />
        </label>
        {error && <div className="error" role="alert">{error}</div>}
        <button className="primary" type="submit" disabled={verifying || code.length !== 6}>
          {verifying ? <LoaderCircle className="spin" size={17} /> : <>进入工作台<ChevronRight size={17} /></>}
        </button>
      </form>
    </main>
  );
}

function Workspace({ me, onLogout }: { me: User; onLogout: () => void }) {
  const [view, setView] = useState<View>("tasks");
  const [devices, setDevices] = useState<Device[]>([]);
  const [models, setModels] = useState<Model[]>([]);
  const [agentOnline, setAgentOnline] = useState(false);
  const [cloudError, setCloudError] = useState("");
  const [binding, setBinding] = useState(false);
  const [bindDialogOpen, setBindDialogOpen] = useState(false);
  const [bindName, setBindName] = useState("");
  const [bindPlatform, setBindPlatform] = useState<"windows" | "macos" | null>(null);
  const [bindVersion, setBindVersion] = useState("");

  const refreshModels = useCallback(async () => {
    setModels(await api<Model[]>("/models"));
  }, []);

  useEffect(() => {
    let active = true;
    Promise.all([api<Device[]>("/devices"), api<Model[]>("/models")])
      .then(([nextDevices, nextModels]) => {
        if (!active) return;
        setDevices(nextDevices);
        setModels(nextModels);
      })
      .catch((loadError: unknown) => {
        if (!active) return;
        if (isUnauthorized(loadError)) onLogout();
        else setCloudError(errorMessage(loadError));
      });
    return () => {
      active = false;
    };
  }, [onLogout]);

  useEffect(() => {
    let active = true;
    const check = async () => {
      const online = await agentHealth();
      if (active) setAgentOnline(online);
    };
    void check();
    const timer = window.setInterval(check, 5_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    if (devices[0]) configureAgentDevice(devices[0].id);
  }, [devices]);

  async function prepareClientBinding() {
    setBinding(true);
    setCloudError("");
    try {
      const health = await getAgentHealth();
      if (!health) throw new ApiError(503, "agent_unavailable");
      const platform = health.platform === "win32" ? "windows" : health.platform === "darwin" ? "macos" : null;
      if (!platform) throw new ApiError(400, "platform_not_supported");
      setBindPlatform(platform);
      setBindVersion(health.version);
      setBindName(platform === "windows" ? "我的 Windows" : "我的 Mac");
      setBindDialogOpen(true);
    } catch (bindError) {
      setCloudError(bindError instanceof ApiError && bindError.code === "agent_unavailable" ? "请先启动 Forge 本地客户端" : errorMessage(bindError));
    } finally {
      setBinding(false);
    }
  }

  async function bindCurrentClient(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!bindPlatform || !bindName.trim()) return;
    setBinding(true);
    setCloudError("");
    try {
      const device = await api<Device>("/devices", {
        method: "POST",
        body: JSON.stringify({ name: bindName.trim().slice(0, 80), platform: bindPlatform, version: bindVersion }),
      });
      configureAgentDevice(device.id);
      setDevices([device]);
      setBindDialogOpen(false);
    } catch (bindError) {
      setCloudError(errorMessage(bindError));
    } finally {
      setBinding(false);
    }
  }

  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <div className="brand-mark"><TerminalSquare size={19} /></div>
          <b>Forge</b>
        </div>
        <nav aria-label="主导航">
          <Nav icon={LayoutDashboard} active={view === "tasks"} onClick={() => setView("tasks")}>任务</Nav>
          <Nav icon={Cpu} active={view === "models"} onClick={() => setView("models")}>模型</Nav>
          <Nav icon={Monitor} active={view === "devices"} onClick={() => setView("devices")}>设备</Nav>
          {me.role === "admin" && (
            <Nav icon={ShieldCheck} active={view === "admin"} onClick={() => setView("admin")}>管理后台</Nav>
          )}
        </nav>
        <div className="aside-bottom">
          <div className={`agent-state ${agentOnline ? "online" : ""}`}>
            <span />{agentOnline ? "本地客户端在线" : "本地客户端离线"}
          </div>
          <button className="user" onClick={onLogout} title="退出登录">
            <div className="avatar">{me.email.charAt(0).toUpperCase()}</div>
            <span>{me.email}<small>{me.role === "admin" ? "管理员" : "用户"}</small></span>
            <LogOut size={15} />
          </button>
        </div>
      </aside>
      <main className="content">
        {cloudError && <div className="page-error" role="alert">{cloudError}</div>}
        {!devices.length && view !== "admin" && (
          <div className="binding-notice">
            <Monitor size={18} />
            <div><b>绑定当前客户端</b><span>绑定后才能选择文件夹、保存密钥并运行本地任务。</span></div>
            <button className="primary" onClick={prepareClientBinding} disabled={!agentOnline || binding}>
              {binding && <LoaderCircle className="spin" size={16} />}绑定
            </button>
          </div>
        )}
        <div className={`view-slot${view === "tasks" ? " active" : ""}`} aria-hidden={view !== "tasks"}>
          <Tasks agentOnline={agentOnline} devices={devices} models={models} />
        </div>
        {view === "models" && (
          <Models
            agentOnline={agentOnline}
            devices={devices}
            models={models}
            refresh={refreshModels}
          />
        )}
        {view === "devices" && <Devices devices={devices} />}
        {view === "admin" && me.role === "admin" && <Admin onUnauthorized={onLogout} />}
        {bindDialogOpen && (
          <div className="modal-bg" role="presentation">
            <form className="modal device-modal" role="dialog" aria-modal="true" aria-labelledby="bind-device-title" onSubmit={bindCurrentClient}>
              <div className="modal-heading">
                <div><h2 id="bind-device-title">绑定当前客户端</h2><p>{bindPlatform === "windows" ? "Windows" : "macOS"} · v{bindVersion}</p></div>
                <button className="icon-button" type="button" onClick={() => setBindDialogOpen(false)} disabled={binding} title="关闭" aria-label="关闭"><X size={18} /></button>
              </div>
              <label>设备名称<input autoFocus value={bindName} onChange={(event) => setBindName(event.target.value)} maxLength={80} required /></label>
              <div className="modal-actions">
                <button className="secondary" type="button" onClick={() => setBindDialogOpen(false)} disabled={binding}>取消</button>
                <button className="primary" type="submit" disabled={binding || !bindName.trim()}>{binding && <LoaderCircle className="spin" size={16} />}确认绑定</button>
              </div>
            </form>
          </div>
        )}
      </main>
    </div>
  );
}

function Nav({
  icon: Icon,
  active,
  onClick,
  children,
}: {
  icon: LucideIcon;
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button className={active ? "active" : ""} aria-current={active ? "page" : undefined} onClick={onClick}>
      <Icon size={17} />{children}
    </button>
  );
}

type AgentTaskStatus = "running" | "waiting" | "completed" | "failed" | "cancelled";
type PublicToolCall = { id: string; name: string; arguments: Record<string, unknown> };
type AgentTaskSnapshot = {
  id: string;
  status: AgentTaskStatus;
  pending?: PublicToolCall;
  turn: number;
  usedTokens: number;
  maxTokens: number;
};
type LocalAgentEvent = {
  taskId: string;
  deviceId: string;
  sequence: number;
  timestamp: string;
  type: "message.delta" | "task.status" | "tool.request" | "approval.request" | "terminal.output" | "file.changed" | "error" | "task.completed";
  payload: Record<string, unknown>;
};
type TaskRun = {
  id: string;
  deviceId: string;
  workspaceId: string;
  workspaceName: string;
  model: Model;
  prompt: string;
};

function validAgentEvent(value: unknown, taskId: string, deviceId: string): value is LocalAgentEvent {
  if (!value || typeof value !== "object") return false;
  const event = value as Partial<LocalAgentEvent>;
  const types = new Set<LocalAgentEvent["type"]>([
    "message.delta", "task.status", "tool.request", "approval.request",
    "terminal.output", "file.changed", "error", "task.completed",
  ]);
  return event.taskId === taskId && event.deviceId === deviceId && typeof event.sequence === "number" && Number.isInteger(event.sequence) &&
    typeof event.timestamp === "string" && typeof event.type === "string" && types.has(event.type as LocalAgentEvent["type"]) &&
    Boolean(event.payload && typeof event.payload === "object" && !Array.isArray(event.payload));
}

function eventText(event: LocalAgentEvent, key: string): string {
  const value = event.payload[key];
  return typeof value === "string" ? value : "";
}

function eventNumber(event: LocalAgentEvent, key: string): number {
  const value = event.payload[key];
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function eventToolCall(event: LocalAgentEvent): PublicToolCall | null {
  const value = event.payload.toolCall;
  if (!value || typeof value !== "object") return null;
  const call = value as Partial<PublicToolCall>;
  if (typeof call.id !== "string" || typeof call.name !== "string") return null;
  const args = call.arguments && typeof call.arguments === "object" && !Array.isArray(call.arguments)
    ? call.arguments as Record<string, unknown>
    : {};
  return { id: call.id, name: call.name, arguments: args };
}

function Tasks({
  agentOnline,
  devices,
  models,
}: {
  agentOnline: boolean;
  devices: Device[];
  models: Model[];
}) {
  const [workspace, setWorkspace] = useState<WorkspaceRecord | null>(null);
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [prompt, setPrompt] = useState("");
  const [opening, setOpening] = useState(false);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");
  const [deviceId, setDeviceId] = useState(devices[0]?.id ?? "");
  const [modelId, setModelId] = useState("");
  const [taskRun, setTaskRun] = useState<TaskRun | null>(null);
  const [task, setTask] = useState<AgentTaskSnapshot | null>(null);
  const [events, setEvents] = useState<LocalAgentEvent[]>([]);
  const [approvalBusy, setApprovalBusy] = useState("");
  const [diff, setDiff] = useState("");
  const sequenceRef = useRef(-1);
  const inputTokensRef = useRef(0);
  const outputTokensRef = useRef(0);
  const errorCodeRef = useRef("");
  const startedAtRef = useRef(0);
  const reportedTaskRef = useRef("");
  const historyRef = useRef<ConversationTurn[]>([]);
  const assistantReplyRef = useRef("");
  const queuedPromptRef = useRef("");
  const [history, setHistory] = useState<ConversationTurn[]>([]);
  const [permissionGranted, setPermissionGranted] = useState(false);
  const [permissionOpen, setPermissionOpen] = useState(false);
  const [choicePrompt, setChoicePrompt] = useState<{ question: string; options: string[] } | null>(null);

  const deviceModels = models.filter((model) => model.deviceId === deviceId);
  const selectedModel = deviceModels.find((model) => model.id === modelId) ?? null;
  const active = task?.status === "running" || task?.status === "waiting";

  useEffect(() => {
    if (!deviceId && devices[0]) setDeviceId(devices[0].id);
  }, [deviceId, devices]);

  useEffect(() => {
    const eligibleModels = models.filter((model) => model.deviceId === deviceId);
    if (eligibleModels.some((model) => model.id === modelId)) return;
    const next = eligibleModels.find((model) => model.isDefault) ?? eligibleModels[0];
    setModelId(next?.id ?? "");
  }, [deviceId, modelId, models]);

  useEffect(() => {
    if (!taskRun) return;
    let disposed = false;
    let timer = 0;
    let socket: WebSocket | null = null;
    let terminal = false;
    let websocketFailures = 0;

    async function finalize(snapshot: AgentTaskSnapshot) {
      if (reportedTaskRef.current === taskRun!.id) return;
      reportedTaskRef.current = taskRun!.id;

      const assistant = assistantReplyRef.current.trim();
      if (assistant) {
        const nextHistory = [...historyRef.current, { user: taskRun!.prompt, assistant }].slice(-12);
        historyRef.current = nextHistory;
        setHistory(nextHistory);
        const options = modelChoices(assistant);
        if (options.length) setChoicePrompt({ question: assistant, options });
      }

      const [nextFiles, nextDiff] = await Promise.allSettled([
        agentApi<FileEntry[]>(`/workspaces/${taskRun!.workspaceId}/files`, {}, taskRun!.deviceId),
        agentApi<{ diff: string; exitCode: number }>(`/workspaces/${taskRun!.workspaceId}/diff`, {}, taskRun!.deviceId),
      ]);
      if (!disposed && nextFiles.status === "fulfilled") setFiles(nextFiles.value);
      if (!disposed && nextDiff.status === "fulfilled") setDiff(nextDiff.value.diff);

      try {
        await api<{ id: string }>("/usage/events", {
          method: "POST",
          body: JSON.stringify({
            deviceId: taskRun!.deviceId,
            workspaceName: usageWorkspaceName(taskRun!.workspaceName),
            status: snapshot.status,
            model: taskRun!.model.model,
            inputTokens: inputTokensRef.current,
            outputTokens: outputTokensRef.current,
            durationMs: Math.min(86_400_000, Math.max(0, Date.now() - startedAtRef.current)),
            ...(errorCodeRef.current ? { errorCode: errorCodeRef.current } : {}),
          }),
          headers: { "idempotency-key": taskRun!.id },
        });
      } catch {
        if (!disposed) setError("任务已结束，但使用统计暂未上报");
      }
    }

    function consume(response: { events: unknown[]; task: AgentTaskSnapshot }) {
      if (disposed) return;
      const incoming = Array.isArray(response.events)
        ? response.events.filter((event) => validAgentEvent(event, taskRun!.id, taskRun!.deviceId))
        : [];
      if (incoming.length) {
        for (const event of incoming) {
          sequenceRef.current = Math.max(sequenceRef.current, event.sequence);
          if (event.type === "message.delta") {
            inputTokensRef.current += eventNumber(event, "inputTokens");
            outputTokensRef.current += eventNumber(event, "outputTokens");
            const content = eventText(event, "content");
            if (content) assistantReplyRef.current += `${assistantReplyRef.current ? "\n" : ""}${content}`;
          }
          if (event.type === "error") errorCodeRef.current = eventText(event, "code").slice(0, 100);
        }
        setEvents((current) => [...current, ...incoming].slice(-2_000));
      }
      setTask(response.task);
      setError("");
      if (["completed", "failed", "cancelled"].includes(response.task.status)) {
        terminal = true;
        void finalize(response.task);
      }
    }

    async function poll() {
      if (disposed || terminal) return;
      try {
        consume(await agentApi<{ events: unknown[]; task: AgentTaskSnapshot }>(
          `/tasks/${taskRun!.id}/events?after=${sequenceRef.current}`,
          {},
          taskRun!.deviceId,
        ));
        if (!terminal) timer = window.setTimeout(poll, 700);
      } catch (pollError) {
        if (disposed) return;
        setError(agentErrorMessage(pollError));
        timer = window.setTimeout(poll, 2_000);
      }
    }

    async function connectEvents() {
      if (disposed || terminal) return;
      try {
        const currentSocket = await agentEventSocket(taskRun!.id, taskRun!.deviceId, sequenceRef.current);
        socket = currentSocket;
        if (disposed) return currentSocket.close();
        let opened = false;
        const openTimer = window.setTimeout(() => currentSocket.close(), 5_000);
        currentSocket.addEventListener("open", () => {
          opened = true;
          websocketFailures = 0;
          window.clearTimeout(openTimer);
        }, { once: true });
        currentSocket.addEventListener("message", (message) => {
          try {
            const parsed = JSON.parse(String(message.data)) as { events: unknown[]; task: AgentTaskSnapshot };
            consume(parsed);
          } catch {
            currentSocket.close(1003, "invalid event payload");
          }
        });
        currentSocket.addEventListener("close", () => {
          window.clearTimeout(openTimer);
          if (disposed || terminal) return;
          if (!opened) websocketFailures += 1;
          timer = window.setTimeout(websocketFailures >= 2 ? poll : connectEvents, 500);
        }, { once: true });
      } catch {
        if (!disposed) timer = window.setTimeout(poll, 500);
      }
    }

    void connectEvents();
    return () => {
      disposed = true;
      window.clearTimeout(timer);
      socket?.close();
    };
  }, [taskRun]);

  function changeDevice(nextDeviceId: string) {
    configureAgentDevice(nextDeviceId);
    setDeviceId(nextDeviceId);
    setWorkspace(null);
    setFiles([]);
    setDiff("");
    setTaskRun(null);
    setTask(null);
    setEvents([]);
    setPermissionGranted(false);
    setChoicePrompt(null);
    historyRef.current = [];
    setHistory([]);
  }

  async function openWorkspace() {
    setOpening(true);
    setError("");
    try {
      const selected = await agentApi<WorkspaceRecord>("/workspaces/select", { method: "POST" }, deviceId);
      const entries = await agentApi<FileEntry[]>(`/workspaces/${selected.id}/files`, {}, deviceId);
      setWorkspace(selected);
      setFiles(entries);
      setDiff("");
      setTaskRun(null);
      setTask(null);
      setEvents([]);
      setPermissionGranted(false);
      setChoicePrompt(null);
      historyRef.current = [];
      setHistory([]);
    } catch (openError) {
      setError(agentErrorMessage(openError));
    } finally {
      setOpening(false);
    }
  }

  async function startTask(forcePermission = false, promptOverride?: string) {
    const submittedPrompt = (promptOverride ?? prompt).trim();
    if (!workspace || !selectedModel || !submittedPrompt || active) return;
    if (!permissionGranted && !forcePermission) {
      queuedPromptRef.current = submittedPrompt;
      setPermissionOpen(true);
      return;
    }
    setStarting(true);
    setError("");
    setDiff("");
    try {
      const snapshot = await agentApiWithApproval<AgentTaskSnapshot>(
        "/tasks",
        {
          workspaceId: workspace.id,
          provider: selectedModel.id,
          kind: selectedModel.kind,
          baseUrl: selectedModel.baseUrl,
          model: selectedModel.model,
          prompt: buildContextPrompt(historyRef.current, submittedPrompt),
          maxTurns: 20,
          maxTokens: Math.max(1_024, Math.min(selectedModel.contextWindow, 1_000_000)),
        },
        deviceId,
      );
      sequenceRef.current = -1;
      inputTokensRef.current = 0;
      outputTokensRef.current = 0;
      errorCodeRef.current = "";
      startedAtRef.current = Date.now();
      reportedTaskRef.current = "";
      assistantReplyRef.current = "";
      setTaskRun({
        id: snapshot.id,
        deviceId,
        workspaceId: workspace.id,
        workspaceName: workspace.name,
        model: selectedModel,
        prompt: submittedPrompt,
      });
      setTask(snapshot);
      setEvents([]);
      setPrompt("");
    } catch (startError) {
      setError(agentErrorMessage(startError));
    } finally {
      setStarting(false);
    }
  }

  async function decideApproval(toolCallId: string, approved: boolean) {
    if (!taskRun) return;
    setApprovalBusy(toolCallId);
    setError("");
    try {
      const snapshot = await agentApi<AgentTaskSnapshot>(
        `/tasks/${taskRun.id}/approvals/${encodeURIComponent(toolCallId)}`,
        { method: "POST", body: JSON.stringify({ approved }) },
        taskRun.deviceId,
      );
      setTask(snapshot);
    } catch (approvalError) {
      setError(agentErrorMessage(approvalError));
    } finally {
      setApprovalBusy("");
    }
  }

  async function cancelTask() {
    if (!taskRun || !active) return;
    setError("");
    try {
      setTask(await agentApi<AgentTaskSnapshot>(
        `/tasks/${taskRun.id}/cancel`,
        { method: "POST", body: "{}" },
        taskRun.deviceId,
      ));
    } catch (cancelError) {
      setError(agentErrorMessage(cancelError));
    }
  }

  return (
    <>
      <header>
        <div><h1>编码任务</h1><p>在授权的本地工作区中规划、编辑并验证代码</p></div>
        <div className="header-actions">
          {devices.length > 0 && (
            <label className="device-picker">
              <span>本机设备</span>
              <select value={deviceId} onChange={(event) => changeDevice(event.target.value)} disabled={opening || active}>
                {devices.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}
              </select>
            </label>
          )}
          <button className="secondary" disabled={!agentOnline || !deviceId || opening || active} onClick={openWorkspace}>
            {opening ? <LoaderCircle className="spin" size={17} /> : <FolderOpen size={17} />}
            打开文件夹
          </button>
        </div>
      </header>
      {error && <div className="page-error" role="alert">{error}</div>}
      <div className="task-layout">
        <section className="explorer">
          <div className="panel-title"><span>工作区</span><Search size={15} /></div>
          {workspace ? (
            <>
              <div className="workspace-name"><FolderOpen size={16} /><span>{workspace.name}</span></div>
              <div className="file-list">
                {files.map((file) => (
                  <div key={file.path} title={file.path}><FileCode2 size={14} /><span>{file.path}</span></div>
                ))}
              </div>
            </>
          ) : (
            <div className="empty compact">
              <FolderOpen size={28} /><b>尚未打开文件夹</b>
              <span>{agentOnline ? "选择一个目录开始" : "请先启动 Forge 托盘客户端"}</span>
            </div>
          )}
        </section>
        <section className="agent-panel">
          <div className="panel-title">
            <span>{task ? taskStatusLabel(task.status) : "新任务"}</span>
            <span className="privacy"><ShieldCheck size={13} />代码仅在本机处理</span>
          </div>
          <div className="conversation" aria-live="polite">
            {!taskRun ? (
              <div className="empty">
                <Bot size={38} /><b>准备处理代码任务</b>
                <span>描述要实现的功能、需要修复的问题或希望分析的代码。</span>
              </div>
            ) : (
              <div className="message-list">
                {history.slice(0, task && ["completed", "failed", "cancelled"].includes(task.status) ? -1 : undefined).map((turn, index) => (
                  <div key={`${index}-${turn.user}`}>
                    <div className="message user-message"><small>你</small><p>{turn.user}</p></div>
                    <div className="message assistant-message"><small>Forge</small><p>{turn.assistant}</p></div>
                  </div>
                ))}
                <div className="message user-message"><small>你</small><p>{taskRun.prompt}</p></div>
                {events.filter((event) => event.type === "message.delta" && eventText(event, "content").length > 0).map((event) => (
                  <div className="message assistant-message" key={event.sequence}>
                    <small>Forge</small><p>{eventText(event, "content")}</p>
                  </div>
                ))}
                {task?.status === "failed" && (
                  <div className="message task-error"><AlertTriangle size={16} /><p>{taskErrorLabel(errorCodeRef.current)}</p></div>
                )}
                {active && <div className="thinking"><LoaderCircle className="spin" size={15} />正在处理</div>}
              </div>
            )}
          </div>
          <div className="composer">
            <textarea
              value={prompt}
              onChange={(event) => setPrompt(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
                  event.preventDefault();
                  void startTask();
                }
              }}
              placeholder={workspace ? "向 Agent 描述任务…" : "先打开一个工作区"}
              disabled={!workspace || active || starting}
              maxLength={100_000}
            />
            <div>
              <label className="model-picker">
                <span>模型</span>
                <select value={modelId} onChange={(event) => setModelId(event.target.value)} disabled={active || starting || !deviceModels.length}>
                  {!deviceModels.length && <option value="">未配置</option>}
                  {deviceModels.map((model) => <option key={model.id} value={model.id}>{model.name} · {model.model}</option>)}
                </select>
              </label>
              <div className="composer-actions">
                {active && (
                  <button className="secondary icon" onClick={cancelTask} aria-label="取消任务" title="取消任务">
                    <CircleStop size={16} />
                  </button>
                )}
                <button
                  className="primary icon"
                  disabled={!workspace || !selectedModel || !prompt.trim() || active || starting}
                  onClick={() => void startTask()}
                  aria-label="运行任务"
                  title="运行任务"
                >
                  {starting ? <LoaderCircle className="spin" size={16} /> : <Play size={16} />}
                </button>
              </div>
            </div>
          </div>
        </section>
        <section className="activity">
          <div className="panel-title">执行记录</div>
          {!events.length && !diff ? (
            <div className="empty compact"><Activity size={26} /><b>暂无活动</b><span>工具调用、审批和 Diff 将显示在这里</span></div>
          ) : (
            <div className="activity-list">
              {events.filter((event) => event.type !== "message.delta").map((event) => {
                const call = event.type === "approval.request" ? eventToolCall(event) : null;
                const pending = call && task?.pending?.id === call.id;
                return (
                  <div className={`activity-item ${event.type === "approval.request" ? "approval-item" : ""}`} key={event.sequence}>
                    {event.type === "approval.request" ? <ShieldCheck size={15} /> : event.type === "error" ? <AlertTriangle size={15} /> : event.type === "task.completed" ? <Check size={15} /> : <Wrench size={15} />}
                    <div>
                      <b>{activityTitle(event, call)}</b>
                      <span>{activityDetail(event, call)}</span>
                      {pending && call && (
                        <div className="approval-actions">
                          <button className="secondary" disabled={approvalBusy === call.id} onClick={() => decideApproval(call.id, false)}>拒绝</button>
                          <button className="primary" disabled={approvalBusy === call.id} onClick={() => decideApproval(call.id, true)}>允许</button>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
              {diff && (
                <div className="diff-block">
                  <b><FileDiff size={15} />Git Diff</b>
                  <pre>{diff}</pre>
                </div>
              )}
            </div>
          )}
        </section>
      </div>
      {permissionOpen && (
        <div className="modal-bg" role="presentation">
          <div className="modal confirm-modal" role="dialog" aria-modal="true" aria-labelledby="workspace-permission-title">
            <div className="modal-heading">
              <div><h2 id="workspace-permission-title">允许本次工作区会话执行操作？</h2><p>确认后，Agent 可在当前工作区读写文件并运行命令，不再逐次询问。高风险系统命令仍会被拒绝。</p></div>
            </div>
            <div className="modal-actions">
              <button className="secondary" onClick={() => setPermissionOpen(false)}>取消</button>
              <button className="primary" onClick={() => {
                setPermissionGranted(true);
                setPermissionOpen(false);
                void startTask(true, queuedPromptRef.current);
              }}>确认并执行</button>
            </div>
          </div>
        </div>
      )}
      {choicePrompt && (
        <div className="modal-bg" role="presentation">
          <div className="modal confirm-modal" role="dialog" aria-modal="true" aria-labelledby="model-choice-title">
            <div className="modal-heading">
              <div><h2 id="model-choice-title">Forge 需要你的选择</h2><p>{choicePrompt.question}</p></div>
            </div>
            <div className="choice-actions">
              {choicePrompt.options.map((option) => (
                <button className="secondary" key={option} onClick={() => {
                  setChoicePrompt(null);
                  void startTask(true, option);
                }}>{option}</button>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function taskStatusLabel(status: AgentTaskStatus): string {
  return { running: "运行中", waiting: "等待审批", completed: "已完成", failed: "失败", cancelled: "已取消" }[status];
}

function usageWorkspaceName(value: string): string {
  const sanitized = value
    .replace(/[\\/\u0000-\u001f\u007f]/g, "_")
    .replace(/^[A-Za-z]:/, "_")
    .trim()
    .slice(0, 120);
  return sanitized || "workspace";
}

function taskErrorLabel(code: string): string {
  const labels: Record<string, string> = {
    context_budget_exceeded: "上下文长度超过限制",
    max_turns_exceeded: "已达到最大执行轮数",
    model_timeout: "模型响应超时",
    token_budget_exceeded: "已达到 Token 预算",
  };
  return labels[code] ?? "任务执行失败";
}

function activityTitle(event: LocalAgentEvent, call: PublicToolCall | null): string {
  if (event.type === "approval.request") return `请求审批：${call?.name ?? "工具"}`;
  if (event.type === "tool.request") return `执行工具：${eventText(event, "name") || "未知工具"}`;
  if (event.type === "task.completed") return "任务完成";
  if (event.type === "error") return "执行失败";
  if (event.type === "file.changed") return "文件已变更";
  if (event.type === "terminal.output") return "终端输出";
  return eventText(event, "status") === "tool_completed" ? "工具执行完成" : "状态更新";
}

function activityDetail(event: LocalAgentEvent, call: PublicToolCall | null): string {
  if (call) {
    const path = call.arguments.path;
    return `${eventText(event, "risk") || "write"}${typeof path === "string" ? ` · ${path}` : ""}`;
  }
  if (event.type === "error") return eventText(event, "code") || "operation_failed";
  if (event.type === "terminal.output") {
    const output = eventText(event, "stderr") || eventText(event, "stdout");
    const exitCode = typeof event.payload.exitCode === "number" ? event.payload.exitCode : "—";
    const timedOut = event.payload.timedOut === true ? " · 已超时" : "";
    return `exit ${exitCode}${timedOut}${output ? ` · ${output.slice(0, 240)}` : ""}`;
  }
  if (event.type === "file.changed") return eventText(event, "path");
  if (event.type === "task.completed") return `${eventNumber(event, "turns")} 轮 · ${eventNumber(event, "totalTokens").toLocaleString()} tokens`;
  return eventText(event, "tool") || eventText(event, "status");
}

function Models({
  agentOnline,
  devices,
  models,
  refresh,
}: {
  agentOnline: boolean;
  devices: Device[];
  models: Model[];
  refresh: () => Promise<void>;
}) {
  const [modalOpen, setModalOpen] = useState(false);
  const [error, setError] = useState("");

  return (
    <>
      <header>
        <div><h1>模型配置</h1><p>API Key 直接保存到当前设备的系统密钥库</p></div>
        <button
          className="primary"
          disabled={!devices.length || !agentOnline}
          onClick={() => setModalOpen(true)}
        >
          <Plus size={17} />添加模型
        </button>
      </header>
      {error && <div className="page-error" role="alert">{error}</div>}
      <div className="notice">
        <ShieldCheck size={18} />
        <div><b>密钥不会上传到云端</b><span>服务端仅保存供应商、模型信息、Key 指纹与末四位。</span></div>
      </div>
      <div className="table">
        <div className="tr th"><span>配置</span><span>模型</span><span>设备</span><span>状态</span></div>
        {models.map((model) => (
          <div className="tr" key={model.id}>
            <span><b>{model.name}</b><small>{model.kind}</small></span>
            <span>{model.model}<small>{model.contextWindow.toLocaleString()} tokens</small></span>
            <span>{devices.find((device) => device.id === model.deviceId)?.name ?? "未知"}</span>
            <span><i className="status-dot" />{model.isDefault ? "默认" : "可用"}</span>
          </div>
        ))}
        {!models.length && <div className="empty-row">尚未配置模型</div>}
      </div>
      {modalOpen && (
        <ModelModal
          devices={devices}
          close={() => setModalOpen(false)}
          done={async () => {
            setModalOpen(false);
            try {
              await refresh();
            } catch (refreshError) {
              setError(errorMessage(refreshError));
            }
          }}
        />
      )}
    </>
  );
}

const MODEL_PRESETS: Record<Exclude<ModelKind, "openai-compatible">, Pick<ModelForm, "name" | "baseUrl" | "model">> = {
  openai: { name: "OpenAI", baseUrl: "https://api.openai.com/v1", model: "gpt-5" },
  anthropic: { name: "Anthropic", baseUrl: "https://api.anthropic.com/v1", model: "claude-sonnet-4-5" },
};

function ModelModal({
  devices,
  close,
  done,
}: {
  devices: Device[];
  close: () => void;
  done: () => Promise<void>;
}) {
  const [form, setForm] = useState<ModelForm>(() => ({
    configId: crypto.randomUUID(),
    name: "OpenAI",
    kind: "openai",
    baseUrl: "https://api.openai.com/v1",
    model: "gpt-5",
    contextWindow: 200_000,
    deviceId: devices[0]?.id ?? "",
    apiKey: "",
    isDefault: true,
  }));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !saving) close();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [close, saving]);

  function changeKind(kind: ModelKind) {
    if (kind === "openai-compatible") {
      setForm((current) => ({ ...current, kind, name: "自定义 API", baseUrl: "", model: "" }));
      return;
    }
    setForm((current) => ({ ...current, kind, ...MODEL_PRESETS[kind] }));
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setSaving(true);
    try {
      const parsedUrl = new URL(form.baseUrl);
      if (!(["http:", "https:"] as const).includes(parsedUrl.protocol as "http:" | "https:")) {
        throw new Error("invalid_url");
      }

      const key = await agentApiWithApproval<KeyMetadata>(
        "/secrets",
        {
          deviceId: form.deviceId,
          provider: form.configId,
          apiKey: form.apiKey,
        },
        form.deviceId,
      );
      if (key.keyLastFour.length !== 4 || !/^[a-f0-9]{64}$/i.test(key.keyFingerprint)) {
        throw new ApiError(502, "invalid_key_metadata");
      }

      const metadata = modelMetadata(form, key);
      const testResult = await agentApiWithApproval<{ ok: boolean; status: number; model: string }>(
        "/models/test",
        {
          deviceId: form.deviceId,
          provider: form.configId,
          kind: form.kind,
          baseUrl: form.baseUrl.trim(),
          model: form.model.trim(),
        },
        form.deviceId,
      );
      if (!testResult.ok) throw new ApiError(502, `model_http_${testResult.status}`);
      setForm((current) => ({ ...current, apiKey: "" }));
      await api<Model>("/models", { method: "POST", body: JSON.stringify(metadata) });
      await done();
    } catch (saveError) {
      if (saveError instanceof TypeError && saveError.message.includes("URL")) {
        setError("请输入有效的 API Base URL");
      } else if (saveError instanceof ApiError && saveError.code.startsWith("agent")) {
        setError(agentErrorMessage(saveError));
      } else if (saveError instanceof ApiError && [401, 403, 408, 409, 502, 503].includes(saveError.status)) {
        setError(agentErrorMessage(saveError));
      } else {
        setError(errorMessage(saveError));
      }
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="modal-bg" role="presentation">
      <form className="modal" role="dialog" aria-modal="true" aria-labelledby="model-dialog-title" onSubmit={save}>
        <div className="modal-heading">
          <div><h2 id="model-dialog-title">添加模型配置</h2><p>连接信息保存在账号中，密钥仅写入所选设备。</p></div>
          <button className="icon-button" type="button" onClick={close} disabled={saving} title="关闭" aria-label="关闭">
            <X size={18} />
          </button>
        </div>
        <div className="form-grid">
          <label>名称<input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} maxLength={80} required /></label>
          <label>
            供应商
            <select value={form.kind} onChange={(event) => changeKind(event.target.value as ModelKind)}>
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
              <option value="openai-compatible">兼容 API</option>
            </select>
          </label>
          <label className="wide">API Base URL<input type="url" value={form.baseUrl} onChange={(event) => setForm({ ...form, baseUrl: event.target.value })} placeholder="https://api.example.com/v1" required /></label>
          <label>模型 ID<input value={form.model} onChange={(event) => setForm({ ...form, model: event.target.value })} maxLength={160} required /></label>
          <label>上下文长度<input type="number" min={1024} max={2_000_000} value={form.contextWindow} onChange={(event) => setForm({ ...form, contextWindow: Number(event.target.value) })} required /></label>
          <label className="wide">API Key<input type="password" autoComplete="new-password" value={form.apiKey} onChange={(event) => setForm({ ...form, apiKey: event.target.value })} minLength={8} required /></label>
          <label className="wide">
            保存到设备
            <select value={form.deviceId} onChange={(event) => setForm({ ...form, deviceId: event.target.value })} required>
              {devices.map((device) => <option value={device.id} key={device.id}>{device.name}</option>)}
            </select>
          </label>
        </div>
        {error && <div className="error" role="alert">{error}</div>}
        <div className="modal-actions">
          <button className="secondary" type="button" onClick={close} disabled={saving}>取消</button>
          <button className="primary" type="submit" disabled={saving}>
            {saving && <LoaderCircle className="spin" size={16} />}保存配置
          </button>
        </div>
      </form>
    </div>
  );
}

function Devices({ devices }: { devices: Device[] }) {
  return (
    <>
      <header><div><h1>设备</h1><p>管理已绑定的本地执行器及其在线状态</p></div></header>
      <div className="cards">
        {devices.map((device) => (
          <div className="card" key={device.id}>
            <Monitor />
            <div><b>{device.name}</b><span>{device.platform} · v{device.version}</span></div>
            <i className="status-dot" />
            <small>{device.keyConfigured ? "已配置密钥" : "未配置密钥"}</small>
          </div>
        ))}
        {!devices.length && (
          <div className="empty wide"><Monitor size={38} /><b>没有已绑定设备</b><span>启动托盘客户端并登录后，设备会出现在这里。</span></div>
        )}
      </div>
    </>
  );
}

function Admin({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [data, setData] = useState<AdminOverview | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [audits, setAudits] = useState<AuditRecord[]>([]);
  const [tasks, setTasks] = useState<AdminTaskRecord[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    Promise.all([
      api<AdminOverview>("/admin/overview"),
      api<AdminUser[]>("/admin/users"),
      api<AuditRecord[]>("/admin/audits"),
      api<AdminTaskRecord[]>("/admin/tasks"),
    ])
      .then(([overview, nextUsers, nextAudits, nextTasks]) => {
        if (!active) return;
        setData(overview);
        setUsers(nextUsers);
        setAudits(nextAudits);
        setTasks(nextTasks);
      })
      .catch((loadError: unknown) => {
        if (!active) return;
        if (isUnauthorized(loadError)) onUnauthorized();
        else setError(errorMessage(loadError));
      });
    return () => {
      active = false;
    };
  }, [onUnauthorized]);

  return (
    <>
      <header><div><h1>管理后台</h1><p>平台运行状态、账号与隐私安全审计</p></div></header>
      {error && <div className="page-error" role="alert">{error}</div>}
      <div className="metrics">
        <Metric icon={Users} label="注册用户" value={data?.users ?? "—"} />
        <Metric icon={Gauge} label="任务总数" value={data?.tasks ?? "—"} />
        <Metric icon={Cpu} label="输入 Token" value={Number(data?.inputTokens ?? 0).toLocaleString()} />
        <Metric icon={Activity} label="输出 Token" value={Number(data?.outputTokens ?? 0).toLocaleString()} />
      </div>
      <h2 className="section-title">最近任务</h2>
      <div className="table">
        <div className="tr usage th"><span>用户</span><span>工作区</span><span>模型</span><span>状态</span><span>Token</span><span>时间</span></div>
        {tasks.map((task) => (
          <div className="tr usage" key={task.id}>
            <span>{task.userEmail}</span>
            <span>{task.workspaceName}</span>
            <span>{task.model}</span>
            <span>{task.status}<small>{task.errorCode ?? (task.durationMs === null ? "—" : `${Math.round(task.durationMs / 1000)}s`)}</small></span>
            <span>{(task.inputTokens + task.outputTokens).toLocaleString()}</span>
            <span>{formatDate(task.createdAt)}</span>
          </div>
        ))}
        {!tasks.length && <div className="empty-row">暂无任务使用记录</div>}
      </div>
      <h2 className="section-title">最近用户</h2>
      <div className="table">
        <div className="tr admin th"><span>账号</span><span>角色</span><span>设备</span><span>状态</span><span>最近登录</span></div>
        {users.map((user) => (
          <div className="tr admin" key={user.id}>
            <span>{user.email}</span><span>{user.role}</span><span>{user.deviceCount}</span><span>{user.status}</span>
            <span>{formatDate(user.lastLoginAt)}</span>
          </div>
        ))}
      </div>
      <h2 className="section-title">审计日志</h2>
      <div className="audit-list">
        {audits.slice(0, 20).map((audit) => (
          <div key={audit.id}>
            <ShieldCheck size={15} /><b>{audit.action}</b><span>{audit.resourceType}</span><time>{formatDate(audit.createdAt)}</time>
          </div>
        ))}
      </div>
    </>
  );
}

function Metric({ icon: Icon, label, value }: { icon: LucideIcon; label: string; value: ReactNode }) {
  return <div className="metric"><Icon size={19} /><span>{label}</span><b>{value}</b></div>;
}

function formatDate(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}
