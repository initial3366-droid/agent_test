import { createHash, randomUUID } from "node:crypto";
import { rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import type { Duplex } from "node:stream";
import cors from "@fastify/cors";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { execa } from "execa";
import keytar from "keytar";
import { fileMutationSchema } from "@forge/protocol";
import { AgentRuntime, HttpModelProvider } from "@forge/agent-core";
import { z, ZodError } from "zod";
import { ApprovalStore, nativeLocalApprover, requestHash, safeChildEnvironment, type ApprovalRisk, type LocalApprover } from "./approvals.js";
import {
  bearerToken,
  FORGE_CLIENT_HEADER,
  generateBootstrapToken,
  SessionManager,
  validateBootstrapToken,
  type AgentSession
} from "./auth.js";
import { assessEndpoint, postModelJson, probeModelEndpoint } from "./network.js";
import { safeGitDiff } from "./git.js";
import { defaultExecutionPolicy, SYSTEM_PROMPT, workspaceTools } from "./task-tools.js";
import { WorkspaceStore } from "./workspaces.js";
import { closeFrame, textFrame, websocketAccept, websocketProtocols } from "./websocket.js";

const VERSION = "0.1.0";
const DEFAULT_PORT = 47_621;
const MAX_OUTPUT_BYTES = 1_000_000;
const COMMAND_LIMIT = 2;
const requestSessions = new WeakMap<FastifyRequest, AgentSession>();

export interface SecretStore {
  setPassword(service: string, account: string, password: string): Promise<void>;
  getPassword(service: string, account: string): Promise<string | null>;
}

export interface AgentServerOptions {
  port?: number;
  origin?: string;
  bootstrapToken?: string;
  sessionTtlMs?: number;
  deviceId?: string;
  expectedHosts?: string[];
  store?: WorkspaceStore;
  secrets?: SecretStore;
  localApprover?: LocalApprover;
  chooseFolder?: () => Promise<string>;
  logger?: boolean;
}

export interface AgentServerRuntime {
  app: FastifyInstance;
  bootstrapToken: string;
}

export function getAgentSession(request: FastifyRequest): AgentSession {
  const session = requestSessions.get(request);
  if (!session) throw new Error("auth_required");
  return session;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function errorCode(error: unknown): string {
  return error instanceof Error && /^[a-z0-9_]+$/i.test(error.message) ? error.message : "request_failed";
}

function statusFor(code: string): number {
  if (["auth_required", "auth_invalid", "auth_expired"].includes(code)) return 401;
  if (["origin_forbidden", "host_forbidden", "fetch_forbidden", "client_forbidden", "device_mismatch", "command_denied", "approval_denied"].includes(code)) return 403;
  if (["workspace_not_found", "path_not_found", "task_not_found"].includes(code)) return 404;
  if (["file_too_large", "output_too_large"].includes(code)) return 413;
  if (["command_busy", "task_limit_reached"].includes(code)) return 429;
  if (["approval_invalid", "approval_expired", "approval_mismatch", "approval_not_pending", "task_active", "version_conflict", "expected_hash_required", "destination_exists", "workspace_changed", "workspace_unavailable", "path_changed"].includes(code)) return 409;
  if (["model_connection_failed", "model_connection_refused", "model_tls_failed", "model_host_unresolved", "model_timeout", "model_dns_timeout", "invalid_model_response", "git_timeout", "git_diff_failed"].includes(code) || code.startsWith("model_http_")) return 502;
  return 400;
}

function commandAllowed(command: string): boolean {
  const normalized = command.normalize("NFKC").replace(/["']/g, "").replace(/\s+/g, " ").trim().toLowerCase();
  const denied = [
    /\brm\s+(?:-[a-z]*r[a-z]*f|-rf|-fr)\s+(?:--no-preserve-root\s+)?\/(?:\s|$)/,
    /\b(?:mkfs(?:\.[a-z0-9]+)?|fdisk|parted|diskutil\s+erase|shutdown|reboot|halt|poweroff)\b/,
    /\bdd\b[^;&|]*\bof=\/(?:dev|system|windows)\b/,
    /\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f)/,
    /\b(?:diskpart|format\s+[a-z]:|bcdedit\b|cipher\s+\/w:)/,
    /(?:^|[;&|])\s*(?:del|erase|rmdir|rd)\b[^;&|]*(?:\/s|\-recurse)[^;&|]*(?:[a-z]:\\|\\\\)/,
    /(?:^|[;&|])\s*(?:remove-item)\b[^;&|]*\-recurse[^;&|]*\-force[^;&|]*(?:[a-z]:\\|\\\\)/
  ];
  return !denied.some(pattern => pattern.test(normalized));
}

export const isCommandAllowed = commandAllowed;

function shellInvocation(command: string): { executable: string; arguments: string[] } {
  if (process.platform === "win32") {
    return { executable: "powershell.exe", arguments: ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command] };
  }
  if (process.platform === "darwin") return { executable: "/bin/zsh", arguments: ["-f", "-c", command] };
  return { executable: "/bin/sh", arguments: ["-c", command] };
}

async function defaultChooseFolder(): Promise<string> {
  if (process.env.FORGE_WORKSPACE) return process.env.FORGE_WORKSPACE;
  if (process.platform === "darwin") {
    const result = await execa("osascript", ["-e", "POSIX path of (choose folder with prompt \"选择 Forge 工作区\")"], {
      env: safeChildEnvironment(), timeout: 120_000, maxBuffer: 16_384
    });
    const selected = result.stdout.trim().replace(/\/$/, "");
    if (!selected) throw new Error("workspace_selection_cancelled");
    return selected;
  }
  if (process.platform === "win32") {
    const script = "Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description='选择 Forge 工作区'; if($d.ShowDialog() -eq 'OK'){[Console]::Write($d.SelectedPath)}";
    const result = await execa("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-STA", "-Command", script], {
      env: safeChildEnvironment(), timeout: 120_000, maxBuffer: 16_384
    });
    const selected = result.stdout.trim();
    if (!selected) throw new Error("workspace_selection_cancelled");
    return selected;
  }
  throw new Error("platform_not_supported");
}

function approvalResponse(challenge: ReturnType<ApprovalStore["create"]>) {
  return { error: "approval_required", approvalId: challenge.id, expiresAt: challenge.expiresAt, risk: challenge.risk, summary: challenge.summary };
}

async function approve(
  approvals: ApprovalStore,
  localApprover: LocalApprover,
  input: {
    approvalId?: string;
    session: AgentSession;
    workspaceId?: string;
    risk: ApprovalRisk;
    payload: unknown;
    summary: string;
  }
): Promise<ReturnType<ApprovalStore["create"]> | undefined> {
  const digest = requestHash(input.payload);
  if (!input.approvalId) {
    return approvals.create({
      sessionId: input.session.id,
      workspaceId: input.workspaceId,
      risk: input.risk,
      requestHash: digest,
      summary: input.summary
    });
  }
  const approval = approvals.consume(input.approvalId, {
    sessionId: input.session.id,
    workspaceId: input.workspaceId,
    risk: input.risk,
    requestHash: digest
  });
  if (!await localApprover({ risk: approval.risk, summary: approval.summary })) throw new Error("approval_denied");
  return undefined;
}

export async function createAgentApp(options: AgentServerOptions = {}): Promise<AgentServerRuntime> {
  const port = options.port ?? DEFAULT_PORT;
  const origin = options.origin ?? process.env.WEB_ORIGIN ?? "http://localhost:3000";
  const bootstrapToken = validateBootstrapToken(options.bootstrapToken ?? process.env.FORGE_AGENT_TOKEN ?? generateBootstrapToken());
  const expectedHosts = new Set((options.expectedHosts ?? [`127.0.0.1:${port}`, `localhost:${port}`]).map(value => value.toLowerCase()));
  const configuredDeviceId = options.deviceId ?? process.env.FORGE_DEVICE_ID;
  if (configuredDeviceId) z.string().uuid().parse(configuredDeviceId);
  const parsedOrigin = new URL(origin);
  if (!['http:', 'https:'].includes(parsedOrigin.protocol) || parsedOrigin.origin !== origin) throw new Error("invalid_web_origin");
  const sessions = new SessionManager(bootstrapToken, options.sessionTtlMs);
  const approvals = new ApprovalStore();
  const store = options.store ?? new WorkspaceStore();
  const secrets = options.secrets ?? keytar;
  const localApprover = options.localApprover ?? nativeLocalApprover;
  const chooseFolder = options.chooseFolder ?? defaultChooseFolder;
  const taskRuntime = new AgentRuntime();
  const taskOwners = new Map<string, { deviceId: string; workspaceId: string; createdAt: number }>();
  const trustedModelEndpoints = new Set<string>();
  const endpointTrustKey = (deviceId: string, provider: string, baseUrl: URL) =>
    createHash("sha256").update(`${deviceId}\0${provider}\0${baseUrl.href}`).digest("hex");
  let activeCommands = 0;

  const executeWorkspaceCommand = async (workspaceId: string, command: string, timeoutMs: number) => {
    if (!commandAllowed(command)) throw new Error("command_denied");
    if (activeCommands >= COMMAND_LIMIT) throw new Error("command_busy");
    const root = await store.root(workspaceId);
    const invocation = shellInvocation(command);
    activeCommands += 1;
    try {
      const result = await execa(invocation.executable, invocation.arguments, {
        cwd: root,
        env: safeChildEnvironment(),
        reject: false,
        timeout: timeoutMs,
        maxBuffer: MAX_OUTPUT_BYTES,
        cleanup: true
      });
      return { stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode, timedOut: result.timedOut };
    } finally {
      activeCommands -= 1;
    }
  };

  const app = Fastify({
    logger: options.logger ?? {
      redact: {
        paths: ["req.headers.authorization", "req.headers.x-forge-agent-token", "body.apiKey", "*.apiKey"],
        censor: "[REDACTED]"
      }
    },
    bodyLimit: 2_100_000,
    requestTimeout: 310_000,
    keepAliveTimeout: 5_000,
    maxRequestsPerSocket: 100
  });

  const taskCleanup = setInterval(() => {
    const cutoff = Date.now() - 60 * 60_000;
    for (const [taskId, owner] of taskOwners) {
      if (owner.createdAt >= cutoff) continue;
      try {
        const snapshot = taskRuntime.snapshot(taskId);
        if (["completed", "failed", "cancelled"].includes(snapshot.status)) {
          taskRuntime.remove(taskId);
          taskOwners.delete(taskId);
        }
      } catch {
        taskOwners.delete(taskId);
      }
    }
  }, 60_000);
  taskCleanup.unref();
  app.addHook("onClose", async () => {
    clearInterval(taskCleanup);
    taskRuntime.cancelAll();
  });

  app.addHook("onRequest", async (request, reply) => {
    const host = headerValue(request.headers.host)?.toLowerCase();
    if (!host || !expectedHosts.has(host)) return reply.code(403).send({ error: "host_forbidden" });
    if (request.url === "/health") return;
    const requestOrigin = headerValue(request.headers.origin);
    if (requestOrigin !== origin) return reply.code(403).send({ error: "origin_forbidden" });
    const fetchMode = headerValue(request.headers["sec-fetch-mode"]);
    if (fetchMode && fetchMode !== "cors" && fetchMode !== "same-origin") {
      return reply.code(403).send({ error: "fetch_forbidden" });
    }
    if (request.method !== "OPTIONS" && headerValue(request.headers["x-forge-client"]) !== FORGE_CLIENT_HEADER) {
      return reply.code(403).send({ error: "client_forbidden" });
    }
  });

  await app.register(cors, {
    origin: (requestOrigin, callback) => callback(null, requestOrigin === origin),
    methods: ["GET", "POST", "DELETE"],
    allowedHeaders: ["authorization", "content-type", "x-forge-client"],
    exposedHeaders: [],
    credentials: false,
    strictPreflight: true,
    maxAge: 600
  });

  app.addHook("preHandler", async (request, reply) => {
    if (request.url === "/health" || request.method === "OPTIONS") return;
    const requestOrigin = headerValue(request.headers.origin)!;
    if (request.url === "/session") return;
    try {
      requestSessions.set(request, sessions.verify(bearerToken(headerValue(request.headers.authorization)), requestOrigin));
    } catch (error) {
      const code = errorCode(error);
      return reply.code(statusFor(code)).send({ error: code });
    }
  });

  app.addHook("onSend", async (_request, reply, payload) => {
    reply.header("cache-control", "no-store");
    reply.header("pragma", "no-cache");
    reply.header("x-content-type-options", "nosniff");
    reply.header("referrer-policy", "no-referrer");
    return payload;
  });

  app.get("/health", async () => ({ status: "ok", platform: process.platform, version: VERSION }));

  app.post("/session", async request => {
    const body = z.object({ deviceId: z.string().uuid() }).strict().parse(request.body);
    if (configuredDeviceId && configuredDeviceId !== body.deviceId) throw new Error("device_mismatch");
    const issued = sessions.issue(
      bearerToken(headerValue(request.headers.authorization)),
      body.deviceId,
      headerValue(request.headers.origin)!
    );
    return { token: issued.token, expiresAt: new Date(issued.session.expiresAt).toISOString(), deviceId: issued.session.deviceId };
  });

  app.post("/session/revoke", async request => {
    const session = getAgentSession(request);
    sessions.revokeSession(session.id);
    return { ok: true };
  });

  app.post("/workspaces/select", async () => store.add(await chooseFolder()));
  app.get("/workspaces/:id/files", async request => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    return store.files(params.id);
  });
  app.get("/workspaces/:id/file", async request => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const query = z.object({ path: z.string().min(1).max(4096) }).strict().parse(request.query);
    return store.read(params.id, query.path);
  });
  app.post("/workspaces/:id/mutate", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const input = fileMutationSchema.parse(request.body);
    if (params.id !== input.workspaceId) throw new Error("workspace_mismatch");
    const { approvalId, ...payload } = input;
    const risk = `file_${input.operation}` as ApprovalRisk;
    const challenge = await approve(approvals, localApprover, {
      approvalId,
      session: getAgentSession(request),
      workspaceId: params.id,
      risk,
      payload,
      summary: `${input.operation}: ${input.path}${input.operation === "rename" ? ` -> ${input.destination}` : ""}`
    });
    if (challenge) return reply.send(approvalResponse(challenge));
    if (input.operation === "write") return store.write(params.id, input.path, input.content, input.expectedHash);
    if (input.operation === "delete") {
      await store.delete(params.id, input.path, input.expectedHash);
      return { ok: true };
    }
    await store.rename(params.id, input.path, input.destination, input.expectedHash);
    return { ok: true };
  });

  app.get("/workspaces/:id/diff", async request => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    return safeGitDiff(store, params.id);
  });

  app.post("/workspaces/:id/search", async request => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const body = z.object({ query: z.string().min(1).max(200) }).strict().parse(request.body);
    return { results: await store.search(params.id, body.query), timedOut: false };
  });

  app.post("/workspaces/:id/command", async (request, reply) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const body = z.object({
      command: z.string().min(1).max(4000).refine(value => !/[\0-\x1f\x7f]/.test(value), "command_contains_control_character"),
      approvalId: z.string().uuid().optional(),
      timeoutMs: z.number().int().min(1000).max(300_000).default(120_000)
    }).strict().parse(request.body);
    if (!commandAllowed(body.command)) return reply.code(403).send({ error: "command_denied" });
    const { approvalId, ...payload } = body;
    const challenge = await approve(approvals, localApprover, {
      approvalId,
      session: getAgentSession(request),
      workspaceId: params.id,
      risk: "command",
      payload,
      summary: body.command
    });
    if (challenge) return reply.send(approvalResponse(challenge));
    return executeWorkspaceCommand(params.id, body.command, body.timeoutMs);
  });

  app.post("/secrets", async (request, reply) => {
    const body = z.object({
      deviceId: z.string().uuid(), provider: z.string().uuid(),
      apiKey: z.string().min(8).max(16_384).refine(value => !/[\0\r\n]/.test(value)),
      approvalId: z.string().uuid().optional()
    }).strict().parse(request.body);
    const session = getAgentSession(request);
    if (body.deviceId !== session.deviceId) return reply.code(403).send({ error: "device_mismatch" });
    const { approvalId, apiKey, ...publicPayload } = body;
    const challenge = await approve(approvals, localApprover, {
      approvalId,
      session,
      risk: "secret_write",
      payload: { ...publicPayload, keyFingerprint: createHash("sha256").update(apiKey).digest("hex") },
      summary: `Store API key for provider \"${body.provider}\" on device ${body.deviceId}`
    });
    if (challenge) return reply.send(approvalResponse(challenge));
    await secrets.setPassword(`forge-agent:${body.deviceId}`, body.provider, apiKey);
    await secrets.setPassword(`forge-agent:endpoint-trust:${body.deviceId}`, body.provider, "revoked");
    return {
      keyLastFour: apiKey.slice(-4),
      keyFingerprint: createHash("sha256").update(apiKey).digest("hex")
    };
  });

  app.post("/models/test", async (request, reply) => {
    const body = z.object({
      deviceId: z.string().uuid(), provider: z.string().uuid(),
      kind: z.enum(["openai", "anthropic", "openai-compatible"]),
      baseUrl: z.string().url().max(2048), model: z.string().min(1).max(160).refine(value => !/[\0-\x1f\x7f]/.test(value)), approvalId: z.string().uuid().optional()
    }).strict().parse(request.body);
    const session = getAgentSession(request);
    if (body.deviceId !== session.deviceId) return reply.code(403).send({ error: "device_mismatch" });
    const assessment = await assessEndpoint(body.baseUrl, body.kind);
    const risk: ApprovalRisk | undefined = assessment.privateNetwork
      ? "private_network"
      : assessment.trustedProviderEndpoint ? undefined : "custom_endpoint";
    if (risk) {
      const { approvalId, ...payload } = body;
      const challenge = await approve(approvals, localApprover, {
        approvalId,
        session,
        risk,
        payload,
        summary: `Connect provider \"${body.provider}\" to ${assessment.target.origin} (${assessment.address})`
      });
      if (challenge) return reply.send(approvalResponse(challenge));
    } else if (body.approvalId) {
      throw new Error("approval_invalid");
    }
    const key = await secrets.getPassword(`forge-agent:${body.deviceId}`, body.provider);
    if (!key) throw new Error("key_not_found");
    const result = await probeModelEndpoint(assessment, body.kind, key);
    if (result.ok) {
      const trustHash = endpointTrustKey(session.deviceId, body.provider, assessment.base);
      trustedModelEndpoints.add(trustHash);
      await secrets.setPassword(`forge-agent:endpoint-trust:${body.deviceId}`, body.provider, trustHash);
    }
    return { ...result, model: body.model };
  });

  app.post("/tasks", async (request, reply) => {
    const body = z.object({
      workspaceId: z.string().uuid(),
      provider: z.string().uuid(),
      kind: z.enum(["openai", "anthropic", "openai-compatible"]),
      baseUrl: z.string().url().max(2048),
      model: z.string().min(1).max(160).refine(value => !/[\0-\x1f\x7f]/.test(value)),
      prompt: z.string().trim().min(1).max(100_000).refine(value => Buffer.byteLength(value) <= 100_000, "prompt_too_large"),
      maxTurns: z.number().int().min(1).max(50).default(20),
      maxTokens: z.number().int().min(1_024).max(1_000_000).default(200_000),
      approvalId: z.string().uuid().optional()
    }).strict().parse(request.body);
    const session = getAgentSession(request);
    await store.root(body.workspaceId);

    if (taskOwners.size >= 100) {
      const oldest = [...taskOwners.entries()].sort((left, right) => left[1].createdAt - right[1].createdAt);
      for (const [taskId] of oldest) {
        const status = taskRuntime.snapshot(taskId).status;
        if (!["completed", "failed", "cancelled"].includes(status)) continue;
        taskRuntime.remove(taskId);
        taskOwners.delete(taskId);
        if (taskOwners.size < 100) break;
      }
      if (taskOwners.size >= 100) throw new Error("task_limit_reached");
    }

    let active = 0;
    for (const taskId of taskOwners.keys()) {
      const status = taskRuntime.snapshot(taskId).status;
      if (status === "running" || status === "waiting") active += 1;
    }
    if (active >= 4) throw new Error("task_limit_reached");

    const assessment = await assessEndpoint(body.baseUrl, body.kind);
    const trustHash = endpointTrustKey(session.deviceId, body.provider, assessment.base);
    const persistedTrust = await secrets.getPassword(`forge-agent:endpoint-trust:${session.deviceId}`, body.provider);
    const endpointAlreadyTrusted = trustedModelEndpoints.has(trustHash) || persistedTrust === trustHash;
    if (persistedTrust === trustHash) trustedModelEndpoints.add(trustHash);
    const endpointRisk: ApprovalRisk | undefined = endpointAlreadyTrusted || assessment.trustedProviderEndpoint
      ? undefined
      : assessment.privateNetwork ? "private_network" : "custom_endpoint";
    if (endpointRisk) {
      const { approvalId, prompt: _prompt, ...publicPayload } = body;
      const challenge = await approve(approvals, localApprover, {
        approvalId,
        session,
        workspaceId: body.workspaceId,
        risk: endpointRisk,
        payload: { ...publicPayload, promptHash: createHash("sha256").update(body.prompt).digest("hex") },
        summary: `Run ${body.model} through ${assessment.target.origin} (${assessment.address})`
      });
      if (challenge) return reply.send(approvalResponse(challenge));
    } else if (body.approvalId) {
      throw new Error("approval_invalid");
    }

    const apiKey = await secrets.getPassword(`forge-agent:${session.deviceId}`, body.provider);
    if (!apiKey) throw new Error("key_not_found");
    if (/[\0\r\n]/.test(apiKey)) throw new Error("invalid_api_key");
    const provider = new HttpModelProvider(
      { kind: body.kind, baseUrl: body.baseUrl, model: body.model, apiKey },
      assessment.privateNetwork,
      ({ path, headers, body: requestBody, signal }) => postModelJson(assessment, path, headers, requestBody, signal)
    );
    const taskId = randomUUID();
    const task = taskRuntime.create({
      taskId,
      deviceId: session.deviceId,
      prompt: body.prompt,
      system: SYSTEM_PROMPT,
      provider,
      tools: workspaceTools(store, body.workspaceId, (command, timeoutMs) => executeWorkspaceCommand(body.workspaceId, command, timeoutMs)),
      policy: defaultExecutionPolicy,
      maxTurns: body.maxTurns,
      maxTokens: body.maxTokens
    });
    taskOwners.set(taskId, { deviceId: session.deviceId, workspaceId: body.workspaceId, createdAt: Date.now() });
    return reply.code(201).send(task);
  });

  app.get("/tasks/:id", async request => {
    const { id } = z.object({ id: z.string().uuid() }).strict().parse(request.params);
    const owner = taskOwners.get(id);
    if (!owner) throw new Error("task_not_found");
    if (owner.deviceId !== getAgentSession(request).deviceId) throw new Error("device_mismatch");
    return taskRuntime.snapshot(id);
  });

  app.get("/tasks/:id/events", async request => {
    const { id } = z.object({ id: z.string().uuid() }).strict().parse(request.params);
    const { after } = z.object({ after: z.coerce.number().int().min(-1).max(10_000_000).default(-1) }).strict().parse(request.query);
    const owner = taskOwners.get(id);
    if (!owner) throw new Error("task_not_found");
    if (owner.deviceId !== getAgentSession(request).deviceId) throw new Error("device_mismatch");
    return { events: taskRuntime.events(id, after), task: taskRuntime.snapshot(id) };
  });

  app.post("/tasks/:id/approvals/:toolCallId", async request => {
    const { id, toolCallId } = z.object({ id: z.string().uuid(), toolCallId: z.string().min(1).max(200) }).strict().parse(request.params);
    const { approved } = z.object({ approved: z.boolean() }).strict().parse(request.body);
    const owner = taskOwners.get(id);
    if (!owner) throw new Error("task_not_found");
    if (owner.deviceId !== getAgentSession(request).deviceId) throw new Error("device_mismatch");
    const snapshot = taskRuntime.snapshot(id);
    if (snapshot.pending?.id !== toolCallId) throw new Error("approval_not_pending");
    if (approved) {
      const args = snapshot.pending.arguments as Record<string, unknown>;
      const pathSummary = typeof args.path === "string" ? `: ${args.path}` : "";
      const risk: ApprovalRisk = snapshot.pending.name === "run_command" ? "command" : snapshot.pending.name === "delete_file" ? "file_delete" : snapshot.pending.name === "rename_file" ? "file_rename" : "file_write";
      const summary = snapshot.pending.name === "run_command" && typeof args.command === "string"
        ? args.command
        : `${snapshot.pending.name}${pathSummary}${typeof args.destination === "string" ? ` -> ${args.destination}` : ""}`;
      if (!await localApprover({ risk, summary })) throw new Error("approval_denied");
    }
    return taskRuntime.approve(id, toolCallId, approved);
  });

  app.post("/tasks/:id/cancel", async request => {
    const { id } = z.object({ id: z.string().uuid() }).strict().parse(request.params);
    const owner = taskOwners.get(id);
    if (!owner) throw new Error("task_not_found");
    if (owner.deviceId !== getAgentSession(request).deviceId) throw new Error("device_mismatch");
    taskRuntime.cancel(id);
    return taskRuntime.snapshot(id);
  });

  const eventSockets = new Set<Duplex>();
  app.server.on("upgrade", (request, socket, head) => {
    let upgraded = false;
    const reject = (status: 400 | 401 | 403 | 404 | 429) => {
      const reason = { 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 429: "Too Many Requests" }[status];
      socket.end(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    };
    try {
      const host = headerValue(request.headers.host)?.toLowerCase();
      const requestOrigin = headerValue(request.headers.origin);
      if (!host || !expectedHosts.has(host) || requestOrigin !== origin) return reject(403);
      if (headerValue(request.headers.upgrade)?.toLowerCase() !== "websocket" || request.headers["sec-websocket-version"] !== "13") return reject(400);
      if (eventSockets.size >= 32) return reject(429);
      const target = new URL(request.url ?? "/", `http://${host}`);
      const match = /^\/tasks\/([0-9a-f-]{36})\/events\/ws$/i.exec(target.pathname);
      if (!match || [...target.searchParams.keys()].some(key => !["after", "deviceId"].includes(key))) return reject(404);
      const taskId = z.string().uuid().parse(match[1]);
      const deviceId = z.string().uuid().parse(target.searchParams.get("deviceId"));
      const afterValue = target.searchParams.get("after") ?? "-1";
      if (!/^-?\d{1,10}$/.test(afterValue)) return reject(400);
      let after = Number(afterValue);
      if (!Number.isSafeInteger(after) || after < -1 || after > 10_000_000) return reject(400);
      const protocols = websocketProtocols(headerValue(request.headers["sec-websocket-protocol"]));
      if (!protocols.eventProtocol || !protocols.token) return reject(401);
      const session = sessions.verify(protocols.token, requestOrigin);
      if (session.deviceId !== deviceId) return reject(403);
      const owner = taskOwners.get(taskId);
      if (!owner) return reject(404);
      if (owner.deviceId !== deviceId) return reject(403);
      const accept = websocketAccept(headerValue(request.headers["sec-websocket-key"]) ?? "");
      socket.write([
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        `Sec-WebSocket-Accept: ${accept}`,
        "Sec-WebSocket-Protocol: forge-events",
        "\r\n"
      ].join("\r\n"));
      upgraded = true;
      eventSockets.add(socket);
      let closed = false;
      let first = true;
      let receivedBytes = head.length;
      const cleanup = () => {
        if (closed) return;
        closed = true;
        clearInterval(timer);
        clearTimeout(expiryTimer);
        eventSockets.delete(socket);
      };
      const close = (code = 1000) => {
        if (closed) return;
        try { socket.end(closeFrame(code)); } catch { socket.destroy(); }
        cleanup();
      };
      const send = () => {
        try {
          if (closed || socket.destroyed) return cleanup();
          if (socket.writableLength > 4 * 1024 * 1024) return close(1009);
          const snapshot = taskRuntime.snapshot(taskId);
          const available = taskRuntime.events(taskId, after);
          const batch: typeof available = [];
          let estimatedBytes = Buffer.byteLength(JSON.stringify({ events: [], task: snapshot }));
          for (const event of available.slice(0, 100)) {
            const eventBytes = Buffer.byteLength(JSON.stringify(event)) + 1;
            if (estimatedBytes + eventBytes > 1_800_000) break;
            batch.push(event);
            estimatedBytes += eventBytes;
          }
          if (!batch.length && available.length) return close(1009);
          if (batch.length || first) {
            socket.write(textFrame(JSON.stringify({ events: batch, task: snapshot })));
            if (batch.length) after = batch[batch.length - 1]!.sequence;
            first = false;
          }
          if (["completed", "failed", "cancelled"].includes(snapshot.status) && taskRuntime.events(taskId, after).length === 0) {
            close(1000);
          }
        } catch {
          close(1011);
        }
      };
      const timer = setInterval(send, 250);
      const expiryTimer = setTimeout(() => close(1008), Math.max(1, session.expiresAt - Date.now()));
      timer.unref();
      expiryTimer.unref();
      socket.on("data", chunk => {
        receivedBytes += chunk.length;
        const opcode = chunk.length ? chunk[0]! & 0x0f : 0;
        if (opcode === 0x8) return close(1000);
        if (receivedBytes > 64 * 1024 || opcode === 0x1 || opcode === 0x2) close(1008);
      });
      socket.once("error", cleanup);
      socket.once("close", cleanup);
      if (head.length) return close(1008);
      send();
    } catch {
      if (upgraded) {
        eventSockets.delete(socket);
        socket.destroy();
      }
      else reject(400);
    }
  });
  app.addHook("onClose", async () => {
    for (const socket of eventSockets) socket.destroy();
    eventSockets.clear();
  });

  app.setErrorHandler((error, _request, reply) => {
    const code = error instanceof ZodError ? "validation_error" : errorCode(error);
    const name = error instanceof Error ? error.name : "UnknownError";
    app.log.warn({ error: { name, code } }, "request rejected");
    return reply.code(statusFor(code)).send({ error: code });
  });

  return { app, bootstrapToken };
}

export async function startAgentMain(): Promise<void> {
  const port = Number(process.env.AGENT_PORT ?? DEFAULT_PORT);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("invalid_agent_port");
  // stdout is a machine-readable readiness channel consumed by the desktop supervisor.
  const runtime = await createAgentApp({ port, logger: false });
  let tokenFile: string | undefined;
  if (!process.env.FORGE_AGENT_TOKEN) {
    tokenFile = process.env.FORGE_AGENT_TOKEN_FILE ?? path.join(os.tmpdir(), `forge-agent-${process.pid}.token`);
    await writeFile(tokenFile, runtime.bootstrapToken, { encoding: "utf8", mode: 0o600, flag: "wx" });
  }
  try {
    await runtime.app.listen({ host: "127.0.0.1", port });
  } catch (error) {
    if (tokenFile) await rm(tokenFile, { force: true }).catch(() => undefined);
    throw error;
  }
  process.stdout.write(`${JSON.stringify({ event: "forge-agent-ready", tokenFile: tokenFile ?? null, deviceId: process.env.FORGE_DEVICE_ID ?? null })}\n`);

  const shutdown = async () => {
    await runtime.app.close().catch(() => undefined);
    if (tokenFile) await rm(tokenFile, { force: true }).catch(() => undefined);
  };
  process.once("SIGINT", () => { void shutdown(); });
  process.once("SIGTERM", () => { void shutdown(); });
}

const entrypoint = process.argv[1] ? pathToFileURL(process.argv[1]).href : undefined;
if (entrypoint === import.meta.url) {
  startAgentMain().catch(error => {
    process.stderr.write(`Forge Agent failed to start: ${errorCode(error)}\n`);
    process.exitCode = 1;
  });
}
