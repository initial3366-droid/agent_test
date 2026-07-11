import { z } from "zod";

const providerBaseUrlSchema = z.string().trim().min(1).max(2048).url().refine((value) => {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password && !url.hash;
  } catch {
    return false;
  }
}, "base_url_must_be_http_without_credentials_or_fragment");

export const providerSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().trim().min(1).max(80),
  kind: z.enum(["openai", "anthropic", "openai-compatible"]),
  baseUrl: providerBaseUrlSchema,
  model: z.string().trim().min(1).max(160),
  contextWindow: z.number().int().min(1024).max(2_000_000),
  isDefault: z.boolean().default(false),
  keyLastFour: z.string().regex(/^[\x21-\x7e]{4}$/).optional(),
  keyFingerprint: z.string().regex(/^[a-f0-9]{64}$/i).optional(),
  deviceId: z.string().uuid()
}).strict().superRefine((value, context) => {
  if (Boolean(value.keyLastFour) !== Boolean(value.keyFingerprint)) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "key metadata must be provided together" });
  }
});

export const agentEventSchema = z.object({
  taskId: z.string().uuid(), deviceId: z.string().uuid(), sequence: z.number().int().nonnegative(),
  timestamp: z.string().datetime(), type: z.enum(["message.delta", "task.status", "tool.request", "approval.request", "terminal.output", "file.changed", "error", "task.completed"]),
  payload: z.record(z.unknown())
});
export type AgentEvent = z.infer<typeof agentEventSchema>;

const clientAuditActionSchema = z.enum([
  "workspace.authorized",
  "workspace.revoked",
  "task.approval",
  "task.cancelled",
  "client.updated",
  "model.tested"
]);
const clientAuditResourceSchema = z.enum(["workspace", "task", "model", "device", "client"]);
const auditMetadataKeySchema = z.enum([
  "status", "result", "risk", "tool", "version", "platform", "provider", "decision", "errorCode"
]);
const auditMetadataValueSchema = z.union([
  z.string().max(120),
  z.number().finite().safe(),
  z.boolean(),
  z.null()
]);

export const auditEventSchema = z.object({
  action: clientAuditActionSchema,
  resourceType: clientAuditResourceSchema,
  resourceId: z.string().uuid().optional(),
  deviceId: z.string().uuid().optional(),
  metadata: z.record(auditMetadataKeySchema, auditMetadataValueSchema).default({})
}).strict().superRefine((event, context) => {
  const expectedResource = {
    "workspace.authorized": "workspace",
    "workspace.revoked": "workspace",
    "task.approval": "task",
    "task.cancelled": "task",
    "client.updated": "client",
    "model.tested": "model"
  } as const;
  if (event.resourceType !== expectedResource[event.action]) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["resourceType"], message: "resource type does not match action" });
  }
  if (event.resourceType !== "client" && !event.resourceId) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["resourceId"], message: "resourceId is required" });
  }
});

export const workspaceSchema = z.object({ id: z.string().uuid(), name: z.string(), gitBranch: z.string().nullable(), lastOpenedAt: z.string().datetime() });
const workspacePathSchema = z.string().min(1).max(4096).refine(value => !value.includes("\0"), "path_contains_nul");
const contentHashSchema = z.string().regex(/^[a-f0-9]{64}$/i);
const approvalIdSchema = z.string().uuid().optional();

export const fileMutationSchema = z.discriminatedUnion("operation", [
  z.object({
    operation: z.literal("write"), workspaceId: z.string().uuid(), path: workspacePathSchema,
    content: z.string().max(2_000_000), expectedHash: contentHashSchema.optional(), approvalId: approvalIdSchema
  }).strict(),
  z.object({
    operation: z.literal("delete"), workspaceId: z.string().uuid(), path: workspacePathSchema,
    expectedHash: contentHashSchema, approvalId: approvalIdSchema
  }).strict(),
  z.object({
    operation: z.literal("rename"), workspaceId: z.string().uuid(), path: workspacePathSchema,
    destination: workspacePathSchema, expectedHash: contentHashSchema, approvalId: approvalIdSchema
  }).strict()
]);

export interface ModelProvider { stream(messages: Array<{role:"system"|"user"|"assistant";content:string}>, signal?: AbortSignal): AsyncIterable<string>; }
export interface ExecutionPolicy { evaluate(input: { tool: string; path?: string; command?: string }): "allow"|"ask"|"deny"; }
export interface ToolDefinition<T> { name: string; risk: "read"|"write"|"network"|"dangerous"; schema: z.ZodType<T>; execute(input: T, signal?: AbortSignal): Promise<unknown>; }
