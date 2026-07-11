import { randomInt, randomUUID } from "node:crypto";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import cors from "@fastify/cors";
import jwt from "@fastify/jwt";
import swagger from "@fastify/swagger";
import { drizzle } from "drizzle-orm/node-postgres";
import { and, count, desc, eq, gte, isNull, lt, sql } from "drizzle-orm";
import { Pool } from "pg";
import { auditEventSchema, providerSchema } from "@forge/protocol";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { createLoginCodeMailer, MailDeliveryError } from "./mailer.js";
import {
  FixedWindowRateLimiter,
  LOGIN_CODE_MAX_ATTEMPTS,
  LOGIN_CODE_TTL_MS,
  keyedHash,
  loginCodeHash,
  matchesHash
} from "./security.js";
import * as s from "./schema.js";

const config = loadConfig();
const pool = new Pool({ connectionString: config.databaseUrl, max: 20 });
const db = drizzle(pool);
const mailer = createLoginCodeMailer(config);
const allowedOrigins = new Set(config.allowedOrigins);
const app = Fastify({
  bodyLimit: 256 * 1024,
  connectionTimeout: 10_000,
  requestTimeout: 30_000,
  trustProxy: config.trustProxy,
  logger: {
    level: config.logLevel,
    redact: [
      "req.headers.authorization",
      "req.headers.cookie",
      "res.headers.set-cookie",
      "body.apiKey",
      "body.code",
      "body.secret",
      "body.token"
    ]
  }
});

await app.register(cors, {
  origin: (origin, callback) => callback(null, origin === undefined || allowedOrigins.has(origin)),
  credentials: false,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  allowedHeaders: ["authorization", "content-type", "idempotency-key"],
  maxAge: 600
});
await app.register(jwt, { secret: config.jwtSecret });
if (!config.production) {
  await app.register(swagger, { openapi: { info: { title: "Forge Agent API", version: "0.1.0" } } });
}

type Role = "user" | "admin";
type Claims = { sub: string; role: Role };
type Account = { id: string; email: string; role: Role; status: "active" | "disabled" };

declare module "fastify" {
  interface FastifyRequest {
    claims: Claims;
    account: Account;
  }
}

app.decorateRequest("claims", null as unknown as Claims);
app.decorateRequest("account", null as unknown as Account);

class ApiError extends Error {
  constructor(readonly statusCode: number, readonly code: string, readonly retryAfter?: number) {
    super(code);
    this.name = "ApiError";
  }
}

const emailSchema = z.string().trim().toLowerCase().email().max(254);
const codeSchema = z.string().regex(/^\d{6}$/);
const uuidParamSchema = z.object({ id: z.string().uuid() }).strict();
const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(100),
  offset: z.coerce.number().int().min(0).max(10_000).default(0)
}).strict();
const adminTaskQuerySchema = paginationSchema.extend({
  userId: z.string().uuid().optional(),
  deviceId: z.string().uuid().optional(),
  status: z.enum(["running", "completed", "failed", "cancelled"]).optional(),
  model: z.string().trim().min(1).max(160).optional(),
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional()
}).strict().refine((value) => !value.from || !value.to || value.from <= value.to, "from must not be after to");
const deviceInputSchema = z.object({
  name: z.string().trim().min(1).max(80).refine((value) => !/[\u0000-\u001f\u007f]/.test(value), "control characters are not allowed"),
  platform: z.enum(["windows", "macos"]),
  version: z.string().trim().regex(/^\d+\.\d+\.\d+$/).max(40)
}).strict();
const usageEventSchema = z.object({
  deviceId: z.string().uuid(),
  workspaceName: z.string().trim().min(1).max(120)
    .refine((value) => !/[\\/\u0000-\u001f\u007f]/.test(value) && !/^[A-Za-z]:/.test(value), "workspaceName must not be a path"),
  status: z.enum(["running", "completed", "failed", "cancelled"]),
  model: z.string().trim().min(1).max(160),
  inputTokens: z.number().int().min(0).max(100_000_000),
  outputTokens: z.number().int().min(0).max(100_000_000),
  durationMs: z.number().int().min(0).max(86_400_000).optional(),
  errorCode: z.string().trim().min(1).max(100).regex(/^[A-Za-z0-9_.:-]+$/).optional()
}).strict();
const settingKeySchema = z.enum([
  "registration_open",
  "minimum_client_version",
  "usage_limit",
  "allowed_model_providers",
  "audit_retention_days"
]);

const requestCodeIpLimiter = new FixedWindowRateLimiter(30, 15 * 60_000);
const verifyIpLimiter = new FixedWindowRateLimiter(40, 15 * 60_000);
const authenticatedWriteLimiter = new FixedWindowRateLimiter(120, 60_000);

function assertRateLimit(limiter: FixedWindowRateLimiter, key: string) {
  const result = limiter.take(key);
  if (!result.allowed) throw new ApiError(429, "rate_limit_exceeded", result.retryAfterSeconds);
}

function parseBearerAlgorithm(request: FastifyRequest) {
  const value = request.headers.authorization;
  if (!value?.startsWith("Bearer ")) throw new ApiError(401, "unauthorized");
  const parts = value.slice(7).split(".");
  if (parts.length !== 3) throw new ApiError(401, "unauthorized");
  try {
    const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")) as { alg?: unknown };
    if (header.alg !== "HS256") throw new ApiError(401, "unauthorized");
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(401, "unauthorized");
  }
}

const auth = async (request: FastifyRequest, _reply: FastifyReply) => {
  let subject: string;
  try {
    parseBearerAlgorithm(request);
    await request.jwtVerify();
    const token = z.object({
      sub: z.string().uuid(),
      iss: z.literal(config.jwtIssuer),
      aud: z.literal(config.jwtAudience)
    }).passthrough().parse(request.user);
    subject = token.sub;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(401, "unauthorized");
  }
  const [account] = await db.select({
    id: s.users.id,
    email: s.users.email,
    role: s.users.role,
    status: s.users.status
  }).from(s.users).where(eq(s.users.id, subject)).limit(1);
  if (!account || account.status !== "active") throw new ApiError(401, "unauthorized");
  request.claims = { sub: account.id, role: account.role };
  request.account = account;
};

const admin = async (request: FastifyRequest, reply: FastifyReply) => {
  await auth(request, reply);
  if (request.account.role !== "admin") throw new ApiError(403, "admin_required");
};

async function insertAudit(input: {
  userId: string | null;
  actorId: string | null;
  action: string;
  resourceType: string;
  resourceId?: string;
  deviceId?: string;
  metadata?: s.AuditMetadata;
}) {
  await db.insert(s.audits).values({
    ...input,
    resourceId: input.resourceId,
    deviceId: input.deviceId,
    metadata: input.metadata ?? {}
  });
}

async function ownedDevice(userId: string, deviceId: string) {
  return (await db.select({ id: s.devices.id }).from(s.devices)
    .where(and(eq(s.devices.id, deviceId), eq(s.devices.userId, userId))).limit(1))[0];
}

function compareVersions(left: string, right: string): number {
  const parse = (value: string) => value.split("-", 1)[0]!.split(".").map(Number);
  const a = parse(left);
  const b = parse(right);
  for (let index = 0; index < 3; index += 1) {
    if (a[index]! !== b[index]!) return a[index]! - b[index]!;
  }
  return 0;
}

function parseSettingValue(key: z.infer<typeof settingKeySchema>, value: unknown) {
  const schemas = {
    registration_open: z.boolean(),
    minimum_client_version: z.string().regex(/^\d+\.\d+\.\d+$/).max(40),
    usage_limit: z.number().int().min(1).max(2_000_000_000),
    allowed_model_providers: z.array(z.enum(["openai", "anthropic", "openai-compatible"])).min(1).max(3)
      .refine((items) => new Set(items).size === items.length, "providers must be unique"),
    audit_retention_days: z.number().int().min(1).max(3650)
  } satisfies Record<z.infer<typeof settingKeySchema>, z.ZodTypeAny>;
  return schemas[key].parse(value);
}

app.addHook("onSend", async (_request, reply, payload) => {
  reply.header("cache-control", "no-store");
  reply.header("x-content-type-options", "nosniff");
  reply.header("x-frame-options", "DENY");
  reply.header("referrer-policy", "no-referrer");
  return payload;
});

app.get("/health", async (_request, reply) => {
  try {
    await pool.query("select 1");
    return { status: "ok" };
  } catch {
    return reply.code(503).send({ status: "unavailable" });
  }
});

app.post("/auth/request-code", async (request, reply) => {
  assertRateLimit(requestCodeIpLimiter, request.ip);
  const { email } = z.object({ email: emailSchema }).strict().parse(request.body);
  const now = new Date();
  const [registrationSetting, existing] = await Promise.all([
    db.select({ value: s.settings.value }).from(s.settings).where(eq(s.settings.key, "registration_open")).limit(1),
    db.select({ status: s.users.status }).from(s.users).where(eq(s.users.email, email)).limit(1)
  ]);
  const registrationOpen = registrationSetting[0]?.value === undefined
    ? config.registrationOpenDefault
    : registrationSetting[0].value === true;

  const eligible = existing[0]?.status === "active" ||
    (!existing[0] && (registrationOpen || email === config.bootstrapAdminEmail));
  const code = String(randomInt(100_000, 1_000_000));
  const requestIpHash = keyedHash(config.otpSecret, "request-ip", request.ip);
  const created = await db.transaction(async (tx) => {
    const locks = [`login-email:${email}`, `login-ip:${requestIpHash}`].sort();
    for (const lock of locks) await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${lock}))`);
    const windowStart = new Date(now.getTime() - 15 * 60_000);
    const [[emailCount], [ipCount]] = await Promise.all([
      tx.select({ value: count() }).from(s.loginCodes)
        .where(and(eq(s.loginCodes.email, email), gte(s.loginCodes.createdAt, windowStart))),
      tx.select({ value: count() }).from(s.loginCodes)
        .where(and(eq(s.loginCodes.requestIpHash, requestIpHash), gte(s.loginCodes.createdAt, windowStart)))
    ]);
    if ((emailCount?.value ?? 0) >= 5 || (ipCount?.value ?? 0) >= 30) {
      throw new ApiError(429, "rate_limit_exceeded", 15 * 60);
    }
    await tx.update(s.loginCodes).set({ usedAt: now })
      .where(and(eq(s.loginCodes.email, email), isNull(s.loginCodes.usedAt)));
    await tx.delete(s.loginCodes).where(lt(s.loginCodes.expiresAt, new Date(now.getTime() - 24 * 60 * 60_000)));
    const [row] = await tx.insert(s.loginCodes).values({
      email,
      codeHash: loginCodeHash(config.otpSecret, email, code),
      requestIpHash,
      registrationAllowed: eligible,
      expiresAt: new Date(now.getTime() + LOGIN_CODE_TTL_MS)
    }).returning({ id: s.loginCodes.id });
    return row!;
  });

  if (eligible) {
    try {
      await mailer.sendLoginCode(email, code);
    } catch (error) {
      await db.update(s.loginCodes).set({ usedAt: new Date() }).where(eq(s.loginCodes.id, created.id));
      throw error;
    }
  }

  return reply.code(202).send({
    sent: true,
    ...(config.returnLoginCode && eligible ? { developmentCode: code } : {})
  });
});

app.post("/auth/verify", async (request, reply) => {
  assertRateLimit(verifyIpLimiter, request.ip);
  const { email, code } = z.object({ email: emailSchema, code: codeSchema }).strict().parse(request.body);
  const now = new Date();
  const result = await db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`login-email:${email}`}))`);
    const [loginCode] = await tx.select().from(s.loginCodes).where(and(
      eq(s.loginCodes.email, email),
      isNull(s.loginCodes.usedAt),
      gte(s.loginCodes.expiresAt, now)
    )).orderBy(desc(s.loginCodes.createdAt)).limit(1);
    if (!loginCode || loginCode.attempts >= LOGIN_CODE_MAX_ATTEMPTS) return null;

    const valid = matchesHash(loginCode.codeHash, loginCodeHash(config.otpSecret, email, code));
    if (!valid) {
      const attempts = loginCode.attempts + 1;
      await tx.update(s.loginCodes).set({
        attempts,
        ...(attempts >= LOGIN_CODE_MAX_ATTEMPTS ? { usedAt: now } : {})
      }).where(eq(s.loginCodes.id, loginCode.id));
      return null;
    }

    await tx.update(s.loginCodes).set({ usedAt: now }).where(eq(s.loginCodes.id, loginCode.id));
    let [user] = await tx.select().from(s.users).where(eq(s.users.email, email)).limit(1);
    if (!user && !loginCode.registrationAllowed) return null;
    if (!user) {
      [user] = await tx.insert(s.users).values({
        email,
        role: email === config.bootstrapAdminEmail ? "admin" : "user"
      }).onConflictDoNothing({ target: s.users.email }).returning();
      if (!user) [user] = await tx.select().from(s.users).where(eq(s.users.email, email)).limit(1);
    }
    if (!user || user.status === "disabled") return { disabled: true as const };
    await tx.update(s.users).set({ lastLoginAt: now }).where(eq(s.users.id, user.id));
    await tx.insert(s.audits).values({
      userId: user.id,
      actorId: user.id,
      action: "auth.login",
      resourceType: "user",
      resourceId: user.id,
      metadata: {}
    });
    return { disabled: false as const, user };
  });

  if (!result) throw new ApiError(401, "invalid_code");
  if (result.disabled) throw new ApiError(403, "account_disabled");
  const token = app.jwt.sign({
    sub: result.user.id,
    role: result.user.role,
    iss: config.jwtIssuer,
    aud: config.jwtAudience,
    jti: randomUUID()
  }, { algorithm: "HS256", expiresIn: "12h" });
  return reply.send({
    token,
    user: { id: result.user.id, email: result.user.email, role: result.user.role }
  });
});

app.get("/me", { preHandler: auth }, async (request) => ({
  id: request.account.id,
  email: request.account.email,
  role: request.account.role,
  status: request.account.status
}));

app.get("/devices", { preHandler: auth }, async (request) => db.select({
  id: s.devices.id,
  name: s.devices.name,
  platform: s.devices.platform,
  version: s.devices.version,
  keyConfigured: s.devices.keyConfigured,
  lastSeenAt: s.devices.lastSeenAt,
  createdAt: s.devices.createdAt
}).from(s.devices).where(eq(s.devices.userId, request.claims.sub)).orderBy(desc(s.devices.lastSeenAt)));

app.post("/devices", { preHandler: auth }, async (request, reply) => {
  assertRateLimit(authenticatedWriteLimiter, request.claims.sub);
  const input = deviceInputSchema.parse(request.body);
  const [minimum] = await db.select({ value: s.settings.value }).from(s.settings)
    .where(eq(s.settings.key, "minimum_client_version")).limit(1);
  if (typeof minimum?.value === "string" && compareVersions(input.version, minimum.value) < 0) {
    throw new ApiError(426, "client_update_required");
  }
  const device = await db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`devices:${request.claims.sub}`}))`);
    const [total] = await tx.select({ value: count() }).from(s.devices)
      .where(eq(s.devices.userId, request.claims.sub));
    if ((total?.value ?? 0) >= 20) throw new ApiError(409, "device_limit_reached");
    const [created] = await tx.insert(s.devices).values({ ...input, userId: request.claims.sub }).returning();
    await tx.insert(s.audits).values({
      userId: request.claims.sub,
      actorId: request.claims.sub,
      action: "device.bound",
      resourceType: "device",
      resourceId: created!.id,
      deviceId: created!.id,
      metadata: { platform: input.platform }
    });
    return created!;
  });
  return reply.code(201).send(device);
});

const modelProjection = {
  id: s.modelConfigs.id,
  deviceId: s.modelConfigs.deviceId,
  name: s.modelConfigs.name,
  kind: s.modelConfigs.kind,
  baseUrl: s.modelConfigs.baseUrl,
  model: s.modelConfigs.model,
  contextWindow: s.modelConfigs.contextWindow,
  isDefault: s.modelConfigs.isDefault,
  keyLastFour: s.modelConfigs.keyLastFour,
  createdAt: s.modelConfigs.createdAt
};

app.get("/models", { preHandler: auth }, async (request) => db.select(modelProjection).from(s.modelConfigs)
  .where(eq(s.modelConfigs.userId, request.claims.sub)).orderBy(desc(s.modelConfigs.createdAt)));

app.post("/models", { preHandler: auth }, async (request, reply) => {
  assertRateLimit(authenticatedWriteLimiter, request.claims.sub);
  const input = providerSchema.parse(request.body);
  const model = await db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`models:${request.claims.sub}`}))`);
    const [device] = await tx.select({ id: s.devices.id }).from(s.devices).where(and(
      eq(s.devices.id, input.deviceId),
      eq(s.devices.userId, request.claims.sub)
    )).limit(1);
    if (!device) throw new ApiError(404, "device_not_found");
    const [allowedSetting] = await tx.select({ value: s.settings.value }).from(s.settings)
      .where(eq(s.settings.key, "allowed_model_providers")).limit(1);
    if (Array.isArray(allowedSetting?.value) && !allowedSetting.value.includes(input.kind)) {
      throw new ApiError(403, "provider_not_allowed");
    }
    const [total] = await tx.select({ value: count() }).from(s.modelConfigs)
      .where(eq(s.modelConfigs.userId, request.claims.sub));
    if ((total?.value ?? 0) >= 50) throw new ApiError(409, "model_limit_reached");
    if (input.isDefault) {
      await tx.update(s.modelConfigs).set({ isDefault: false }).where(eq(s.modelConfigs.userId, request.claims.sub));
    }
    const [created] = await tx.insert(s.modelConfigs).values({ ...input, userId: request.claims.sub }).returning();
    if (input.keyFingerprint && input.keyLastFour) {
      await tx.update(s.devices).set({ keyConfigured: true, lastSeenAt: new Date() })
        .where(and(eq(s.devices.id, input.deviceId), eq(s.devices.userId, request.claims.sub)));
    }
    await tx.insert(s.audits).values({
      userId: request.claims.sub,
      actorId: request.claims.sub,
      deviceId: input.deviceId,
      action: "model.configured",
      resourceType: "model",
      resourceId: created!.id,
      metadata: { kind: input.kind, model: input.model }
    });
    return created!;
  });
  return reply.code(201).send({
    id: model.id,
    deviceId: model.deviceId,
    name: model.name,
    kind: model.kind,
    baseUrl: model.baseUrl,
    model: model.model,
    contextWindow: model.contextWindow,
    isDefault: model.isDefault,
    keyLastFour: model.keyLastFour,
    createdAt: model.createdAt
  });
});

app.get("/tasks", { preHandler: auth }, async (request) => db.select({
  id: s.tasks.id,
  deviceId: s.tasks.deviceId,
  workspaceName: s.tasks.workspaceName,
  status: s.tasks.status,
  model: s.tasks.model,
  inputTokens: s.tasks.inputTokens,
  outputTokens: s.tasks.outputTokens,
  durationMs: s.tasks.durationMs,
  errorCode: s.tasks.errorCode,
  createdAt: s.tasks.createdAt,
  completedAt: s.tasks.completedAt
}).from(s.tasks).where(eq(s.tasks.userId, request.claims.sub)).orderBy(desc(s.tasks.createdAt)).limit(100));

app.post("/usage/events", { preHandler: auth }, async (request, reply) => {
  assertRateLimit(authenticatedWriteLimiter, request.claims.sub);
  const input = usageEventSchema.parse(request.body);
  const idempotencyHeader = request.headers["idempotency-key"];
  const idempotencyKey = idempotencyHeader === undefined
    ? undefined
    : z.string().uuid().parse(Array.isArray(idempotencyHeader) ? idempotencyHeader[0] : idempotencyHeader);
  const result = await db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`usage:${request.claims.sub}`}))`);
    if (idempotencyKey) {
      const [existing] = await tx.select({ id: s.tasks.id }).from(s.tasks).where(and(
        eq(s.tasks.userId, request.claims.sub),
        eq(s.tasks.idempotencyKey, idempotencyKey)
      )).limit(1);
      if (existing) return { id: existing.id, existing: true };
    }
    const [device] = await tx.select({ id: s.devices.id }).from(s.devices).where(and(
      eq(s.devices.id, input.deviceId),
      eq(s.devices.userId, request.claims.sub)
    )).limit(1);
    if (!device) throw new ApiError(404, "device_not_found");
    const [limitSetting] = await tx.select({ value: s.settings.value }).from(s.settings)
      .where(eq(s.settings.key, "usage_limit")).limit(1);
    if (typeof limitSetting?.value === "number") {
      const monthStart = new Date();
      monthStart.setUTCDate(1);
      monthStart.setUTCHours(0, 0, 0, 0);
      const [usage] = await tx.select({
        value: sql<number>`coalesce(sum(${s.tasks.inputTokens} + ${s.tasks.outputTokens}), 0)`
      }).from(s.tasks).where(and(
        eq(s.tasks.userId, request.claims.sub),
        gte(s.tasks.createdAt, monthStart)
      ));
      if (Number(usage?.value ?? 0) + input.inputTokens + input.outputTokens > limitSetting.value) {
        throw new ApiError(429, "usage_limit_exceeded");
      }
    }
    const [task] = await tx.insert(s.tasks).values({
      ...input,
      userId: request.claims.sub,
      idempotencyKey,
      completedAt: input.status === "running" ? undefined : new Date()
    }).returning({ id: s.tasks.id });
    return { id: task!.id, existing: false };
  });
  return reply.code(result.existing ? 200 : 201).send({ id: result.id });
});

app.post("/audit", { preHandler: auth }, async (request, reply) => {
  assertRateLimit(authenticatedWriteLimiter, request.claims.sub);
  const event = auditEventSchema.parse(request.body);
  if (event.deviceId && !(await ownedDevice(request.claims.sub, event.deviceId))) {
    throw new ApiError(404, "device_not_found");
  }
  if (event.resourceId && event.resourceType === "task") {
    const [task] = await db.select({ id: s.tasks.id }).from(s.tasks).where(and(
      eq(s.tasks.id, event.resourceId),
      eq(s.tasks.userId, request.claims.sub)
    )).limit(1);
    if (!task) throw new ApiError(404, "resource_not_found");
  }
  if (event.resourceId && event.resourceType === "model") {
    const [model] = await db.select({ id: s.modelConfigs.id }).from(s.modelConfigs).where(and(
      eq(s.modelConfigs.id, event.resourceId),
      eq(s.modelConfigs.userId, request.claims.sub)
    )).limit(1);
    if (!model) throw new ApiError(404, "resource_not_found");
  }
  await insertAudit({
    userId: request.claims.sub,
    actorId: request.claims.sub,
    deviceId: event.deviceId,
    action: event.action,
    resourceType: event.resourceType,
    resourceId: event.resourceId,
    metadata: event.metadata
  });
  return reply.code(202).send({ accepted: true });
});

app.get("/admin/overview", { preHandler: admin }, async () => {
  const [[users], [tasks], [tokens]] = await Promise.all([
    db.select({ value: count() }).from(s.users),
    db.select({ value: count() }).from(s.tasks),
    db.select({
      input: sql<number>`coalesce(sum(${s.tasks.inputTokens}), 0)`,
      output: sql<number>`coalesce(sum(${s.tasks.outputTokens}), 0)`
    }).from(s.tasks)
  ]);
  return {
    users: users?.value ?? 0,
    tasks: tasks?.value ?? 0,
    inputTokens: Number(tokens?.input ?? 0),
    outputTokens: Number(tokens?.output ?? 0)
  };
});

app.get("/admin/tasks", { preHandler: admin }, async (request) => {
  const { limit, offset, userId, deviceId, status, model, from, to } = adminTaskQuerySchema.parse(request.query);
  const conditions = [
    ...(userId ? [eq(s.tasks.userId, userId)] : []),
    ...(deviceId ? [eq(s.tasks.deviceId, deviceId)] : []),
    ...(status ? [eq(s.tasks.status, status)] : []),
    ...(model ? [eq(s.tasks.model, model)] : []),
    ...(from ? [gte(s.tasks.createdAt, from)] : []),
    ...(to ? [lt(s.tasks.createdAt, new Date(to.getTime() + 1))] : [])
  ];
  return db.select({
    id: s.tasks.id,
    userId: s.tasks.userId,
    userEmail: s.users.email,
    deviceId: s.tasks.deviceId,
    workspaceName: s.tasks.workspaceName,
    status: s.tasks.status,
    model: s.tasks.model,
    inputTokens: s.tasks.inputTokens,
    outputTokens: s.tasks.outputTokens,
    durationMs: s.tasks.durationMs,
    errorCode: s.tasks.errorCode,
    createdAt: s.tasks.createdAt,
    completedAt: s.tasks.completedAt
  }).from(s.tasks).innerJoin(s.users, eq(s.tasks.userId, s.users.id))
    .where(and(...conditions)).orderBy(desc(s.tasks.createdAt)).limit(limit).offset(offset);
});

app.get("/admin/users", { preHandler: admin }, async (request) => {
  const { limit, offset } = paginationSchema.parse(request.query);
  return db.select({
    id: s.users.id,
    email: s.users.email,
    role: s.users.role,
    status: s.users.status,
    createdAt: s.users.createdAt,
    lastLoginAt: s.users.lastLoginAt,
    deviceCount: count(s.devices.id)
  }).from(s.users).leftJoin(s.devices, eq(s.users.id, s.devices.userId)).groupBy(s.users.id)
    .orderBy(desc(s.users.createdAt)).limit(limit).offset(offset);
});

app.patch("/admin/users/:id", { preHandler: admin }, async (request) => {
  assertRateLimit(authenticatedWriteLimiter, request.claims.sub);
  assertRateLimit(authenticatedWriteLimiter, request.claims.sub);
  const { status } = z.object({ status: z.enum(["active", "disabled"]) }).strict().parse(request.body);
  const { id } = uuidParamSchema.parse(request.params);
  if (id === request.claims.sub && status === "disabled") throw new ApiError(400, "cannot_disable_self");
  await db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext('admin-user-status'))`);
    const [actor] = await tx.select({ role: s.users.role, status: s.users.status }).from(s.users)
      .where(eq(s.users.id, request.claims.sub)).limit(1);
    if (!actor || actor.role !== "admin" || actor.status !== "active") throw new ApiError(403, "admin_required");
    const [target] = await tx.select({ role: s.users.role, status: s.users.status }).from(s.users)
      .where(eq(s.users.id, id)).limit(1);
    if (!target) throw new ApiError(404, "user_not_found");
    if (target.role === "admin" && target.status === "active" && status === "disabled") {
      const [activeAdmins] = await tx.select({ value: count() }).from(s.users).where(and(
        eq(s.users.role, "admin"),
        eq(s.users.status, "active")
      ));
      if ((activeAdmins?.value ?? 0) <= 1) throw new ApiError(409, "last_admin_required");
    }
    await tx.update(s.users).set({ status }).where(eq(s.users.id, id));
    await tx.insert(s.audits).values({
      userId: id,
      actorId: request.claims.sub,
      action: "admin.user_status",
      resourceType: "user",
      resourceId: id,
      metadata: { status }
    });
  });
  return { updated: true };
});

app.get("/admin/audits", { preHandler: admin }, async (request) => {
  const { limit, offset } = paginationSchema.parse(request.query);
  return db.select({
    id: s.audits.id,
    userId: s.audits.userId,
    actorId: s.audits.actorId,
    deviceId: s.audits.deviceId,
    action: s.audits.action,
    resourceType: s.audits.resourceType,
    createdAt: s.audits.createdAt
  }).from(s.audits).orderBy(desc(s.audits.createdAt)).limit(limit).offset(offset);
});

app.get("/admin/settings", { preHandler: admin }, async () => db.select({
  key: s.settings.key,
  value: s.settings.value,
  updatedAt: s.settings.updatedAt
}).from(s.settings).orderBy(s.settings.key));

app.put("/admin/settings/:key", { preHandler: admin }, async (request) => {
  assertRateLimit(authenticatedWriteLimiter, request.claims.sub);
  assertRateLimit(authenticatedWriteLimiter, request.claims.sub);
  const key = settingKeySchema.parse((request.params as { key?: unknown }).key);
  const body = z.object({ value: z.unknown() }).strict().parse(request.body);
  const value = parseSettingValue(key, body.value);
  await db.transaction(async (tx) => {
    await tx.insert(s.settings).values({ key, value }).onConflictDoUpdate({
      target: s.settings.key,
      set: { value, updatedAt: new Date() }
    });
    await tx.insert(s.audits).values({
      userId: null,
      actorId: request.claims.sub,
      action: "admin.setting_changed",
      resourceType: "setting",
      resourceId: key,
      metadata: {}
    });
    if (key === "audit_retention_days") {
      const cutoff = new Date(Date.now() - Number(value) * 24 * 60 * 60_000);
      await tx.delete(s.audits).where(lt(s.audits.createdAt, cutoff));
    }
  });
  return { updated: true };
});

app.setNotFoundHandler((_request, reply) => reply.code(404).send({ error: "not_found" }));
app.setErrorHandler((error, request, reply) => {
  if (error instanceof z.ZodError) {
    return reply.code(400).send({
      error: "validation_error",
      issues: error.issues.map((issue) => ({ path: issue.path, code: issue.code, message: issue.message }))
    });
  }
  if (error instanceof ApiError) {
    if (error.retryAfter) reply.header("retry-after", String(error.retryAfter));
    return reply.code(error.statusCode).send({ error: error.code });
  }
  if (error instanceof MailDeliveryError) return reply.code(503).send({ error: error.message });
  const databaseCode = (error as { code?: unknown }).code;
  if (databaseCode === "23505") return reply.code(409).send({ error: "conflict" });
  if (databaseCode === "23503") return reply.code(409).send({ error: "invalid_reference" });
  const normalizedError = error instanceof Error ? error : new Error("unknown_error");
  request.log.error({
    error: {
      name: normalizedError.name,
      message: config.production ? "request_failed" : normalizedError.message,
      code: typeof databaseCode === "string" ? databaseCode : undefined
    }
  }, "request failed");
  return reply.code(500).send({ error: "internal_error" });
});

await pool.query("select 1");
await app.listen({ host: config.host, port: config.port });

const shutdown = async () => {
  await app.close();
  await pool.end();
};
process.once("SIGINT", () => void shutdown());
process.once("SIGTERM", () => void shutdown());
