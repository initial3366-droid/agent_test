import { sql } from "drizzle-orm";
import {
  boolean,
  check,
  foreignKey,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid
} from "drizzle-orm/pg-core";

export const role = pgEnum("role", ["user", "admin"]);
export const userStatus = pgEnum("user_status", ["active", "disabled"]);
export const devicePlatform = pgEnum("device_platform", ["windows", "macos"]);
export const providerKind = pgEnum("provider_kind", ["openai", "anthropic", "openai-compatible"]);
export const taskStatus = pgEnum("task_status", ["running", "completed", "failed", "cancelled"]);

export const users = pgTable("users", {
  id: uuid("id").defaultRandom().primaryKey(),
  email: text("email").notNull().unique(),
  role: role("role").notNull().default("user"),
  status: userStatus("status").notNull().default("active"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  lastLoginAt: timestamp("last_login_at", { withTimezone: true })
}, (table) => [
  index("users_created_at_idx").on(table.createdAt)
]);

export const loginCodes = pgTable("login_codes", {
  id: uuid("id").defaultRandom().primaryKey(),
  email: text("email").notNull(),
  codeHash: text("code_hash").notNull(),
  requestIpHash: text("request_ip_hash").notNull(),
  registrationAllowed: boolean("registration_allowed").notNull().default(false),
  attempts: integer("attempts").notNull().default(0),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  usedAt: timestamp("used_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull()
}, (table) => [
  index("login_codes_email_created_idx").on(table.email, table.createdAt),
  index("login_codes_ip_created_idx").on(table.requestIpHash, table.createdAt),
  index("login_codes_expires_at_idx").on(table.expiresAt),
  check("login_codes_attempts_nonnegative", sql`${table.attempts} >= 0`)
]);

export const devices = pgTable("devices", {
  id: uuid("id").defaultRandom().primaryKey(),
  userId: uuid("user_id").references(() => users.id, { onDelete: "cascade" }).notNull(),
  name: text("name").notNull(),
  platform: devicePlatform("platform").notNull(),
  version: text("version").notNull(),
  keyConfigured: boolean("key_configured").default(false).notNull(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).defaultNow().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull()
}, (table) => [
  uniqueIndex("devices_user_id_id_unique").on(table.userId, table.id),
  index("devices_user_last_seen_idx").on(table.userId, table.lastSeenAt)
]);

export const modelConfigs = pgTable("model_configs", {
  id: uuid("id").defaultRandom().primaryKey(),
  userId: uuid("user_id").references(() => users.id, { onDelete: "cascade" }).notNull(),
  deviceId: uuid("device_id").notNull(),
  name: text("name").notNull(),
  kind: providerKind("kind").notNull(),
  baseUrl: text("base_url").notNull(),
  model: text("model").notNull(),
  contextWindow: integer("context_window").notNull(),
  isDefault: boolean("is_default").default(false).notNull(),
  keyLastFour: text("key_last_four"),
  keyFingerprint: text("key_fingerprint"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull()
}, (table) => [
  foreignKey({
    name: "model_configs_owned_device_fk",
    columns: [table.userId, table.deviceId],
    foreignColumns: [devices.userId, devices.id]
  }).onDelete("cascade"),
  uniqueIndex("model_configs_one_default_per_user")
    .on(table.userId)
    .where(sql`${table.isDefault} = true`),
  index("model_configs_user_created_idx").on(table.userId, table.createdAt),
  check("model_configs_context_window_positive", sql`${table.contextWindow} > 0`)
]);

export const tasks = pgTable("tasks", {
  id: uuid("id").defaultRandom().primaryKey(),
  userId: uuid("user_id").references(() => users.id, { onDelete: "cascade" }).notNull(),
  deviceId: uuid("device_id").notNull(),
  idempotencyKey: text("idempotency_key"),
  workspaceName: text("workspace_name").notNull(),
  status: taskStatus("status").notNull(),
  model: text("model").notNull(),
  inputTokens: integer("input_tokens").default(0).notNull(),
  outputTokens: integer("output_tokens").default(0).notNull(),
  durationMs: integer("duration_ms"),
  errorCode: text("error_code"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  completedAt: timestamp("completed_at", { withTimezone: true })
}, (table) => [
  foreignKey({
    name: "tasks_owned_device_fk",
    columns: [table.userId, table.deviceId],
    foreignColumns: [devices.userId, devices.id]
  }),
  uniqueIndex("tasks_user_idempotency_unique")
    .on(table.userId, table.idempotencyKey)
    .where(sql`${table.idempotencyKey} is not null`),
  index("tasks_user_created_idx").on(table.userId, table.createdAt),
  check("tasks_input_tokens_nonnegative", sql`${table.inputTokens} >= 0`),
  check("tasks_output_tokens_nonnegative", sql`${table.outputTokens} >= 0`),
  check("tasks_duration_nonnegative", sql`${table.durationMs} is null or ${table.durationMs} >= 0`)
]);

export type AuditMetadata = Record<string, string | number | boolean | null>;

export const audits = pgTable("audits", {
  id: uuid("id").defaultRandom().primaryKey(),
  userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
  actorId: uuid("actor_id").references(() => users.id, { onDelete: "set null" }),
  deviceId: uuid("device_id").references(() => devices.id, { onDelete: "set null" }),
  action: text("action").notNull(),
  resourceType: text("resource_type").notNull(),
  resourceId: text("resource_id"),
  metadata: jsonb("metadata").$type<AuditMetadata>().default({}).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull()
}, (table) => [
  index("audits_created_at_idx").on(table.createdAt),
  index("audits_user_created_idx").on(table.userId, table.createdAt),
  index("audits_actor_created_idx").on(table.actorId, table.createdAt)
]);

export const settings = pgTable("settings", {
  key: text("key").primaryKey(),
  value: jsonb("value").notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull()
});
