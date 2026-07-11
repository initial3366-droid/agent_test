import { z } from "zod";

const DEFAULT_DATABASE_URL = "postgres://forge:forge@localhost:5432/forge";
const DEFAULT_JWT_SECRET = "development-secret-change-before-production";

const rawEnvironmentSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_HOST: z.string().trim().min(1).default("127.0.0.1"),
  API_PORT: z.coerce.number().int().min(1).max(65_535).default(4000),
  DATABASE_URL: z.string().trim().min(1).optional(),
  JWT_SECRET: z.string().min(32).optional(),
  OTP_SECRET: z.string().min(32).optional(),
  JWT_ISSUER: z.string().trim().min(1).max(200).default("forge-api"),
  JWT_AUDIENCE: z.string().trim().min(1).max(200).default("forge-web"),
  WEB_ORIGIN: z.string().trim().min(1).default("http://localhost:3000"),
  ALLOW_INSECURE_PUBLIC_ORIGIN: z.enum(["true", "false"]).default("false"),
  TRUST_PROXY: z.string().trim().optional(),
  BOOTSTRAP_ADMIN_EMAIL: z.string().trim().email().max(254).optional(),
  REGISTRATION_OPEN_DEFAULT: z.enum(["true", "false"]).optional(),
  RETURN_LOGIN_CODE: z.enum(["true", "false"]).optional(),
  RESEND_API_KEY: z.string().trim().min(1).optional(),
  RESEND_FROM_EMAIL: z.string().trim().email().max(254).optional(),
  RESEND_API_URL: z.string().url().default("https://api.resend.com/emails"),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info")
});

function parseOrigins(value: string): string[] {
  const origins = value.split(",").map((entry) => entry.trim()).filter(Boolean);
  if (origins.length === 0) throw new Error("WEB_ORIGIN must contain at least one origin");

  return origins.map((entry) => {
    const url = new URL(entry);
    if (!["http:", "https:"].includes(url.protocol) || url.origin !== entry) {
      throw new Error(`WEB_ORIGIN contains an invalid origin: ${entry}`);
    }
    return url.origin;
  });
}

function weakSecret(value: string): boolean {
  return /(replace|change|example|password|secret)/i.test(value) || new Set(value).size < 12;
}

export type ApiConfig = ReturnType<typeof loadConfig>;

export function loadConfig(environment: NodeJS.ProcessEnv = process.env) {
  const raw = rawEnvironmentSchema.parse(environment);
  const production = raw.NODE_ENV === "production";
  const databaseUrl = raw.DATABASE_URL ?? (production ? undefined : DEFAULT_DATABASE_URL);
  const jwtSecret = raw.JWT_SECRET ?? (production ? undefined : DEFAULT_JWT_SECRET);
  const otpSecret = raw.OTP_SECRET ?? (production ? undefined : jwtSecret);
  const returnLoginCode = raw.RETURN_LOGIN_CODE === "true" ||
    (raw.RETURN_LOGIN_CODE === undefined && !production && ["127.0.0.1", "localhost", "::1"].includes(raw.API_HOST));
  const loopbackBinding = ["127.0.0.1", "localhost", "::1"].includes(raw.API_HOST);
  const allowedOrigins = parseOrigins(raw.WEB_ORIGIN);
  const allowInsecurePublicOrigin = raw.ALLOW_INSECURE_PUBLIC_ORIGIN === "true";

  if (!databaseUrl) throw new Error("DATABASE_URL is required in production");
  if (production && databaseUrl === DEFAULT_DATABASE_URL) {
    throw new Error("The development DATABASE_URL cannot be used in production");
  }
  if (!jwtSecret || jwtSecret === DEFAULT_JWT_SECRET) {
    if (production) throw new Error("A non-default JWT_SECRET is required in production");
  }
  if (production && jwtSecret && weakSecret(jwtSecret)) {
    throw new Error("JWT_SECRET does not meet production entropy requirements");
  }
  if (!otpSecret || (production && otpSecret === jwtSecret)) {
    if (production) throw new Error("A distinct OTP_SECRET is required in production");
  }
  if (production && otpSecret && weakSecret(otpSecret)) {
    throw new Error("OTP_SECRET does not meet production entropy requirements");
  }
  if (production && returnLoginCode) throw new Error("RETURN_LOGIN_CODE cannot be enabled in production");
  if (production && (!raw.RESEND_API_KEY || !raw.RESEND_FROM_EMAIL)) {
    throw new Error("RESEND_API_KEY and RESEND_FROM_EMAIL are required in production");
  }
  if (production && raw.RESEND_API_KEY && raw.RESEND_API_KEY.length < 16) {
    throw new Error("RESEND_API_KEY is invalid");
  }
  if (production && !raw.BOOTSTRAP_ADMIN_EMAIL) {
    throw new Error("BOOTSTRAP_ADMIN_EMAIL is required in production");
  }
  if (!production && !loopbackBinding && (jwtSecret === DEFAULT_JWT_SECRET || databaseUrl === DEFAULT_DATABASE_URL)) {
    throw new Error("Non-loopback API bindings require non-default database and JWT configuration");
  }
  if (production && !allowInsecurePublicOrigin && allowedOrigins.some((origin) => new URL(origin).protocol !== "https:")) {
    throw new Error("WEB_ORIGIN must use HTTPS in production");
  }

  const resendUrl = new URL(raw.RESEND_API_URL);
  if (production && resendUrl.protocol !== "https:") {
    throw new Error("RESEND_API_URL must use HTTPS in production");
  }

  return {
    nodeEnv: raw.NODE_ENV,
    production,
    host: raw.API_HOST,
    port: raw.API_PORT,
    databaseUrl,
    jwtSecret: jwtSecret!,
    otpSecret: otpSecret!,
    jwtIssuer: raw.JWT_ISSUER,
    jwtAudience: raw.JWT_AUDIENCE,
    allowedOrigins,
    allowInsecurePublicOrigin,
    trustProxy: raw.TRUST_PROXY ? raw.TRUST_PROXY.split(",").map((entry) => entry.trim()).filter(Boolean) : false,
    bootstrapAdminEmail: raw.BOOTSTRAP_ADMIN_EMAIL?.toLowerCase(),
    registrationOpenDefault: raw.REGISTRATION_OPEN_DEFAULT === "true" ||
      (raw.REGISTRATION_OPEN_DEFAULT === undefined && !production),
    returnLoginCode,
    resendApiKey: raw.RESEND_API_KEY,
    resendFromEmail: raw.RESEND_FROM_EMAIL,
    resendApiUrl: raw.RESEND_API_URL,
    logLevel: raw.LOG_LEVEL
  };
}
