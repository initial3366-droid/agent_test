import { defineConfig } from "drizzle-kit";
export default defineConfig({ schema: "./src/schema.ts", out: "./drizzle", dialect: "postgresql", dbCredentials: { url: process.env.DATABASE_URL ?? "postgres://forge:forge@localhost:5432/forge" } });
