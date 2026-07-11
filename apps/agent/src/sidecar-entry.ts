import { startAgentMain } from "./server.js";

startAgentMain().catch((error: unknown) => {
  const code = error instanceof Error && /^[A-Za-z0-9_]+$/.test(error.message) ? error.message : "startup_failed";
  process.stderr.write(`Forge Agent failed to start: ${code}\n`);
  if (process.env.FORGE_AGENT_DEBUG === "1" && error instanceof Error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
  }
  process.exitCode = 1;
});
