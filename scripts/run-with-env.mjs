import { spawn } from "node:child_process";
import { loadEnvFile } from "node:process";

try {
  loadEnvFile(".env");
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}

const [command, ...arguments_] = process.argv.slice(2);
if (!command) throw new Error("A command is required");
const executable = process.platform === "win32" && command === "pnpm" ? "pnpm.cmd" : command;
const child = spawn(executable, arguments_, { stdio: "inherit", env: process.env, shell: false });
child.once("error", (error) => {
  console.error(error.message);
  process.exitCode = 1;
});
child.once("exit", (code, signal) => {
  process.exitCode = code ?? (signal ? 1 : 0);
});
