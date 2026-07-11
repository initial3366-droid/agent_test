import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { build } from "esbuild";

const targets = {
  "darwin-arm64": { pkg: "node22-macos-arm64", rust: "aarch64-apple-darwin" },
  "darwin-x64": { pkg: "node22-macos-x64", rust: "x86_64-apple-darwin" },
  "win32-x64": { pkg: "node22-win-x64", rust: "x86_64-pc-windows-msvc" },
};
const selected = targets[`${process.platform}-${process.arch}`];
if (!selected) throw new Error(`Unsupported sidecar build target: ${process.platform}-${process.arch}`);

const root = path.resolve(import.meta.dirname, "..");
const temporary = path.join(root, "apps", "desktop", ".sidecar-build");
const binaries = path.join(root, "apps", "desktop", "src-tauri", "binaries");
await mkdir(temporary, { recursive: true });
await mkdir(binaries, { recursive: true });
const bundle = path.join(temporary, "forge-agent.cjs");
const output = path.join(binaries, `forge-agent-${selected.rust}${process.platform === "win32" ? ".exe" : ""}`);

await build({
  entryPoints: [path.join(root, "apps", "agent", "src", "sidecar-entry.ts")],
  outfile: bundle,
  bundle: true,
  platform: "node",
  target: "node22",
  format: "cjs",
  define: { "import.meta.url": "undefined" },
  sourcemap: false,
  minify: false,
  external: ["keytar"],
});

await new Promise((resolve, reject) => {
  const executable = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
  const child = spawn(executable, ["exec", "pkg", bundle, "--config", path.join(root, "apps", "desktop", "package.json"), "--targets", selected.pkg, "--output", output, "--compress", "Brotli"], {
    cwd: root,
    env: { ...process.env, PKG_CACHE_PATH: path.join(temporary, "pkg-cache") },
    stdio: "inherit",
    shell: false,
  });
  child.once("error", reject);
  child.once("exit", code => code === 0 ? resolve() : reject(new Error(`pkg exited with code ${code}`)));
});

process.stdout.write(`${output}\n`);
