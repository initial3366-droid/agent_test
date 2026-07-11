import { execa } from "execa";
import { safeChildEnvironment } from "./approvals.js";
import type { WorkspaceStore } from "./workspaces.js";

function gitEnvironment(): NodeJS.ProcessEnv {
  return {
    ...safeChildEnvironment(),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_PAGER: "cat"
  };
}

export async function safeGitDiff(store: WorkspaceStore, workspaceId: string): Promise<{ diff: string; exitCode: number | undefined; timedOut: boolean }> {
  const root = await store.root(workspaceId);
  const options = { cwd: root, env: gitEnvironment(), reject: false as const, timeout: 15_000, maxBuffer: 512_000 };
  const [names, untracked] = await Promise.all([
    execa("git", ["--literal-pathspecs", "-c", "core.fsmonitor=false", "diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv", "--"], options),
    execa("git", ["--literal-pathspecs", "-c", "core.fsmonitor=false", "ls-files", "--others", "--exclude-standard", "-z", "--"], options)
  ]);
  if (names.timedOut || untracked.timedOut) throw new Error("git_timeout");
  if (names.failed || untracked.failed) throw new Error("git_diff_failed");
  const changedPaths = names.stdout.split("\0").filter(Boolean);
  const untrackedPaths = untracked.stdout.split("\0").filter(Boolean);
  const allPaths = [...changedPaths, ...untrackedPaths];
  if (allPaths.length === 0) return { diff: "", exitCode: 0, timedOut: false };
  if (untrackedPaths.length > 100 || allPaths.reduce((total, value) => total + Buffer.byteLength(value), 0) > 100_000) throw new Error("too_many_changed_files");
  await store.validateDiffPaths(workspaceId, allPaths);

  let diff = "";
  let exitCode: number | undefined = 0;
  if (changedPaths.length) {
    const result = await execa("git", ["--literal-pathspecs", "-c", "core.fsmonitor=false", "diff", "--no-ext-diff", "--no-textconv", "--", ...changedPaths], {
      ...options, maxBuffer: 2_000_000
    });
    if (result.timedOut) throw new Error("git_timeout");
    if (result.failed) throw new Error("git_diff_failed");
    diff = result.stdout;
    exitCode = result.exitCode;
  }
  const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";
  for (const relative of untrackedPaths) {
    const remaining = 2_000_000 - Buffer.byteLength(diff);
    if (remaining <= 0) throw new Error("output_too_large");
    const result = await execa("git", ["--literal-pathspecs", "-c", "core.fsmonitor=false", "diff", "--no-index", "--no-ext-diff", "--no-textconv", "--", nullDevice, relative], {
      ...options, maxBuffer: remaining
    });
    if (result.timedOut) throw new Error("git_timeout");
    if (result.exitCode !== 0 && result.exitCode !== 1) throw new Error("git_diff_failed");
    diff += `${diff && result.stdout ? "\n" : ""}${result.stdout}`;
  }
  return { diff, exitCode, timedOut: false };
}
