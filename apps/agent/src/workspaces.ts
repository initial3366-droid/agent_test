import { createHash, randomUUID } from "node:crypto";
import {
  constants as fsConstants,
  link,
  lstat,
  open,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  unlink
} from "node:fs/promises";
import path from "node:path";

const MAX_FILE_BYTES = 2_000_000;
const MAX_FILES = 2_000;
const MAX_SCANNED_ENTRIES = 20_000;
const MAX_TREE_DEPTH = 40;
const MAX_SEARCH_BYTES = 20_000_000;
const MAX_SEARCH_RESULTS = 200;
const IGNORED_DIRECTORIES = new Set([".git", ".next", "node_modules", "target"]);
const WINDOWS_RESERVED_NAME = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;

type Platform = NodeJS.Platform;

export type Workspace = {
  id: string;
  name: string;
  root: string;
  rootDevice: number;
  rootInode: number;
  lastOpenedAt: string;
};

export type PublicWorkspace = {
  id: string;
  name: string;
  lastOpenedAt: string;
  gitBranch: null;
};

function isMissing(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT";
}

function isExisting(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "EEXIST";
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`));
}

function samePath(left: string, right: string, platform: Platform): boolean {
  return platform === "win32" ? left.toLocaleLowerCase("en-US") === right.toLocaleLowerCase("en-US") : left === right;
}

export function validateRelativePath(value: string, platform: Platform = process.platform): string {
  if (!value || value.length > 4096 || /[\0-\x1f\x7f]/.test(value)) throw new Error("invalid_path");
  if (path.isAbsolute(value) || path.posix.isAbsolute(value) || path.win32.isAbsolute(value)) {
    throw new Error("absolute_path_forbidden");
  }

  const nativeSegments = platform === "win32" ? value.split(/[\\/]+/).filter(Boolean) : value.split("/").filter(Boolean);
  if (nativeSegments.length === 0 || nativeSegments.some(segment => segment === "..")) throw new Error("path_escape");
  if (platform === "win32") {
    for (const segment of nativeSegments) {
      if (segment.includes(":")) throw new Error("windows_ads_forbidden");
      if (/[. ]$/.test(segment) || WINDOWS_RESERVED_NAME.test(segment)) throw new Error("windows_path_forbidden");
    }
  }

  const normalized = path.normalize(value);
  if (normalized === "." || normalized === ".." || normalized.startsWith(`..${path.sep}`)) throw new Error("path_escape");
  return normalized;
}

function decodeText(content: Buffer): string {
  if (content.includes(0)) throw new Error("binary_file");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(content);
  } catch {
    throw new Error("binary_file");
  }
}

export class WorkspaceStore {
  private readonly items = new Map<string, Workspace>();

  async add(inputRoot: string): Promise<PublicWorkspace> {
    if (!inputRoot || inputRoot.includes("\0")) throw new Error("invalid_workspace");
    const root = await realpath(path.resolve(inputRoot));
    const info = await stat(root);
    if (!info.isDirectory()) throw new Error("workspace_not_directory");
    const id = randomUUID();
    const workspace: Workspace = {
      id,
      name: path.basename(root) || root,
      root,
      rootDevice: info.dev,
      rootInode: info.ino,
      lastOpenedAt: new Date().toISOString()
    };
    this.items.set(id, workspace);
    return this.public(workspace);
  }

  public(workspace: Workspace): PublicWorkspace {
    return { id: workspace.id, name: workspace.name, lastOpenedAt: workspace.lastOpenedAt, gitBranch: null };
  }

  get(id: string): Workspace {
    const workspace = this.items.get(id);
    if (!workspace) throw new Error("workspace_not_found");
    return workspace;
  }

  async root(id: string): Promise<string> {
    const workspace = this.get(id);
    let currentRoot: string;
    try {
      currentRoot = await realpath(workspace.root);
    } catch (error) {
      if (isMissing(error)) throw new Error("workspace_unavailable");
      throw error;
    }
    const info = await stat(currentRoot);
    if (
      !info.isDirectory() ||
      !samePath(currentRoot, workspace.root, process.platform) ||
      info.dev !== workspace.rootDevice ||
      (workspace.rootInode !== 0 && info.ino !== workspace.rootInode)
    ) {
      throw new Error("workspace_changed");
    }
    return workspace.root;
  }

  private async assertNoLinks(root: string, candidate: string, includeFinal: boolean): Promise<void> {
    const relative = path.relative(root, candidate);
    const parts = relative.split(path.sep).filter(Boolean);
    const count = includeFinal ? parts.length : Math.max(parts.length - 1, 0);
    let current = root;
    for (let index = 0; index < count; index += 1) {
      current = path.join(current, parts[index]!);
      let info;
      try {
        info = await lstat(current);
      } catch (error) {
        if (isMissing(error)) throw new Error(index === count - 1 ? "path_not_found" : "parent_not_found");
        throw error;
      }
      if (info.isSymbolicLink()) throw new Error("symlink_forbidden");
      if (index < count - 1 && !info.isDirectory()) throw new Error("parent_not_directory");
    }
  }

  async resolve(id: string, relativeInput: string, allowMissing = false): Promise<string> {
    const root = await this.root(id);
    const relative = validateRelativePath(relativeInput);
    const candidate = path.resolve(root, relative);
    if (!isWithin(root, candidate) || samePath(root, candidate, process.platform)) throw new Error("path_escape");

    if (allowMissing) {
      await this.assertNoLinks(root, candidate, false);
      const parent = await realpath(path.dirname(candidate)).catch(error => {
        if (isMissing(error)) throw new Error("parent_not_found");
        throw error;
      });
      if (!isWithin(root, parent)) throw new Error("parent_escape");
      return candidate;
    }

    await this.assertNoLinks(root, candidate, true);
    const actual = await realpath(candidate).catch(error => {
      if (isMissing(error)) throw new Error("path_not_found");
      throw error;
    });
    if (!isWithin(root, actual)) throw new Error("symlink_escape");
    return candidate;
  }

  private async readBuffer(id: string, relative: string): Promise<{ file: string; content: Buffer; mode: number }> {
    const file = await this.resolve(id, relative);
    const handle = await open(file, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    try {
      const info = await handle.stat();
      if (!info.isFile()) throw new Error("not_a_file");
      if (info.nlink > 1) throw new Error("hardlink_forbidden");
      if (info.size > MAX_FILE_BYTES) throw new Error("file_too_large");

      const root = await this.root(id);
      const actualAfterOpen = await realpath(file);
      if (!isWithin(root, actualAfterOpen)) throw new Error("path_changed");
      await this.assertNoLinks(root, file, true);
      const pathInfo = await lstat(file);
      if (pathInfo.isSymbolicLink() || pathInfo.dev !== info.dev || (info.ino !== 0 && pathInfo.ino !== info.ino)) {
        throw new Error("path_changed");
      }
      return { file, content: await handle.readFile(), mode: info.mode };
    } finally {
      await handle.close();
    }
  }

  async files(id: string): Promise<Array<{ path: string }>> {
    const root = await this.root(id);
    const files: Array<{ path: string }> = [];
    const queue: Array<{ directory: string; depth: number }> = [{ directory: root, depth: 0 }];
    let scanned = 0;

    while (queue.length > 0 && files.length < MAX_FILES && scanned < MAX_SCANNED_ENTRIES) {
      const current = queue.shift()!;
      const actual = await realpath(current.directory);
      if (!isWithin(root, actual)) throw new Error("directory_escape");
      await this.assertNoLinks(root, current.directory, true);
      const entries = await readdir(current.directory, { withFileTypes: true });
      entries.sort((left, right) => left.name.localeCompare(right.name));
      for (const entry of entries) {
        scanned += 1;
        if (scanned > MAX_SCANNED_ENTRIES || files.length >= MAX_FILES) break;
        if (entry.isSymbolicLink()) continue;
        const absolute = path.join(current.directory, entry.name);
        const relative = path.relative(root, absolute);
        if (entry.isDirectory()) {
          if (current.depth < MAX_TREE_DEPTH && !IGNORED_DIRECTORIES.has(entry.name)) {
            queue.push({ directory: absolute, depth: current.depth + 1 });
          }
        } else if (entry.isFile()) {
          files.push({ path: relative });
        }
      }
    }
    return files;
  }

  async read(id: string, relative: string): Promise<{ path: string; content: string; hash: string; size: number }> {
    const result = await this.readBuffer(id, relative);
    return { path: relative, content: decodeText(result.content), hash: hash(result.content), size: result.content.length };
  }

  async validateDiffPaths(id: string, paths: string[]): Promise<void> {
    if (paths.length > MAX_FILES) throw new Error("too_many_changed_files");
    for (const relative of paths) {
      try {
        await this.readBuffer(id, relative);
      } catch (error) {
        if (error instanceof Error && ["path_not_found", "parent_not_found"].includes(error.message)) continue;
        throw error;
      }
    }
  }

  async search(id: string, query: string): Promise<Array<{ path: string; lineNumber: number; line: string; matchStart: number; matchEnd: number }>> {
    if (!query || query.length > 200 || /[\0-\x1f\x7f]/.test(query)) throw new Error("invalid_search_query");
    const results: Array<{ path: string; lineNumber: number; line: string; matchStart: number; matchEnd: number }> = [];
    let scannedBytes = 0;
    for (const entry of await this.files(id)) {
      if (results.length >= MAX_SEARCH_RESULTS || scannedBytes >= MAX_SEARCH_BYTES) break;
      let file;
      try {
        file = await this.read(id, entry.path);
      } catch (error) {
        if (error instanceof Error && ["binary_file", "file_too_large", "hardlink_forbidden"].includes(error.message)) continue;
        throw error;
      }
      scannedBytes += file.size;
      if (scannedBytes > MAX_SEARCH_BYTES) break;
      const lines = file.content.split(/\r?\n/);
      for (let index = 0; index < lines.length && results.length < MAX_SEARCH_RESULTS; index += 1) {
        const matchStart = lines[index]!.indexOf(query);
        if (matchStart >= 0) {
          results.push({ path: entry.path, lineNumber: index + 1, line: lines[index]!, matchStart, matchEnd: matchStart + query.length });
        }
      }
    }
    return results;
  }

  async write(id: string, relative: string, content: string, expectedHash?: string): Promise<{ hash: string }> {
    const bytes = Buffer.from(content, "utf8");
    if (bytes.length > MAX_FILE_BYTES) throw new Error("file_too_large");
    const file = await this.resolve(id, relative, true);
    const parent = path.dirname(file);
    let existing: { content: Buffer; mode: number } | undefined;
    try {
      existing = await this.readBuffer(id, relative);
    } catch (error) {
      if (!(error instanceof Error) || error.message !== "path_not_found") throw error;
    }

    if (existing) {
      if (!expectedHash) throw new Error("expected_hash_required");
      if (hash(existing.content) !== expectedHash) throw new Error("version_conflict");
    } else if (expectedHash) {
      throw new Error("version_conflict");
    }

    const temporary = path.join(parent, `.forge-${randomUUID()}.tmp`);
    try {
      const handle = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, existing?.mode ?? 0o600);
      try {
        const root = await this.root(id);
        const actualTemporary = await realpath(temporary);
        if (!isWithin(root, actualTemporary)) throw new Error("path_changed");
        await this.assertNoLinks(root, temporary, true);
        const handleInfo = await handle.stat();
        const pathInfo = await lstat(temporary);
        if (pathInfo.isSymbolicLink() || pathInfo.dev !== handleInfo.dev || (handleInfo.ino !== 0 && pathInfo.ino !== handleInfo.ino)) {
          throw new Error("path_changed");
        }
        await handle.writeFile(bytes);
        await handle.sync();
      } finally {
        await handle.close();
      }

      await this.root(id);
      await this.assertNoLinks(await this.root(id), file, false);
      if (existing) {
        const latest = await this.readBuffer(id, relative);
        if (hash(latest.content) !== expectedHash) throw new Error("version_conflict");
        await rename(temporary, file);
      } else {
        try {
          await link(temporary, file);
        } catch (error) {
          if (isExisting(error)) throw new Error("version_conflict");
          throw error;
        }
        await unlink(temporary);
      }
    } finally {
      await rm(temporary, { force: true }).catch(() => undefined);
    }
    return { hash: hash(bytes) };
  }

  async delete(id: string, relative: string, expectedHash: string): Promise<void> {
    const current = await this.readBuffer(id, relative);
    if (hash(current.content) !== expectedHash) throw new Error("version_conflict");
    const latest = await this.readBuffer(id, relative);
    if (hash(latest.content) !== expectedHash) throw new Error("version_conflict");
    await unlink(latest.file);
  }

  async rename(id: string, source: string, destination: string, expectedHash: string): Promise<void> {
    const current = await this.readBuffer(id, source);
    if (hash(current.content) !== expectedHash) throw new Error("version_conflict");
    const target = await this.resolve(id, destination, true);
    try {
      await lstat(target);
      throw new Error("destination_exists");
    } catch (error) {
      if (error instanceof Error && error.message === "destination_exists") throw error;
      if (!isMissing(error)) throw error;
    }
    const latest = await this.readBuffer(id, source);
    if (hash(latest.content) !== expectedHash) throw new Error("version_conflict");
    try {
      await link(latest.file, target);
    } catch (error) {
      if (isExisting(error)) throw new Error("destination_exists");
      throw error;
    }
    try {
      await unlink(latest.file);
    } catch (error) {
      await unlink(target).catch(() => undefined);
      throw error;
    }
  }
}

export const hash = (value: string | Buffer): string => createHash("sha256").update(value).digest("hex");
