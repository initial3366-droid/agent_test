import { link, mkdtemp, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { validateRelativePath, WorkspaceStore } from "./workspaces.js";

describe("WorkspaceStore", () => {
  it("detects conflicts, missing hashes and path escapes", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "forge-"));
    await writeFile(path.join(root, "a.txt"), "one");
    const store = new WorkspaceStore();
    const workspace = await store.add(root);
    const file = await store.read(workspace.id, "a.txt");
    await expect(store.write(workspace.id, "a.txt", "unsafe")).rejects.toThrow("expected_hash_required");
    await store.write(workspace.id, "a.txt", "two", file.hash);
    await expect(store.write(workspace.id, "a.txt", "three", file.hash)).rejects.toThrow("version_conflict");
    await expect(store.read(workspace.id, "../outside")).rejects.toThrow("path_escape");
  });

  it("blocks symlinks for reads and writes", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "forge-"));
    const outside = await mkdtemp(path.join(os.tmpdir(), "outside-"));
    await writeFile(path.join(outside, "secret"), "x");
    await symlink(outside, path.join(root, "link"));
    const store = new WorkspaceStore();
    const workspace = await store.add(root);
    await expect(store.read(workspace.id, "link/secret")).rejects.toThrow("symlink_forbidden");
    await expect(store.write(workspace.id, "link/new.txt", "x")).rejects.toThrow("symlink_forbidden");
  });

  it("blocks hardlinks and destination replacement", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "forge-"));
    await writeFile(path.join(root, "a.txt"), "one");
    await link(path.join(root, "a.txt"), path.join(root, "linked.txt"));
    await writeFile(path.join(root, "destination.txt"), "keep");
    const store = new WorkspaceStore();
    const workspace = await store.add(root);
    await expect(store.read(workspace.id, "linked.txt")).rejects.toThrow("hardlink_forbidden");
    await expect(store.rename(workspace.id, "a.txt", "destination.txt", "0".repeat(64))).rejects.toThrow();
  });

  it("does not expose hardlink content through search", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "forge-"));
    const outside = await mkdtemp(path.join(os.tmpdir(), "outside-"));
    await writeFile(path.join(outside, "secret.txt"), "DO_NOT_EXPOSE");
    await link(path.join(outside, "secret.txt"), path.join(root, "linked.txt"));
    const store = new WorkspaceStore();
    const workspace = await store.add(root);
    expect(await store.search(workspace.id, "DO_NOT_EXPOSE")).toEqual([]);
  });
});

describe("validateRelativePath", () => {
  it("rejects Windows device paths, ADS and UNC paths", () => {
    expect(() => validateRelativePath("CON.txt", "win32")).toThrow("windows_path_forbidden");
    expect(() => validateRelativePath("file.txt:stream", "win32")).toThrow("windows_ads_forbidden");
    expect(() => validateRelativePath("\\\\server\\share", "win32")).toThrow("absolute_path_forbidden");
  });
});
