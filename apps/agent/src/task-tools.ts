import { z } from "zod";
import type { ExecutionPolicy, ToolDefinition } from "@forge/protocol";
import { safeGitDiff } from "./git.js";
import type { WorkspaceStore } from "./workspaces.js";

export function workspaceTools(store:WorkspaceStore,workspaceId:string,runCommand?:(command:string,timeoutMs:number)=>Promise<unknown>):ToolDefinition<any>[] { return [
  {name:"list_files",risk:"read",schema:z.object({}).strict(),execute:async()=>store.files(workspaceId)},
  {name:"read_file",risk:"read",schema:z.object({path:z.string().min(1).max(4096)}).strict(),execute:async({path})=>store.read(workspaceId,path)},
  {name:"search_code",risk:"read",schema:z.object({query:z.string().min(1).max(200)}).strict(),execute:async({query})=>store.search(workspaceId,query)},
  {name:"git_diff",risk:"read",schema:z.object({}).strict(),execute:async()=>safeGitDiff(store,workspaceId)},
  {name:"write_file",risk:"write",schema:z.object({path:z.string().min(1).max(4096),content:z.string().max(2_000_000),expectedHash:z.string().regex(/^[a-f0-9]{64}$/i).optional()}).strict(),execute:async({path,content,expectedHash})=>store.write(workspaceId,path,content,expectedHash)},
  {name:"delete_file",risk:"write",schema:z.object({path:z.string().min(1).max(4096),expectedHash:z.string().regex(/^[a-f0-9]{64}$/i)}).strict(),execute:async({path,expectedHash})=>store.delete(workspaceId,path,expectedHash)},
  {name:"rename_file",risk:"write",schema:z.object({path:z.string().min(1).max(4096),destination:z.string().min(1).max(4096),expectedHash:z.string().regex(/^[a-f0-9]{64}$/i)}).strict(),execute:async({path,destination,expectedHash})=>store.rename(workspaceId,path,destination,expectedHash)},
  ...(runCommand?[{name:"run_command",risk:"dangerous" as const,schema:z.object({command:z.string().min(1).max(4000).refine(value=>!/[\0-\x1f\x7f]/.test(value)),timeoutMs:z.number().int().min(1000).max(300_000).default(120_000)}).strict(),execute:async({command,timeoutMs}:{command:string;timeoutMs:number})=>runCommand(command,timeoutMs)}]:[])
] }

export const defaultExecutionPolicy:ExecutionPolicy={evaluate({tool}){return ["list_files","read_file","search_code","git_diff","write_file","delete_file","rename_file","run_command"].includes(tool)?"allow":"deny"}};

export const SYSTEM_PROMPT=`You are Forge Agent, a local coding agent. Inspect the repository before changing it. Call at most one tool per response. The user grants tool execution for the current workspace session through the UI, so do not ask again before ordinary file operations or commands. Ask only when requirements are genuinely ambiguous or multiple materially different solutions exist. Never overwrite a file after a version conflict; read it again first. Keep changes scoped to the user's task, preserve unknown modifications, run focused verification when appropriate, and finish with a concise summary and verification status.`;
