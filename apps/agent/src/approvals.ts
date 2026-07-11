import { createHash, randomUUID } from "node:crypto";
import { execa } from "execa";

export type ApprovalRisk = "file_write" | "file_delete" | "file_rename" | "command" | "secret_write" | "custom_endpoint" | "private_network";

type Approval = {
  id: string;
  sessionId: string;
  workspaceId?: string;
  risk: ApprovalRisk;
  requestHash: string;
  summary: string;
  expiresAt: number;
};

export type ApprovalChallenge = Pick<Approval, "id" | "risk" | "summary"> & { expiresAt: string };

export function requestHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export class ApprovalStore {
  private readonly approvals = new Map<string, Approval>();

  constructor(private readonly ttlMs = 2 * 60 * 1000, private readonly maximum = 128) {}

  create(input: Omit<Approval, "id" | "expiresAt">): ApprovalChallenge {
    this.cleanup();
    while (this.approvals.size >= this.maximum) {
      const oldest = this.approvals.keys().next().value as string | undefined;
      if (!oldest) break;
      this.approvals.delete(oldest);
    }
    const approval: Approval = { ...input, id: randomUUID(), expiresAt: Date.now() + this.ttlMs };
    this.approvals.set(approval.id, approval);
    return { id: approval.id, risk: approval.risk, summary: approval.summary, expiresAt: new Date(approval.expiresAt).toISOString() };
  }

  consume(id: string, expected: Omit<Approval, "id" | "expiresAt" | "summary" | "risk"> & { risk: ApprovalRisk }): Approval {
    const approval = this.approvals.get(id);
    this.approvals.delete(id);
    if (!approval) throw new Error("approval_invalid");
    if (approval.expiresAt <= Date.now()) throw new Error("approval_expired");
    if (
      approval.sessionId !== expected.sessionId ||
      approval.workspaceId !== expected.workspaceId ||
      approval.risk !== expected.risk ||
      approval.requestHash !== expected.requestHash
    ) {
      throw new Error("approval_mismatch");
    }
    return approval;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [id, approval] of this.approvals) {
      if (approval.expiresAt <= now) this.approvals.delete(id);
    }
  }
}

export type LocalApprover = (approval: { risk: ApprovalRisk; summary: string }) => Promise<boolean>;

function approvalMessage(risk: ApprovalRisk, summary: string): string {
  const clipped = summary.length > 1200 ? `${summary.slice(0, 1200)}\n...` : summary;
  return `Forge Agent 请求本机授权\n\n风险类型：${risk}\n\n${clipped}`;
}

export const nativeLocalApprover: LocalApprover = async ({ risk, summary }) => {
  const message = approvalMessage(risk, summary);
  if (process.platform === "darwin") {
    const script = "on run argv\nset answer to display dialog (item 1 of argv) buttons {\"拒绝\", \"允许\"} default button \"拒绝\" with icon caution\nreturn button returned of answer\nend run";
    const result = await execa("osascript", ["-e", script, "--", message], { reject: false, timeout: 60_000, maxBuffer: 4096 });
    return result.exitCode === 0 && result.stdout.trim() === "允许";
  }
  if (process.platform === "win32") {
    const script = "Add-Type -AssemblyName PresentationFramework; $r=[System.Windows.MessageBox]::Show($env:FORGE_APPROVAL_MESSAGE,'Forge Agent',[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Warning,[System.Windows.MessageBoxResult]::No); if($r -eq 'Yes'){exit 0}else{exit 2}";
    const result = await execa("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-STA", "-Command", script], {
      env: { ...safeChildEnvironment(), FORGE_APPROVAL_MESSAGE: message }, reject: false, timeout: 60_000, maxBuffer: 4096
    });
    return result.exitCode === 0;
  }
  throw new Error("local_approval_unavailable");
};

export function safeChildEnvironment(): NodeJS.ProcessEnv {
  const allowed = [
    "APPDATA", "COMSPEC", "HOME", "HOMEDRIVE", "HOMEPATH", "LANG", "LC_ALL", "LC_CTYPE", "LOCALAPPDATA",
    "PATH", "PATHEXT", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TERM", "TMP", "TMPDIR", "USER", "USERPROFILE", "WINDIR"
  ];
  const environment: NodeJS.ProcessEnv = {};
  for (const key of allowed) {
    const value = process.env[key];
    if (value !== undefined) environment[key] = value;
  }
  return environment;
}
