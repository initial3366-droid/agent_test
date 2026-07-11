# Forge Agent

Forge is a local-first AI coding agent with a cloud account/audit control plane and a Windows/macOS execution client.

The web application manages accounts, devices, model metadata, coding tasks, approvals, usage totals, and administration. The local agent selects workspaces, stores API keys in the operating-system credential store, calls model APIs, reads and changes files, and runs approved commands. Source code and task content are not sent to the cloud API.

## Development

Requirements: Node.js 22 LTS, pnpm 11, Docker, Git, and ripgrep. Rust is additionally required to build the Tauri shell.

1. Copy `.env.example` to `.env`. Replace all secrets and set `BOOTSTRAP_ADMIN_EMAIL`.
2. Keep `FORGE_AGENT_TOKEN` and `NEXT_PUBLIC_FORGE_AGENT_TOKEN` equal only for local development. Never use a `NEXT_PUBLIC_*` bootstrap token in production.
3. Start development infrastructure with `docker compose up -d`.
4. Install dependencies with `pnpm install`.
5. Create or update the development schema with `pnpm db:push`.
6. Start the API, web app, and local agent with `pnpm dev`.
7. Open `http://localhost:3000`.

The development login code is returned by the request-code endpoint when `RETURN_LOGIN_CODE=true`. Set `FORGE_WORKSPACE` to bypass the native folder picker in automated tests.

Useful checks:

```sh
pnpm typecheck
pnpm test
pnpm build
```

## Workspace layout

- `apps/web`: Next.js workbench, same-origin authentication BFF, task and admin UI.
- `apps/api`: Fastify account, device, model metadata, usage, and audit API.
- `apps/agent`: loopback-only local filesystem, command, keychain, model, and task service.
- `apps/desktop`: Tauri tray shell scaffold for signed Windows/macOS packaging.
- `packages/protocol`: strict shared request/event contracts.
- `packages/agent-core`: provider adapters and the bounded approval-aware Agent state machine.

## Release boundary

The Tauri source supervises the packaged local-agent sidecar, consumes and deletes its bootstrap token file, opens the web workbench with a one-time URL fragment, and terminates the child on exit. The web workbench uses authenticated WebSocket events with sequence-based HTTP recovery. Before distribution, build the sidecar for each target, verify keychain native-module packaging, persist the cloud device ID, and code-sign Windows/macOS installers and update artifacts.

Read [SECURITY.md](./SECURITY.md) before deployment. It documents trust boundaries, enforced controls, required production configuration, and residual risks.
# agent_test
