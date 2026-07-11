# Security model

Forge separates the cloud control plane from the local execution plane. Source files, prompts, tool results, diffs, command output, and API keys must not be sent to the cloud API. The cloud stores account data, device/model metadata, usage totals, and allow-listed audit events only.

## Trust boundaries

- The selected workspace and its repository scripts are trusted by the user. Running tests or package scripts can execute repository-controlled code.
- The Forge web origin, signed desktop bundle, cloud API, and local agent are trusted components.
- Model output, repository contents, custom model endpoints, browser input, and cloud request payloads are untrusted.
- Other websites, LAN peers, and unpaired local processes must not be able to call local agent tools.

## Enforced controls

- Local APIs bind to `127.0.0.1`, validate `Host`, exact `Origin`, Fetch Metadata, a client marker, and short-lived bearer sessions.
- A high-entropy bootstrap token is written with exclusive creation to a user-only temporary file. The desktop client must read it, delete it, and pass it in a URL fragment that the web app immediately removes.
- Workspace paths reject absolute paths, traversal, control characters, Windows alternate streams/reserved names, symbolic links, junction escapes, and hard links.
- Reads use bounded file handles. Writes require a baseline hash, use exclusive temporary files, and fail on concurrent changes.
- Search and Git diff validate files through the workspace boundary and do not invoke textconv, external diff, fsmonitor, or user Git configuration.
- File changes, commands, secrets, private-network endpoints, and custom endpoints require a single-use payload-bound challenge plus a native local confirmation.
- Commands run with a reduced environment, concurrency/output/time limits, and a destructive-command deny policy.
- Model traffic is DNS-resolved before approval and pinned to the approved address with TLS hostname verification. Redirects are not followed.
- Model responses, tool arguments/results, event history, turns, context, and token use have explicit limits.
- Cloud JWTs are held in an HttpOnly, SameSite=Strict BFF cookie. The API rechecks current account status and role on every protected request.
- Login codes use a distinct HMAC secret, constant-time comparison, expiry, single consumption, attempt limits, and database-backed email/IP throttling.
- Device ownership is enforced in application queries and composite database foreign keys. Client audit fields use strict allow lists.

## Production requirements

- Use distinct, randomly generated `JWT_SECRET` and `OTP_SECRET` values and an HTTPS-only `WEB_ORIGIN`.
- Keep PostgreSQL and Redis on a private network, require TLS and unique production credentials, and do not use the Compose development passwords.
- Configure transactional email, database backups, log retention, and centralized rate limiting for multi-instance deployments.
- Code-sign Windows and macOS bundles. Enable updates only after signing and updater key rotation are operational.
- Build and sign the supervised Tauri sidecar for every target and persist `FORGE_DEVICE_ID` in the platform credential store.
- Generate and review a lockfile, run dependency auditing, TypeScript tests, Rust tests, and platform end-to-end tests before release.
- Use an OS sandbox or disposable VM/container for untrusted repositories. Native approval does not make repository scripts safe.

## Known residual risks

- The Node compatibility agent cannot completely eliminate a narrow race with a malicious local process replacing a path between validation and `unlink`/`rename`. The production Rust implementation should use directory handles and `openat`-style operations, plus Windows reparse-point handles.
- General shell commands cannot be made safe with a deny list. They always require native confirmation, but strong isolation requires an OS sandbox.
- Short-lived access JWTs are not deny-listed on logout. Disabled users and role changes still take effect immediately because the API checks the database on every request.
- Per-process authenticated-write throttles need a shared Redis-backed limiter when the API is deployed with multiple replicas.
- Audit retention currently runs when the setting changes; production needs a scheduled cleanup job.

Do not include source code, prompts, API keys, tokens, or full local paths in vulnerability reports or logs.
