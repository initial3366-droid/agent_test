# Forge Desktop

The desktop shell intentionally has no shell or updater plugin permissions. It
provides the tray lifecycle for the separately packaged local executor.

Signed automatic updates are disabled until production release infrastructure
provides a real HTTPS endpoint and signing public key. Do not replace this with
placeholder updater configuration: enable `tauri-plugin-updater` only together
with signed artifacts and release verification.

The desktop supervisor starts the packaged Agent, reads and immediately deletes
its exclusive token file, then opens the workbench with a one-time URL fragment.
The web client removes it immediately with `history.replaceState`. Never put the
token in a query string, cloud request, browser storage, application log, or a
compiled `NEXT_PUBLIC_*` value. Development builds may use
`FORGE_AGENT_SCRIPT`; release builds ignore executable overrides and require the
bundled sidecar.
