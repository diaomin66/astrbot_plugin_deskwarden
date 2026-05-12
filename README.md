# DeskWarden

DeskWarden is an owner-only AstrBot plugin for controlling a local Windows desktop through a guarded loopback daemon. The plugin never talks directly to the operating system. It proposes structured actions, sends signed RPC requests to the daemon, and requires owner approval for risky or mutating work.

Implementation status: Phase 1 through Phase 9 from `PLAN.md` are now covered. High-risk capabilities are still safe-by-default: restricted shell and isolated browser endpoints are daemon-disabled until explicitly enabled.

## Capabilities

- Plugin skeleton and owner-private command gate.
- Loopback daemon pairing with HMAC, timestamp, and nonce replay protection.
- Read-only desktop observation with sensitive window redaction.
- Mouse, keyboard, and window focus interactions with risk escalation.
- One-time approval flow and JSONL audit logging.
- File sandbox reads and approved writes inside configured workspaces.
- Restricted shell with explicit daemon allowlist, workspace cwd, timeout, output truncation, and mandatory approval.
- Isolated Playwright browser profile for opening pages, reading titles, screenshots, clicks, typing, and isolated downloads.
- Hardening defaults for loopback-only RPC, private-host browser blocking, forbidden shell operations, audit redaction, backups, and emergency stop.

## Commands

- `/desk pair <token>`: pair the plugin with the local daemon token.
- `/desk start`: start an owner session after signed RPC health checks pass.
- `/desk status`: show plugin, daemon, pairing, emergency, shell, browser, and pending approval state.
- `/desk stop`: stop the current session and clear pending approvals.
- `/desk pause` / `/desk resume`: pause or resume the plugin session.
- `/desk rotate-key`: rotate the daemon shared secret through a signed request.
- `/desk observe [screen|active]`: capture the full screen or active window if no sensitive window would be exposed.
- `/desk windows`: list visible windows with sensitive titles redacted.
- `/desk summarize`: return a compact desktop/window/process summary.
- `/desk click <x> <y>`, `/desk double-click <x> <y>`, `/desk right-click <x> <y>`, `/desk scroll <x> <y> <delta>`, `/desk drag <x1> <y1> <x2> <y2> [duration_ms]`: mouse controls.
- `/desk type <text>` and `/desk hotkey <ctrl+s>`: keyboard controls. Risky text or keys require approval.
- `/desk focus <window_id>`: focus a visible window from `/desk windows`.
- `/desk emergency`: activate daemon emergency stop. Later actions are refused.
- `/desk approve <id>` / `/desk deny <id>`: consume or reject a pending one-time approval.
- `/desk read-file <path>`: read a UTF-8 file inside a daemon-configured workspace.
- `/desk write-file <path> <content>`: generate a diff and require approval before writing.
- `/desk shell <allowlisted command>`: plan a restricted shell command. Every shell command requires approval before execution.
- `/desk browser open <https-url>`: open a URL in the isolated browser.
- `/desk browser title`: read the isolated browser page title.
- `/desk browser screenshot`: capture the isolated browser page.
- `/desk browser click <selector>`: click in the isolated browser. Sensitive targets require approval.
- `/desk browser type <selector> <text>`: fill text in the isolated browser. Sensitive text or selectors require approval.
- `/desk browser download <selector>`: click and save a download into the isolated downloads directory. Requires approval.
- `/desk audit latest [limit]`: show recent audit records.
- `/desk audit purge`: purge daemon audit records.

## Start The Daemon

Run this from the plugin directory:

```powershell
python .\deskwarden_daemon.py --workspace "D:\path\to\allowed\workspace"
```

The daemon binds to `http://127.0.0.1:8765` by default and starts in `LOCKED` state. On first start it prints a one-time pairing token:

```text
DeskWarden daemon listening on http://127.0.0.1:8765
Daemon state: LOCKED
Restricted shell: disabled
Isolated browser: disabled
Pairing token: <one-time token>
```

Send the token to the bot in an owner private chat:

```text
/desk pair <one-time token>
```

If DeskWarden refuses the command because `owner_id` is not configured, copy the
reported `sender_id` into the plugin `owner_id` config and retry from a private
chat with the bot.

State, audit logs, screenshots, browser profile, downloads, and backups default under `.deskwarden/`. Do not commit that directory.

## Daemon Options

```powershell
python .\deskwarden_daemon.py `
  --host 127.0.0.1 `
  --port 8765 `
  --state-path .\.deskwarden\daemon_state.json `
  --audit-path .\.deskwarden\audit.jsonl `
  --screenshot-dir .\.deskwarden\screenshots `
  --backup-dir .\.deskwarden\backups `
  --workspace "D:\safe-workspace" `
  --enable-shell `
  --shell-allow "git status" `
  --shell-allow "python -m unittest" `
  --enable-browser
```

Repeat `--workspace` to allow multiple file and shell roots. If no workspace is configured, file and shell operations are refused.

Browser control uses Playwright:

```powershell
python -m pip install -r requirements.txt
python -m playwright install chromium
```

The isolated browser uses `.deskwarden/browser_profile` and does not reuse the user's main browser profile or cookies. Private, loopback, and local-network hosts are blocked unless the daemon is started with `--browser-allow-private-hosts`.

## Safety Model

- Only the configured `owner_id` can use `/desk`, and only in private chat.
- The daemon only accepts loopback clients.
- All non-pairing RPC endpoints require HMAC headers:
  `X-DeskWarden-Timestamp`, `X-DeskWarden-Nonce`, and `X-DeskWarden-Signature`.
- Nonces are one-use and timestamps must be within tolerance.
- Repeated auth failures lock the daemon.
- Sensitive window titles are redacted in window lists.
- Full-screen and active-window screenshots are refused when sensitive windows are visible.
- Interactions are blocked on sensitive active windows.
- Risky interaction keywords such as submit, login, pay, transfer, confirm, and delete require approval.
- File writes always require diff review, a fresh one-time approval, backup creation, and verification.
- File paths must stay inside configured workspaces; credential, token, secret, key, `.env`, SSH, browser, system, and program directories are refused.
- Restricted shell is disabled by default; enabled shell commands must match an allowlist prefix, run inside a configured workspace, use `shell=False`, and pass forbidden-operation checks.
- Browser downloads are saved into the isolated downloads directory.
- Browser login, payment, identity, submission, and credential-like actions require approval.
- Audit records redact file content, typed text, tokens, signatures, credentials, and secrets.

## Tests

```powershell
python -m compileall -q .
python -m unittest discover -s tests
```

Current regression coverage includes pairing/signature/replay protection, sensitive observation redaction, interaction approval and emergency stop, file sandbox diff/write/backup/path rejection, restricted shell approval/replay protection, browser sensitive-action approval, and audit redaction.
