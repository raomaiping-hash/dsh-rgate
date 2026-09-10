# dsh-rgate

[![CI](https://github.com/raomaiping-hash/dsh-rgate/actions/workflows/ci.yml/badge.svg)](https://github.com/raomaiping-hash/dsh-rgate/actions/workflows/ci.yml)
[![version](https://img.shields.io/github/v/tag/raomaiping-hash/dsh-rgate)](https://github.com/raomaiping-hash/dsh-rgate/tags)
[![license](https://img.shields.io/github/license/raomaiping-hash/dsh-rgate)](LICENSE)

[中文](README.zh.md) | English

A remote access login gate for the [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) Web UI. Put a password wall in front of the whole browser surface: anonymous visitors on a public (non-loopback) address see only a login page, and every `/api` RPC is refused until they authenticate.

## Why

The Harness's built-in browser-trust fence (`trustedHosts`) is a DNS-rebinding defense, explicitly *not* authentication. Anyone whose `Host` header passes the fence can use the Web UI. This plugin adds the missing authentication layer for self-hosted deployments: IP scanners hit a login page instead of your agent.

## What it does

- **Full-page login wall** — a gate script is injected into every `index.html` (via `webServer.tapIndex`); unauthenticated non-loopback visitors are redirected to `/rgate-login`, a self-contained login page.
- **Complete `/api` gating** — modern Harness releases authenticate the `/api` RPC surface themselves (no credentials → `401`), so rgate no longer proxies or shadows those routes. It registers only its own `/api/remote-auth.*` endpoints plus `/rgate-login`; loopback hosts pass straight through, and non-loopback visitors need a session cookie or the injected gate script redirects them to the login wall.
- **Cookie sessions** — `rgate_session`, HttpOnly + SameSite=Strict, 7-day in-memory sessions; logout and password change invalidate all sessions.
- **No more `?token=` URLs** — the stock harness (`dsh-client-connection`) only accepts the cookie minted by its process token: any address without `?token=<launchToken>` returns `401`, so every visit starts by hunting for that printed URL. After the login wall is passed, rgate also mints an HMAC-signed cookie in the same format (`rgate_auth`, key `~/.dsh/.rgate-signing.key`) and patches the harness `isAuthenticated` to verify it and `authorizeIndex` to serve the index — so visiting the plain host lands on the login page, and `?token=` is never needed again. `/api` still requires the signature, so anonymous requests stay `401`.
- **Login throttling** — 5 failed attempts per client → exponential backoff (30s doubling, capped at 16 min). Behind Cloudflare Tunnel the client key is `Cf-Connecting-Ip` (fallback `X-Forwarded-For`, then socket address), so one attacker cannot lock everyone out.
- **Audit logging** — login success/failure/lockout and password changes go to the harness log (journald) without passwords.
- **Hashed password storage** — scrypt (N=16384, r=8, p=1) with a random salt and constant-time comparison in `~/.dsh/remote-auth.json` (mode 0600). Legacy plaintext files are migrated automatically. A forgotten password is recovered by deleting the file and restarting: the fresh password is printed once in the service log.
- **Remote Access settings section** — a `settings.section` entry showing gate status, login/logout, and password change. Password display is hashed-only by design.
- **Origin validation** on login/logout/password endpoints (cross-site form posts are refused).

## Install

From GitHub (plain ESM, **no build step and no install scripts** — nothing runs at install time):

```sh
dsh plugin --profile web add github:raomaiping-hash/dsh-rgate
```

Pin a commit sha for reproducibility: later pushes cannot silently change what runs on your machine (`dsh plugin --profile web add github:raomaiping-hash/dsh-rgate#<commit-sha>`).

From npm or a tarball:

```sh
dsh plugin --profile web add dsh-rgate          # npm
dsh plugin --profile web add ./dsh-rgate-0.1.0.tgz   # tarball
```

Then restart the web profile. The plugin prints `[rgate] 门禁已启用 …` (or `[rgate] gate enabled …`) when it activates, and creates `~/.dsh/remote-auth.json` with a random password on first boot:

```sh
journalctl -u deepseek-harness | grep rgate
```

## Configuration

There is no config file for the gate itself. Two behaviors are worth knowing:

- **Loopback is always trusted.** `127.0.0.1` / `localhost` / `::1` never see the wall — that is the admin path.
- **All other Hosts require login** (LAN, Tailscale, public domain alike). If you want a friction-free host, protect it upstream instead (see below).

The password file lives at `$DSH_HOME/remote-auth.json` (default `~/.dsh/remote-auth.json` — the harness convention, beside `settings.yaml`):

| field | meaning |
| --- | --- |
| `version: 2` | scrypt-hashed storage |
| `salt`, `N`, `r`, `p`, `hash` | scrypt parameters and derived key |
| `createdAt`, `updatedAt` | bookkeeping |

## HTTP endpoints added

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/rgate-login` | GET | Self-contained login page (redirects to `/` when already allowed) |
| `/api/remote-auth.login` | POST `{password}` | Verify password, set session cookie |
| `/api/remote-auth.logout` | POST | Drop session + clear cookie |
| `/api/remote-auth.status` | GET | `{configured, authenticated, loopback}` |
| `/api/remote-auth.secret` | GET | Loopback only: `{mode, path, createdAt, updatedAt}` — never the password |
| `/api/remote-auth.password` | POST `{current?, next}` | Change password (authenticated session, or loopback + current password) |

## Known limitations

- **WebSocket event streams are not gated.** `/api/events.mux` and `/api/events.host` upgrades are owned by the shipped `dsh-client-connection` plugin; registering the same upgrade path throws, and pre-registering breaks boot. A fence-passing client can still open them and receive live session event frames. The robust fix is **upstream**: enable Cloudflare Access (Zero Trust) on your public domain, or put an authenticating reverse proxy (e.g. nginx `auth_request`) in front. That closes UI, API and WebSockets before traffic reaches the Harness.
- **The `/api` method table is not owned here.** Harness-native `/api` authentication (no credentials → `401`) covers new RPCs as they are added; rgate never shadows that table.
- **Sessions are in-memory.** A Harness restart signs everyone out (7-day cookie otherwise).
- Static assets are still served to unauthenticated visitors (they are public code); all data lives behind the API gate.

## Threat model

The gate is an *authentication* layer for a single-password, personal/small-team deployment. It assumes the Harness process and its host filesystem are trusted; anyone who can read `remote-auth.json` or the process memory already owns the host. It is not a substitute for OS/network hygiene, HTTPS termination, or upstream access control on the public entry point.

## Test

`tests/smoke.mjs` runs the plugin's real route handlers against a stubbed context in an isolated `HOME` (no real credentials touched):

```sh
node tests/smoke.mjs
```

## License

MIT

## Settings plane note

Harness 0.1.2-rc.2+ serves the settings plane (model providers, credentials,
preset authoring) to loopback pages only, pending a real authentication layer.
Since rgate is that layer, at every start it reapplies a one-line client patch
that lets **logged-in** remote browsers use settings normally; anonymous
visitors remain blocked by the wall. The anchor expression
(`ctx.remote.$host.isLoopback ? "host" : "memory"` in
`@deepseek-ai/dsh-client-ui-settings/lib/client.js`) was re-verified against
Harness 0.1.5-rc.2. The original file is backed up next to the target
(`client.js.rgate-backup`) and the patch reapplies automatically after each
Harness upgrade.
