# Remote settings plane behind the login wall

## Problem

Harness rc.2 pins the whole configuration plane (`settings.*`, `credentials.*`,
`agentPreset` authoring) client-side to loopback pages "until a real
authentication layer exists". Remote users of dsh-rgate get
"settings are unavailable in this browser" on the models/provider page even
after logging in, and every Harness upgrade re-overwrites any local fix.

## Decision

dsh-rgate owns restoring remote access for authenticated sessions: at every
plugin start it idempotently rewrites one persistence decision in
`@deepseek-ai/dsh-client-ui-settings/lib/client.js`
(`connection.isLoopback ? "host" : "memory"` → `"host"`), resolving the target
through `createRequire` so any install layout works. The host side enforces no
loopback restriction itself; rgate's session cookie is the authentication layer
upstream asked for.

## Alternatives considered

- Do nothing; tell users to manage settings on the machine (upstream's implicit
  answer). Rejected: defeats the plugin's purpose for headless/remote boxes.
- pnpm patchedDependencies: does not cover built-in bundles shipped inside the
  global Harness install.
- SSH tunnel to localhost: works per-user per-session, not a deployment fix.

## Consequences

- The patch touches an upstream-owned file; a Harness upgrade overwrites it and
  the next rgate start reapplies it automatically (idempotent, logged).
- If upstream changes the gated line's shape, the pattern match silently skips;
  the gate itself is unaffected.
- Security posture is unchanged for anonymous visitors: the wall still blocks
  them; logged-in admins regain exactly the settings surface upstream intends
  to protect behind real authentication.
