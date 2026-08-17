# Contributing

Thanks for considering a contribution! This is a small, security-sensitive plugin, so the bar for clarity is high.

## Ground rules

- Plain ESM JavaScript only — no TypeScript, no build step, no install scripts (the [DSH publishing guide](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/user/develop/basic/publish.md) explains why install-time execution matters).
- Every change that touches routing, cookies, password storage, or request parsing must state its threat-model impact.
- Never commit credentials, hostnames, or machine-specific paths. `tests/smoke.mjs` must run against an isolated `HOME` with a seeded test password only.
- Keep the RPC `UNARY` table in sync with the Harness version you verified against, and note the tested version in the PR.

## Development

```sh
node --check index.js client.js tests/smoke.mjs   # syntax
node tests/smoke.mjs                               # 23 smoke checks, isolated HOME
```

## Release

```sh
git tag vX.Y.Z && git push origin vX.Y.Z
```

Users can then pin the tag: `dsh plugin --profile web add github:raomaiping-hash/dsh-rgate#vX.Y.Z`.
