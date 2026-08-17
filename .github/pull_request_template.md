## Summary

<!-- What does this change and why? -->

## Checks

- [ ] `node tests/smoke.mjs` passes
- [ ] No secrets, machine-specific paths, or private hostnames added
- [ ] README updated if the public contract (endpoints, install, configuration) changed

## Security notes

This plugin is an authentication layer for a security-sensitive surface. If the change touches routing, cookies, password storage, or request parsing, describe the threat model impact here.
