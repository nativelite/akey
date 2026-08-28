# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-28

### Added
- Vault-stored API keys: `set` / `ls` / `rm` / `use`, stored via the org's
  `cred` crate in the OS credential vault (never files). First stored key
  becomes the default.
- `run <target> -- <cmd...>` — per-process credential injection: key names
  set `ANTHROPIC_API_KEY`; `wif:<name>` sets the five documented federation
  variables and clears leftover static-key vars so they cannot shadow the
  profile. Child exit code is forwarded.
- `helper [<name>]` — Claude Code's documented `apiKeyHelper` contract
  (key on stdout, everything else on stderr).
- WIF profiles (`wif set`) storing the documented client inputs of
  Anthropic's Workload Identity Federation; the RFC 7523 exchange itself is
  deliberately left to the vendor SDKs.
- `status` — pure, testable walk of the SDKs' documented five-tier
  credential precedence, naming the winner and calling out the
  API-key-shadows-federation footgun and partial federation setups.
- Input sanitization for pasted/piped keys: strips whitespace and U+FEFF
  BOMs (Windows PowerShell prepends one when piping into native programs —
  caught by the release smoke test).
- 13 tests: CLI parse tables, WIF JSON round-trips, env-pair sets, status
  engine scenarios, and Windows real-vault integration including a child
  process asserting the injected environment. 394 KB release binary.

Second app of the nativelite **agent terminal** suite (see
`roadmap/agent-terminal-suite.md` in `nativelite/ops`).

[Unreleased]: https://github.com/nativelite/akey/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nativelite/akey/releases/tag/v0.1.0
