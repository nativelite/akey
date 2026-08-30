# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-08-29

### Changed
- `akey set <name>` is now **mode-aware** when reading the secret. When stdin
  is an interactive terminal, it prints a hidden prompt to stderr
  (`Enter API key for "work" (input hidden): `), reads **one line** with
  terminal echo disabled — so **Enter finishes** the entry and the secret is
  never shown — and prints a trailing newline. Previously it read stdin to
  EOF and echoed the key, so an interactive user who pressed Enter just hung
  (Enter is not EOF) and saw their secret on screen. When stdin is **piped or
  redirected** the behavior is unchanged: it reads to EOF verbatim, so
  `Get-Content key.txt | akey set work` and password-manager pipes work
  exactly as before. The no-echo terminal mode is toggled with the platform's
  own FFI (Windows `GetConsoleMode`/`SetConsoleMode`; Unix `termios`) — no new
  dependency — and is always restored via a `Drop` guard, so a panic or early
  return cannot leave the terminal with echo off. The secret still flows only
  into the vault; it is never logged or printed.

## [0.2.0] - 2026-08-29

### Added
- `akey::resolve(target) -> io::Result<Vec<(String, String)>>` — a library
  seam returning the environment variables to **set** for a target (the same
  mapping `run` injects: a key name -> `ANTHROPIC_API_KEY`; `wif:<name>` ->
  the federation variables). Lets an in-process caller (e.g. amux's native
  `--identity`) obtain the env and inject it itself, without akey spawning.
  The returned values are secret; the doc comment states the caller is
  trusted and must not log/print/persist them. akey never logs the values
  and its vault posture is unchanged.

### Changed
- `run` now calls `resolve` for the env vars to set (extract-and-reuse); its
  external behavior is byte-identical, including clearing leftover static-key
  vars before injecting a federation profile.

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

[Unreleased]: https://github.com/nativelite/akey/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/nativelite/akey/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/nativelite/akey/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nativelite/akey/releases/tag/v0.1.0
