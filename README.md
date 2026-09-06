# akey
**API keys and Workload Identity Federation profiles for agent tooling**:
vault-stored, per-process injected, precedence-diagnosed. Built on the
nativelite stack (`json` + `cred`): **zero third-party dependencies.**

"I want to test this with an API key instead of OAuth" should be a
one-liner, and the key should live in the **OS credential vault** (Windows
Credential Manager / macOS Keychain), not in a dotfile or shell profile.

```bash
akey set work                      # paste once; stored in the OS vault
akey run work -- claude -p "hi"    # ANTHROPIC_API_KEY exists for this process only
akey status                        # which credential source wins in this shell, and why
```

## Commands

| Command | What it does |
| --- | --- |
| `akey set <name>` | store a key (read from stdin) in the vault; first key becomes the default |
| `akey ls` | list keys and WIF profiles, default marked `*` |
| `akey rm <name>` / `akey use <name>` | delete / make default |
| `akey run <target> -- <cmd...>` | spawn `<cmd>` with credentials injected into **its environment only**: a key name sets `ANTHROPIC_API_KEY`; `wif:<name>` sets the five federation variables (and clears any leftover static key so it can't shadow them) |
| `akey helper [<name>]` | print the default/named key on stdout: Claude Code's documented `apiKeyHelper` contract |
| `akey status` | walk the SDKs' documented five-tier credential precedence for the current environment and name the winner |
| `akey wif set <name> --rule fdrl_... --org <uuid> --svc svac_... [--workspace wrkspc_...] --token-file <path>` | store a federation profile |

**Claude Code integration:** point `apiKeyHelper` at akey and the CLI pulls
keys from the vault instead of a file: `"apiKeyHelper": "akey helper"` in
`~/.claude/settings.json`.

**Workload Identity Federation:** a profile is the five documented client
inputs (`ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID`,
`ANTHROPIC_SERVICE_ACCOUNT_ID`, `ANTHROPIC_WORKSPACE_ID`,
`ANTHROPIC_IDENTITY_TOKEN_FILE`). `akey run wif:prod -- <cmd>` injects
them; the SDK in the child performs the RFC 7523 exchange and refresh loop
itself; akey deliberately does **not** mint tokens.

`akey status` exists because the precedence is a documented footgun: a
leftover `ANTHROPIC_API_KEY` sits *above* the federation tier and silently
shadows it. `status` prints the five tiers, marks the winner, and calls
that case out explicitly.

## Security posture

- Secrets live **only** in the OS vault (via [`cred`](https://github.com/nativelite/cred-rs);
  no plaintext files, no fallback) and are injected only into processes you
  spawn. akey makes no network calls and never sees another tool's
  credentials.
- Pasted/piped input is sanitized: Windows PowerShell prepends an invisible
  BOM when piping into native programs; akey strips it, because a key that
  secretly starts with U+FEFF fails at the API with a baffling 401. (Found
  by our own smoke test.)
- `set` is mode-aware: run interactively it shows a **hidden prompt** and
  reads one line with terminal echo disabled (Enter finishes; the key is
  never shown), and it still accepts piped input (`Get-Content key.txt |
  akey set work`, or a password-manager pipe), reading to EOF unchanged.
- Linux inherits `cred`'s honest state: vault calls return `Unsupported`
  until the Secret Service backend lands.

## Correctness

CLI parsing, WIF profile JSON round-trips, env-pair injection sets, and the
whole status engine are pure functions with table tests. On Windows the
store layer is tested against the **real** Credential Manager, including an
end-to-end child process that must see the injected `ANTHROPIC_API_KEY`.
13 tests; the release binary is 394 KB.

## Development

```bash
python dev.py check   # dependency guard + cargo test (the pre-push gate)
```

No CI runs right now (GitHub Actions are off, 2026-08-30); the local `dev.py check` is the gate. A lean CI may return once the nativelite crates are public; it would need an org-read token to fetch the private git deps.
