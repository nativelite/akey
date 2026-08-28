//! akey — API keys and Workload Identity Federation profiles for agent
//! tooling, on the nativelite stack alone (the org's `json` + `cred`
//! crates; zero third-party dependencies).
//!
//! The problem it solves: "I want to test something with an API key instead
//! of OAuth" should be a one-liner, not an env-var scavenger hunt — and the
//! key should live in the **OS credential vault**, not a dotfile.
//!
//! * **Static keys** — `akey set/use/rm/ls`; `akey run <name> -- <cmd>`
//!   injects `ANTHROPIC_API_KEY` into that process only; `akey helper`
//!   prints the default key for Claude Code's documented `apiKeyHelper`
//!   hook.
//! * **WIF profiles** — named sets of the five documented federation
//!   variables (`ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID`,
//!   `ANTHROPIC_SERVICE_ACCOUNT_ID`, `ANTHROPIC_WORKSPACE_ID`,
//!   `ANTHROPIC_IDENTITY_TOKEN_FILE`); `akey run wif:<name> -- <cmd>`
//!   injects them. The RFC 7523 token exchange itself stays with the
//!   vendor SDKs — deliberately out of scope.
//! * **Diagnosis** — `akey status` walks the SDKs' documented five-tier
//!   credential precedence for the current environment and names the
//!   winner, surfacing the footgun where a leftover `ANTHROPIC_API_KEY`
//!   silently shadows federation.
//!
//! Secrets are transmitted nowhere: this tool reads and writes the local
//! vault and the environment of processes *you* spawn, and nothing else.

pub mod cli;
pub mod status;
pub mod store;
