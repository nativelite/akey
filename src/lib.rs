//! akey: API keys and Workload Identity Federation profiles for agent
//! tooling, on the nativelite stack alone (the org's `json` + `cred`
//! crates; zero third-party dependencies).
//!
//! The problem it solves: "I want to test something with an API key instead
//! of OAuth" should be a one-liner, not an env-var scavenger hunt, and the
//! key should live in the **OS credential vault**, not a dotfile.
//!
//! * **Static keys**: `akey set/use/rm/ls`; `akey run <name> -- <cmd>`
//!   injects `ANTHROPIC_API_KEY` into that process only; `akey helper`
//!   prints the default key for Claude Code's documented `apiKeyHelper`
//!   hook.
//! * **WIF profiles**: named sets of the five documented federation
//!   variables (`ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID`,
//!   `ANTHROPIC_SERVICE_ACCOUNT_ID`, `ANTHROPIC_WORKSPACE_ID`,
//!   `ANTHROPIC_IDENTITY_TOKEN_FILE`); `akey run wif:<name> -- <cmd>`
//!   injects them. The RFC 7523 token exchange itself stays with the
//!   vendor SDKs: deliberately out of scope.
//! * **Diagnosis**: `akey status` walks the SDKs' documented five-tier
//!   credential precedence for the current environment and names the
//!   winner, surfacing the footgun where a leftover `ANTHROPIC_API_KEY`
//!   silently shadows federation.
//!
//! Secrets are transmitted nowhere: this tool reads and writes the local
//! vault and the environment of processes *you* spawn, and nothing else.

pub mod cli;
pub mod prompt;
pub mod status;
pub mod store;

use std::io;

/// Resolve a credential `target` to the environment variables to **set** for
/// it: the same mapping `akey run` injects, exposed as a library seam so an
/// in-process caller can inject them itself instead of having akey spawn:
///
/// * a key name        -> `[("ANTHROPIC_API_KEY", <vault value>)]`
/// * `wif:<name>`      -> the federation variables from the stored profile
///   (four required, plus `ANTHROPIC_WORKSPACE_ID` when the profile has one)
///
/// A plain name resolves a key first, then a WIF profile, exactly as `run`
/// does. A missing target is an `io::ErrorKind::NotFound` error.
///
/// This is the WIF profile's stored **config** values (as `run` injects
/// them), never a minted token; akey does not perform the RFC 7523
/// exchange.
///
/// # Security
///
/// The returned pairs contain **secret material** (a static key's value).
/// This seam exists for a trusted, in-process caller (e.g. amux injecting
/// credentials into the agent it spawns on its pty): the caller MUST treat
/// the values as secret and MUST NOT log, print, or persist them. akey
/// itself never logs or prints the values, and this function does not change
/// akey's on-disk / vault posture: it only reads the vault, as `run` does.
pub fn resolve(target: &str) -> io::Result<Vec<(String, String)>> {
    match store::resolve(target)? {
        Some(store::Resolved::Key(secret)) => {
            // A key injects its stored env var (e.g. `HF_TOKEN`), or Anthropic's
            // `ANTHROPIC_API_KEY` when none was set: the historical default.
            let var = store::key_env(target)?.unwrap_or_else(|| store::DEFAULT_ENV.to_string());
            Ok(vec![(var, String::from_utf8_lossy(&secret).into_owned())])
        }
        Some(store::Resolved::Wif(profile)) => Ok(profile.env_pairs()),
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no key or WIF profile named {target:?}"),
        )),
    }
}
