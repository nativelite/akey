//! `akey status`: walk the SDKs' documented five-tier credential
//! precedence for a given environment and say which source wins and why.
//! Pure: takes an env map and a vault listing, returns report lines, so
//! the whole diagnosis is testable.
//!
//! Documented order (first hit wins): constructor arguments (invisible to
//! us), `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`, an explicit
//! `ANTHROPIC_PROFILE`, the federation environment variables, the implicit
//! active profile.

use crate::store::{Listing, WIF_ENV};
use std::collections::HashMap;

pub fn report(env: &HashMap<String, String>, vault: Option<&Listing>) -> Vec<String> {
    let mut out = Vec::new();
    let has = |k: &str| env.get(k).map(|v| !v.is_empty()).unwrap_or(false);
    let fed_present: Vec<&str> = WIF_ENV.iter().copied().filter(|k| has(k)).collect();
    // ANTHROPIC_WORKSPACE_ID is optional; the other four are required.
    let fed_required: Vec<&str> = WIF_ENV
        .iter()
        .copied()
        .filter(|k| *k != "ANTHROPIC_WORKSPACE_ID")
        .collect();
    let fed_missing: Vec<&str> = fed_required.iter().copied().filter(|k| !has(k)).collect();
    let fed_complete = fed_missing.is_empty();

    out.push("credential precedence in this environment (first hit wins):".into());

    let mut winner: Option<&str> = None;
    let tier = |line: String,
                hit: bool,
                out: &mut Vec<String>,
                winner: &mut Option<&str>,
                tag: &'static str| {
        let mark = if hit && winner.is_none() {
            *winner = Some(tag);
            ">>"
        } else if hit {
            " +"
        } else {
            "  "
        };
        out.push(format!(" {mark} {line}"));
    };

    tier(
        "1. constructor arguments (only visible inside an application)".into(),
        false,
        &mut out,
        &mut winner,
        "ctor",
    );
    tier(
        format!(
            "2. ANTHROPIC_API_KEY {} / ANTHROPIC_AUTH_TOKEN {}",
            if has("ANTHROPIC_API_KEY") {
                "set"
            } else {
                "unset"
            },
            if has("ANTHROPIC_AUTH_TOKEN") {
                "set"
            } else {
                "unset"
            },
        ),
        has("ANTHROPIC_API_KEY") || has("ANTHROPIC_AUTH_TOKEN"),
        &mut out,
        &mut winner,
        "env-key",
    );
    tier(
        format!(
            "3. ANTHROPIC_PROFILE {}",
            env.get("ANTHROPIC_PROFILE")
                .map(|v| format!("= {v:?}"))
                .unwrap_or_else(|| "unset".into())
        ),
        has("ANTHROPIC_PROFILE"),
        &mut out,
        &mut winner,
        "profile",
    );
    tier(
        format!(
            "4. federation env ({}/{} required vars set)",
            fed_required.len() - fed_missing.len(),
            fed_required.len()
        ),
        fed_complete,
        &mut out,
        &mut winner,
        "federation",
    );
    tier(
        "5. implicit active profile (if a profile file exists)".into(),
        false,
        &mut out,
        &mut winner,
        "active-profile",
    );

    match winner {
        Some("env-key") => {
            if has("ANTHROPIC_API_KEY") && !fed_present.is_empty() {
                out.push(String::new());
                out.push(
                    "!! ANTHROPIC_API_KEY is set AND federation variables are present:".into(),
                );
                out.push(
                    "   the static key silently shadows federation (documented footgun).".into(),
                );
                out.push("   unset ANTHROPIC_API_KEY to let federation win.".into());
            }
        }
        Some("federation") => {}
        _ => {
            if !fed_present.is_empty() && !fed_complete {
                out.push(String::new());
                out.push(format!(
                    "!! federation is partially configured, missing: {}",
                    fed_missing.join(", ")
                ));
            }
        }
    }
    if winner.is_none() {
        out.push(String::new());
        out.push("no credentials in this environment.".into());
        out.push(
            "   (Claude Code's own OAuth login is separate and still applies to the CLI.)".into(),
        );
    }

    out.push(String::new());
    match vault {
        Some(l) => {
            out.push(format!(
                "vault: {} key(s) [{}], {} WIF profile(s) [{}], default = {}",
                l.keys.len(),
                l.keys.join(", "),
                l.wifs.len(),
                l.wifs.join(", "),
                l.default.as_deref().unwrap_or("none"),
            ));
            out.push("   inject one with: akey run <name> -- <cmd>".into());
        }
        None => out.push("vault: listing not supported on this platform".into()),
    }
    out
}
