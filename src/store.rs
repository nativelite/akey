//! Vault layout over the `cred` crate. Everything akey persists lives in
//! the OS credential vault under one service namespace:
//!
//! * `key.<name>`  — an API key (the secret bytes as entered)
//! * `wif.<name>`  — a WIF profile serialized as JSON (IDs and a token-file
//!   path; kept in the vault anyway so there is exactly one store)
//! * `default`     — the entry name (`key.x` or `wif.x`) that `helper` and
//!   `run` use when none is named

use std::io;

pub const SERVICE: &str = "akey";

/// The five documented federation environment variables, in the order the
/// SDKs document them.
pub const WIF_ENV: [&str; 5] = [
    "ANTHROPIC_FEDERATION_RULE_ID",
    "ANTHROPIC_ORGANIZATION_ID",
    "ANTHROPIC_SERVICE_ACCOUNT_ID",
    "ANTHROPIC_WORKSPACE_ID",
    "ANTHROPIC_IDENTITY_TOKEN_FILE",
];

/// A named Workload Identity Federation profile — the client-side inputs of
/// the documented exchange. Not the exchange itself: tokens are the SDKs'
/// job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifProfile {
    pub rule: String,
    pub org: String,
    pub svc: String,
    pub workspace: Option<String>,
    pub token_file: String,
}

impl WifProfile {
    pub fn to_json(&self) -> String {
        let mut members = vec![
            ("rule".into(), json::Value::String(self.rule.clone())),
            ("org".into(), json::Value::String(self.org.clone())),
            ("svc".into(), json::Value::String(self.svc.clone())),
            (
                "token_file".into(),
                json::Value::String(self.token_file.clone()),
            ),
        ];
        if let Some(w) = &self.workspace {
            members.push(("workspace".into(), json::Value::String(w.clone())));
        }
        json::Value::Object(members).to_string()
    }

    pub fn from_json(text: &str) -> Option<WifProfile> {
        let v = json::parse(text).ok()?;
        let field = |k: &str| v.get(k).and_then(json::Value::as_str).map(str::to_string);
        Some(WifProfile {
            rule: field("rule")?,
            org: field("org")?,
            svc: field("svc")?,
            workspace: field("workspace"),
            token_file: field("token_file")?,
        })
    }

    /// The environment this profile injects into a spawned process.
    pub fn env_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = vec![
            (WIF_ENV[0].to_string(), self.rule.clone()),
            (WIF_ENV[1].to_string(), self.org.clone()),
            (WIF_ENV[2].to_string(), self.svc.clone()),
            (WIF_ENV[4].to_string(), self.token_file.clone()),
        ];
        if let Some(w) = &self.workspace {
            pairs.push((WIF_ENV[3].to_string(), w.clone()));
        }
        pairs.sort();
        pairs
    }
}

/// A credential target resolved from the vault.
#[derive(Debug)]
pub enum Resolved {
    Key(Vec<u8>),
    Wif(WifProfile),
}

/// Clean pasted/piped key input: strip surrounding whitespace and any BOMs.
/// Windows PowerShell in particular prepends U+FEFF when piping text into a
/// native program, and `str::trim` does not remove it — a stored key that
/// invisibly starts with a BOM fails at the API with a baffling 401.
pub fn clean_secret_input(input: &str) -> &str {
    let mut s = input.trim();
    loop {
        let stripped = s.trim_start_matches('\u{feff}').trim();
        if stripped == s {
            return s;
        }
        s = stripped;
    }
}

pub fn set_key(name: &str, secret: &[u8]) -> io::Result<()> {
    cred::set(SERVICE, &format!("key.{name}"), secret)
}

pub fn set_wif(name: &str, profile: &WifProfile) -> io::Result<()> {
    cred::set(
        SERVICE,
        &format!("wif.{name}"),
        profile.to_json().as_bytes(),
    )
}

/// Delete `name` wherever it lives (key or wif); returns whether anything
/// was deleted. Clears the default if it pointed at the deleted entry.
pub fn remove(name: &str) -> io::Result<bool> {
    let plain = name.strip_prefix("wif:").unwrap_or(name);
    let mut removed = false;
    for entry in [format!("key.{plain}"), format!("wif.{plain}")] {
        if cred::delete(SERVICE, &entry)? {
            removed = true;
            if default()?.as_deref() == Some(entry.as_str()) {
                cred::delete(SERVICE, "default")?;
            }
        }
    }
    Ok(removed)
}

/// Resolve a run/helper target: `wif:<name>` forces a profile; a plain
/// name tries `key.<name>` first, then `wif.<name>`.
pub fn resolve(target: &str) -> io::Result<Option<Resolved>> {
    if let Some(wif_name) = target.strip_prefix("wif:") {
        return Ok(load_wif(wif_name)?.map(Resolved::Wif));
    }
    if let Some(secret) = cred::get(SERVICE, &format!("key.{target}"))? {
        return Ok(Some(Resolved::Key(secret)));
    }
    Ok(load_wif(target)?.map(Resolved::Wif))
}

fn load_wif(name: &str) -> io::Result<Option<WifProfile>> {
    let Some(bytes) = cred::get(SERVICE, &format!("wif.{name}"))? else {
        return Ok(None);
    };
    let text = String::from_utf8_lossy(&bytes);
    match WifProfile::from_json(&text) {
        Some(p) => Ok(Some(p)),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("stored WIF profile {name:?} is corrupt"),
        )),
    }
}

/// Set the default entry. Accepts `name` or `wif:<name>`; verifies the
/// entry exists and stores its canonical entry name.
pub fn set_default(target: &str) -> io::Result<()> {
    let entry = match resolve(target)? {
        Some(Resolved::Key(_)) => format!("key.{target}"),
        Some(Resolved::Wif(_)) => {
            format!("wif.{}", target.strip_prefix("wif:").unwrap_or(target))
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no key or WIF profile named {target:?}"),
            ))
        }
    };
    cred::set(SERVICE, "default", entry.as_bytes())
}

pub fn default() -> io::Result<Option<String>> {
    Ok(cred::get(SERVICE, "default")?.map(|b| String::from_utf8_lossy(&b).into_owned()))
}

/// The default or a named key's secret — the `apiKeyHelper` contract.
pub fn helper_secret(name: Option<&str>) -> io::Result<Option<Vec<u8>>> {
    let entry = match name {
        Some(n) => format!("key.{n}"),
        None => match default()? {
            Some(e) => e,
            None => return Ok(None),
        },
    };
    if !entry.starts_with("key.") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the default is a WIF profile; apiKeyHelper needs a static key \
             (use `akey helper <name>` or `akey use <key-name>`)",
        ));
    }
    cred::get(SERVICE, &entry)
}

/// Everything stored, for `ls` and `status`. Uses vault enumeration where
/// available (Windows); elsewhere reports that listing is unsupported.
pub struct Listing {
    pub keys: Vec<String>,
    pub wifs: Vec<String>,
    pub default: Option<String>,
}

pub fn list() -> io::Result<Listing> {
    let mut keys = Vec::new();
    let mut wifs = Vec::new();
    for entry in cred::entries(SERVICE)? {
        if let Some(k) = entry.strip_prefix("key.") {
            keys.push(k.to_string());
        } else if let Some(w) = entry.strip_prefix("wif.") {
            wifs.push(w.to_string());
        }
    }
    Ok(Listing {
        keys,
        wifs,
        default: default()?,
    })
}
