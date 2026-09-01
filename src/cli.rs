//! Argument parsing: a plain `&[String] -> Command` function, fully
//! testable, no clap. Errors are the usage message to print.

use crate::store::WifProfile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Store a key read from stdin under `name`, optionally with the environment
    /// variable it injects (`--for <service>` preset or `--env <VAR>`); `None` ⇒
    /// the historical `ANTHROPIC_API_KEY`.
    Set {
        name: String,
        env: Option<String>,
    },
    /// List keys, WIF profiles, and the default.
    Ls,
    /// Delete a key or WIF profile.
    Rm {
        name: String,
    },
    /// Mark a key (or `wif:<name>`) as the default.
    Use {
        name: String,
    },
    /// Print the default (or named) key — the `apiKeyHelper` contract.
    Helper {
        name: Option<String>,
    },
    /// Spawn a command with credentials injected into its environment only.
    Run {
        target: String,
        cmd: Vec<String>,
    },
    /// Diagnose the credential precedence of the current environment.
    Status,
    /// Create/replace a WIF profile.
    WifSet {
        name: String,
        profile: WifProfile,
    },
    Help,
}

pub const USAGE: &str = "\
akey — API keys & WIF profiles for agent tooling (vault-stored)

  akey set <name> [--for <svc> | --env <VAR>]
                                  store a key (read from stdin) in the OS vault.
                                  --for maps a preset service to its env var
                                  (huggingface->HF_TOKEN, github->GITHUB_TOKEN,
                                  openai->OPENAI_API_KEY, ...); --env sets any var.
                                  Default (neither): ANTHROPIC_API_KEY.
  akey ls                         list keys (with their env var), WIF profiles, default
  akey rm <name>                  delete a key or WIF profile
  akey use <name>                 make <name> (or wif:<name>) the default
  akey helper [<name>]            print the default/named key (apiKeyHelper)
  akey run <target> -- <cmd...>   run <cmd> with credentials injected:
                                    <name>      -> its env var (default ANTHROPIC_API_KEY)
                                    wif:<name>  -> the five ANTHROPIC_* federation vars
  akey status                     which credential source wins in this shell, and why
  akey wif set <name> --rule fdrl_... --org <uuid> --svc svac_...
              [--workspace wrkspc_...] --token-file <path>
";

/// Parse `set <name> [--for <service> | --env <VAR>]`. The env-var choice is
/// resolved here (a preset is looked up now) so the command carries the final
/// variable, or `None` for the default.
fn parse_set(rest: &[&String]) -> Result<Command, String> {
    const USAGE: &str = "usage: akey set <name> [--for <service> | --env <VAR>]";
    let mut name: Option<String> = None;
    let mut env: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--env" => {
                let v = rest.get(i + 1).ok_or(USAGE)?;
                env = Some((*v).clone());
                i += 2;
            }
            "--for" => {
                let svc = rest.get(i + 1).ok_or(USAGE)?;
                let var = crate::store::preset_env(svc).ok_or_else(|| {
                    let known: Vec<&str> =
                        crate::store::PRESETS.iter().map(|(n, _)| *n).collect();
                    format!(
                        "akey set: unknown --for service {svc:?} (known: {})",
                        known.join(", ")
                    )
                })?;
                env = Some(var.to_string());
                i += 2;
            }
            s if s.starts_with('-') => return Err(format!("akey set: unexpected flag {s:?}\n{USAGE}")),
            _ if name.is_some() => return Err(USAGE.into()),
            _ => {
                name = Some(rest[i].clone());
                i += 1;
            }
        }
    }
    match name {
        Some(name) => Ok(Command::Set { name, env }),
        None => Err(USAGE.into()),
    }
}

pub fn parse(args: &[String]) -> Result<Command, String> {
    let mut it = args.iter();
    let cmd = match it.next().map(String::as_str) {
        None | Some("help") | Some("--help") | Some("-h") => return Ok(Command::Help),
        Some(c) => c,
    };
    let rest: Vec<&String> = it.collect();
    let one_name = |what: &str| -> Result<String, String> {
        match rest.as_slice() {
            [n] if !n.starts_with('-') => Ok((*n).clone()),
            _ => Err(format!("usage: akey {what} <name>")),
        }
    };
    match cmd {
        "set" => parse_set(&rest),
        "ls" => Ok(Command::Ls),
        "rm" => Ok(Command::Rm {
            name: one_name("rm")?,
        }),
        "use" => Ok(Command::Use {
            name: one_name("use")?,
        }),
        "status" => Ok(Command::Status),
        "helper" => match rest.as_slice() {
            [] => Ok(Command::Helper { name: None }),
            [n] => Ok(Command::Helper {
                name: Some((*n).clone()),
            }),
            _ => Err("usage: akey helper [<name>]".into()),
        },
        "run" => {
            let sep = rest.iter().position(|a| a.as_str() == "--");
            match (rest.first(), sep) {
                (Some(target), Some(1)) if rest.len() > 2 => Ok(Command::Run {
                    target: (*target).clone(),
                    cmd: rest[2..].iter().map(|s| (*s).clone()).collect(),
                }),
                _ => Err("usage: akey run <target> -- <cmd...>".into()),
            }
        }
        "wif" => parse_wif(&rest),
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    }
}

fn parse_wif(rest: &[&String]) -> Result<Command, String> {
    match rest.first().map(|s| s.as_str()) {
        Some("set") => {}
        _ => return Err("usage: akey wif set <name> --rule ... --org ... --svc ... [--workspace ...] --token-file ...".into()),
    }
    let name = match rest.get(1) {
        Some(n) if !n.starts_with('-') => (*n).clone(),
        _ => return Err("wif set: profile name required".into()),
    };
    let (mut rule, mut org, mut svc, mut workspace, mut token_file) =
        (None, None, None, None, None);
    let mut i = 2;
    while i < rest.len() {
        let flag = rest[i].as_str();
        let value = rest
            .get(i + 1)
            .ok_or_else(|| format!("wif set: {flag} needs a value"))?;
        match flag {
            "--rule" => rule = Some((*value).clone()),
            "--org" => org = Some((*value).clone()),
            "--svc" => svc = Some((*value).clone()),
            "--workspace" => workspace = Some((*value).clone()),
            "--token-file" => token_file = Some((*value).clone()),
            other => return Err(format!("wif set: unknown flag {other:?}")),
        }
        i += 2;
    }
    let need = |v: Option<String>, f: &str| v.ok_or(format!("wif set: {f} is required"));
    Ok(Command::WifSet {
        name,
        profile: WifProfile {
            rule: need(rule, "--rule")?,
            org: need(org, "--org")?,
            svc: need(svc, "--svc")?,
            workspace,
            token_file: need(token_file, "--token-file")?,
        },
    })
}
