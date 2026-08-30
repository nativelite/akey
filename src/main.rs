//! The akey binary. All logic lives in the library; this file reads stdin,
//! talks to the vault, spawns processes, and prints.

use akey::cli::{parse, Command, USAGE};
use akey::store;
use std::io::Read;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match parse(&args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    match dispatch(cmd) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("akey: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cmd: Command) -> std::io::Result<ExitCode> {
    match cmd {
        Command::Help => {
            print!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Set { name } => {
            eprintln!(
                "paste the key for {name:?} and press Enter \
                 (input is not hidden; you can also pipe it in):"
            );
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            let secret = store::clean_secret_input(&input);
            if secret.is_empty() {
                eprintln!("akey: empty input; nothing stored");
                return Ok(ExitCode::FAILURE);
            }
            store::set_key(&name, secret.as_bytes())?;
            if store::default()?.is_none() {
                store::set_default(&name)?;
                eprintln!("stored {name:?} in the OS vault (and made it the default)");
            } else {
                eprintln!("stored {name:?} in the OS vault");
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Ls => {
            let l = store::list()?;
            let default = l.default.as_deref().unwrap_or("");
            for k in &l.keys {
                let mark = if default == format!("key.{k}") {
                    "*"
                } else {
                    " "
                };
                println!("{mark} key  {k}");
            }
            for w in &l.wifs {
                let mark = if default == format!("wif.{w}") {
                    "*"
                } else {
                    " "
                };
                println!("{mark} wif  {w}");
            }
            if l.keys.is_empty() && l.wifs.is_empty() {
                eprintln!("(vault is empty; `akey set <name>` stores a key)");
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Rm { name } => {
            if store::remove(&name)? {
                eprintln!("removed {name:?}");
                Ok(ExitCode::SUCCESS)
            } else {
                eprintln!("akey: nothing named {name:?}");
                Ok(ExitCode::FAILURE)
            }
        }
        Command::Use { name } => {
            store::set_default(&name)?;
            eprintln!("default is now {name:?}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Helper { name } => match store::helper_secret(name.as_deref())? {
            Some(secret) => {
                // The apiKeyHelper contract: the key, on stdout, nothing else.
                use std::io::Write;
                let mut out = std::io::stdout();
                out.write_all(&secret)?;
                out.write_all(b"\n")?;
                Ok(ExitCode::SUCCESS)
            }
            None => {
                eprintln!("akey: no default key set (akey set <name>, akey use <name>)");
                Ok(ExitCode::FAILURE)
            }
        },
        Command::WifSet { name, profile } => {
            store::set_wif(&name, &profile)?;
            eprintln!("stored WIF profile {name:?} (inject with: akey run wif:{name} -- <cmd>)");
            Ok(ExitCode::SUCCESS)
        }
        Command::Run { target, cmd } => {
            // Reuse the library seam so `run` and amux inject identical env.
            let pairs = match akey::resolve(&target) {
                Ok(p) => p,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!("akey: no key or WIF profile named {target:?}");
                    return Ok(ExitCode::FAILURE);
                }
                Err(e) => return Err(e),
            };
            let mut child = std::process::Command::new(&cmd[0]);
            child.args(&cmd[1..]);
            // A federation profile never sets ANTHROPIC_API_KEY; a static key
            // sets exactly that. Documented footgun: a leftover static key
            // would shadow the federation vars, so clear the static-key vars
            // for the child before injecting a profile.
            if !pairs.iter().any(|(k, _)| k == "ANTHROPIC_API_KEY") {
                child.env_remove("ANTHROPIC_API_KEY");
                child.env_remove("ANTHROPIC_AUTH_TOKEN");
            }
            for (k, v) in pairs {
                child.env(k, v);
            }
            let status = child.status()?;
            Ok(ExitCode::from(
                status.code().unwrap_or(1).clamp(0, 255) as u8
            ))
        }
        Command::Status => {
            let env: std::collections::HashMap<String, String> = std::env::vars().collect();
            let listing = store::list().ok();
            for line in akey::status::report(&env, listing.as_ref()) {
                println!("{line}");
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
