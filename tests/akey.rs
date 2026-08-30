//! Integration tests for akey's library layer: CLI parsing, WIF profile
//! JSON round-trips and env injection, the pure status/precedence engine,
//! and (on Windows) the store layout against the real OS vault, including
//! an end-to-end `run`-style child process that must see the injected key.

use akey::cli::{parse, Command};
use akey::status;
use akey::store::{Listing, WifProfile, WIF_ENV};
use std::collections::HashMap;

fn args(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| x.to_string()).collect()
}

fn profile() -> WifProfile {
    WifProfile {
        rule: "fdrl_abc".into(),
        org: "00000000-0000-0000-0000-000000000000".into(),
        svc: "svac_xyz".into(),
        workspace: Some("wrkspc_1".into()),
        token_file: "/var/run/secrets/anthropic.com/token".into(),
    }
}

// --- CLI parsing -----------------------------------------------------------

#[test]
fn parse_basic_commands() {
    assert_eq!(parse(&args(&[])).unwrap(), Command::Help);
    assert_eq!(parse(&args(&["help"])).unwrap(), Command::Help);
    assert_eq!(
        parse(&args(&["set", "work"])).unwrap(),
        Command::Set {
            name: "work".into()
        }
    );
    assert_eq!(parse(&args(&["ls"])).unwrap(), Command::Ls);
    assert_eq!(
        parse(&args(&["rm", "old"])).unwrap(),
        Command::Rm { name: "old".into() }
    );
    assert_eq!(
        parse(&args(&["use", "wif:prod"])).unwrap(),
        Command::Use {
            name: "wif:prod".into()
        }
    );
    assert_eq!(
        parse(&args(&["helper"])).unwrap(),
        Command::Helper { name: None }
    );
    assert_eq!(
        parse(&args(&["helper", "work"])).unwrap(),
        Command::Helper {
            name: Some("work".into())
        }
    );
    assert_eq!(parse(&args(&["status"])).unwrap(), Command::Status);
}

#[test]
fn parse_run_requires_separator_and_command() {
    assert_eq!(
        parse(&args(&["run", "work", "--", "claude", "-p", "hi"])).unwrap(),
        Command::Run {
            target: "work".into(),
            cmd: args(&["claude", "-p", "hi"]),
        }
    );
    assert!(parse(&args(&["run", "work"])).is_err());
    assert!(parse(&args(&["run", "work", "--"])).is_err());
    assert!(parse(&args(&["run", "--", "cmd"])).is_err());
}

#[test]
fn parse_wif_set() {
    let cmd = parse(&args(&[
        "wif",
        "set",
        "prod",
        "--rule",
        "fdrl_abc",
        "--org",
        "00000000-0000-0000-0000-000000000000",
        "--svc",
        "svac_xyz",
        "--workspace",
        "wrkspc_1",
        "--token-file",
        "/var/run/secrets/anthropic.com/token",
    ]))
    .unwrap();
    assert_eq!(
        cmd,
        Command::WifSet {
            name: "prod".into(),
            profile: profile()
        }
    );
    // required flags enforced
    assert!(parse(&args(&["wif", "set", "p", "--rule", "r"])).is_err());
    assert!(parse(&args(&["wif", "set", "--rule", "r"])).is_err());
    assert!(parse(&args(&["wif", "list"])).is_err());
}

#[test]
fn unknown_command_shows_usage() {
    let err = parse(&args(&["frobnicate"])).unwrap_err();
    assert!(err.contains("unknown command"));
    assert!(err.contains("akey set <name>"));
}

// --- WIF profiles ----------------------------------------------------------

#[test]
fn wif_profile_json_round_trip() {
    let p = profile();
    assert_eq!(WifProfile::from_json(&p.to_json()).unwrap(), p);
    let no_ws = WifProfile {
        workspace: None,
        ..profile()
    };
    assert_eq!(WifProfile::from_json(&no_ws.to_json()).unwrap(), no_ws);
    assert!(WifProfile::from_json("{}").is_none());
    assert!(WifProfile::from_json("not json").is_none());
}

#[test]
fn wif_env_pairs_are_the_documented_variables() {
    let pairs = profile().env_pairs();
    let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
    for var in WIF_ENV {
        assert!(keys.contains(&var), "missing {var}");
    }
    let no_ws = WifProfile {
        workspace: None,
        ..profile()
    };
    let keys: Vec<String> = no_ws.env_pairs().into_iter().map(|(k, _)| k).collect();
    assert!(!keys.contains(&"ANTHROPIC_WORKSPACE_ID".to_string()));
}

#[test]
fn secret_input_is_cleaned_of_boms_and_whitespace() {
    use akey::store::clean_secret_input;
    // PowerShell 5.1 prepends U+FEFF when piping into a native program.
    assert_eq!(clean_secret_input("\u{feff}sk-abc\r\n"), "sk-abc");
    assert_eq!(clean_secret_input("  sk-abc \n"), "sk-abc");
    assert_eq!(clean_secret_input("\u{feff} \u{feff}sk-abc"), "sk-abc");
    assert_eq!(clean_secret_input("sk-abc"), "sk-abc");
    assert_eq!(clean_secret_input("\u{feff}\n"), "");
}

// --- set input path (piped seam) -------------------------------------------

#[test]
fn piped_set_input_reads_to_eof_verbatim() {
    use akey::prompt::read_secret_from;
    use akey::store::clean_secret_input;

    // Not a TTY -> read the whole reader to EOF, byte-for-byte as before.
    // Multi-line/no-trailing-newline content is preserved by the read; the
    // store's clean step then trims + strips the BOM exactly as it does for
    // the real `set` path.
    let raw = "\u{feff}sk-piped-123\r\n";
    let mut reader = std::io::Cursor::new(raw.as_bytes());
    let got = read_secret_from(&mut reader, false, "work").unwrap();
    assert_eq!(got, raw, "piped read must return the bytes verbatim");
    assert_eq!(clean_secret_input(&got), "sk-piped-123");

    // An empty pipe yields empty input (the caller treats it as "nothing
    // stored"), and never blocks waiting for a TTY line.
    let mut empty = std::io::Cursor::new(Vec::new());
    let got = read_secret_from(&mut empty, false, "work").unwrap();
    assert_eq!(got, "");
    assert!(clean_secret_input(&got).is_empty());
}

// --- status engine ---------------------------------------------------------

fn env_of(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn joined(lines: &[String]) -> String {
    lines.join("\n")
}

#[test]
fn status_names_the_env_key_winner_and_the_shadowing_footgun() {
    let env = env_of(&[
        ("ANTHROPIC_API_KEY", "sk-ant-xxx"),
        ("ANTHROPIC_FEDERATION_RULE_ID", "fdrl_1"),
    ]);
    let text = joined(&status::report(&env, None));
    assert!(text.contains(">> 2."), "tier 2 should win:\n{text}");
    assert!(text.contains("silently shadows federation"), "{text}");
}

#[test]
fn status_recognizes_complete_federation() {
    let env = env_of(&[
        ("ANTHROPIC_FEDERATION_RULE_ID", "fdrl_1"),
        ("ANTHROPIC_ORGANIZATION_ID", "org"),
        ("ANTHROPIC_SERVICE_ACCOUNT_ID", "svac_1"),
        ("ANTHROPIC_IDENTITY_TOKEN_FILE", "/tok"),
    ]);
    let text = joined(&status::report(&env, None));
    assert!(text.contains(">> 4."), "federation should win:\n{text}");
    assert!(!text.contains("shadows"));
}

#[test]
fn status_flags_partial_federation() {
    let env = env_of(&[("ANTHROPIC_FEDERATION_RULE_ID", "fdrl_1")]);
    let text = joined(&status::report(&env, None));
    assert!(text.contains("partially configured"), "{text}");
    assert!(text.contains("ANTHROPIC_ORGANIZATION_ID"), "{text}");
    assert!(
        text.contains("no credentials in this environment"),
        "{text}"
    );
}

#[test]
fn status_reports_vault_contents() {
    let listing = Listing {
        keys: vec!["work".into()],
        wifs: vec!["prod".into()],
        default: Some("key.work".into()),
    };
    let text = joined(&status::report(&env_of(&[]), Some(&listing)));
    assert!(text.contains("1 key(s) [work]"), "{text}");
    assert!(text.contains("default = key.work"), "{text}");
}

// --- the real vault + real child process (Windows) --------------------------

#[cfg(windows)]
mod windows_vault {
    use akey::store::{self, Resolved};

    /// Isolate this test run's entries from any real akey data: unique names.
    fn n(tag: &str) -> String {
        format!("test-{tag}-{}", std::process::id())
    }

    #[test]
    fn store_round_trip_and_resolution() {
        let key = n("k");
        let wif = n("w");
        store::set_key(&key, b"sk-test-123").unwrap();
        store::set_wif(&wif, &super::profile()).unwrap();

        match store::resolve(&key).unwrap().unwrap() {
            Resolved::Key(s) => assert_eq!(s, b"sk-test-123"),
            other => panic!("expected key, got {other:?}"),
        }
        match store::resolve(&format!("wif:{wif}")).unwrap().unwrap() {
            Resolved::Wif(p) => assert_eq!(p, super::profile()),
            other => panic!("expected wif, got {other:?}"),
        }
        assert!(store::resolve(&n("missing")).unwrap().is_none());

        assert!(store::remove(&key).unwrap());
        assert!(store::remove(&wif).unwrap());
        assert!(!store::remove(&key).unwrap());
    }

    #[test]
    fn resolve_seam_maps_a_key_to_anthropic_api_key() {
        let key = n("rk");
        store::set_key(&key, b"sk-resolve-789").unwrap();

        let pairs = akey::resolve(&key).unwrap();
        let names: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, ["ANTHROPIC_API_KEY"]);
        assert_eq!(pairs[0].1, "sk-resolve-789");

        assert!(store::remove(&key).unwrap());
    }

    #[test]
    fn resolve_seam_maps_a_wif_to_the_five_federation_vars() {
        let wif = n("rw");
        store::set_wif(&wif, &super::profile()).unwrap();

        let pairs = akey::resolve(&format!("wif:{wif}")).unwrap();
        let names: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        // profile() carries a workspace, so all five federation vars appear.
        for var in store::WIF_ENV {
            assert!(names.contains(&var), "missing {var} in {names:?}");
        }
        // The seam sets only the federation vars — never a static key.
        assert!(!names.contains(&"ANTHROPIC_API_KEY"));

        assert!(store::remove(&wif).unwrap());
    }

    #[test]
    fn resolve_seam_reports_a_missing_target_as_not_found() {
        let err = akey::resolve(&n("rmissing")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn child_process_sees_the_injected_key() {
        let key = n("inject");
        store::set_key(&key, b"sk-injected-456").unwrap();
        let Resolved::Key(secret) = store::resolve(&key).unwrap().unwrap() else {
            panic!("expected key");
        };
        let out = std::process::Command::new("cmd")
            .args(["/C", "echo %ANTHROPIC_API_KEY%"])
            .env(
                "ANTHROPIC_API_KEY",
                String::from_utf8_lossy(&secret).as_ref(),
            )
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("sk-injected-456"), "child saw: {stdout}");
        assert!(store::remove(&key).unwrap());
    }
}
