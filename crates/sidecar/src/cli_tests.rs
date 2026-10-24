use std::collections::HashMap;

use sidecar_core::{DeploymentPreset, LocalAuthzMode, LocalAuthzRemoteFallback};

use crate::cli::{Cli, ParseOutcome, doctor_report};

#[test]
fn given_required_values_as_environment_when_cli_is_parsed_then_aux_prefix_values_are_used() {
    let env = env_map([
        ("AUX_BASE_URL", "https://tenant.example.test"),
        ("AUX_API_KEY", "ak_test"),
        ("AUX_TENANT_DOMAIN", "tenant.example.test"),
        ("AUX_BIND_ADDR", "0.0.0.0:9100"),
        ("AUX_UNSAFE_BIND_NON_LOOPBACK", "true"),
        ("AUX_RESOURCE_AUDIENCES", "registry,api://orders"),
        ("AUX_AUTHZ_LOCAL_MODE", "shadow"),
        ("AUX_AUTHZ_CACHE_TTL_SECONDS", "8"),
        ("AUX_AUTHZ_STALE_CACHE_TTL_SECONDS", "12"),
        ("AUX_AUTHZ_REFRESH_AFTER_PERCENT", "60"),
        ("AUX_AUTHZ_REMOTE_FALLBACK", "never"),
    ]);

    let parsed = parse([], &env);

    assert_eq!(parsed.base_url, "https://tenant.example.test");
    assert_eq!(parsed.api_key, "ak_test");
    assert_eq!(parsed.tenant_domain.as_deref(), Some("tenant.example.test"));
    assert_eq!(parsed.bind_addr, "0.0.0.0:9100");
    assert!(parsed.unsafe_bind_non_loopback);
    assert_eq!(parsed.resource_audiences, ["registry", "api://orders"]);
    assert_eq!(parsed.authz_local_mode, LocalAuthzMode::Shadow);
    assert_eq!(parsed.authz_cache_ttl_seconds, 8);
    assert_eq!(parsed.authz_stale_cache_ttl_seconds, 12);
    assert_eq!(parsed.authz_refresh_after_percent, 60);
    assert_eq!(
        parsed.authz_remote_fallback,
        LocalAuthzRemoteFallback::Never
    );
    assert!(!parsed.audience_check_disabled);
}

#[test]
fn given_argument_values_and_environment_when_cli_is_parsed_then_arguments_win() {
    let env = env_map([
        ("AUX_BASE_URL", "https://env.example.test"),
        ("AUX_API_KEY", "env_key"),
        ("AUX_CACHE_TTL_SECONDS", "10"),
        ("AUX_SIDECAR_PRESET", "worker"),
    ]);

    let parsed = parse(
        [
            "--base-url=https://arg.example.test",
            "--api-key",
            "arg_key",
            "--tenant-domain",
            "arg.example.test",
            "--cache-ttl-seconds",
            "25",
            "--authz-cache-ttl-seconds",
            "6",
            "--authz-local-mode",
            "remote-only",
            "--authz-refresh-after-percent",
            "75",
            "--authz-remote-fallback",
            "refresh-error",
            "--resource-audience",
            "registry",
            "--resource-audience=api://orders",
            "--preset=lambda",
        ],
        &env,
    );

    assert_eq!(parsed.base_url, "https://arg.example.test");
    assert_eq!(parsed.api_key, "arg_key");
    assert_eq!(parsed.tenant_domain.as_deref(), Some("arg.example.test"));
    assert_eq!(parsed.cache_ttl_seconds, 25);
    assert_eq!(parsed.authz_local_mode, LocalAuthzMode::RemoteOnly);
    assert_eq!(parsed.authz_cache_ttl_seconds, 6);
    assert_eq!(parsed.authz_refresh_after_percent, 75);
    assert_eq!(
        parsed.authz_remote_fallback,
        LocalAuthzRemoteFallback::RefreshError
    );
    assert_eq!(parsed.resource_audiences, ["registry", "api://orders"]);
    assert_eq!(parsed.preset, DeploymentPreset::Lambda);
    assert_eq!(parsed.bind_addr, "127.0.0.1:2773");
}

#[test]
fn given_no_preset_when_cli_is_parsed_then_kubernetes_defaults_are_used() {
    let parsed = parse(
        [
            "--base-url=https://tenant.example.test",
            "--api-key=arg_key",
            "--no-audience-check",
        ],
        &HashMap::new(),
    );

    assert_eq!(parsed.preset, DeploymentPreset::Kubernetes);
    assert_eq!(parsed.bind_addr, "127.0.0.1:9001");
}

#[test]
fn given_preset_in_environment_when_cli_is_parsed_then_environment_preset_is_used() {
    let env = env_map([
        ("AUX_BASE_URL", "https://tenant.example.test"),
        ("AUX_API_KEY", "ak_test"),
        ("AUX_SIDECAR_PRESET", "lambda"),
    ]);

    let parsed = parse(["--no-audience-check"], &env);

    assert_eq!(parsed.preset, DeploymentPreset::Lambda);
}

#[test]
fn given_invalid_preset_when_cli_is_parsed_then_error_names_value() {
    let error = Cli::parse_from(
        [
            "--base-url=https://tenant.example.test",
            "--api-key=arg_key",
            "--no-audience-check",
            "--preset=invalid",
        ],
        |_| Err(std::env::VarError::NotPresent),
    )
    .expect_err("invalid preset should fail");

    assert!(
        error
            .to_string()
            .contains("worker, lambda, kubernetes, proxy, or embedded")
    );
}

#[test]
fn given_non_listener_preset_when_native_cli_is_parsed_then_actionable_conflict_is_returned() {
    for preset in ["worker", "embedded"] {
        let preset_arg = format!("--preset={preset}");
        let error = Cli::parse_from(
            [
                "--base-url=https://tenant.example.test",
                "--api-key=arg_key",
                "--no-audience-check",
                preset_arg.as_str(),
            ],
            |_| Err(std::env::VarError::NotPresent),
        )
        .expect_err("non-listener preset should fail native CLI");

        assert!(error.to_string().contains("cannot start a native listener"));
    }
}

#[test]
fn given_proxy_preset_when_listener_is_not_explicit_then_private_unix_socket_is_used() {
    let parsed = parse(
        [
            "--base-url=https://tenant.example.test",
            "--api-key=arg_key",
            "--no-audience-check",
            "--preset=proxy",
            "--proxy-policy-path=config/proxy-policy.example.json",
        ],
        &HashMap::new(),
    );

    assert_eq!(
        parsed.unix_socket_path.as_deref(),
        Some(std::path::Path::new("/var/run/aux-sidecar/sidecar.sock"))
    );
    assert_eq!(parsed.authz_local_mode, LocalAuthzMode::RemoteOnly);
}

#[test]
fn given_tcp_and_unix_listeners_when_cli_is_parsed_then_conflict_is_rejected() {
    let error = Cli::parse_from(
        [
            "--base-url=https://tenant.example.test",
            "--api-key=arg_key",
            "--no-audience-check",
            "--bind-addr=127.0.0.1:9001",
            "--unix-socket=/tmp/sidecar.sock",
            "--preset=lambda",
        ],
        |_| Err(std::env::VarError::NotPresent),
    )
    .expect_err("listener conflict should fail");

    assert!(error.to_string().contains("not both"));
}

#[test]
fn given_invalid_authz_refresh_percent_when_cli_is_parsed_then_error_is_returned() {
    let error = Cli::parse_from(
        [
            "--base-url=https://tenant.example.test",
            "--api-key",
            "arg_key",
            "--no-audience-check",
            "--authz-refresh-after-percent",
            "0",
        ],
        |_| Err(std::env::VarError::NotPresent),
    )
    .expect_err("invalid authz refresh percent should fail");

    assert!(error.to_string().contains("between 1 and 100"));
}

#[test]
fn given_missing_required_values_when_cli_is_parsed_then_error_names_argument_and_environment() {
    let error = Cli::parse_from(Vec::<&str>::new(), |_| Err(std::env::VarError::NotPresent))
        .expect_err("missing required value should fail");

    assert!(error.to_string().contains("--base-url or AUX_BASE_URL"));
}

#[test]
fn given_no_audience_check_when_cli_is_parsed_then_audience_check_is_disabled() {
    let parsed = parse(
        [
            "--base-url=https://tenant.example.test",
            "--api-key",
            "arg_key",
            "--no-audience-check",
        ],
        &HashMap::new(),
    );

    assert!(parsed.resource_audiences.is_empty());
    assert!(parsed.audience_check_disabled);
}

#[test]
fn given_no_audience_check_and_resource_audience_when_cli_is_parsed_then_error_is_returned() {
    let error = Cli::parse_from(
        [
            "--base-url=https://tenant.example.test",
            "--api-key",
            "arg_key",
            "--resource-audience",
            "api://orders",
            "--no-audience-check",
        ],
        |_| Err(std::env::VarError::NotPresent),
    )
    .expect_err("mutually exclusive audience config should fail");

    assert!(error.to_string().contains("not both"));
}

#[test]
fn given_too_many_resource_audiences_when_cli_is_parsed_then_rejects_them() {
    let mut args = vec![
        "--base-url=https://tenant.example.test".to_string(),
        "--api-key=arg_key".to_string(),
    ];
    for index in 0..=sidecar_core::MAX_RESOURCE_AUDIENCES {
        args.push("--resource-audience".to_string());
        args.push(format!("api://audience-{index}"));
    }

    let error = Cli::parse_from(args, |_| Err(std::env::VarError::NotPresent))
        .expect_err("too many resource audiences should fail");

    assert!(error.to_string().contains("configured limit"));
}

#[test]
fn given_oversized_resource_audience_when_cli_is_parsed_then_rejects_it() {
    let argument = "a".repeat(sidecar_core::MAX_RESOURCE_AUDIENCE_BYTES + 1);
    let error = Cli::parse_from(
        [
            "--base-url=https://tenant.example.test",
            "--api-key=arg_key",
            "--resource-audience",
            argument.as_str(),
        ],
        |_| Err(std::env::VarError::NotPresent),
    )
    .expect_err("oversized resource audience should fail");

    assert!(error.to_string().contains("at most"));
}

#[test]
fn given_plaintext_non_loopback_base_url_when_cli_is_parsed_then_error_is_returned() {
    let error = Cli::parse_from(
        [
            "--base-url=http://tenant.example.test",
            "--api-key",
            "arg_key",
            "--no-audience-check",
        ],
        |_| Err(std::env::VarError::NotPresent),
    )
    .expect_err("plaintext non-loopback base URL should fail");

    assert!(error.to_string().contains("must use https"));
}

#[test]
fn given_plaintext_loopback_base_url_when_cli_is_parsed_then_parse_succeeds() {
    let parsed = parse(
        [
            "--base-url=http://127.0.0.1:3000",
            "--api-key",
            "arg_key",
            "--no-audience-check",
        ],
        &HashMap::new(),
    );

    assert_eq!(parsed.base_url, "http://127.0.0.1:3000");
}

#[test]
fn given_base_url_with_embedded_credentials_when_cli_is_parsed_then_rejects_it() {
    let error = Cli::parse_from(
        [
            "--base-url=https://user:secret@tenant.example.test",
            "--api-key",
            "arg_key",
            "--no-audience-check",
        ],
        |_| Err(std::env::VarError::NotPresent),
    )
    .expect_err("URL credentials must not be accepted");

    assert!(
        error
            .to_string()
            .contains("must not include URL credentials")
    );
}

#[test]
fn given_non_loopback_bind_without_unsafe_flag_when_cli_is_parsed_then_error_is_returned() {
    let error = Cli::parse_from(
        [
            "--base-url=https://tenant.example.test",
            "--api-key",
            "arg_key",
            "--bind-addr",
            "0.0.0.0:9100",
            "--no-audience-check",
        ],
        |_| Err(std::env::VarError::NotPresent),
    )
    .expect_err("non-loopback bind should require unsafe flag");

    assert!(error.to_string().contains("unsafe-bind-non-loopback"));
}

#[test]
fn given_help_flag_when_cli_is_parsed_then_help_outcome_is_returned() {
    let outcome = Cli::parse_from(["--help"], |_| Err(std::env::VarError::NotPresent))
        .expect("help should parse");

    assert!(matches!(outcome, ParseOutcome::Help));
}

#[test]
fn given_doctor_command_when_cli_is_parsed_then_report_is_sanitized() {
    let outcome = Cli::parse_from(
        [
            "doctor",
            "--base-url=https://tenant.example.test",
            "--api-key=secret-do-not-print",
            "--no-audience-check",
        ],
        |_| Err(std::env::VarError::NotPresent),
    )
    .expect("doctor should parse");
    let ParseOutcome::Doctor(cli) = outcome else {
        panic!("expected doctor outcome");
    };

    let report = doctor_report(&cli).to_string();

    assert!(report.contains("configuration_valid"));
    assert!(report.contains("<redacted>"));
    assert!(!report.contains("secret-do-not-print"));
}

fn parse<const N: usize>(args: [&str; N], env: &HashMap<&'static str, &'static str>) -> Cli {
    match Cli::parse_from(args, |name| {
        env.get(name)
            .map(|value| (*value).to_string())
            .ok_or(std::env::VarError::NotPresent)
    })
    .expect("cli should parse")
    {
        ParseOutcome::Run(cli) => *cli,
        ParseOutcome::Doctor(_) => panic!("expected runnable cli"),
        ParseOutcome::Help => panic!("expected runnable cli"),
    }
}

fn env_map<const N: usize>(
    pairs: [(&'static str, &'static str); N],
) -> HashMap<&'static str, &'static str> {
    pairs.into_iter().collect()
}

#[test]
fn given_private_backend_and_public_issuer_when_cli_is_parsed_then_protocol_identity_stays_separate()
 {
    let values = env_map([
        ("AUX_BASE_URL", "http://127.0.0.1:8080"),
        ("AUX_ISSUER", "https://account.example.test"),
        ("AUX_API_KEY", "fixture-secret"),
        ("AUX_RESOURCE_AUDIENCES", "https://documents.example.test"),
    ]);
    let config = parse([], &values);
    assert_eq!(config.base_url, "http://127.0.0.1:8080");
    assert_eq!(config.issuer, "https://account.example.test");
    let overridden = parse(["--issuer=https://other.example.test"], &values);
    assert_eq!(overridden.issuer, "https://other.example.test");
}

#[test]
fn given_no_issuer_override_when_cli_is_parsed_then_public_base_url_is_the_default_issuer() {
    let config = parse(
        [
            "--base-url=https://account.example.test/",
            "--api-key=fixture-secret",
            "--no-audience-check",
        ],
        &HashMap::new(),
    );
    assert_eq!(config.issuer, "https://account.example.test");
}

#[test]
fn given_invalid_explicit_issuer_when_cli_is_parsed_then_configuration_is_rejected() {
    for issuer in [
        "https://account.example.test/.",
        "https://account.example.test/a/..",
        "https://account.example.test/%2e",
        "",
        "/relative",
        "https://account.example.test/path",
        "https://account.example.test/",
        "http://remote.example.test",
        "https://user@account.example.test",
        "https://account.example.test?query=value",
        "https://account.example.test#fragment",
        " https://account.example.test",
        "https://account.example.test\\path",
    ] {
        let result = Cli::parse_from(
            [
                "--base-url=http://127.0.0.1:8080",
                "--api-key=fixture-secret",
                "--no-audience-check",
                "--issuer",
                issuer,
            ],
            |_| Err(std::env::VarError::NotPresent),
        );
        assert!(
            result.is_err(),
            "invalid issuer must not reach a runtime verifier"
        );
    }
}
