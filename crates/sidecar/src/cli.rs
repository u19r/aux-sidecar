use std::path::PathBuf;

use sidecar_core::{DeploymentPreset, LocalAuthzMode, LocalAuthzRemoteFallback};

use crate::{cli_values::*, config::SidecarConfig, server::serve};

const HELP: &str = "\
AuxFn sidecar server

Usage:
  sidecar --base-url <tenant-url> --api-key <key> (--resource-audience <audience>... | \
                    --no-audience-check) [options]
  sidecar doctor --base-url <tenant-url> --api-key <key> (--resource-audience <audience>... | \
                    --no-audience-check) [options]
  sidecar healthcheck <live|ready>

Required arguments:
  --base-url <url>       AuxFn tenant subdomain URL, or AUX_BASE_URL
  --api-key <key>        AuxFn runtime API key (prefer AUX_API_KEY to avoid process-list exposure)
  --resource-audience <audience>
                         Protected resource audience; repeatable, or comma-separated \
                    AUX_RESOURCE_AUDIENCES
  --no-audience-check    Disable OAuth resource-audience validation, or AUX_NO_AUDIENCE_CHECK=true

Optional arguments:
  --preset <worker|lambda|kubernetes|proxy|embedded>
                                 Deployment preset, or AUX_SIDECAR_PRESET (default: kubernetes)
  --bind-addr <addr>             Listen address, or AUX_BIND_ADDR (default: 127.0.0.1:9001)
  --unix-socket <path>           Private Unix socket path, or AUX_UNIX_SOCKET
  --proxy-policy-path <path>     Required proxy mapping policy for the proxy preset
  --route-policy-path <path>     Startup-compiled OpenAPI HTTP route policy, or \
                    AUX_ROUTE_POLICY_PATH
  --upstream-url <url>           HTTP upstream for whole-upstream or route-aware proxying, or \
                    AUX_UPSTREAM_URL
  --issuer <url>                Expected JWT issuer, or AUX_ISSUER (default: base URL)
  --tenant-domain <domain>       Optional AuxFn tenant authority, or AUX_TENANT_DOMAIN
  --login-redirect-url <url>     Hosted-login redirect URL, or AUX_LOGIN_REDIRECT_URL
  --jwt-clock-skew-seconds <n>   JWT clock skew seconds, or AUX_JWT_CLOCK_SKEW_SECONDS (default: 0)
  --config-path <path>           Runtime config JSON file, or AUX_CONFIG_PATH
  --cache-ttl-seconds <n>        Fresh runtime-config cache TTL, or AUX_CACHE_TTL_SECONDS \
                    (default: 60)
  --stale-cache-ttl-seconds <n>  Stale runtime-config cache TTL, or AUX_STALE_CACHE_TTL_SECONDS \
                    (default: 300)
  --authz-local-mode <remote-only|shadow|enforced>
                                 Local AuthZ rollout mode, or AUX_AUTHZ_LOCAL_MODE (default: \
                    remote-only)
  --authz-cache-ttl-seconds <n>  Fresh local AuthZ snapshot cache TTL, or \
                    AUX_AUTHZ_CACHE_TTL_SECONDS (default: 10)
  --authz-stale-cache-ttl-seconds <n>
                                 Stale local AuthZ snapshot cache TTL, or \
                    AUX_AUTHZ_STALE_CACHE_TTL_SECONDS (default: 30)
  --authz-refresh-after-percent <n>
                                 Refresh local AuthZ snapshots after this percent of fresh TTL, or \
                    AUX_AUTHZ_REFRESH_AFTER_PERCENT (default: 50)
  --authz-remote-fallback <cache-miss|refresh-error|never>
                                 Remote fallback policy for future enforced mode, or \
                    AUX_AUTHZ_REMOTE_FALLBACK (default: cache-miss)
  --unsafe-bind-non-loopback     Allow native HTTP sidecar to bind outside loopback, or \
                    AUX_UNSAFE_BIND_NON_LOOPBACK=true
  --external-base-url <URL>      Public HTTPS request base (AUX_EXTERNAL_BASE_URL), separate from \
                    upstream
  --help                         Print this help

The healthcheck command probes AUX_BIND_ADDR (default 127.0.0.1:9001) without loading secrets.
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cli {
    pub(crate) preset: DeploymentPreset,
    pub(crate) bind_addr: String,
    pub(crate) unix_socket_path: Option<PathBuf>,
    pub(crate) proxy_policy_path: Option<PathBuf>,
    pub(crate) route_policy_path: Option<PathBuf>,
    pub(crate) upstream_url: Option<String>,
    pub(crate) external_base_url: Option<String>,
    pub(crate) base_url: String,
    pub(crate) issuer: String,
    pub(crate) api_key: String,
    pub(crate) tenant_domain: Option<String>,
    pub(crate) login_redirect_url: Option<String>,
    pub(crate) resource_audiences: Vec<String>,
    pub(crate) audience_check_disabled: bool,
    pub(crate) jwt_clock_skew_seconds: u64,
    pub(crate) config_path: Option<PathBuf>,
    pub(crate) cache_ttl_seconds: u64,
    pub(crate) stale_cache_ttl_seconds: u64,
    pub(crate) authz_local_mode: LocalAuthzMode,
    pub(crate) authz_cache_ttl_seconds: u64,
    pub(crate) authz_stale_cache_ttl_seconds: u64,
    pub(crate) authz_refresh_after_percent: u8,
    pub(crate) authz_remote_fallback: LocalAuthzRemoteFallback,
    pub(crate) unsafe_bind_non_loopback: bool,
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("healthcheck") {
        let kind = args.get(1).map(String::as_str).unwrap_or("");
        let address =
            std::env::var("AUX_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:9001".to_string());
        return crate::healthcheck::run(kind, &address)
            .map_err(|error| Box::new(CliError::new(error)) as Box<dyn std::error::Error>);
    }
    tracing_subscriber::fmt::init();
    let (cli, doctor) = match Cli::parse_from(args, |name| std::env::var(name)) {
        Ok(ParseOutcome::Run(cli)) => (*cli, false),
        Ok(ParseOutcome::Doctor(cli)) => (*cli, true),
        Ok(ParseOutcome::Help) => {
            print!("{HELP}");
            return Ok(());
        }
        Err(error) => return Err(Box::new(error)),
    };

    if doctor {
        println!("{}", doctor_report(&cli));
        return Ok(());
    }

    serve(SidecarConfig {
        preset: cli.preset,
        bind_addr: cli.bind_addr,
        unix_socket_path: cli.unix_socket_path,
        proxy_policy_path: cli.proxy_policy_path,
        route_policy_path: cli.route_policy_path,
        upstream_url: cli.upstream_url,
        external_base_url: cli.external_base_url,
        base_url: cli.base_url,
        issuer: cli.issuer,
        api_key: cli.api_key,
        tenant_domain: cli.tenant_domain,
        login_redirect_url: cli.login_redirect_url,
        resource_audiences: cli.resource_audiences,
        audience_check_disabled: cli.audience_check_disabled,
        jwt_clock_skew_seconds: cli.jwt_clock_skew_seconds,
        config_path: cli.config_path,
        cache_ttl_seconds: cli.cache_ttl_seconds,
        stale_cache_ttl_seconds: cli.stale_cache_ttl_seconds,
        authz_local_mode: cli.authz_local_mode,
        authz_cache_ttl_seconds: cli.authz_cache_ttl_seconds,
        authz_stale_cache_ttl_seconds: cli.authz_stale_cache_ttl_seconds,
        authz_refresh_after_percent: cli.authz_refresh_after_percent,
        authz_remote_fallback: cli.authz_remote_fallback,
        unsafe_bind_non_loopback: cli.unsafe_bind_non_loopback,
    })
    .await
}

impl Cli {
    pub(crate) fn parse_from<I, S, F>(args: I, env: F) -> Result<ParseOutcome, CliError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        F: Fn(&str) -> Result<String, std::env::VarError>,
    {
        let mut parsed = ParsedArgs::default();
        let mut args = args.into_iter().map(Into::into).peekable();
        let doctor = args.peek().is_some_and(|arg| arg == "doctor");
        if doctor {
            let _ = args.next();
        }
        while let Some(arg) = args.next() {
            if arg == "--help" || arg == "-h" {
                return Ok(ParseOutcome::Help);
            }
            let Some(name) = arg.strip_prefix("--") else {
                return Err(CliError::new(format!(
                    "unexpected positional argument '{arg}'"
                )));
            };
            if name == "no-audience-check" {
                parsed.no_audience_check = true;
                continue;
            }
            if name == "unsafe-bind-non-loopback" {
                parsed.unsafe_bind_non_loopback = true;
                continue;
            }
            let (name, value) = if let Some((name, value)) = name.split_once('=') {
                (name.to_string(), value.to_string())
            } else {
                let Some(value) = args.next() else {
                    return Err(CliError::new(format!("missing value for '--{name}'")));
                };
                if value.starts_with("--") {
                    return Err(CliError::new(format!("missing value for '--{name}'")));
                }
                (name.to_string(), value)
            };
            parsed.set(&name, value)?;
        }

        let cli = Box::new(parsed.into_cli(env)?);
        if doctor {
            Ok(ParseOutcome::Doctor(cli))
        } else {
            Ok(ParseOutcome::Run(cli))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseOutcome {
    Run(Box<Cli>),
    Doctor(Box<Cli>),
    Help,
}

pub(crate) fn doctor_report(cli: &Cli) -> serde_json::Value {
    serde_json::json!({
        "status": "configuration_valid",
        "preset": cli.preset.as_str(),
        "bind_addr": cli.bind_addr,
        "base_url": cli.base_url,
        "api_key": "<redacted>",
        "tenant_domain_configured": cli.tenant_domain.is_some(),
        "resource_audience_count": cli.resource_audiences.len(),
        "audience_check_disabled": cli.audience_check_disabled,
        "cache_ttl_seconds": cli.cache_ttl_seconds,
        "stale_cache_ttl_seconds": cli.stale_cache_ttl_seconds,
        "host_transport": "configured",
    })
}

#[derive(Default)]
struct ParsedArgs {
    preset: Option<String>,
    bind_addr: Option<String>,
    unix_socket: Option<String>,
    proxy_policy_path: Option<String>,
    route_policy_path: Option<String>,
    upstream_url: Option<String>,
    external_base_url: Option<String>,
    base_url: Option<String>,
    issuer: Option<String>,
    api_key: Option<String>,
    tenant_domain: Option<String>,
    login_redirect_url: Option<String>,
    resource_audiences: Vec<String>,
    no_audience_check: bool,
    jwt_clock_skew_seconds: Option<String>,
    config_path: Option<String>,
    cache_ttl_seconds: Option<String>,
    stale_cache_ttl_seconds: Option<String>,
    authz_local_mode: Option<String>,
    authz_cache_ttl_seconds: Option<String>,
    authz_stale_cache_ttl_seconds: Option<String>,
    authz_refresh_after_percent: Option<String>,
    authz_remote_fallback: Option<String>,
    unsafe_bind_non_loopback: bool,
}

impl ParsedArgs {
    fn set(&mut self, name: &str, value: String) -> Result<(), CliError> {
        match name {
            "preset" => self.preset = Some(value),
            "bind-addr" => self.bind_addr = Some(value),
            "unix-socket" => self.unix_socket = Some(value),
            "proxy-policy-path" => self.proxy_policy_path = Some(value),
            "route-policy-path" => self.route_policy_path = Some(value),
            "upstream-url" => self.upstream_url = Some(value),
            "external-base-url" => self.external_base_url = Some(value),
            "base-url" => self.base_url = Some(value),
            "api-key" => self.api_key = Some(value),
            "issuer" => self.issuer = Some(value),
            "tenant-domain" => self.tenant_domain = Some(value),
            "login-redirect-url" => self.login_redirect_url = Some(value),
            "resource-audience" => self.resource_audiences.push(value),
            "jwt-clock-skew-seconds" => self.jwt_clock_skew_seconds = Some(value),
            "config-path" => self.config_path = Some(value),
            "cache-ttl-seconds" => self.cache_ttl_seconds = Some(value),
            "stale-cache-ttl-seconds" => self.stale_cache_ttl_seconds = Some(value),
            "authz-local-mode" => self.authz_local_mode = Some(value),
            "authz-cache-ttl-seconds" => self.authz_cache_ttl_seconds = Some(value),
            "authz-stale-cache-ttl-seconds" => self.authz_stale_cache_ttl_seconds = Some(value),
            "authz-refresh-after-percent" => self.authz_refresh_after_percent = Some(value),
            "authz-remote-fallback" => self.authz_remote_fallback = Some(value),
            _ => return Err(CliError::new(format!("unknown argument '--{name}'"))),
        }
        Ok(())
    }

    fn into_cli<F>(self, env: F) -> Result<Cli, CliError>
    where F: Fn(&str) -> Result<String, std::env::VarError> {
        let base_url = required_value(self.base_url, "AUX_BASE_URL", "--base-url", &env)?;
        validate_base_url(&base_url)?;
        let issuer = crate::config::resolve_issuer(
            &base_url,
            match self.issuer {
                Some(value) => Some(value),
                None => match env("AUX_ISSUER") {
                    Ok(value) => Some(value),
                    Err(std::env::VarError::NotPresent) => None,
                    Err(std::env::VarError::NotUnicode(_)) => {
                        return Err(CliError::new("AUX_ISSUER must contain valid Unicode"));
                    }
                },
            },
        )
        .map_err(CliError::new)?;
        let api_key = required_value(self.api_key, "AUX_API_KEY", "--api-key", &env)?;
        let resource_audiences = resource_audiences(self.resource_audiences, &env)?;
        let audience_check_disabled = audience_check_disabled(self.no_audience_check, &env)?;
        let preset = deployment_preset(self.preset, &env)?;
        if matches!(
            preset,
            DeploymentPreset::Worker | DeploymentPreset::Embedded
        ) {
            return Err(CliError::new(
                "worker and embedded presets use the library/WASM API and cannot start a native \
                 listener",
            ));
        }
        let default_bind_addr = match preset {
            DeploymentPreset::Lambda => "127.0.0.1:2773",
            _ => "127.0.0.1:9001",
        };
        let explicit_bind_addr = optional_value(self.bind_addr, "AUX_BIND_ADDR", &env)?;
        let explicit_unix_socket = optional_value(self.unix_socket, "AUX_UNIX_SOCKET", &env)?;
        if explicit_bind_addr.is_some()
            && explicit_unix_socket.is_some()
            && !matches!(preset, DeploymentPreset::Kubernetes)
        {
            return Err(CliError::new(
                "configure --bind-addr or --unix-socket, not both",
            ));
        }
        let unix_socket_path = explicit_unix_socket
            .or_else(|| {
                matches!(preset, DeploymentPreset::Proxy)
                    .then(|| "/var/run/aux-sidecar/sidecar.sock".to_string())
            })
            .map(PathBuf::from);
        let proxy_policy_path =
            optional_value(self.proxy_policy_path, "AUX_PROXY_POLICY_PATH", &env)?
                .map(PathBuf::from);
        let route_policy_path =
            optional_value(self.route_policy_path, "AUX_ROUTE_POLICY_PATH", &env)?
                .map(PathBuf::from);
        let external_base_url =
            optional_value(self.external_base_url, "AUX_EXTERNAL_BASE_URL", &env)?;
        let upstream_url = optional_value(self.upstream_url, "AUX_UPSTREAM_URL", &env)?;
        if let Some(upstream_url) = upstream_url.as_deref() {
            crate::config::validate_upstream_url(upstream_url).map_err(CliError::new)?;
        }
        if matches!(preset, DeploymentPreset::Proxy) && proxy_policy_path.is_none() {
            return Err(CliError::new(
                "the proxy preset requires --proxy-policy-path or AUX_PROXY_POLICY_PATH",
            ));
        }
        let bind_addr = explicit_bind_addr.unwrap_or_else(|| default_bind_addr.to_string());
        let unsafe_bind_non_loopback =
            unsafe_bind_non_loopback(self.unsafe_bind_non_loopback, &env)?;
        validate_audience_config(&resource_audiences, audience_check_disabled)?;
        validate_bind_addr(&bind_addr, unsafe_bind_non_loopback)?;
        // Proxy requests carry validated JWT context to the upstream AuthZ
        // service. Local AuthZ deliberately rejects caller-supplied credential
        // context, so enabling it implicitly would make every authenticated
        // proxy request fail closed with a 503. Keep the documented remote-only
        // default; deployments can opt into local rollout explicitly.
        let authz_default = LocalAuthzMode::RemoteOnly;

        Ok(Cli {
            preset,
            bind_addr,
            unix_socket_path,
            proxy_policy_path,
            route_policy_path,
            upstream_url,
            external_base_url,
            base_url,
            issuer,
            api_key,
            tenant_domain: optional_value(self.tenant_domain, "AUX_TENANT_DOMAIN", &env)?,
            login_redirect_url: optional_value(
                self.login_redirect_url,
                "AUX_LOGIN_REDIRECT_URL",
                &env,
            )?,
            resource_audiences,
            audience_check_disabled,
            jwt_clock_skew_seconds: seconds_value(
                self.jwt_clock_skew_seconds,
                "AUX_JWT_CLOCK_SKEW_SECONDS",
                0,
                &env,
            )?,
            config_path: optional_value(self.config_path, "AUX_CONFIG_PATH", &env)?
                .map(PathBuf::from),
            cache_ttl_seconds: seconds_value(
                self.cache_ttl_seconds,
                "AUX_CACHE_TTL_SECONDS",
                60,
                &env,
            )?,
            stale_cache_ttl_seconds: seconds_value(
                self.stale_cache_ttl_seconds,
                "AUX_STALE_CACHE_TTL_SECONDS",
                300,
                &env,
            )?,
            authz_local_mode: authz_local_mode(self.authz_local_mode, authz_default, &env)?,
            authz_cache_ttl_seconds: seconds_value(
                self.authz_cache_ttl_seconds,
                "AUX_AUTHZ_CACHE_TTL_SECONDS",
                10,
                &env,
            )?,
            authz_stale_cache_ttl_seconds: seconds_value(
                self.authz_stale_cache_ttl_seconds,
                "AUX_AUTHZ_STALE_CACHE_TTL_SECONDS",
                30,
                &env,
            )?,
            authz_refresh_after_percent: percent_value(
                self.authz_refresh_after_percent,
                "AUX_AUTHZ_REFRESH_AFTER_PERCENT",
                50,
                &env,
            )?,
            authz_remote_fallback: authz_remote_fallback(self.authz_remote_fallback, &env)?,
            unsafe_bind_non_loopback,
        })
    }
}

fn deployment_preset<F>(explicit: Option<String>, env: &F) -> Result<DeploymentPreset, CliError>
where F: Fn(&str) -> Result<String, std::env::VarError> {
    let value = optional_value(explicit, "AUX_SIDECAR_PRESET", env)?
        .unwrap_or_else(|| "kubernetes".to_string());
    value
        .parse::<DeploymentPreset>()
        .map_err(|error| CliError::new(error.message))
}

fn required_value<F>(
    explicit: Option<String>,
    env_name: &str,
    arg_name: &str,
    env: &F,
) -> Result<String, CliError>
where
    F: Fn(&str) -> Result<String, std::env::VarError>,
{
    optional_value(explicit, env_name, env)?
        .ok_or_else(|| CliError::new(format!("missing required {arg_name} or {env_name}")))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliError {
    message: String,
}

impl CliError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}\n\n{HELP}", self.message)
    }
}

impl std::error::Error for CliError {}
