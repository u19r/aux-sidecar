use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use crate::config::LambdaExtensionConfig;

const EXTENSION_NAME: &str = "aux-sidecar";
const EXTENSION_ID_HEADER: &str = "lambda-extension-identifier";
const REGISTER_PATH: &str = "/2020-01-01/extension/register";
const NEXT_EVENT_PATH: &str = "/2020-01-01/extension/event/next";
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(2);
const EVENT_BODY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_EVENT_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_EXTENSION_ID_BYTES: usize = 256;

#[derive(Debug, Serialize)]
struct RegisterRequest {
    events: [&'static str; 2],
}

#[derive(Debug, Deserialize)]
#[serde(tag = "eventType")]
pub(crate) enum NextEvent {
    #[serde(rename = "INVOKE")]
    Invoke,
    #[serde(rename = "SHUTDOWN")]
    Shutdown,
}

pub(crate) async fn run(config: LambdaExtensionConfig) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(&config.sidecar.bind_addr).await?;
    let client = Client::builder()
        .connect_timeout(REGISTRATION_TIMEOUT)
        .build()?;
    let extension_id = register(&client, &config.runtime_api).await?;
    let server_config = config.sidecar.clone();
    let mut server = tokio::spawn(async move {
        sidecar::server::serve_listener(server_config, listener)
            .await
            .map_err(|error| error.to_string())
    });

    let lifecycle = async {
        loop {
            if matches!(
                next_event(&client, &config.runtime_api, &extension_id).await?,
                NextEvent::Shutdown
            ) {
                return Ok::<(), ExtensionError>(());
            }
        }
    };
    let (result, server_completed) = tokio::select! {
        lifecycle_result = lifecycle => (
            lifecycle_result.map_err(|error| Box::new(error) as Box<dyn std::error::Error>),
            false,
        ),
        server_result = &mut server => (
            match server_result {
                Ok(Ok(())) => Err("sidecar server stopped unexpectedly".into()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(format!("sidecar server task failed: {error}").into()),
            },
            true,
        ),
    };
    if !server_completed {
        server.abort();
        let _ = server.await;
    }
    result
}

pub(crate) async fn register(client: &Client, runtime_api: &str) -> Result<String, ExtensionError> {
    let url = crate::config::runtime_api_url(runtime_api, REGISTER_PATH)
        .map_err(|_| ExtensionError::RuntimeUnavailable)?;
    let response = tokio::time::timeout(
        REGISTRATION_TIMEOUT,
        client
            .post(url)
            .header("lambda-extension-name", EXTENSION_NAME)
            .json(&RegisterRequest {
                events: ["INVOKE", "SHUTDOWN"],
            })
            .send(),
    )
    .await
    .map_err(|_| ExtensionError::RuntimeUnavailable)?
    .map_err(|_| ExtensionError::RuntimeUnavailable)?;
    if response.status() != StatusCode::OK {
        return Err(ExtensionError::RegistrationRejected);
    }
    let value = response
        .headers()
        .get(EXTENSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(ExtensionError::IdentifierMissing)?;
    if value.is_empty()
        || value.len() > MAX_EXTENSION_ID_BYTES
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(ExtensionError::IdentifierInvalid);
    }
    Ok(value.to_string())
}

pub(crate) async fn next_event(
    client: &Client,
    runtime_api: &str,
    extension_id: &str,
) -> Result<NextEvent, ExtensionError> {
    let url = crate::config::runtime_api_url(runtime_api, NEXT_EVENT_PATH)
        .map_err(|_| ExtensionError::RuntimeUnavailable)?;
    let response = client
        .get(url)
        .header(EXTENSION_ID_HEADER, extension_id)
        .send()
        .await
        .map_err(|_| ExtensionError::RuntimeUnavailable)?
        .error_for_status()
        .map_err(|_| ExtensionError::EventRejected)?;
    let body = tokio::time::timeout(EVENT_BODY_TIMEOUT, read_bounded_body(response))
        .await
        .map_err(|_| ExtensionError::EventInvalid)??;
    serde_json::from_slice(&body).map_err(|_| ExtensionError::EventInvalid)
}

async fn read_bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>, ExtensionError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_EVENT_RESPONSE_BYTES as u64)
    {
        return Err(ExtensionError::EventInvalid);
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(MAX_EVENT_RESPONSE_BYTES as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ExtensionError::EventInvalid)?
    {
        if body.len().saturating_add(chunk.len()) > MAX_EVENT_RESPONSE_BYTES {
            return Err(ExtensionError::EventInvalid);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Debug)]
pub(crate) enum ExtensionError {
    RuntimeUnavailable,
    RegistrationRejected,
    IdentifierMissing,
    IdentifierInvalid,
    EventRejected,
    EventInvalid,
}

impl std::fmt::Display for ExtensionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Lambda extension lifecycle error: {self:?}")
    }
}

impl std::error::Error for ExtensionError {}
