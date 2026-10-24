use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    constants::{
        HOSTED_LOGIN_CLIENT_ID_MAX_BYTES, HOSTED_LOGIN_FIELD_MAX_BYTES,
        HOSTED_LOGIN_REDIRECT_URI_MAX_BYTES, HOSTED_LOGIN_SCOPE_MAX_ITEMS,
    },
    serde_bounds,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginHostedLoginRequest {
    #[serde(deserialize_with = "deserialize_client_id")]
    pub client_id: String,
    #[serde(deserialize_with = "deserialize_redirect_uri")]
    pub redirect_uri: String,
    #[serde(default, deserialize_with = "deserialize_scopes")]
    pub scopes: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_field"
    )]
    pub login_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginHostedLoginResult {
    pub login_url: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompleteHostedLoginRequest {
    #[serde(deserialize_with = "deserialize_state")]
    pub state: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_field"
    )]
    pub code: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_field"
    )]
    pub error: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_field"
    )]
    pub error_description: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostedLoginTokenSet {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

impl fmt::Debug for HostedLoginTokenSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostedLoginTokenSet")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

pub type TokenResponse = HostedLoginTokenSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompleteHostedLoginResult {
    pub tokens: HostedLoginTokenSet,
    pub access_token_claims: serde_json::Value,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshHostedLoginRequest {
    #[serde(deserialize_with = "deserialize_client_id")]
    pub client_id: String,
    #[serde(deserialize_with = "deserialize_refresh_token")]
    pub refresh_token: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_field"
    )]
    pub scope: Option<String>,
}

fn deserialize_client_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_non_empty_string_with_limit(
        deserializer,
        HOSTED_LOGIN_CLIENT_ID_MAX_BYTES,
    )
}

fn deserialize_redirect_uri<'de, D>(deserializer: D) -> Result<String, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_non_empty_string_with_limit(
        deserializer,
        HOSTED_LOGIN_REDIRECT_URI_MAX_BYTES,
    )
}

fn deserialize_state<'de, D>(deserializer: D) -> Result<String, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_non_empty_string_with_limit(
        deserializer,
        HOSTED_LOGIN_FIELD_MAX_BYTES,
    )
}

fn deserialize_refresh_token<'de, D>(deserializer: D) -> Result<String, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_non_empty_string_with_limit(
        deserializer,
        HOSTED_LOGIN_FIELD_MAX_BYTES,
    )
}

fn deserialize_optional_field<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_optional_bounded_string(deserializer)
}

fn deserialize_scopes<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where D: serde::Deserializer<'de> {
    serde_bounds::deserialize_bounded_string_vec(deserializer, HOSTED_LOGIN_SCOPE_MAX_ITEMS)
}

impl fmt::Debug for RefreshHostedLoginRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshHostedLoginRequest")
            .field("client_id", &self.client_id)
            .field("refresh_token", &"<redacted>")
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RefreshHostedLoginResult {
    pub tokens: HostedLoginTokenSet,
    pub access_token_claims: serde_json::Value,
}
