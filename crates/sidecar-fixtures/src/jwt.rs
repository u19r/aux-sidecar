use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

const KEY_ID: &str = "sidecar-fixture-key";
const ISSUER: &str = "https://sidecar-fixture.example.test";
const SUBJECT: &str = "user_fixture";
const EXPIRY: i64 = 4_102_444_800;
const FIXTURE_PRIVATE_KEY_BODY: &str = "\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJETqse41HRBsc
7cfcq3ak4oZWFCoZlcic525A3FfO4qW9BMtRO/iXiyCCHn8JhiL9y8j5JdVP2Q9Z
IpfElcFd3/guS9w+5RqQGgCR+H56IVUyHZWtTJbKPcwWXQdNUX0rBFcsBzCRESJL
eelOEdHIjG7LRkx5l/FUvlqsyHDVJEQsHwegZ8b8C0fz0EgT2MMEdn10t6Ur1rXz
jMB/wvCg8vG8lvciXmedyo9xJ8oMOh0wUEgxziVDMMovmC+aJctcHUAYubwoGN8T
yzcvnGqL7JSh36Pwy28iPzXZ2RLhAyJFU39vLaHdljwthUaupldlNyCfa6Ofy4qN
ctlUPlN1AgMBAAECggEAdESTQjQ70O8QIp1ZSkCYXeZjuhj081CK7jhhp/4ChK7J
GlFQZMwiBze7d6K84TwAtfQGZhQ7km25E1kOm+3hIDCoKdVSKch/oL54f/BK6sKl
qlIzQEAenho4DuKCm3I4yAw9gEc0DV70DuMTR0LEpYyXcNJY3KNBOTjN5EYQAR9s
2MeurpgK2MdJlIuZaIbzSGd+diiz2E6vkmcufJLtmYUT/k/ddWvEtz+1DnO6bRHh
xuuDMeJA/lGB/EYloSLtdyCF6sII6C6slJJtgfb0bPy7l8VtL5iDyz46IKyzdyzW
tKAn394dm7MYR1RlUBEfqFUyNK7C+pVMVoTwCC2V4QKBgQD64syfiQ2oeUlLYDm4
CcKSP3RnES02bcTyEDFSuGyyS1jldI4A8GXHJ/lG5EYgiYa1RUivge4lJrlNfjyf
dV230xgKms7+JiXqag1FI+3mqjAgg4mYiNjaao8N8O3/PD59wMPeWYImsWXNyeHS
55rUKiHERtCcvdzKl4u35ZtTqQKBgQDNKnX2bVqOJ4WSqCgHRhOm386ugPHfy+8j
m6cicmUR46ND6ggBB03bCnEG9OtGisxTo/TuYVRu3WP4KjoJs2LD5fwdwJqpgtHl
yVsk45Y1Hfo+7M6lAuR8rzCi6kHHNb0HyBmZjysHWZsn79ZM+sQnLpgaYgQGRbKV
DZWlbw7g7QKBgQCl1u+98UGXAP1jFutwbPsx40IVszP4y5ypCe0gqgon3UiY/G+1
zTLp79GGe/SjI2VpQ7AlW7TI2A0bXXvDSDi3/5Dfya9ULnFXv9yfvH1QwWToySpW
Kvd1gYSoiX84/WCtjZOr0e0HmLIb0vw0hqZA4szJSqoxQgvF22EfIWaIaQKBgQCf
34+OmMYw8fEvSCPxDxVvOwW2i7pvV14hFEDYIeZKW2W1HWBhVMzBfFB5SE8yaCQy
pRfOzj9aKOCm2FjjiErVNpkQoi6jGtLvScnhZAt/lr2TXTrl8OwVkPrIaN0bG/AS
aUYxmBPCpXu3UjhfQiWqFq/mFyzlqlgvuCc9g95HPQKBgAscKP8mLxdKwOgX8yFW
GcZ0izY/30012ajdHY+/QK5lsMoxTnn0skdS+spLxaS5ZEO4qvPVb8RAoCkWMMal
2pOhmquJQVDPDLuZHdrIiKiDM20dy9sMfHygWcZjQ4WSxf/J7T9canLZIXFhHAZT
3wc9h4G8BBCtWN2TN/LsGZdB";

pub fn issuer() -> &'static str {
    ISSUER
}

pub fn audience() -> &'static str {
    "sidecar-fixture-client"
}

pub fn jwks() -> Value {
    json!({
        "keys": [{
            "kty": "RSA",
            "kid": KEY_ID,
            "use": "sig",
            "alg": "RS256",
            "n": "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ",
            "e": "AQAB"
        }]
    })
}

pub fn authn_token() -> String {
    token_with_kind(ISSUER, None, TokenFixtureKind::Authn, None)
}

pub fn authn_token_with_issuer(issuer: &str) -> String {
    token_with_kind(issuer, None, TokenFixtureKind::Authn, None)
}

pub fn oauth_token() -> String {
    token_with_kind(ISSUER, Some(audience()), TokenFixtureKind::Access, None)
}

pub fn oauth_token_without_audience() -> String {
    token_with_kind(ISSUER, None, TokenFixtureKind::Access, None)
}

pub fn oauth_token_with_issuer(issuer: &str) -> String {
    token_with_kind(issuer, Some(audience()), TokenFixtureKind::Access, None)
}

pub fn token(audience: Option<&str>) -> String {
    token_with_issuer(ISSUER, audience)
}

pub fn token_with_issuer(issuer: &str, audience: Option<&str>) -> String {
    let kind = if audience.is_some() {
        TokenFixtureKind::Access
    } else {
        TokenFixtureKind::Authn
    };
    token_with_kind(issuer, audience, kind, None)
}

fn token_with_kind(
    issuer: &str,
    audience: Option<&str>,
    kind: TokenFixtureKind,
    confirmation: Option<Value>,
) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KEY_ID.to_string());
    header.typ = Some(kind.header_type().to_string());
    let mut claims = json!({
        "iss": issuer,
        "sub": SUBJECT,
        "iat": 1_700_000_000_i64,
        "exp": EXPIRY,
        "token_type": kind.claim_value(),
    });
    if let Some(audience) = audience {
        claims["aud"] = json!(audience);
        claims["client_id"] = json!(audience);
        claims["scope"] = json!("openid profile");
        claims["tenant"] = json!("fixture-tenant");
        claims["principal_type"] = json!("user");
        claims["jti"] = json!("fixture-jti");
    }

    if let Some(confirmation) = confirmation {
        claims["cnf"] = confirmation;
    }
    let private_key = fixture_private_key_pem();
    let key = EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap_or_else(|err| {
        panic!("fixture RSA key load failed: {err}");
    });
    encode(&header, &claims, &key).unwrap_or_else(|err| {
        panic!("fixture JWT generation failed: {err}");
    })
}

#[derive(Debug, Clone, Copy)]
enum TokenFixtureKind {
    Authn,
    Access,
}

impl TokenFixtureKind {
    fn header_type(self) -> &'static str {
        match self {
            Self::Authn => "JWT",
            Self::Access => "at+jwt",
        }
    }

    fn claim_value(self) -> &'static str {
        match self {
            Self::Authn => "id",
            Self::Access => "access_token",
        }
    }
}

fn fixture_private_key_pem() -> String {
    format!(
        "{}\n{}\n{}",
        concat!("-----BEGIN ", "PRIVATE KEY-----"),
        FIXTURE_PRIVATE_KEY_BODY,
        concat!("-----END ", "PRIVATE KEY-----")
    )
}

pub fn oauth_token_with_confirmation(confirmation: Value) -> String {
    token_with_kind(
        ISSUER,
        Some(audience()),
        TokenFixtureKind::Access,
        Some(confirmation),
    )
}

pub fn oauth_token_with_confirmation_for_issuer(issuer: &str, confirmation: Value) -> String {
    token_with_kind(
        issuer,
        Some(audience()),
        TokenFixtureKind::Access,
        Some(confirmation),
    )
}
