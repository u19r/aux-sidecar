use axum::http::{HeaderMap, Method, Uri};

use crate::oauth_presenter::{request_from_headers, request_from_original_headers};

#[test]
fn given_configured_public_base_when_absolute_or_forwarded_target_changes_then_authority_cannot_be_replaced()
 {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer test-token".parse().unwrap());
    headers.insert("x-forwarded-host", "attacker.example".parse().unwrap());
    headers.insert("x-forwarded-proto", "http".parse().unwrap());
    let base = Some("https://resource.example/prefix");
    let valid = request_from_headers(
        &headers,
        &Method::GET,
        &Uri::from_static("/a?ignored=1"),
        base,
    )
    .unwrap();
    assert_eq!(valid.target_uri, "https://resource.example/prefix/a");
    for target in [
        "https://attacker.example/prefix/a",
        "http://resource.example/prefix/a",
        "https://resource.example/other/a",
    ] {
        assert_eq!(
            request_from_headers(&headers, &Method::GET, &target.parse().unwrap(), base)
                .unwrap_err()
                .status_code,
            400
        );
    }
    assert!(
        request_from_headers(
            &headers,
            &Method::GET,
            &Uri::from_static("https://resource.example/a"),
            None
        )
        .is_err()
    );
    headers.insert("x-original-method", "GET".parse().unwrap());
    headers.insert("x-original-uri", "/a".parse().unwrap());
    assert_eq!(
        request_from_original_headers(&headers, base)
            .unwrap()
            .target_uri,
        valid.target_uri
    );
    headers.append("x-original-uri", "/b".parse().unwrap());
    assert!(request_from_original_headers(&headers, base).is_err());
}
