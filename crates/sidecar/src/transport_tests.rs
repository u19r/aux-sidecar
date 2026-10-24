use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use crate::transport::NativeSidecarTransport;

#[tokio::test]
async fn given_configured_tenant_when_connecting_to_loopback_then_authority_ignores_caller_hint() {
    for configured in [Some("tenant.example.test"), None] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
        let address = listener.local_addr().expect("loopback address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("native request");
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 1024];
                let count = stream.read(&mut chunk).await.expect("request bytes");
                assert_ne!(count, 0);
                request.extend_from_slice(&chunk[..count]);
                if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .expect("response");
            String::from_utf8(request).expect("HTTP headers")
        });
        let context = sidecar_contract::RequestContext {
            tenant_domain: Some("attacker.example.test".to_owned()),
            ..Default::default()
        };
        let client = http_request::reqwest::Client::new();
        crate::transport_helpers::with_context_headers(
            client.get(format!("http://{address}/runtime")),
            &context,
            configured,
        )
        .send()
        .await
        .expect("native transport")
        .error_for_status()
        .expect("response");
        let wire = server.await.expect("captured request").to_ascii_lowercase();
        let authority = configured
            .map(str::to_owned)
            .unwrap_or_else(|| address.to_string());
        assert!(
            wire.contains(&format!("\r\nhost: {authority}\r\n")),
            "configured authority must reach the wire: {wire}"
        );
        assert!(!wire.contains("attacker.example.test"));
    }
}

#[tokio::test]
async fn upstream_client_timeout_rejects_a_server_that_never_returns_headers() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let transport = NativeSidecarTransport::with_timeout(None, Duration::from_millis(50));
    let result = transport.http.get(format!("http://{address}")).send().await;

    assert!(result.is_err());
}

#[tokio::test]
async fn upstream_client_does_not_follow_redirects_with_credentials() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let mut chunk = [0; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&chunk[..count]);
        }
        stream
            .write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/exfil\r\nContent-Length: \
                     0\r\nConnection: close\r\n\r\n",
                    address.port() + 1
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });

    let transport = NativeSidecarTransport::with_timeout(None, Duration::from_secs(1));
    let response = transport
        .http
        .get(format!("http://{address}"))
        .header("x-api-key", "secret")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), http_request::StatusCode::FOUND);
}
