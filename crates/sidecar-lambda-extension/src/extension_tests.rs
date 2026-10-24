use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    config::LambdaExtensionConfig,
    extension::{ExtensionError, NextEvent, next_event, register, run},
};

#[tokio::test]
async fn lifecycle_given_runtime_api_then_registers_and_handles_invoke_and_shutdown() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let register_request = serve_once(
            &listener,
            "HTTP/1.1 200 OK\r\nLambda-Extension-Identifier: ext-123\r\nContent-Length: \
             2\r\n\r\n{}",
        )
        .await;
        let invoke_request = serve_once(
            &listener,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
             22\r\n\r\n{\"eventType\":\"INVOKE\"}",
        )
        .await;
        let shutdown_request = serve_once(
            &listener,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
             24\r\n\r\n{\"eventType\":\"SHUTDOWN\"}",
        )
        .await;
        (register_request, invoke_request, shutdown_request)
    });
    let client = reqwest::Client::new();

    let extension_id = register(&client, &address.to_string()).await.unwrap();
    let invoke = next_event(&client, &address.to_string(), &extension_id)
        .await
        .unwrap();
    let shutdown = next_event(&client, &address.to_string(), &extension_id)
        .await
        .unwrap();
    let (register_request, invoke_request, shutdown_request) = server.await.unwrap();

    assert_eq!(extension_id, "ext-123");
    assert!(matches!(invoke, NextEvent::Invoke));
    assert!(matches!(shutdown, NextEvent::Shutdown));
    assert!(register_request.starts_with("POST /2020-01-01/extension/register"));
    assert!(
        register_request
            .to_ascii_lowercase()
            .contains("lambda-extension-name: aux-sidecar")
    );
    assert!(
        invoke_request
            .to_ascii_lowercase()
            .contains("lambda-extension-identifier: ext-123")
    );
    assert!(
        shutdown_request
            .to_ascii_lowercase()
            .contains("lambda-extension-identifier: ext-123")
    );
}

#[tokio::test]
async fn lifecycle_given_oversized_event_then_rejects_it() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let body = format!(
        "{{\"eventType\":\"INVOKE\",\"padding\":\"{}\"}}",
        "x".repeat(70 * 1024)
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let server = tokio::spawn(async move {
        serve_once(&listener, &response).await;
    });

    let result = next_event(&reqwest::Client::new(), &address.to_string(), "ext-123").await;
    server.await.unwrap();

    assert!(matches!(result, Err(ExtensionError::EventInvalid)));
}

#[tokio::test]
async fn lifecycle_given_stalled_registration_then_fails_within_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        drop(socket);
    });

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        register(&reqwest::Client::new(), &address.to_string()),
    )
    .await
    .expect("registration should have a finite deadline");
    server.abort();

    assert!(matches!(result, Err(ExtensionError::RuntimeUnavailable)));
}

#[tokio::test]
async fn lifecycle_given_oversized_extension_identifier_then_rejects_it() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let identifier = "x".repeat(300);
    let response = format!(
        "HTTP/1.1 200 OK\r\nLambda-Extension-Identifier: {identifier}\r\nContent-Length: \
         2\r\n\r\n{{}}"
    );
    let server = tokio::spawn(async move {
        serve_once(&listener, &response).await;
    });

    let result = register(&reqwest::Client::new(), &address.to_string()).await;
    server.await.unwrap();

    assert!(matches!(result, Err(ExtensionError::IdentifierInvalid)));
}

#[tokio::test]
async fn lifecycle_given_sidecar_task_failure_then_returns_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        serve_once(
            &listener,
            "HTTP/1.1 200 OK\r\nLambda-Extension-Identifier: ext-123\r\nContent-Length: \
             2\r\n\r\n{}",
        )
        .await;
        let _ = listener.accept().await;
    });
    let values = std::collections::HashMap::from([
        ("AWS_LAMBDA_RUNTIME_API", address.to_string()),
        ("AUX_BASE_URL", "https://tenant.example.test".to_string()),
        ("AUX_API_KEY", "fixture-secret".to_string()),
        ("AUX_NO_AUDIENCE_CHECK", "true".to_string()),
        ("AUX_BIND_ADDR", "127.0.0.1:0".to_string()),
    ]);
    let mut config = LambdaExtensionConfig::from_source(|name| values.get(name).cloned()).unwrap();
    config.sidecar.proxy_policy_path = Some("/definitely/missing/proxy-policy.json".into());

    let result = tokio::time::timeout(std::time::Duration::from_secs(2), run(config))
        .await
        .expect("sidecar task failure should be observed");
    server.abort();

    assert!(result.is_err());
}

async fn serve_once(listener: &tokio::net::TcpListener, response: &str) -> String {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut request = vec![0; 4096];
    let size = socket.read(&mut request).await.unwrap();
    socket.write_all(response.as_bytes()).await.unwrap();
    String::from_utf8(request[..size].to_vec()).unwrap()
}
