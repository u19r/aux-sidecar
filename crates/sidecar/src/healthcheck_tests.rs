use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

#[test]
fn healthcheck_given_live_200_then_succeeds() {
    let address = fixture("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

    crate::healthcheck::run("live", &address).unwrap();
}

#[test]
fn healthcheck_given_ready_503_then_fails_probe() {
    let address = fixture("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");

    assert_eq!(
        crate::healthcheck::run("ready", &address).unwrap_err(),
        "sidecar health endpoint is not ready"
    );
}

fn fixture(response: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 256];
        let _ = stream.read(&mut request).unwrap();
        stream.write_all(response.as_bytes()).unwrap();
    });
    address
}
