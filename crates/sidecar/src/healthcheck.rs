use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

pub(crate) fn run(kind: &str, address: &str) -> Result<(), String> {
    let path = match kind {
        "live" => "/sidecar/live",
        "ready" => "/sidecar/ready",
        _ => return Err("healthcheck requires live or ready".to_string()),
    };
    let mut stream = TcpStream::connect(address)
        .map_err(|_| "sidecar health endpoint is unavailable".to_string())?;
    let timeout = Some(Duration::from_secs(1));
    stream
        .set_read_timeout(timeout)
        .and_then(|()| stream.set_write_timeout(timeout))
        .map_err(|_| "sidecar healthcheck timeout could not be configured".to_string())?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .map_err(|_| "sidecar health request could not be written".to_string())?;
    let mut status = [0_u8; 12];
    stream
        .read_exact(&mut status)
        .map_err(|_| "sidecar health response could not be read".to_string())?;
    if &status == b"HTTP/1.1 200" {
        Ok(())
    } else {
        Err("sidecar health endpoint is not ready".to_string())
    }
}
