use std::net::SocketAddr;

use crate::{config::SidecarConfig, router::build_router, state::build_state};

pub async fn serve(config: SidecarConfig) -> Result<(), Box<dyn std::error::Error>> {
    config.validate().map_err(std::io::Error::other)?;
    if let Some(path) = config.unix_socket_path.clone() {
        return serve_with_unix(config, path).await;
    }
    let addr: SocketAddr = config.bind_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    serve_listener(config, listener).await
}

#[cfg(unix)]
async fn serve_with_unix(
    config: SidecarConfig,
    path: std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if !metadata.file_type().is_socket() {
            return Err(format!("refusing to replace non-socket path {}", path.display()).into());
        }
        std::fs::remove_file(&path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let preset = config.preset;
    let router = build_router(build_state(config.clone())?);
    if matches!(preset, sidecar_core::DeploymentPreset::Proxy) {
        axum::serve(listener, router).await?;
        return Ok(());
    }
    let addr: SocketAddr = config.bind_addr.parse()?;
    let tcp_listener = tokio::net::TcpListener::bind(addr).await?;
    let unix_router = router.clone();
    tokio::try_join!(async { axum::serve(listener, unix_router).await }, async {
        axum::serve(tcp_listener, router).await
    },)?;
    Ok(())
}

#[cfg(not(unix))]
async fn serve_with_unix(
    _config: SidecarConfig,
    _path: std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("Unix sockets are not supported on this platform".into())
}

pub async fn serve_listener(
    config: SidecarConfig,
    listener: tokio::net::TcpListener,
) -> Result<(), Box<dyn std::error::Error>> {
    config.validate().map_err(std::io::Error::other)?;
    let bound_addr = listener.local_addr()?;
    crate::config::validate_bind_addr(&bound_addr.to_string(), config.unsafe_bind_non_loopback)
        .map_err(std::io::Error::other)?;
    axum::serve(listener, build_router(build_state(config)?)).await?;
    Ok(())
}
