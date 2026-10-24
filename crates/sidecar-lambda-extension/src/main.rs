mod config;
mod extension;

#[cfg(test)]
mod extension_tests;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let config = config::LambdaExtensionConfig::from_env()?;
    extension::run(config).await
}
