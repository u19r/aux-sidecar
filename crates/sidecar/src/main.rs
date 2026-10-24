#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sidecar::cli::run().await
}
