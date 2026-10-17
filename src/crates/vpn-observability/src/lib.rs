//! Safe metadata logging; callers must never emit packet bodies or secrets.
pub fn init() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
        .with_writer(std::io::stderr)
        .try_init()
}
