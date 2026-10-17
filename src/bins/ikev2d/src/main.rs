//! Offline foundation entry point. No network listeners or protocol actions.
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    vpn_observability::init()?;
    let mut args = std::env::args_os().skip(1);
    let config = if let Some(path) = args.next() {
        if args.next().is_some() {
            return Err("usage: ikev2d [config.toml]".into());
        }
        let input = std::fs::read_to_string(path)?;
        vpn_config::Config::parse(&input).map_err(|e| e.to_string())?
    } else {
        vpn_config::Config::default()
    };
    let limits = config.limits()?;
    tracing::info!(
        component = "ikev2d",
        event = "offline_config_validated",
        message_bytes = limits.message_bytes,
        payloads = limits.payloads,
        "Milestone 1 offline foundation; exiting"
    );
    Ok(())
}
