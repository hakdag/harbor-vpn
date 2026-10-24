//! IKE responder; authentication and IPv4 XFRM PoC are explicit opt-ins.
use std::{
    error::Error,
    time::{Duration, Instant},
};
fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    vpn_observability::init()?;
    let mut args = std::env::args_os().skip(1);
    let first = args.next();
    let serve = first.as_deref() == Some(std::ffi::OsStr::new("--serve"));
    if first.as_deref() == Some(std::ffi::OsStr::new("--help")) {
        println!(
            "usage: ikev2d [config.toml] | ikev2d --serve config.toml\nDefault: validate only. --serve runs lab sockets; IKE_AUTH requires explicit configuration and protected credentials; PoC networking requires explicit configuration."
        );
        return Ok(());
    }
    let path = if serve {
        Some(
            args.next()
                .ok_or("--serve requires an explicit config file")?,
        )
    } else {
        first
    };
    if args.next().is_some() {
        return Err("usage: ikev2d [config.toml] | ikev2d --serve config.toml".into());
    }
    let config = if let Some(path) = path {
        let input = std::fs::read_to_string(path)?;
        vpn_config::Config::parse(&input).map_err(|e| e.to_string())?
    } else {
        vpn_config::Config::default()
    };
    let wire = config.limits()?;
    if !serve {
        tracing::info!(
            component = "ikev2d",
            event = "config_validated",
            message_bytes = wire.message_bytes,
            "Configuration valid; listener not started"
        );
        return Ok(());
    }
    config.udp.validate()?;
    let provider = ikev2_crypto::OpenSslProvider::new()?;
    let mut core = ikev2_core::Responder::new(provider, config.handshake_policy()?, wire)?;
    if config.authentication.enabled {
        let credentials = vpn_auth::credentials::ServiceCredentials::load()?;
        let signer = ikev2_crypto::identity::ServerIdentity::load(
            &credentials.certificate_chain,
            credentials.signing_key.expose(),
        )?;
        let store =
            vpn_auth::AuthStore::from_encrypted(&credentials.verifiers, credentials.master_key)?;
        let mut context = ikev2_core::AuthContext::new(Box::new(signer), store)?;
        if config.poc.enabled {
            let backend =
                xfrm_linux::LinuxXfrm::new(config.poc.reqid_start, config.poc.policy_priority)?;
            context = context.with_child(ikev2_core::child::ChildService::new(
                config.poc.child(),
                Box::new(backend),
            )?);
        }
        core = core.with_auth(context)?;
    }
    let mut server = ikev2_transport::UdpResponder::bind(core, config.udp.ike, config.udp.natt)?;
    if config.poc.enabled {
        server.enable_kernel_esp()?;
    }
    let stopping = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(signal, stopping.clone())?;
    }
    let addresses = server.addresses()?;
    tracing::info!(component="ikev2d",event="initial_exchange_listener",ike=%addresses[0],natt=%addresses[1],
        authentication_enabled=config.authentication.enabled, openssl=ikev2_crypto::OpenSslProvider::version(),encryption=20,key_bits=256,prf=5,dh=19,
        "IKE listener; IPv4 PoC requires explicit configuration");
    let start = Instant::now();
    let mut last_report = Duration::ZERO;
    let mut diagnostic_id = 0u64;
    while !stopping.load(std::sync::atomic::Ordering::Relaxed) {
        let now = start.elapsed();
        server.tick(now)?;
        for sample in server.take_diagnostics() {
            diagnostic_id = diagnostic_id.saturating_add(1);
            log_diagnostic(diagnostic_id, sample);
        }
        if now.saturating_sub(last_report) >= Duration::from_secs(1) {
            let s = server.core().stats();
            let io = server.stats();
            tracing::info!(
                component = "ikev2d",
                event = "initial_exchange_metrics",
                requests = s.requests,
                initial_exchanges = s.accepted,
                pending = server.core().pending_count(),
                active_children = server.core().active_child_count(),
                retransmits = s.retransmits,
                cookie_challenges = s.cookies,
                rejected = s.rejected,
                no_proposal = s.no_proposal,
                invalid_ke = s.invalid_ke,
                invalid_syntax = s.invalid_syntax,
                unsupported_critical = s.unsupported_critical,
                invalid_version = s.invalid_version,
                dropped = s.dropped,
                busy = s.busy,
                expired = s.expired,
                crypto_errors = s.crypto_errors,
                rate_limited = s.rate_limited,
                auth_messages = s.auth_messages,
                authenticated_ike = s.authenticated,
                authentication_failed = s.authentication_failed,
                diagnostics_suppressed = io.diagnostics_suppressed,
                ignored_datagrams = io.ignored,
                processing_errors = io.processing_errors,
                send_errors = io.send_errors,
                max_processing_micros = io.max_processing_micros,
                "Bounded IKE session counters"
            );
            last_report = now;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(server); // Owned CHILD resources are removed before process exit.
    Ok(())
}

/// Scalar tracing fields remain structured JSON; never format an Outcome or packet.
fn log_diagnostic(sample_id: u64, sample: ikev2_transport::Diagnostic) {
    let accepted = sample.selected_proposal.is_some();
    let (event_name, state_from, state_to) = match sample.event {
        ikev2_core::Event::Auth { from, to } => ("ike_auth_diagnostic", from.as_str(), to.as_str()),
        _ => ("ike_sa_init_diagnostic", "", ""),
    };
    let nat_present = sample.nat.is_some();
    let nat = sample.nat.unwrap_or(ikev2_core::NatStatus {
        source_changed: false,
        destination_changed: false,
    });
    tracing::info!(component="ikev2d", event=event_name, sample_id, state_from,state_to,
        channel=?sample.channel, outcome=?sample.event,
        selected=accepted, selected_proposal=sample.selected_proposal.unwrap_or(0),
        encryption=if accepted {20u16} else {0}, key_bits=if accepted {256u16} else {0},
        prf=if accepted {5u16} else {0}, dh=if accepted {19u16} else {0},
        nat_evaluated=nat_present, nat_present, source_nat_changed=nat.source_changed,
        destination_nat_changed=nat.destination_changed, offers_truncated=sample.offers_truncated,
        "IKE exchange metadata; no tunnel");
    for offer in sample.offers {
        tracing::info!(
            component = "ikev2d",
            event = "ike_proposal_offer",
            sample_id,
            proposal = offer.number,
            protocol = offer.protocol,
            transforms_truncated = offer.transforms_truncated,
            "Offered proposal metadata"
        );
        for transform in offer.transforms {
            tracing::info!(
                component = "ikev2d",
                event = "ike_proposal_transform",
                sample_id,
                proposal = offer.number,
                kind = transform.kind,
                algorithm = transform.id,
                key_bits_present = transform.key_bits.is_some(),
                key_bits = transform.key_bits.unwrap_or(0),
                attributes_omitted = transform.attributes_omitted,
                "Offered transform metadata"
            );
        }
    }
}
