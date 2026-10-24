//! Execute only under `unshare --user --map-root-user --net` on a Linux test host.
use ikev2_core::child::{ChildBackend, ChildSpec};
use ikev2_crypto::SecretBytes;
use std::process::Command;
fn count(what: &str) -> String {
    let output = Command::new("ip")
        .args(["xfrm", what, "count"])
        .output()
        .unwrap();
    assert!(output.status.success(), "ip count failed");
    String::from_utf8(output.stdout).unwrap()
}
fn spec(spi: u32) -> ChildSpec {
    ChildSpec {
        local: "127.0.0.1:4500".parse().unwrap(),
        peer: "127.0.0.2:4500".parse().unwrap(),
        address: "10.77.0.10".parse().unwrap(),
        inbound_spi: spi,
        outbound_spi: spi + 1,
        inbound_key: SecretBytes::new(vec![7; 36]),
        outbound_key: SecretBytes::new(vec![8; 36]),
        lifetime_secs: 60,
        udp_encap: true,
    }
}
#[test]
#[ignore = "requires a fresh isolated Linux network namespace and CAP_NET_ADMIN there"]
fn kernel_install_collision_rollback_and_owned_delete() {
    assert_eq!(std::env::var("POC_ISOLATED_XFRM_TEST").as_deref(), Ok("1"));
    let original = std::env::var("POC_PARENT_NETNS").expect("parent namespace required");
    assert!(original.starts_with("net:["));
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::path::PathBuf::from(original),
        "refusing parent network namespace"
    );
    let before_sa = count("state");
    let before_policy = count("policy");
    let mut backend = xfrm_linux::LinuxXfrm::new(65536, 10000).unwrap();
    let first = backend
        .install(&spec(0x1000))
        .expect("kernel accepts RFC4106/NAT-T SA and policies");
    assert_ne!(count("state"), before_sa);
    assert_ne!(count("policy"), before_policy);
    let established_sa = count("state");
    let established_policy = count("policy");
    // New SAs install, then exact selectors conflict. Rollback must retain first session.
    assert!(backend.install(&spec(0x2000)).is_err());
    assert_eq!(count("state"), established_sa);
    assert_eq!(count("policy"), established_policy);
    drop(first);
    assert_eq!(count("state"), before_sa);
    assert_eq!(count("policy"), before_policy);
    let next = backend.install(&spec(0x3000)).unwrap();
    let cleanup =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/poc/cleanup_xfrm.py");
    let cleanup_ok = Command::new("python3")
        .arg(cleanup)
        .args(["--reqid-start", "65536", "--apply"])
        .status()
        .unwrap()
        .success();
    if !cleanup_ok {
        // Policy metadata has no ESP key material.
        let _ = Command::new("ip")
            .args(["-s", "-d", "xfrm", "policy"])
            .status();
    }
    assert!(cleanup_ok, "owned crash reconciliation failed");
    assert_eq!(count("state"), before_sa);
    assert_eq!(count("policy"), before_policy);
    // Normal Drop remains idempotent after operator crash reconciliation.
    drop(next);
    assert_eq!(count("state"), before_sa);
    assert_eq!(count("policy"), before_policy);
}
