use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    time::Duration,
};
struct Stop(Child);
impl Drop for Stop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn default_is_offline_and_serve_requires_config() {
    let out = Command::new(env!("CARGO_BIN_EXE_ikev2d")).output().unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("config_validated"));
    assert!(!stderr.contains("initial_exchange_listener"));
    let out = Command::new(env!("CARGO_BIN_EXE_ikev2d"))
        .arg("--serve")
        .output()
        .unwrap();
    assert!(!out.status.success());
}
#[test]
fn opt_in_cli_serves_initial_exchange_on_unprivileged_loopback() {
    let config = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        config.path(),
        "[udp]\nike='127.0.0.1:0'\nnatt='127.0.0.1:0'\n",
    )
    .unwrap();
    let mut child = Stop(
        Command::new(env!("CARGO_BIN_EXE_ikev2d"))
            .arg("--serve")
            .arg(config.path())
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stderr = child.0.stderr.take().unwrap();
    let (send, recv) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stderr).read_line(&mut line);
        let _ = send.send((result, line));
    });
    let (result, line) = recv
        .recv_timeout(Duration::from_secs(3))
        .expect("listener startup timed out");
    result.unwrap();
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    let fields = &value["fields"];
    assert_eq!(fields["event"], "initial_exchange_listener");
    let address: std::net::SocketAddrV4 = fields["ike"].as_str().unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let text = include_str!("../../../crates/ikev2-core/tests/fixtures/request.hex");
    let hex: String = text.split_whitespace().collect();
    let request: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    client.send_to(&request, address).unwrap();
    let mut response = [0; 2048];
    let (n, from) = client.recv_from(&mut response).unwrap();
    assert_eq!(from, std::net::SocketAddr::V4(address));
    assert!(n >= 28);
    assert_eq!(response[..8], request[..8]);
    assert_ne!(response[8..16], [0; 8]);
    assert_eq!(response[19], 32);
}

#[test]
fn structured_offer_selection_and_nat_logs_exclude_payload_bytes() {
    let config = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        config.path(),
        "[udp]\nike='127.0.0.1:0'\nnatt='127.0.0.1:0'\n",
    )
    .unwrap();
    let mut child = Stop(
        Command::new(env!("CARGO_BIN_EXE_ikev2d"))
            .arg("--serve")
            .arg(config.path())
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stderr = child.0.stderr.take().unwrap();
    let (send, recv) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            if send.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let line = recv.recv_timeout(Duration::from_secs(3)).unwrap();
    let startup: serde_json::Value = serde_json::from_str(&line).unwrap();
    let address: std::net::SocketAddrV4 =
        startup["fields"]["ike"].as_str().unwrap().parse().unwrap();
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let text = include_str!("../../../crates/ikev2-core/tests/fixtures/request.hex");
    let hex: String = text.split_whitespace().collect();
    let original: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let mut logs = line;
    for accepted in [false, true] {
        if accepted {
            std::thread::sleep(Duration::from_millis(1100));
        }
        let mut m = ikev2_wire::decode(&original, ikev2_wire::Limits::default()).unwrap();
        m.header.initiator_spi = if accepted { 2 } else { 1 };
        m.payloads.push(ikev2_wire::Payload {
            offset: 0,
            critical: false,
            body: ikev2_wire::Body::VendorId(b"DO-NOT-LOG-PAYLOAD"),
        });
        if !accepted && let ikev2_wire::Body::Sa(p) = &mut m.payloads[0].body {
            p[0].transforms[0].id = 65000;
            p[0].transforms[0]
                .attributes
                .push(ikev2_wire::Attribute::Tlv {
                    kind: 123,
                    value: b"DO-NOT-LOG-ATTRIBUTE",
                });
        }
        let request = ikev2_wire::encode(&m, ikev2_wire::Limits::default()).unwrap();
        client.send_to(&request, address).unwrap();
        let mut response = [0; 2048];
        client.recv_from(&mut response).unwrap();
        let mut count = 0;
        while count < 5 {
            let line = recv.recv_timeout(Duration::from_secs(3)).unwrap();
            logs.push_str(&line);
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            let f = &v["fields"];
            match f["event"].as_str().unwrap() {
                "ike_sa_init_diagnostic" => {
                    assert_eq!(f["selected"], accepted);
                    assert_eq!(f["offers_truncated"], false);
                    assert_eq!(f["nat_evaluated"], accepted);
                    if accepted {
                        assert_eq!(f["encryption"], 20);
                        assert_eq!(f["key_bits"], 256);
                        assert_eq!(f["prf"], 5);
                        assert_eq!(f["dh"], 19);
                        assert_eq!(f["source_nat_changed"], true);
                        assert_eq!(f["destination_nat_changed"], true);
                    }
                    count += 1;
                }
                "ike_proposal_offer" => {
                    assert_eq!(f["protocol"], 1);
                    count += 1;
                }
                "ike_proposal_transform" => {
                    assert!(f["kind"].is_number());
                    assert!(f["algorithm"].is_number());
                    if f["kind"] == 1 && !accepted {
                        assert_eq!(f["algorithm"], 65000);
                        assert_eq!(f["attributes_omitted"], true);
                    }
                    count += 1;
                }
                "initial_exchange_metrics" => {}
                other => panic!("unexpected event {other}"),
            }
            for forbidden in [
                "packet",
                "keys",
                "nonce",
                "cookie",
                "credentials",
                "raw",
                "public_value",
            ] {
                assert!(f.get(forbidden).is_none());
            }
        }
    }
    assert!(!logs.contains("DO-NOT-LOG"));
    assert!(!logs.contains(&hex));
}

#[test]
fn enabled_authentication_fails_closed_without_service_credentials() {
    let config = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        config.path(),
        "[udp]\nike='127.0.0.1:0'\nnatt='127.0.0.1:0'\n[authentication]\nenabled=true\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ikev2d"))
        .arg("--serve")
        .arg(config.path())
        .env_remove("CREDENTIALS_DIRECTORY")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let log = String::from_utf8(output.stderr).unwrap();
    assert!(!log.contains("initial_exchange_listener"));
    assert!(!log.contains("PRIVATE KEY"));
}

#[test]
fn sigterm_exits_successfully_instead_of_terminating_without_cleanup() {
    let config = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        config.path(),
        "[udp]\nike='127.0.0.1:0'\nnatt='127.0.0.1:0'\n",
    )
    .unwrap();
    let mut child = Stop(
        Command::new(env!("CARGO_BIN_EXE_ikev2d"))
            .arg("--serve")
            .arg(config.path())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut reader = BufReader::new(child.0.stderr.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("initial_exchange_listener"));
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "SIGTERM cleanup timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
