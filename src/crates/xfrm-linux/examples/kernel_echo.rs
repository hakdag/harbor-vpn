//! Synthetic keys ONLY, for fresh isolated namespace integration. Never deploy.
use ikev2_core::child::{ChildBackend, ChildSpec};
use ikev2_crypto::SecretBytes;
use std::{
    io::{self, Write},
    net::UdpSocket,
    time::Duration,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("POC_ISOLATED_XFRM_TEST").as_deref() != Ok("1") {
        return Err("isolated test only".into());
    }
    let natt = UdpSocket::bind(if std::env::args().nth(1).as_deref() == Some("server") {
        "192.0.2.1:4500"
    } else {
        "192.0.2.2:4500"
    })?;
    xfrm_linux::socket::enable_esp_in_udp(&natt)?;
    let mut data = [0; 256];
    if std::env::args().nth(1).as_deref() == Some("server") {
        let spec = ChildSpec {
            local: "192.0.2.1:4500".parse()?,
            peer: "192.0.2.2:4500".parse()?,
            address: "10.77.0.10".parse()?,
            inbound_spi: 0x1000,
            outbound_spi: 0x1001,
            inbound_key: SecretBytes::new(vec![7; 36]),
            outbound_key: SecretBytes::new(vec![8; 36]),
            lifetime_secs: 60,
            udp_encap: true,
        };
        let mut backend = xfrm_linux::LinuxXfrm::new(65536, 10000)?;
        let _resource = backend.install(&spec)?;
        let socket = UdpSocket::bind("203.0.113.1:18473")?;
        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        println!("ready");
        io::stdout().flush()?;
        let (n, peer) = socket.recv_from(&mut data)?;
        if peer.ip() != spec.address {
            return Err("unexpected inner source".into());
        }
        socket.send_to(&data[..n], peer)?;
        // Allow the synchronous send to pass kernel processing before removal.
        std::thread::sleep(Duration::from_millis(100));
    } else {
        // A peer holding its legitimate ESP keys must not impersonate another lease.
        let forged = UdpSocket::bind("10.77.0.11:18475")?;
        forged.send_to(b"forged inner source must be dropped", "203.0.113.1:18473")?;
        let socket = UdpSocket::bind("10.77.0.10:18474")?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.send_to(b"isolated XFRM ESP-in-UDP round trip", "203.0.113.1:18473")?;
        let (n, peer) = socket.recv_from(&mut data)?;
        if peer.to_string() != "203.0.113.1:18473"
            || &data[..n] != b"isolated XFRM ESP-in-UDP round trip"
        {
            return Err("echo mismatch".into());
        }
        println!("IPv4 UDP round trip through kernel RFC4106 ESP-in-UDP passed");
    }
    Ok(())
}
