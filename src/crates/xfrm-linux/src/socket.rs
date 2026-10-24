//! The single socket-option FFI boundary. Linux UDP_ENCAP_ESPINUDP = 2.
use std::{io, net::UdpSocket, os::fd::AsRawFd};
#[allow(unsafe_code)]
pub fn enable_esp_in_udp(socket: &UdpSocket) -> io::Result<()> {
    let value: libc::c_int = 2;
    // SAFETY: socket owns a live descriptor; pointer and length refer to an
    // initialized c_int for the duration of this synchronous setsockopt call.
    let status = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_UDP,
            libc::UDP_ENCAP,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
