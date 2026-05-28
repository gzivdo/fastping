// fastping — raw-ICMP-socket backend (portable default).
//
// Two raw ICMP sockets: one for TX, one for RX. The kernel builds the IP header
// and handles routing/ARP, so this works on any link (including loopback) and on
// any setup, at the cost of a per-packet kernel round trip. For very high packet
// rates use the `fastping-afpacket` backend instead.

use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};

use fastping::{cli, Backend, Config};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

struct SocketBackend {
    tx: Socket,
    rx: Socket,
}

impl Backend for SocketBackend {
    fn send_to(&self, icmp: &[u8], dst: Ipv4Addr) -> io::Result<()> {
        self.tx
            .send_to(icmp, &SockAddr::from(SocketAddrV4::new(dst, 0)))
            .map(|_| ())
    }

    fn recv(&self, buf: &mut [u8]) -> Option<(usize, Ipv4Addr)> {
        let mut raw = [MaybeUninit::<u8>::uninit(); 2048];
        let (len, from) = match self.rx.recv_from(&mut raw) {
            Ok(v) => v,
            Err(_) => return None, // WouldBlock (read timeout) or transient error
        };
        let data = unsafe { std::slice::from_raw_parts(raw.as_ptr() as *const u8, len) };
        let src = *from.as_socket_ipv4()?.ip();
        // raw IPPROTO_ICMP delivers the IP header too; skip it
        if data.len() < 20 {
            return None;
        }
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        let icmp = data.get(ihl..)?;
        let n = icmp.len().min(buf.len());
        buf[..n].copy_from_slice(&icmp[..n]);
        Some((n, src))
    }
}

fn make(_cfg: &Config) -> io::Result<SocketBackend> {
    let tx = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    let rx = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    rx.set_read_timeout(Some(std::time::Duration::from_millis(200)))?;
    // grow the RX buffer so we do not drop replies under high pps
    let _ = rx.set_recv_buffer_size(8 << 20);
    Ok(SocketBackend { tx, rx })
}

fn main() {
    cli(make);
}
