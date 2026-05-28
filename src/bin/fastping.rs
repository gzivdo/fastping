// fastping — raw-ICMP-socket backend (portable, dual-stack default).
//
// One raw socket per family (ICMP for v4, ICMPv6 for v6); the kernel builds the
// IP header and handles routing/ARP/ND, so this works on any link (including
// loopback and same-subnet) for both IPv4 and IPv6. The sender thread writes and
// the receiver thread reads the same fds concurrently (safe on POSIX). For very
// high packet rates over IPv4, use the `fastping-afpacket` backend.

use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::time::Duration;

use fastping::{cli, Backend, Config};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

struct SocketBackend {
    v4: Option<Socket>,
    v6: Option<Socket>,
}

impl Backend for SocketBackend {
    fn send_to(&self, icmp: &[u8], dst: IpAddr) -> io::Result<()> {
        match dst {
            IpAddr::V4(a) => self
                .v4
                .as_ref()
                .ok_or_else(|| io::Error::other("no IPv4 socket"))?
                .send_to(icmp, &SockAddr::from(SocketAddrV4::new(a, 0)))
                .map(|_| ()),
            IpAddr::V6(a) => self
                .v6
                .as_ref()
                .ok_or_else(|| io::Error::other("no IPv6 socket"))?
                .send_to(icmp, &SockAddr::from(SocketAddrV6::new(a, 0, 0, 0)))
                .map(|_| ()),
        }
    }

    fn recv(&self, buf: &mut [u8]) -> Option<(usize, IpAddr)> {
        // poll whichever family sockets exist, then read from a ready one
        let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(2);
        let mut is_v6: Vec<bool> = Vec::with_capacity(2);
        if let Some(s) = &self.v4 {
            pfds.push(libc::pollfd { fd: s.as_raw_fd(), events: libc::POLLIN, revents: 0 });
            is_v6.push(false);
        }
        if let Some(s) = &self.v6 {
            pfds.push(libc::pollfd { fd: s.as_raw_fd(), events: libc::POLLIN, revents: 0 });
            is_v6.push(true);
        }
        if pfds.is_empty() {
            return None;
        }
        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 200) };
        if rc <= 0 {
            return None;
        }
        for (k, pfd) in pfds.iter().enumerate() {
            if pfd.revents & libc::POLLIN == 0 {
                continue;
            }
            let v6 = is_v6[k];
            let sock = if v6 { self.v6.as_ref()? } else { self.v4.as_ref()? };
            let mut raw = [MaybeUninit::<u8>::uninit(); 2048];
            let (len, from) = match sock.recv_from(&mut raw) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let data = unsafe { std::slice::from_raw_parts(raw.as_ptr() as *const u8, len) };
            if v6 {
                // raw IPPROTO_ICMPV6 delivers the ICMPv6 message with no IP header
                let src = IpAddr::V6(*from.as_socket_ipv6()?.ip());
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                return Some((n, src));
            } else {
                // raw IPPROTO_ICMP delivers the IPv4 header too; skip it
                let src = IpAddr::V4(*from.as_socket_ipv4()?.ip());
                if data.len() < 20 {
                    continue;
                }
                let ihl = ((data[0] & 0x0f) as usize) * 4;
                let icmp = data.get(ihl..)?;
                let n = icmp.len().min(buf.len());
                buf[..n].copy_from_slice(&icmp[..n]);
                return Some((n, src));
            }
        }
        None
    }
}

fn open(domain: Domain, proto: Protocol) -> io::Result<Socket> {
    let s = Socket::new(domain, Type::RAW, Some(proto))?;
    s.set_read_timeout(Some(Duration::from_millis(200)))?;
    let _ = s.set_recv_buffer_size(8 << 20); // avoid dropping replies under load
    Ok(s)
}

fn make(_cfg: &Config) -> io::Result<SocketBackend> {
    let v4 = open(Domain::IPV4, Protocol::ICMPV4);
    let v6 = open(Domain::IPV6, Protocol::ICMPV6);
    match (v4, v6) {
        (Ok(a), Ok(b)) => Ok(SocketBackend { v4: Some(a), v6: Some(b) }),
        (Ok(a), Err(_)) => Ok(SocketBackend { v4: Some(a), v6: None }),
        (Err(_), Ok(b)) => Ok(SocketBackend { v4: None, v6: Some(b) }),
        // both failed — surface the v4 error (usually the CAP_NET_RAW one)
        (Err(e), Err(_)) => Err(e),
    }
}

fn main() {
    cli(make);
}
