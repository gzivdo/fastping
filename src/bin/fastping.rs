// fastping — raw-ICMP-socket backend (portable, dual-stack default).
//
// One raw socket per family (ICMP for v4, ICMPv6 for v6); the kernel builds the
// IP header and handles routing/ARP/ND, so this works on any link (incl. loopback
// and same-subnet) for both IPv4 and IPv6.
//
// Receive side: one blocking thread per socket, each draining its fd with
// recvmmsg(MSG_WAITFORONE) — a whole batch of replies per syscall, no poll. The
// socket's SO_RCVTIMEO wakes the thread periodically so it can observe shutdown.
// Only the families actually present in the target set are opened, so there is no
// idle IPv6 thread when there are no v6 targets.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fastping::{cli, Backend, Config, Families};
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

    fn receive(&self, running: &AtomicBool, on_reply: &(dyn Fn(&[u8], IpAddr) + Sync)) {
        // one blocking recvmmsg loop per present family
        std::thread::scope(|s| {
            if let Some(sock) = &self.v4 {
                s.spawn(|| recv_loop(sock, false, running, on_reply));
            }
            if let Some(sock) = &self.v6 {
                s.spawn(|| recv_loop(sock, true, running, on_reply));
            }
        });
    }
}

const VLEN: usize = 64; // messages received per recvmmsg syscall
const BUFSZ: usize = 2048;

// Blocking recvmmsg drain loop for one socket: a whole batch of replies per
// syscall, no poll. SO_RCVTIMEO wakes it periodically so it can observe `running`.
fn recv_loop(
    sock: &Socket,
    v6: bool,
    running: &AtomicBool,
    on_reply: &(dyn Fn(&[u8], IpAddr) + Sync),
) {
    let fd = sock.as_raw_fd();
    let mut bufs: Vec<[u8; BUFSZ]> = vec![[0u8; BUFSZ]; VLEN];
    let mut names: Vec<libc::sockaddr_storage> =
        (0..VLEN).map(|_| unsafe { std::mem::zeroed() }).collect();
    let mut iovs: Vec<libc::iovec> = (0..VLEN)
        .map(|i| libc::iovec {
            iov_base: bufs[i].as_mut_ptr() as *mut c_void,
            iov_len: BUFSZ,
        })
        .collect();
    let mut msgs: Vec<libc::mmsghdr> = (0..VLEN)
        .map(|i| {
            let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
            m.msg_hdr.msg_name = (&mut names[i] as *mut libc::sockaddr_storage) as *mut c_void;
            m.msg_hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as u32;
            m.msg_hdr.msg_iov = &mut iovs[i] as *mut libc::iovec;
            m.msg_hdr.msg_iovlen = 1;
            m
        })
        .collect();

    while running.load(Ordering::Relaxed) {
        // the kernel rewrites msg_namelen per message; reset before each call
        for m in msgs.iter_mut() {
            m.msg_hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as u32;
        }
        let n = unsafe {
            libc::recvmmsg(
                fd,
                msgs.as_mut_ptr(),
                VLEN as libc::c_uint,
                libc::MSG_WAITFORONE,
                std::ptr::null_mut(),
            )
        };
        if n <= 0 {
            continue; // EAGAIN (SO_RCVTIMEO) / EINTR — loop re-checks `running`
        }
        for i in 0..n as usize {
            let len = (msgs[i].msg_len as usize).min(BUFSZ);
            if len == 0 {
                continue;
            }
            let data = &bufs[i][..len];
            let src = match parse_src(&names[i]) {
                Some(s) => s,
                None => continue,
            };
            if v6 {
                // raw IPPROTO_ICMPV6 delivers the ICMPv6 message, no IP header
                on_reply(data, src);
            } else {
                // raw IPPROTO_ICMP delivers the IPv4 header too; skip it
                if data.len() < 20 {
                    continue;
                }
                let ihl = ((data[0] & 0x0f) as usize) * 4;
                if let Some(icmp) = data.get(ihl..) {
                    on_reply(icmp, src);
                }
            }
        }
    }
}

fn parse_src(ss: &libc::sockaddr_storage) -> Option<IpAddr> {
    match ss.ss_family as i32 {
        libc::AF_INET => {
            let sin = ss as *const _ as *const libc::sockaddr_in;
            // s_addr is in network byte order; its in-memory bytes are the octets
            let bytes = unsafe { (*sin).sin_addr.s_addr }.to_ne_bytes();
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        libc::AF_INET6 => {
            let s6 = ss as *const _ as *const libc::sockaddr_in6;
            Some(IpAddr::V6(Ipv6Addr::from(unsafe { (*s6).sin6_addr.s6_addr })))
        }
        _ => None,
    }
}

fn open(domain: Domain, proto: Protocol) -> io::Result<Socket> {
    let s = Socket::new(domain, Type::RAW, Some(proto))?;
    // SO_RCVTIMEO so the blocking recvmmsg wakes to observe shutdown
    s.set_read_timeout(Some(Duration::from_millis(200)))?;
    let _ = s.set_recv_buffer_size(8 << 20); // avoid dropping replies under load
    Ok(s)
}

fn make(_cfg: &Config, fam: Families) -> io::Result<SocketBackend> {
    // open only the families present in the target set
    let v4 = if fam.v4 {
        Some(open(Domain::IPV4, Protocol::ICMPV4)?)
    } else {
        None
    };
    let v6 = if fam.v6 {
        Some(open(Domain::IPV6, Protocol::ICMPV6)?)
    } else {
        None
    };
    Ok(SocketBackend { v4, v6 })
}

fn main() {
    cli(make);
}
