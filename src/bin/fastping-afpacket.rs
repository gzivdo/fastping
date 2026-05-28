// fastping — AF_PACKET + PACKET_RX_RING backend (Linux, high throughput).
//
// Sends fully-formed Ethernet+IP+ICMP frames straight out an AF_PACKET socket,
// bypassing the kernel's per-packet routing/neighbour lookups, and receives
// replies through a mmap'd PACKET_RX_RING so high reply rates are not dropped in
// a socket buffer (the usual cause of false "down" + wasted retries).
//
// Scope: frames are addressed to the default gateway's MAC, i.e. this backend is
// for routed / off-subnet sweeps. For same-subnet targets (which need per-host
// ARP) or loopback, use the portable `fastping` socket backend.
//
// Requires CAP_NET_RAW and a populated ARP entry for the gateway.

use std::ffi::c_void;
use std::io::{self, Read};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::RawFd;
use std::sync::atomic::{fence, AtomicU16, AtomicUsize, Ordering};

use fastping::{checksum, cli, Backend, Config};

const TP_STATUS_USER: libc::c_ulong = 1;
const TP_STATUS_KERNEL: libc::c_ulong = 0;
const FRAME_SIZE: usize = 2048;
const FRAMES_PER_BLOCK: usize = 64; // FRAME_SIZE * 64 = 128 KiB block
const BLOCK_NR: usize = 64; // 64 blocks => 4096 frames, 8 MiB ring

struct AfPacket {
    fd: RawFd,
    ring: *mut u8,
    ring_size: usize,
    frame_nr: usize,
    cursor: AtomicUsize,
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: Ipv4Addr,
    ifindex: i32,
    ip_id: AtomicU16,
}

// Safety: send_to (TX thread) only issues send() syscalls on `fd` and reads
// immutable fields; recv (single RX thread) is the sole accessor of the ring and
// the cursor. The two never touch the same mutable state.
unsafe impl Sync for AfPacket {}
unsafe impl Send for AfPacket {}

impl Backend for AfPacket {
    fn send_to(&self, icmp: &[u8], dst: IpAddr) -> io::Result<()> {
        // IPv4-only: ICMPv6 needs a pseudo-header checksum we'd compute by hand.
        let dst = match dst {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => {
                return Err(io::Error::other("afpacket backend is IPv4-only (use fastping for IPv6)"))
            }
        };
        let total_ip = 20 + icmp.len();
        let mut frame = Vec::with_capacity(14 + total_ip);
        // Ethernet
        frame.extend_from_slice(&self.dst_mac);
        frame.extend_from_slice(&self.src_mac);
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4 header
        let id = self.ip_id.fetch_add(1, Ordering::Relaxed);
        let ip_start = frame.len();
        frame.push(0x45); // version 4, IHL 5
        frame.push(0x00); // DSCP/ECN
        frame.extend_from_slice(&(total_ip as u16).to_be_bytes());
        frame.extend_from_slice(&id.to_be_bytes());
        frame.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
        frame.push(64); // TTL
        frame.push(1); // proto ICMP
        frame.extend_from_slice(&[0, 0]); // checksum placeholder
        frame.extend_from_slice(&self.src_ip.octets());
        frame.extend_from_slice(&dst.octets());
        let ip_cks = checksum(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_cks.to_be_bytes());
        // ICMP (already checksummed by the shared builder)
        frame.extend_from_slice(icmp);

        let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sa.sll_family = libc::AF_PACKET as u16;
        sa.sll_protocol = (libc::ETH_P_IP as u16).to_be();
        sa.sll_ifindex = self.ifindex;
        sa.sll_halen = 6;
        sa.sll_addr[..6].copy_from_slice(&self.dst_mac);
        let rc = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const c_void,
                frame.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> Option<(usize, IpAddr)> {
        loop {
            let i = self.cursor.load(Ordering::Relaxed) % self.frame_nr;
            let frame = unsafe { self.ring.add(i * FRAME_SIZE) };
            let hdr = frame as *mut libc::tpacket_hdr;
            let status = unsafe { std::ptr::read_volatile(&(*hdr).tp_status) };
            if status & TP_STATUS_USER == 0 {
                // nothing ready in this slot — wait briefly, then re-check
                if !self.poll(200) {
                    return None;
                }
                continue;
            }
            fence(Ordering::Acquire);
            let tp_mac = unsafe { (*hdr).tp_mac } as usize;
            let tp_len = unsafe { (*hdr).tp_len } as usize;
            let parsed = unsafe { parse_frame(frame, tp_mac, tp_len, buf) };
            // release the slot back to the kernel
            fence(Ordering::Release);
            unsafe { std::ptr::write_volatile(&raw mut (*hdr).tp_status, TP_STATUS_KERNEL) };
            self.cursor.fetch_add(1, Ordering::Relaxed);
            if parsed.is_some() {
                return parsed;
            }
            // not an ICMP reply — keep scanning
        }
    }
}

impl AfPacket {
    fn poll(&self, timeout_ms: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        rc > 0
    }
}

// Parse one captured frame; copy the ICMP message into `buf` if it is ICMP.
unsafe fn parse_frame(
    frame: *const u8,
    tp_mac: usize,
    tp_len: usize,
    buf: &mut [u8],
) -> Option<(usize, IpAddr)> {
    let data = std::slice::from_raw_parts(frame.add(tp_mac), tp_len);
    // Ethernet
    if data.len() < 14 || data[12] != 0x08 || data[13] != 0x00 {
        return None;
    }
    let ip = &data[14..];
    if ip.len() < 20 || (ip[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ip[9] != 1 {
        return None; // not ICMP
    }
    let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let icmp = ip.get(ihl..)?;
    let n = icmp.len().min(buf.len());
    buf[..n].copy_from_slice(&icmp[..n]);
    Some((n, src))
}

impl Drop for AfPacket {
    fn drop(&mut self) {
        unsafe {
            if !self.ring.is_null() {
                libc::munmap(self.ring as *mut c_void, self.ring_size);
            }
            libc::close(self.fd);
        }
    }
}

// ---- network discovery (no ioctl/ifreq juggling) ---------------------------

fn discover_route() -> io::Result<(String, Ipv4Addr)> {
    let mut s = String::new();
    std::fs::File::open("/proc/net/route")?.read_to_string(&mut s)?;
    for line in s.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || f[1] != "00000000" {
            continue; // not the default route
        }
        let gw = u32::from_str_radix(f[2], 16).map_err(|_| io::Error::other("bad gw"))?;
        return Ok((f[0].to_string(), Ipv4Addr::from(gw.to_le_bytes())));
    }
    Err(io::Error::other("no default route found"))
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = s.trim().split(':');
    for b in mac.iter_mut() {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    Some(mac)
}

fn iface_mac(iface: &str) -> io::Result<[u8; 6]> {
    let mut s = String::new();
    std::fs::File::open(format!("/sys/class/net/{iface}/address"))?.read_to_string(&mut s)?;
    parse_mac(&s).ok_or_else(|| io::Error::other("cannot parse interface MAC"))
}

fn arp_lookup(ip: Ipv4Addr, iface: &str) -> io::Result<[u8; 6]> {
    let mut s = String::new();
    std::fs::File::open("/proc/net/arp")?.read_to_string(&mut s)?;
    let want = ip.to_string();
    for line in s.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // IP  HWtype  Flags  HWaddr  Mask  Device
        if f.len() >= 6 && f[0] == want && f[5] == iface {
            if f[2] == "0x0" {
                continue; // incomplete entry
            }
            return parse_mac(f[3]).ok_or_else(|| io::Error::other("bad ARP MAC"));
        }
    }
    Err(io::Error::other(format!(
        "no ARP entry for gateway {ip} on {iface}; ping the gateway once to populate it"
    )))
}

// Source IP the kernel would use to reach `gw` (UDP connect needs no traffic).
fn local_src_ip(gw: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let u = std::net::UdpSocket::bind("0.0.0.0:0")?;
    u.connect((gw, 9))?;
    match u.local_addr()?.ip() {
        std::net::IpAddr::V4(v4) => Ok(v4),
        _ => Err(io::Error::other("expected IPv4 source")),
    }
}

fn make(cfg: &Config) -> io::Result<AfPacket> {
    let (route_if, gw) = discover_route()?;
    let iface = cfg.iface.clone().unwrap_or(route_if);
    let ifindex = {
        let cname = std::ffi::CString::new(iface.clone()).unwrap();
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if idx == 0 {
            return Err(io::Error::other(format!("unknown interface {iface}")));
        }
        idx as i32
    };
    let src_mac = iface_mac(&iface)?;
    let dst_mac = arp_lookup(gw, &iface)?;
    let src_ip = local_src_ip(gw)?;

    // AF_PACKET raw socket, IPv4 frames only
    let proto = (libc::ETH_P_IP as u16).to_be() as i32;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let guard = FdGuard(fd);

    // bind to the interface
    let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as u16;
    sa.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    sa.sll_ifindex = ifindex;
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    // set up the RX ring (TPACKET_V1)
    let req = libc::tpacket_req {
        tp_block_size: (FRAME_SIZE * FRAMES_PER_BLOCK) as u32,
        tp_block_nr: BLOCK_NR as u32,
        tp_frame_size: FRAME_SIZE as u32,
        tp_frame_nr: (FRAMES_PER_BLOCK * BLOCK_NR) as u32,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_RX_RING,
            &req as *const _ as *const c_void,
            size_of::<libc::tpacket_req>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let ring_size = (FRAME_SIZE * FRAMES_PER_BLOCK) * BLOCK_NR;
    let ring = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            ring_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if ring == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }

    guard.disarm();
    Ok(AfPacket {
        fd,
        ring: ring as *mut u8,
        ring_size,
        frame_nr: FRAMES_PER_BLOCK * BLOCK_NR,
        cursor: AtomicUsize::new(0),
        dst_mac,
        src_mac,
        src_ip,
        ifindex,
        ip_id: AtomicU16::new(1),
    })
}

// Close the fd if construction fails before the AfPacket takes ownership.
struct FdGuard(RawFd);
impl FdGuard {
    fn disarm(self) {
        std::mem::forget(self);
    }
}
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn main() {
    cli(make);
}
