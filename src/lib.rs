// fastping — stateless mass ICMP-echo sweeper (shared core).
//
// Design (mirrors zmap/masscan, with an adaptive retry queue on top):
//   * one path sends a whole batch, another records replies — no locking between;
//   * RX is fully stateless: the target index, a validation cookie and the send
//     timestamp are embedded in the ICMP payload and echoed back, so a reply alone
//     carries everything needed to score it and compute RTT;
//   * discovery modes re-send only the not-yet-answered targets, up to N retries.
//
// The transport differs per backend (see the `Backend` trait): the default
// `fastping` binary uses two raw ICMP sockets; `fastping-afpacket` uses AF_PACKET
// with a mmap'd PACKET_RX_RING. Everything else is shared here.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::{Duration, Instant};

pub const MAGIC: u32 = 0x5046_5031; // "FPP1"
pub const HDR: usize = 8; // ICMP(v6) echo header length
// ICMP echo types: v4 request/reply, then v6 request/reply.
pub const ICMP4_ECHO: u8 = 8;
pub const ICMP4_REPLY: u8 = 0;
pub const ICMP6_ECHO: u8 = 128;
pub const ICMP6_REPLY: u8 = 129;
// payload layout after the 8-byte ICMP header:
//   [0..4] magic, [4..8] index, [8..12] cookie, [12..20] send-ts nanos
pub const PAYLOAD_MIN: usize = 20;

// ---- transport abstraction -------------------------------------------------

/// A packet transport. Implementors handle only the wire; all ICMP building and
/// the stateless validation/scoring live in this module.
pub trait Backend {
    /// Send the ICMP(v6) message bytes (8-byte header + payload) to `dst`.
    fn send_to(&self, icmp: &[u8], dst: IpAddr) -> io::Result<()>;
    /// Block up to a short internal timeout for one echo reply. On success copy
    /// the ICMP(v6) message (starting at the ICMP header) into `buf` and return
    /// its length plus the source address. Return `None` on timeout so the caller
    /// can observe shutdown.
    fn recv(&self, buf: &mut [u8]) -> Option<(usize, IpAddr)>;
}

// ---- config ----------------------------------------------------------------

pub struct Config {
    pub timeout: Duration,
    pub retries: u32,
    pub rate: u64, // packets/sec across the whole batch, 0 = unbounded
    pub payload: usize,
    pub output: Output,
    pub count: u32, // fping -C count
    pub zbx_key: String,
    pub zbx_host_mode: HostMode,
    pub zbx_server: Option<String>,
    pub zbx_batch: usize, // values per Zabbix sender connection; 0 = all in one
    pub discover: bool,   // zabbix/json: use adaptive retry (alive-only) instead of -C probes
    pub iface: Option<String>, // AF_PACKET backend only
}

/// Probing strategy: adaptive (send once, retry only the silent ones — the
/// original idea, good for pure alive/down) vs. fixed `-C` probes to every host
/// (needed to measure loss%). plain is always adaptive; fping always fixed;
/// zabbix/json default to fixed but switch to adaptive with `--discover`.
pub fn is_adaptive(cfg: &Config) -> bool {
    match cfg.output {
        Output::Plain => true,
        Output::Fping => false,
        Output::Zabbix | Output::Json => cfg.discover,
    }
}

#[derive(PartialEq)]
pub enum Output {
    Plain,
    Fping,
    Zabbix,
    Json,
}

#[derive(PartialEq)]
pub enum HostMode {
    Ip,
    Resolved,
}

// ---- results ---------------------------------------------------------------

// Shared results table. rtt[round * n + idx] in microseconds, -1 means no reply.
pub struct Results {
    pub n: usize,
    pub rounds: usize,
    rtt: Vec<AtomicI64>,
}

impl Results {
    pub fn new(n: usize, rounds: usize) -> Self {
        let mut rtt = Vec::with_capacity(n * rounds);
        for _ in 0..n * rounds {
            rtt.push(AtomicI64::new(-1));
        }
        Results { n, rounds, rtt }
    }
    fn record(&self, round: usize, idx: usize, rtt_us: i64) {
        if round < self.rounds && idx < self.n {
            let cell = &self.rtt[round * self.n + idx];
            // keep the first reply for this (round, idx)
            let _ = cell.compare_exchange(-1, rtt_us, Ordering::Relaxed, Ordering::Relaxed);
        }
    }
    fn responded_any(&self, idx: usize) -> bool {
        (0..self.rounds).any(|r| self.rtt[r * self.n + idx].load(Ordering::Relaxed) >= 0)
    }
    fn round(&self, round: usize, idx: usize) -> i64 {
        self.rtt[round * self.n + idx].load(Ordering::Relaxed)
    }
    // (alive 0/1, loss 0..1, avg rtt seconds) over all rounds for one host
    fn stats(&self, idx: usize) -> (u8, f64, f64) {
        let mut got = 0u32;
        let mut sum = 0i64;
        for r in 0..self.rounds {
            let v = self.round(r, idx);
            if v >= 0 {
                got += 1;
                sum += v;
            }
        }
        let total = self.rounds as u32;
        let loss = (total - got) as f64 / total as f64;
        let avg = if got > 0 {
            (sum as f64 / got as f64) / 1_000_000.0
        } else {
            0.0
        };
        ((got > 0) as u8, loss, avg)
    }
    // Adaptive (alive-only) view: liveness + first RTT seconds. Loss is binary
    // here because adaptive mode does not send a fixed probe count per host.
    fn liveness(&self, idx: usize) -> (u8, f64, f64) {
        let first = (0..self.rounds).map(|r| self.round(r, idx)).find(|&v| v >= 0);
        match first {
            Some(us) => (1, 0.0, us as f64 / 1_000_000.0),
            None => (0, 1.0, 0.0),
        }
    }
    // (alive, loss, avg-rtt-seconds) honouring the probing strategy.
    fn score(&self, idx: usize, adaptive: bool) -> (u8, f64, f64) {
        if adaptive {
            self.liveness(idx)
        } else {
            self.stats(idx)
        }
    }
}

// ---- ICMP helpers ----------------------------------------------------------

pub fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

pub fn cookie_for(ip: IpAddr, secret: u32) -> u32 {
    let mut buf = Vec::with_capacity(20);
    match ip {
        IpAddr::V4(a) => buf.extend_from_slice(&a.octets()),
        IpAddr::V6(a) => buf.extend_from_slice(&a.octets()),
    }
    buf.extend_from_slice(&secret.to_le_bytes());
    fnv1a32(&buf)
}

/// Internet checksum (RFC 1071) over `data`.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build the ICMP(v6) echo-request message (header + payload). For IPv4 the ICMP
/// checksum is computed here; for ICMPv6 it depends on a pseudo-header, which the
/// kernel fills in for raw IPPROTO_ICMPV6 sockets, so the field is left zero.
pub fn build_icmp(
    v6: bool,
    run_id: u16,
    round: u16,
    idx: u32,
    cookie: u32,
    ts: u64,
    payload: usize,
) -> Vec<u8> {
    let body = payload.max(PAYLOAD_MIN);
    let mut pkt = vec![0u8; HDR + body];
    pkt[0] = if v6 { ICMP6_ECHO } else { ICMP4_ECHO };
    pkt[1] = 0; // code
                // [2..4] checksum, filled below (v4) or by the kernel (v6)
    pkt[4..6].copy_from_slice(&run_id.to_be_bytes());
    pkt[6..8].copy_from_slice(&round.to_be_bytes());
    pkt[HDR..HDR + 4].copy_from_slice(&MAGIC.to_be_bytes());
    pkt[HDR + 4..HDR + 8].copy_from_slice(&idx.to_be_bytes());
    pkt[HDR + 8..HDR + 12].copy_from_slice(&cookie.to_be_bytes());
    pkt[HDR + 12..HDR + 20].copy_from_slice(&ts.to_be_bytes());
    if !v6 {
        let cks = checksum(&pkt);
        pkt[2..4].copy_from_slice(&cks.to_be_bytes());
    }
    pkt
}

// Validate one received ICMP message against our run and record its RTT.
fn validate_and_record(
    icmp: &[u8],
    src: IpAddr,
    targets: &[IpAddr],
    run_id: u16,
    secret: u32,
    now_ns: u64,
    results: &Results,
) {
    if icmp.len() < HDR + PAYLOAD_MIN {
        return;
    }
    if icmp[0] != ICMP4_REPLY && icmp[0] != ICMP6_REPLY {
        return; // not an echo reply (v4 or v6)
    }
    if u16::from_be_bytes([icmp[4], icmp[5]]) != run_id {
        return; // not ours
    }
    let round = u16::from_be_bytes([icmp[6], icmp[7]]) as usize;
    let p = &icmp[HDR..];
    if u32::from_be_bytes([p[0], p[1], p[2], p[3]]) != MAGIC {
        return;
    }
    let idx = u32::from_be_bytes([p[4], p[5], p[6], p[7]]) as usize;
    let cookie = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
    let ts = u64::from_be_bytes([p[12], p[13], p[14], p[15], p[16], p[17], p[18], p[19]]);
    if idx >= targets.len() {
        return;
    }
    if src != targets[idx] || cookie != cookie_for(targets[idx], secret) {
        return; // stale / spoofed / mismatched
    }
    let rtt_us = (now_ns.saturating_sub(ts) / 1000) as i64;
    results.record(round, idx, rtt_us);
}

// ---- orchestration ---------------------------------------------------------

// Send one round to the given indices, paced to cfg.rate.
fn send_round<B: Backend>(
    backend: &B,
    targets: &[IpAddr],
    idxs: &[usize],
    round: u16,
    run_id: u16,
    secret: u32,
    start: Instant,
    cfg: &Config,
) {
    let gap = if cfg.rate > 0 {
        Some(Duration::from_nanos(1_000_000_000 / cfg.rate))
    } else {
        None
    };
    let mut next = Instant::now();
    for &i in idxs {
        let ip = targets[i];
        let ts = start.elapsed().as_nanos() as u64;
        let pkt = build_icmp(
            ip.is_ipv6(),
            run_id,
            round,
            i as u32,
            cookie_for(ip, secret),
            ts,
            cfg.payload,
        );
        let _ = backend.send_to(&pkt, ip);
        if let Some(g) = gap {
            next += g;
            let now = Instant::now();
            if next > now {
                std::thread::sleep(next - now);
            }
        }
    }
}

/// Drive a full sweep over `targets` using `backend`, returning the results.
pub fn run<B: Backend + Sync>(backend: &B, cfg: &Config, targets: &[IpAddr]) -> Results {
    let n = targets.len();
    // adaptive: send once, retry only the silent ones (alive/down, minimal traffic).
    // fixed: -C probes to every host (needed for loss%).
    let adaptive = is_adaptive(cfg);
    let rounds = if adaptive {
        (cfg.retries + 1) as usize
    } else {
        cfg.count.max(1) as usize
    };
    let results = Results::new(n, rounds);

    let run_id: u16 = (std::process::id() & 0xffff) as u16;
    let secret: u32 = {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(0);
        fnv1a32(&t.to_le_bytes()) ^ (run_id as u32).rotate_left(16)
    };
    let start = Instant::now();
    let running = AtomicBool::new(true);

    std::thread::scope(|s| {
        // receiver: stateless, runs until the sender signals shutdown
        s.spawn(|| {
            let mut buf = [0u8; 2048];
            while running.load(Ordering::Relaxed) {
                if let Some((len, src)) = backend.recv(&mut buf) {
                    let now = start.elapsed().as_nanos() as u64;
                    validate_and_record(&buf[..len], src, targets, run_id, secret, now, &results);
                }
            }
        });

        if adaptive {
            let mut pending: Vec<usize> = (0..n).collect();
            for r in 0..rounds {
                if pending.is_empty() {
                    break;
                }
                send_round(backend, targets, &pending, r as u16, run_id, secret, start, cfg);
                std::thread::sleep(cfg.timeout);
                pending.retain(|&i| !results.responded_any(i));
            }
        } else {
            let all: Vec<usize> = (0..n).collect();
            for r in 0..rounds {
                send_round(backend, targets, &all, r as u16, run_id, secret, start, cfg);
                std::thread::sleep(cfg.timeout);
            }
        }

        // brief drain for stragglers, then stop the receiver
        std::thread::sleep(Duration::from_millis(200));
        running.store(false, Ordering::Relaxed);
    });

    results
}

// ---- reporting -------------------------------------------------------------

pub fn report(cfg: &Config, targets: &[IpAddr], names: &[String], res: &Results) {
    let out = io::stdout();
    let mut w = out.lock();
    match cfg.output {
        Output::Plain => {
            for (i, ip) in targets.iter().enumerate() {
                let rtt = (0..res.rounds).map(|r| res.round(r, i)).find(|&v| v >= 0);
                match rtt {
                    Some(us) => {
                        let _ = writeln!(w, "{ip} alive {:.3} ms", us as f64 / 1000.0);
                    }
                    None => {
                        let _ = writeln!(w, "{ip} down");
                    }
                }
            }
        }
        Output::Fping => {
            for (i, ip) in targets.iter().enumerate() {
                let mut parts = Vec::with_capacity(res.rounds);
                for r in 0..res.rounds {
                    let v = res.round(r, i);
                    parts.push(if v >= 0 {
                        format!("{:.2}", v as f64 / 1000.0)
                    } else {
                        "-".to_string()
                    });
                }
                let _ = writeln!(w, "{ip} : {}", parts.join(" "));
            }
        }
        Output::Zabbix => {
            let adaptive = is_adaptive(cfg);
            let mut items: Vec<(String, String, String)> = Vec::with_capacity(targets.len() * 3);
            for (i, ip) in targets.iter().enumerate() {
                let host = match cfg.zbx_host_mode {
                    HostMode::Ip => ip.to_string(),
                    HostMode::Resolved => names[i].clone(),
                };
                let (alive, loss, avg) = res.score(i, adaptive);
                items.push((host.clone(), format!("{}.alive", cfg.zbx_key), alive.to_string()));
                items.push((host.clone(), format!("{}.loss", cfg.zbx_key), format!("{loss:.4}")));
                items.push((host, format!("{}.rtt", cfg.zbx_key), format!("{avg:.6}")));
            }
            match &cfg.zbx_server {
                Some(server) => match send_zabbix(server, &items, cfg.zbx_batch) {
                    Ok(info) => eprintln!("fastping: zabbix {server}: {info}"),
                    Err(e) => {
                        eprintln!("fastping: zabbix send to {server} failed: {e}");
                        for (h, k, v) in &items {
                            let _ = writeln!(w, "\"{h}\" {k} {v}");
                        }
                    }
                },
                None => {
                    for (h, k, v) in &items {
                        let _ = writeln!(w, "\"{h}\" {k} {v}");
                    }
                }
            }
        }
        Output::Json => {
            let adaptive = is_adaptive(cfg);
            let mut sbuf = String::from("[");
            for (i, ip) in targets.iter().enumerate() {
                let (alive, loss, avg) = res.score(i, adaptive);
                if i > 0 {
                    sbuf.push(',');
                }
                sbuf.push_str("{\"ip\":\"");
                json_escape(&ip.to_string(), &mut sbuf);
                sbuf.push_str("\",\"name\":\"");
                json_escape(&names[i], &mut sbuf);
                sbuf.push_str(&format!(
                    "\",\"alive\":{alive},\"loss\":{loss:.4},\"rtt\":{avg:.6}}}"
                ));
            }
            sbuf.push(']');
            let _ = writeln!(w, "{sbuf}");
        }
    }
}

// ---- Zabbix sender protocol (native, no zabbix_sender binary) -------------
// Wire format: "ZBXD" 0x01 | <8-byte LE payload length> | <JSON payload>.

fn json_escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

fn build_sender_json(items: &[(String, String, String)]) -> String {
    let mut s = String::from("{\"request\":\"sender data\",\"data\":[");
    for (n, (host, key, value)) in items.iter().enumerate() {
        if n > 0 {
            s.push(',');
        }
        s.push_str("{\"host\":\"");
        json_escape(host, &mut s);
        s.push_str("\",\"key\":\"");
        json_escape(key, &mut s);
        s.push_str("\",\"value\":\"");
        json_escape(value, &mut s);
        s.push_str("\"}");
    }
    s.push_str("]}");
    s
}

// Send all items, splitting into chunks of `batch` values per TCP session
// (0 = one session for everything). Returns a combined summary; a failed chunk
// aborts and propagates the error (earlier chunks are already committed).
fn send_zabbix(
    server: &str,
    items: &[(String, String, String)],
    batch: usize,
) -> io::Result<String> {
    let addr = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:10051")
    };
    let chunk = if batch == 0 { items.len().max(1) } else { batch };
    let mut infos: Vec<String> = Vec::new();
    for group in items.chunks(chunk) {
        infos.push(send_zabbix_one(&addr, group)?);
    }
    Ok(match infos.len() {
        1 => infos.pop().unwrap(),
        n => format!("{n} batches: {}", infos.join(" | ")),
    })
}

// One Zabbix sender request over a single TCP connection.
fn send_zabbix_one(addr: &str, items: &[(String, String, String)]) -> io::Result<String> {
    use std::io::Read;
    use std::net::TcpStream;

    let payload = build_sender_json(items);
    let mut frame = Vec::with_capacity(13 + payload.len());
    frame.extend_from_slice(b"ZBXD\x01");
    frame.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    frame.extend_from_slice(payload.as_bytes());

    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(&frame)?;

    let mut hdr = [0u8; 13];
    stream.read_exact(&mut hdr)?;
    if &hdr[0..4] != b"ZBXD" {
        return Err(io::Error::other("bad response header"));
    }
    let len = u64::from_le_bytes(hdr[5..13].try_into().unwrap()) as usize;
    let mut body = vec![0u8; len.min(64 * 1024)];
    stream.read_exact(&mut body)?;
    let text = String::from_utf8_lossy(&body);
    Ok(extract_json_string(&text, "info").unwrap_or_else(|| text.into_owned()))
}

// Minimal extractor for a top-level string field: "<key>" : "<value>".
fn extract_json_string(text: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let mut rest = &text[text.find(&pat)? + pat.len()..];
    rest = rest.trim_start();
    rest = rest.strip_prefix(':')?.trim_start();
    rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                other => out.push(other),
            },
            '"' => return Some(out),
            other => out.push(other),
        }
    }
    None
}

// ---- CLI -------------------------------------------------------------------

fn next_val(
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

pub fn parse_args() -> Result<(Config, Vec<(IpAddr, String)>), String> {
    let mut cfg = Config {
        timeout: Duration::from_millis(1500),
        retries: 2,
        rate: 0,
        payload: PAYLOAD_MIN,
        output: Output::Plain,
        count: 3,
        zbx_key: "icmp".to_string(),
        zbx_host_mode: HostMode::Ip,
        zbx_server: None,
        zbx_batch: 1000,
        discover: false,
        iface: None,
    };
    let mut targets: Vec<(IpAddr, String)> = Vec::new();
    let mut file: Option<String> = None;
    let mut cidrs: Vec<String> = Vec::new();

    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "-t" | "--timeout" => {
                cfg.timeout = Duration::from_millis(
                    next_val(&mut args, &a)?.parse().map_err(|_| "bad timeout")?,
                )
            }
            "-r" | "--retries" => {
                cfg.retries = next_val(&mut args, &a)?.parse().map_err(|_| "bad retries")?
            }
            "--rate" => cfg.rate = next_val(&mut args, &a)?.parse().map_err(|_| "bad rate")?,
            "--payload" => {
                cfg.payload = next_val(&mut args, &a)?.parse().map_err(|_| "bad payload")?
            }
            "-C" | "--count" => {
                cfg.count = next_val(&mut args, &a)?.parse().map_err(|_| "bad count")?
            }
            "-o" | "--output" => {
                cfg.output = match next_val(&mut args, &a)?.as_str() {
                    "plain" => Output::Plain,
                    "fping" => Output::Fping,
                    "zabbix" => Output::Zabbix,
                    "json" => Output::Json,
                    o => return Err(format!("unknown output: {o}")),
                }
            }
            "--key" => cfg.zbx_key = next_val(&mut args, &a)?,
            "--server" => cfg.zbx_server = Some(next_val(&mut args, &a)?),
            "--batch" => cfg.zbx_batch = next_val(&mut args, &a)?.parse().map_err(|_| "bad batch")?,
            "--discover" | "--alive" => cfg.discover = true,
            "-i" | "--iface" => cfg.iface = Some(next_val(&mut args, &a)?),
            "-f" | "--file" => file = Some(next_val(&mut args, &a)?),
            "-c" | "--cidr" => cidrs.push(next_val(&mut args, &a)?),
            "-h" | "--help" => return Err("help".to_string()),
            other if !other.starts_with('-') => {
                // an IPv4/IPv6 literal or a hostname to resolve
                let ip = resolve_ip(other)?;
                targets.push((ip, other.to_string()));
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }

    for c in &cidrs {
        for ip in expand_cidr(c)? {
            targets.push((ip, ip.to_string()));
        }
    }
    if let Some(path) = file {
        let f = std::fs::File::open(&path).map_err(|e| format!("{path}: {e}"))?;
        read_lines(io::BufReader::new(f), &mut targets)?;
    }
    if targets.is_empty() {
        let stdin = io::stdin();
        read_lines(stdin.lock(), &mut targets)?;
    }
    if targets.is_empty() {
        return Err("no targets".to_string());
    }
    Ok((cfg, targets))
}

fn read_lines<R: BufRead>(r: R, out: &mut Vec<(IpAddr, String)>) -> Result<(), String> {
    for line in r.lines() {
        let line = line.map_err(|e| e.to_string())?;
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let mut it = s.split_whitespace();
        let ipt = it.next().unwrap();
        let ip = resolve_ip(ipt)?;
        // explicit display name if given, else the token (IP or hostname) itself
        let name = it.next().unwrap_or(ipt).to_string();
        out.push((ip, name));
    }
    Ok(())
}

// Accept an IPv4/IPv6 literal, or resolve a hostname to its first A/AAAA record.
// Resolution is blocking and serial — fine for CLI/file convenience; for mass
// sweeps pass IPs (those never trigger DNS).
fn resolve_ip(host: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    use std::net::ToSocketAddrs;
    (host, 0u16)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .map(|sa| sa.ip())
        .next()
        .ok_or_else(|| format!("no address for {host}"))
}

// IPv4-only: expanding IPv6 prefixes is intentionally unsupported (the space is
// astronomically large). List explicit IPv6 addresses instead.
fn expand_cidr(s: &str) -> Result<Vec<IpAddr>, String> {
    let (base, prefix) = s.split_once('/').ok_or_else(|| format!("not a CIDR: {s}"))?;
    if base.contains(':') {
        return Err("IPv6 CIDR expansion is not supported — list explicit addresses".to_string());
    }
    let ip: Ipv4Addr = base.parse().map_err(|_| format!("bad IP: {base}"))?;
    let p: u32 = prefix.parse().map_err(|_| format!("bad prefix: {prefix}"))?;
    if p > 32 {
        return Err(format!("bad prefix: {prefix}"));
    }
    let base = u32::from(ip) & if p == 0 { 0 } else { !0u32 << (32 - p) };
    let count = 1u64 << (32 - p);
    let (lo, hi) = if p <= 30 && count >= 4 {
        (base as u64 + 1, base as u64 + count - 1)
    } else {
        (base as u64, base as u64 + count)
    };
    Ok((lo..hi).map(|a| IpAddr::V4(Ipv4Addr::from(a as u32))).collect())
}

/// Dedupe targets, preserving order and the chosen display name. Returns the IPs,
/// matching names, and whether any name differs from its IP (→ resolved host mode).
pub fn dedupe(raw: Vec<(IpAddr, String)>) -> (Vec<IpAddr>, Vec<String>, bool) {
    let mut seen: HashMap<IpAddr, ()> = HashMap::new();
    let mut targets = Vec::with_capacity(raw.len());
    let mut names = Vec::with_capacity(raw.len());
    for (ip, name) in raw {
        if seen.insert(ip, ()).is_none() {
            targets.push(ip);
            names.push(name);
        }
    }
    let resolved = names.iter().zip(&targets).any(|(n, ip)| n != &ip.to_string());
    (targets, names, resolved)
}

pub const USAGE: &str = "\
fastping — stateless mass ICMP-echo sweeper

USAGE:
    fastping [OPTIONS] [IP...]
    fastping -c 10.0.0.0/24 -o zabbix --key icmp
    cat hosts.txt | fastping -o fping -C 3

TARGETS (combine freely; stdin used if none given):
    IP...                 IPv4/IPv6 literals or hostnames (resolved to A/AAAA)
    -f, --file <path>     file with one \"ip|host\" or \"ip|host name\" per line
    -c, --cidr <cidr>     expand an IPv4 CIDR (repeatable; IPv6 not supported)

OPTIONS:
    -t, --timeout <ms>    per-round wait before retry        [default 1500]
    -r, --retries <n>     extra rounds for silent hosts       [default 2]
        --rate <pps>      send rate across the batch, 0=max   [default 0]
        --payload <n>     ICMP payload bytes (min 20)         [default 20]
    -o, --output <mode>   plain | fping | zabbix | json      [default plain]
    -C, --count <n>       probes per host (fixed-probe modes)  [default 3]
        --discover        zabbix/json: adaptive retry (alive-only, retries just
                          the silent ones) instead of -C probes; loss is 0/1
        --key <prefix>    item key prefix in zabbix mode      [default icmp]
        --server <addr>   Zabbix server/proxy host[:10051]
        --batch <n>       values per Zabbix sender connection, 0=all [default 1000]
    -i, --iface <name>    egress interface (afpacket backend only)
    -h, --help

ZABBIX MODE emits per host: <key>.alive (0/1), <key>.loss (0..1), <key>.rtt (s).
Requires CAP_NET_RAW (run as root or: setcap cap_net_raw+ep ./fastping).
";

/// Shared CLI entry point. `make_backend` constructs the transport from the
/// parsed config; everything else (arg parsing, sweep, reporting) is common.
pub fn cli<B: Backend + Sync>(make_backend: impl FnOnce(&Config) -> io::Result<B>) -> ! {
    let (cfg, raw_targets) = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            if e == "help" {
                print!("{USAGE}");
                std::process::exit(0);
            }
            eprintln!("fastping: {e}\n");
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    };

    let (targets, names, resolved) = dedupe(raw_targets);
    let mut cfg = cfg;
    if resolved {
        cfg.zbx_host_mode = HostMode::Resolved;
    }

    let backend = match make_backend(&cfg) {
        Ok(b) => b,
        Err(e) => {
            let denied = e.kind() == io::ErrorKind::PermissionDenied;
            eprintln!("fastping: {e}");
            if denied {
                eprintln!("hint: raw sockets need CAP_NET_RAW — run as root or setcap.");
            }
            std::process::exit(1);
        }
    };

    let res = run(&backend, &cfg, &targets);
    report(&cfg, &targets, &names, &res);
    std::process::exit(0);
}
