# fastping

📖 **[Документация на русском →](README.ru.md)**

Stateless mass ICMP-echo sweeper. Fires a whole batch of echo requests from one
raw socket while a second raw socket records replies — no per-packet locking
between them — then re-sends only the hosts that stayed silent, for a few
retries. Same async send/receive architecture as `zmap`/`masscan`, but with an
adaptive per-host retry queue on top, which the mass scanners deliberately omit.

* Single static binary, ~380 KB.
* No state map on the hot path: the target index, a per-run validation cookie and
  the send timestamp are embedded in the ICMP payload and echoed back, so a reply
  alone is enough to score the host and compute RTT.
* Output modes: `plain`, `fping`-compatible, `zabbix` (native sender protocol),
  and `json` (for Zabbix LLD / Nagios). Integrations for Zabbix and Nagios.
* **Dual-stack** IPv4 + IPv6; targets as literals, hostnames (A/AAAA), IPv4
  CIDRs, or files.

## The idea in plain terms

Ordinary `ping` walks one host at a time: send, wait for the reply (or timeout),
move on. `fping` is smarter — it interleaves many hosts round-robin — but still
runs everything through one process loop. With thousands of hosts, most of the
wall-clock time is spent *waiting*.

fastping instead **mails all the letters at once**: one thread blasts the entire
batch of echo requests, a second thread just catches whatever comes back. It
keeps a checklist of who answered; after a short wait it re-sends **only the
silent ones**, a couple of times. So the total time is roughly "one timeout, plus
a couple of retries for stragglers" — not "timeout × number of hosts".

The trick that makes the receiver cheap: every probe carries its target's index,
a validation cookie and the send timestamp *inside the ICMP payload*, which the
host echoes back. So a single reply packet is self-describing — the receiver
needs no shared lookup table to know which host it is or how long it took.

## How it compares

| Tool | Model | Adaptive retry | Per-host loss/RTT | Monitoring output | Best at |
|---|---|---|---|---|---|
| `ping` | 1 host, blocking | — | yes | — | a single host |
| `fping` | many hosts, round-robin, 1 socket | blind resend | yes | text | LAN sweeps, scripts |
| `nmap -sn` | host discovery, feature-rich | yes | limited | XML/grep | discovery + extra probes |
| `zmap` | stateless, Internet-scale | **no** (fire-and-forget) | no (survey) | needs post-proc | one-shot Internet surveys |
| `masscan` | stateless, TCP-focused | no | no | lists | Internet-wide port scans |
| **fastping** | **stateless batch + adaptive retry** | **yes** | **yes** | **Zabbix/Nagios/JSON built-in** | **repeated monitoring sweeps of many known hosts** |

**Why it's different / better for its niche:**

* **vs `fping`** — same "alive + loss + RTT with retries" semantics, but the
  zmap-style async batch scales to far larger host counts, and the AF_PACKET +
  `PACKET_RX_RING` backend stops dropping replies under load (a dropped reply in
  `fping` looks like a false "down"). Plus native Zabbix/Nagios/JSON output, so
  there's nothing to parse.
* **vs `zmap`/`masscan`** — they're faster for one-shot Internet surveys, but are
  deliberately *fire-and-forget*: no per-host retry, no convenient loss/RTT, and
  you post-process a result dump. fastping keeps their stateless hot path yet adds
  exactly the bits monitoring needs — an adaptive retry queue and ready-to-ship
  per-host metrics.
* **The niche:** you have N *known* hosts (a Zabbix/Nagios inventory, a few /16s)
  and you want to sweep them **repeatedly, fast, and reliably**, pushing
  alive/loss/RTT straight into your monitoring — without a 1-process-per-host
  fan-out or a heavyweight scanner.

**Honest limitations:** ICMP echo only; targets can be IPv4 **or IPv6** (the
default socket backend is dual-stack; the AF_PACKET backend is IPv4-only). IPv6
CIDR expansion is intentionally unsupported — list explicit addresses. The
validation cookie is FNV (fast, not cryptographic — fine for a LAN/monitoring,
not for hostile Internet spoofing yet); the AF_PACKET backend routes via the
gateway MAC (off-subnet sweeps) and its TX isn't zero-copy yet; not tuned for
true Internet-scale like zmap (no PF_RING / multi-queue). See the roadmap.

## Backends

Two binaries, same CLI and output modes (shared core in `src/lib.rs`):

| Binary | Transport | Use when |
|---|---|---|
| `fastping` | raw ICMP + ICMPv6 sockets (kernel builds IP/does routing+ARP/ND) | default; **dual-stack** (IPv4+IPv6), any link incl. loopback and same-subnet |
| `fastping-afpacket` | AF_PACKET TX + mmap'd `PACKET_RX_RING` | high pps routed/off-subnet sweeps; won't drop replies in a socket buffer; **IPv4-only** |

The `fastping` receive side uses **one blocking thread per address family**, each
draining its socket with `recvmmsg(MSG_WAITFORONE)` — a whole batch of replies
per syscall, no `poll` on the hot path. Only the families present in the target
set are opened, so there's no idle IPv6 thread when there are no v6 targets.

`fastping-afpacket` addresses frames to the **default gateway's MAC** (so it is
for routed sweeps; same-subnet/loopback → use `fastping`). It needs a populated
ARP entry for the gateway (`ping <gw>` once if missing) and `-i/--iface` to
override the egress interface.

## Build

```sh
cargo build --release
# raw sockets need CAP_NET_RAW — either run as root, or grant the cap once:
sudo setcap cap_net_raw+ep ./target/release/fastping
```

## Usage

```
fastping [OPTIONS] [IP...]

TARGETS (combine freely; stdin used if none given):
    IP...                 IPv4/IPv6 literals or hostnames (resolved to A/AAAA)
    -f, --file <path>     file with one "ip|host" or "ip|host name" per line
    -c, --cidr <cidr>     expand an IPv4 CIDR (repeatable; IPv6 not supported)

OPTIONS:
    -t, --timeout <ms>    per-round wait before retry        [default 1500]
    -r, --retries <n>     extra rounds for silent hosts       [default 2]
        --rate <pps>      send rate across the batch, 0=max   [default 0]
        --payload <n>     ICMP payload bytes (min 20)         [default 20]
    -o, --output <mode>   plain | fping | zabbix | json      [default plain]
    -C, --count <n>       probes per host (fixed-probe modes) [default 3]
        --discover        zabbix/json: adaptive retry (alive-only) not -C probes
        --key <prefix>    item key prefix in zabbix mode      [default icmp]
        --server <addr>   Zabbix server/proxy host[:10051]
        --batch <n>       values per Zabbix sender connection [default 1000]
    -i, --iface <name>    egress interface (afpacket backend only)
```

### Examples

```sh
# discovery: alive/dead + first RTT, retry only the silent ones
fastping -c 10.0.0.0/16 --rate 50000 -t 1000 -r 2

# fping-compatible: N probes to every host, '-' marks a loss
cat hosts.txt | fastping -o fping -C 3

# zabbix: push straight to a server/proxy over the native sender protocol
fastping -f hosts.txt -o zabbix --key icmp -C 3 --server zbx-proxy.example:10051

# zabbix: print zabbix_sender input lines instead (pipe to zabbix_sender -i -)
fastping -f hosts.txt -o zabbix --key icmp | zabbix_sender -z zbx -i -
```

The targets file accepts `ip` or `ip displayname`. When a display name is given,
zabbix mode uses it as the Zabbix host name (so it can match `host.host` in
Zabbix); otherwise the IP string is used.

## Modes in detail

| Mode     | Probing                          | Output                                            |
|----------|----------------------------------|---------------------------------------------------|
| `plain`  | round 0 to all, retry silent     | `IP alive <ms>` / `IP down`                       |
| `fping`  | `-C` probes to **every** host    | `IP : r0 r1 r2` (`-` = lost), like `fping -C -q`  |
| `zabbix` | `-C` probes to every host, or `--discover` | `<key>.alive` (0/1), `<key>.loss` (0..1), `<key>.rtt` (s) |
| `json`   | `-C` probes to every host, or `--discover` | one JSON array `[{ip,name,alive,loss,rtt},…]`     |

Two probing strategies, independent of the output format:

* **fixed `-C` probes** to *every* host — needed to measure loss%. Default for
  `fping`/`zabbix`/`json`.
* **adaptive retry** — send the batch once, then re-send *only the silent hosts*
  up to `-r` times (the original idea: fast up/down, no extra traffic to hosts
  that already answered). Always used by `plain`; opt in for `zabbix`/`json` with
  `--discover` when you only need alive/down (then `loss` is reported as 0 or 1).

So for a pure liveness check into Zabbix, `fastping -o zabbix --discover -r 2`
pings each host once and retries just the non-responders — unlike the default
`-C` mode, which probes everyone N times.

## sysctl / NIC tuning

For large batches the bottleneck is dropped *replies*, which turn into wasted
retries. Raise buffers and backlog:

```sh
# receive buffer (fastping already requests 8 MiB via setsockopt, but cap it)
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.rmem_default=16777216
# softirq backlog before the kernel drops incoming packets
sysctl -w net.core.netdev_max_backlog=250000
# let the host answer its own pings without ICMP rate-limiting skewing tests
sysctl -w net.ipv4.icmp_ratelimit=0          # on the *prober*, optional
# NIC ring buffers
ethtool -G eth0 rx 4096 tx 4096
```

Always set `--rate` for real scans. Without it you can overrun your own TX ring
and trip ICMP rate-limits on intermediate routers, producing false "down" and
needless retries. Start around 20k–50k pps and watch loss.

> Note: targets themselves rate-limit ICMP (`net.ipv4.icmp_ratelimit`, default
> 1000/s). That is the main reason a single pass yields false negatives — and
> exactly what the retry rounds are for.

## Zabbix integration

Two models, usable together.

### Model A — trapper items + native sender protocol (recommended)

Preserves batching: one `fastping` run pings everything and pushes all results
in a single TCP session. See [`zabbix/template.md`](zabbix/template.md) for the
item/trigger definitions and [`zabbix/fastping.timer`](zabbix/) for a systemd
timer that runs it on an interval.

Per host, three trapper items are fed: `icmp.alive`, `icmp.loss`, `icmp.rtt`
(rename via `--key`).

Results are pushed **once, after the whole sweep finishes** (all `-C` probes —
loss% needs every probe per host, so a host's value isn't final until then). The
final push is split into chunks of `--batch` values per TCP session (default
1000, `0` = one session) so a 30k-host run doesn't become one giant request and
partial progress survives a mid-run failure.

Get the host list out of Zabbix with [`zabbix/zbx-hosts.sh`](zabbix/zbx-hosts.sh)
(API `host.get`, writes the `IP host.host` lines `-f` expects).

### Model C — one active check on localhost feeds every host

A single agent item runs `fastping -o json`, returning the whole batch as one
JSON array; a Zabbix **master item + dependent items + LLD** fan it out with
JSONPath preprocessing, no re-running and no trapper push. This is the cleanest
answer to "call it once on localhost and pass all hosts." See
[`zabbix/template.md`](zabbix/template.md) (Model C) and
[`zabbix/fastping.conf`](zabbix/fastping.conf) (the agent UserParameter).

### Model B — fping-compatible drop-in

Zabbix's built-in `icmpping*` items shell out to `fping`. `fastping -o fping`
emits the `fping -C -q` line format, so it can back scripted/external checks.
Caveat: Zabbix invokes `fping` with its own flag set (`-C`, `-i`, `-t`, `-b`…),
so it is **not** a transparent 1:1 replacement for the `Fping location` setting
without a small wrapper that maps those flags. Use Model A for the Zabbix server
path; use `-o fping` for scripts and external checks.

### Fallback when no data arrives

Zabbix can't auto-switch a single item from push to active poll. The working
pattern (in the template):

1. `nodata()` trigger on `icmp.alive` to alert when the push stream stops, and
2. a low-frequency built-in `icmpping` (active, fping-based) backup item, read
   only when the trapper item is stale.

## Nagios / Icinga integration

Two wrappers in [`nagios/`](nagios/):

**Active, single host** — [`nagios/check_fastping`](nagios/check_fastping), a
drop-in-ish replacement for `check_icmp`/`check_ping`:

```
check_fastping -H 8.8.8.8 -w 20,200 -c 100,500 -C 5
# FASTPING OK - 8.8.8.8 rta 2.207ms, lost 0% | rta=2.207ms;200;500;0; pl=0%;20;100;0;100
```

Returns OK/WARNING/CRITICAL/UNKNOWN with `rta`/`pl` perfdata. `-w`/`-c` are
`loss%,rta_ms`. Use `-b afpacket` for the AF_PACKET backend. One process per
host, like the stock plugins — simple, but no batching.

**Batch, passive (preserves batching)** —
[`nagios/fastping-passive.sh`](nagios/fastping-passive.sh) sweeps the whole list
in one run, then submits one passive result per host **as text** to the Nagios
external command pipe (a FIFO) or to an NSCA daemon over TCP:

```sh
# host file: "ip nagios_host_name" per line
fastping-passive.sh -f hosts.txt -s ICMP -C 5 -P /usr/local/nagios/var/rw/nagios.cmd
# -> [<ts>] PROCESS_SERVICE_CHECK_RESULT;<host>;ICMP;<rc>;<output|perfdata>
fastping-passive.sh -f hosts.txt -s ICMP --nsca nagios-host:5667
```

This is the Nagios analogue of the Zabbix trapper model: one fast batch sweep,
many passive results pushed. Define the services as passive on the Nagios side.

## Roadmap

* `AF_PACKET` + `PACKET_TX/RX_RING` (mmap) for true multi-Mpps and to stop
  dropping replies in the socket buffer.
* Encode the cookie cryptographically (SipHash) instead of FNV for spoof
  resistance on the open Internet.
* IPv6 in the AF_PACKET backend (needs a hand-computed ICMPv6 pseudo-header
  checksum); parallel DNS resolution for large hostname lists.
* Optional `--stream` mode for early discovery.

## License

MIT — see [LICENSE](LICENSE).
