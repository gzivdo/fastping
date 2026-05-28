# fastping

Stateless mass ICMP-echo sweeper. Fires a whole batch of echo requests from one
raw socket while a second raw socket records replies — no per-packet locking
between them — then re-sends only the hosts that stayed silent, for a few
retries. Same async send/receive architecture as `zmap`/`masscan`, but with an
adaptive per-host retry queue on top, which the mass scanners deliberately omit.

* Single static binary, ~380 KB.
* No state map on the hot path: the target index, a per-run validation cookie and
  the send timestamp are embedded in the ICMP payload and echoed back, so a reply
  alone is enough to score the host and compute RTT.
* Three output modes: `plain`, `fping`-compatible, and `zabbix` (native sender
  protocol or `zabbix_sender` input lines).

## Backends

Two binaries, same CLI and output modes (shared core in `src/lib.rs`):

| Binary | Transport | Use when |
|---|---|---|
| `fastping` | two raw ICMP sockets (kernel builds IP/does routing+ARP) | default; any link incl. loopback and same-subnet hosts |
| `fastping-afpacket` | AF_PACKET TX + mmap'd `PACKET_RX_RING` | high pps routed/off-subnet sweeps; won't drop replies in a socket buffer |

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
    IP...                 literal IPv4 addresses
    -f, --file <path>     file with one "ip" or "ip name" per line
    -c, --cidr <cidr>     expand an IPv4 CIDR (repeatable)

OPTIONS:
    -t, --timeout <ms>    per-round wait before retry        [default 1500]
    -r, --retries <n>     extra rounds for silent hosts       [default 2]
        --rate <pps>      send rate across the batch, 0=max   [default 0]
        --payload <n>     ICMP payload bytes (min 20)         [default 20]
    -o, --output <mode>   plain | fping | zabbix             [default plain]
    -C, --count <n>       probes per host in fping/zabbix     [default 3]
        --key <prefix>    item key prefix in zabbix mode      [default icmp]
        --server <addr>   Zabbix server/proxy host[:10051]
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
| `zabbix` | `-C` probes to **every** host    | `<key>.alive` (0/1), `<key>.loss` (0..1), `<key>.rtt` (s) |
| `json`   | `-C` probes to **every** host    | one JSON array `[{ip,name,alive,loss,rtt},…]`     |

Loss% is only meaningful when every host gets a fixed number of probes, so
`fping`/`zabbix` send `-C` probes to all hosts. `plain` keeps the adaptive
retry (fast alive/dead, no extra traffic to hosts that already answered).

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

## Roadmap

* `AF_PACKET` + `PACKET_TX/RX_RING` (mmap) for true multi-Mpps and to stop
  dropping replies in the socket buffer.
* Encode the cookie cryptographically (SipHash) instead of FNV for spoof
  resistance on the open Internet.
* IPv6 echo.
