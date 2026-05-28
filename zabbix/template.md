# Getting the host list out of Zabbix

Don't read the DB — use the API (`host.get` + `hostinterface.get`). The script
`zbx-hosts.sh` in this directory writes `IP host.host` lines, which is exactly
the `fastping -f` format (the name becomes the Zabbix host name on the way back).
Run it from cron a bit more often than the sweep, e.g. every 5 min.

# Model C: one active check on localhost feeds ALL hosts (master + dependent + LLD)

The most Zabbix-native option, and the answer to "call it once on localhost and
pass every host." A single item runs `fastping -o json` and returns the whole
batch as one JSON array; Zabbix then fans it out without re-running anything.

1. Install the agent UserParameter (`fastping.conf` in this dir) on the host
   running the agent, so the key `fastping.sweep` becomes available.
2. **Master item** (template/host = your ping aggregator):
   * Type: *Zabbix agent (active)* (or passive), Key: `fastping.sweep`
   * Type of information: *Text*, update interval e.g. `1m`
   * It returns: `[{"ip":"…","name":"…","alive":1,"loss":0.0,"rtt":0.001}, …]`
3. **LLD rule** on the same data to auto-create per-host items:
   * Discovery key: a second key `fastping.discovery` (or reuse the master via a
     dependent LLD rule), preprocessing → JSONPath, macros:
     `{#IP}` ← `$.ip`, `{#NAME}` ← `$.name`
4. **Item prototypes** (dependent on the master item), one per metric, with
   preprocessing *JSONPath*:
   * `icmp.alive[{#IP}]`  →  `$[?(@.ip=='{#IP}')].alive`
   * `icmp.loss[{#IP}]`   →  `$[?(@.ip=='{#IP}')].loss`
   * `icmp.rtt[{#IP}]`    →  `$[?(@.ip=='{#IP}')].rtt`

`fastping` runs once per interval; Zabbix splits the JSON into all per-host
items. No trapper push, no per-host polling. Triggers are the same as below but
on the `[{#IP}]` keys.

> Reshape for an older LLD rule that wants `{"data":[…]}`:
> `fastping -o json … | jq -c '{data:[.[]|{"{#IP}":.ip,"{#NAME}":.name}]}'`

---

# Model A: trapper + native sender

`fastping` pings the whole batch and pushes results in one TCP session straight
to the Zabbix server/proxy. On the Zabbix side you only need **trapper** items.

## 1. Items (per monitored host, or on a single "ping aggregator" host)

Create three trapper items. Key prefix matches `fastping --key` (default `icmp`).

| Name            | Type           | Key          | Type of info | Units |
|-----------------|----------------|--------------|--------------|-------|
| ICMP alive      | Zabbix trapper | `icmp.alive` | Numeric (unsigned) | |
| ICMP loss       | Zabbix trapper | `icmp.loss`  | Numeric (float) | % (×100) |
| ICMP latency    | Zabbix trapper | `icmp.rtt`   | Numeric (float) | s |

The host name in Zabbix must equal the name `fastping` sends:
* by default that is the IP string (e.g. `10.0.0.5`);
* if you list `ip displayname` in the targets file, it is `displayname` — set
  it to the Zabbix `host.host`.

## 2. Triggers

```
# host is down (no successful probe in the last sample)
last(/HOST/icmp.alive)=0

# high packet loss
last(/HOST/icmp.loss)>0.20

# high latency (seconds)
last(/HOST/icmp.rtt)>0.150

# FALLBACK: push stream stopped — fastping or the timer died.
# Period should be a few times the run interval.
nodata(/HOST/icmp.alive,300)=1
```

## 3. Running it on an interval

Use the systemd timer in this directory, or cron:

```
*/1 * * * *  /usr/local/bin/fastping -f /etc/fastping/hosts.txt \
             -o zabbix --key icmp -C 3 --rate 50000 \
             --server 127.0.0.1:10051 >/dev/null 2>>/var/log/fastping.err
```

`--server` can point at a Zabbix **proxy**; it speaks the same sender protocol.

## 4. Fallback to active fping polling

A trapper item cannot poll itself. To get a real fallback, add a backup built-in
item that Zabbix polls on its own, at a low frequency:

| Name              | Type             | Key                              | Interval |
|-------------------|------------------|----------------------------------|----------|
| ICMP alive (poll) | Simple check     | `icmpping[,3,,,]`                | 5m       |

Then in dashboards/triggers prefer `icmp.alive` (fast push), and when
`nodata(/HOST/icmp.alive,300)=1` fires, rely on `icmpping[...]`. Optionally fold
both into one calculated item:

```
# icmp.alive.eff  (calculated, float)
( nodata(//icmp.alive,300)=0 ) * last(//icmp.alive)
+ ( nodata(//icmp.alive,300)=1 ) * last(//icmpping[,3,,,])
```
