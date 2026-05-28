#!/usr/bin/env bash
# fastping-passive.sh — batch ICMP sweep -> Nagios/Icinga PASSIVE check results.
#
# Pings the whole host list in ONE fastping run (preserving the batch advantage),
# then submits one PROCESS_SERVICE_CHECK_RESULT line per host as text to either
# the Nagios external command pipe (a FIFO) or an NSCA daemon over TCP.
#
# The hosts file uses "ip nagios_host_name" lines; the second column becomes the
# Nagios host name (fastping carries it through as the JSON "name").
#
# Usage:
#   fastping-passive.sh -f hosts.txt -s "PING" [-w 20] [-c 100] [-C 5] [-t 1000]
#                       [-b socket|afpacket] [-P /usr/local/nagios/var/rw/nagios.cmd]
#                       [--nsca host[:5667]] [--nsca-cfg send_nsca.cfg]
# Requires: jq, and the chosen fastping binary on PATH (or FASTPING_BIN).
set -u

file=""; service="PING"; wloss=20; closs=100; count=5; timeout=1000; backend="socket"
pipe="/usr/local/nagios/var/rw/nagios.cmd"; nsca=""; nsca_cfg="/etc/send_nsca.cfg"

while [ $# -gt 0 ]; do
  case "$1" in
    -f) file="$2"; shift 2;;
    -s) service="$2"; shift 2;;
    -w) wloss="$2"; shift 2;;
    -c) closs="$2"; shift 2;;
    -C) count="$2"; shift 2;;
    -t) timeout="$2"; shift 2;;
    -b) backend="$2"; shift 2;;
    -P) pipe="$2"; shift 2;;
    --nsca) nsca="$2"; shift 2;;
    --nsca-cfg) nsca_cfg="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 3;;
  esac
done
[ -n "$file" ] || { echo "missing -f hosts.txt" >&2; exit 3; }
command -v jq >/dev/null 2>&1 || { echo "jq required" >&2; exit 3; }

if [ -n "${FASTPING_BIN:-}" ]; then bin="$FASTPING_BIN"
elif [ "$backend" = "afpacket" ]; then bin="fastping-afpacket"
else bin="fastping"; fi

json="$("$bin" -o json -C "$count" -t "$timeout" -f "$file")" || {
  echo "fastping failed" >&2; exit 3; }

# Emit "host\tservice\trc\toutput" rows; thresholds applied in jq (float-safe).
rows="$(printf '%s' "$json" | jq -r --arg svc "$service" \
  --argjson wl "$wloss" --argjson cl "$closs" '
  .[] |
  (.loss*100) as $pl | (.rtt*1000) as $rta |
  (if .alive==0 or $pl>=$cl then 2 elif $pl>=$wl then 1 else 0 end) as $rc |
  (if $rc==2 then "CRITICAL" elif $rc==1 then "WARNING" else "OK" end) as $st |
  (if .alive==0
     then "FASTPING \($st) - \(.ip) is DOWN (100% loss) | rta=;;;0; pl=100%;\($wl);\($cl);0;100"
     else "FASTPING \($st) - \(.ip) rta \($rta|.*1000|round/1000)ms, lost \($pl|round)% | rta=\($rta|.*1000|round/1000)ms;\($wl);\($cl);0; pl=\($pl|round)%;\($wl);\($cl);0;100"
   end) as $out |
  [ .name, $svc, ($rc|tostring), $out ] | @tsv')"

now=$(date +%s)
count_sent=0
if [ -n "$nsca" ]; then
  hostport="${nsca%:*}"; port="${nsca##*:}"; [ "$port" = "$nsca" ] && port=5667
  # send_nsca expects: host<TAB>service<TAB>rc<TAB>output  (no timestamp)
  printf '%s\n' "$rows" | while IFS=$'\t' read -r h s rc o; do
      printf '%s\t%s\t%s\t%s\n' "$h" "$s" "$rc" "$o"
    done | send_nsca -H "$hostport" -p "$port" -c "$nsca_cfg" >/dev/null
  count_sent=$(printf '%s\n' "$rows" | grep -c .)
else
  [ -p "$pipe" ] || { echo "command pipe not found: $pipe" >&2; exit 3; }
  while IFS=$'\t' read -r h s rc o; do
    [ -n "$h" ] || continue
    printf '[%s] PROCESS_SERVICE_CHECK_RESULT;%s;%s;%s;%s\n' "$now" "$h" "$s" "$rc" "$o" >> "$pipe"
    count_sent=$((count_sent+1))
  done <<< "$rows"
fi
echo "submitted $count_sent passive results (service '$service')"
