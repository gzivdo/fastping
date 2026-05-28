#!/bin/sh
# Fetch monitored hosts + their main agent IP from the Zabbix API and write
# "IP host.host" lines (the format `fastping -f` expects).
#
# Usage: ZBX_URL=... ZBX_TOKEN=... ./zbx-hosts.sh [groupid] > /etc/fastping/hosts.txt
set -eu

: "${ZBX_URL:?set ZBX_URL=https://zabbix.example/api_jsonrpc.php}"
: "${ZBX_TOKEN:?set ZBX_TOKEN=<api token>}"
GROUP="${1:-}"

# optional host-group filter
if [ -n "$GROUP" ]; then
    GROUPFILTER="\"groupids\":[\"$GROUP\"],"
else
    GROUPFILTER=""
fi

curl -s -H "Content-Type: application/json" -H "Authorization: Bearer $ZBX_TOKEN" "$ZBX_URL" -d "{
  \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"host.get\",
  \"params\":{
    ${GROUPFILTER}
    \"output\":[\"host\"],
    \"selectInterfaces\":[\"ip\",\"type\",\"main\"],
    \"filter\":{\"status\":0},
    \"monitored_hosts\":true
  }}" \
| jq -r '.result[] | . as $h
         | ($h.interfaces[]? | select(.type=="1" and .main=="1") | .ip)
           + " " + $h.host'
