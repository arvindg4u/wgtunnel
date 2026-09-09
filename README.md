# WGTunnel — rotating WireGuard peer pool + local HTTP proxy

WireGuard counterpart to [FlareTunnel](https://github.com/arvindg4u/FlareTunnel):
there the egress pool is Cloudflare Workers, here it is N WireGuard peers.
One peer is active at a time; rotation switches the tunnel on a timer,
so long-lived egress IPs keep changing.

The local proxy is a **plain CONNECT passthrough** (no TLS interception),
so there is no CA to install and strict HTTP clients work unchanged.

## Requirements

- Go 1.21+
- `wg` + `ip` (`wireguard-tools`, `iproute2`)
- Kernel WireGuard **or** `wireguard-go` userspace (auto-detected)
- root (interface + routing)

## Setup

```sh
cp peers.json.example peers.json   # fill in real keys (never commit!)
./build.sh
./wgtunnel proxy --peers peers.json --listen 127.0.0.1:8080 --interval 300 --verbose
```

`peers.json` format:

```json
[
  {"name": "peer-01", "private_key": "...", "public_key": "...",
   "endpoint": "203.0.113.10:51820", "address": "10.2.0.2/32"}
]
```

## Commands

```sh
./wgtunnel proxy --peers peers.json --listen 127.0.0.1:8080 --interval 300 --verbose
./wgtunnel proxy --peers peers.json --route opencode.ai,api.kilo.ai --blocklist blocklist.txt
./wgtunnel rotate --peers peers.json --iface flare   # switch to next healthy peer now
./wgtunnel status --iface flare                      # handshake / transfer info
./wgtunnel list --peers peers.json                   # all peers, active marked
./wgtunnel test --peers peers.json                   # exit IP per peer (scratch iface)
./wgtunnel test --peers peers.json --peer 4          # single peer only
./wgtunnel export --output peers-backup.json         # backup (keep secret!)
./wgtunnel import --input peers-backup.json          # restore
```

`proxy` flags: `--route` re-applies policy routes every 15s (Android
flushes them); `--blocklist` blocks telemetry/tracker domains with 403
before they touch the VPN; `--interval 0` disables rotation.

> ⚠️ Go slow: rotating or mass-testing too fast triggers server-side
> session throttling (handshakes succeed, data stops). Prefer `--interval`
> 1800s+ and test single peers with gaps.

Proxy config for clients:

```
HTTP_PROXY=http://127.0.0.1:8080
HTTPS_PROXY=http://127.0.0.1:8080
```

## Routing notes

WGTunnel activates the tunnel interface but does **not** touch routes by
default (safe on Termux/Android with policy routing). Direct the traffic
you want through the tunnel, e.g. per-host policy rules:

```sh
ip route add <host-ip>/32 dev flare
ip rule add to <host-ip>/32 lookup main pref 100
```

On regular Linux you can instead route everything:

```sh
ip route add default dev flare table 51820
ip rule add not fwmark 51820 table 51820
ip rule add table main suppress_prefixlength 0
sysctl -w net.ipv4.conf.all.src_valid_mark=1
```

## Termux (rooted, no kernel module)

```sh
apt install wireguard wireguard-go
# wg-quick fails on DNS/policy-routing steps there; WGTunnel shells out to
# wireguard-go + wg + ip directly and works around that.
```
