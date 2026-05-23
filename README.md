# netscan

A Python subnet scanner that discovers online hosts, resolves their hostnames, detects OS hints, looks up MAC vendors, scans open ports, and grabs service banners.

## Features

- **Auto-detects** your local IP and scans the `/24` subnet
- **Three-phase parallel scan:**
  1. **Host discovery** — ICMP ping with TTL capture; TCP fallback for ICMP-blocked hosts
  2. **Port scan** — 63 well-known ports scanned per host by default (see list below)
  3. **Banner grab** — identifies the service version on each open port
- **OS hint from TTL** — infers Linux/macOS, Windows, or network device from the ping TTL
- **Three hostname resolution methods**, tried in order:
  | Method | Catches |
  |---|---|
  | mDNS / Bonjour | Macs, iPhones, iPads, printers, Apple TV, Avahi Linux |
  | DNS (reverse PTR) | Routers, servers with DNS entries |
  | NetBIOS (port 137) | Windows PCs, Samba / NAS devices |
- **MAC address + vendor** — reads the ARP cache and looks up the IEEE OUI manufacturer
- Shows resolution method tag `[mDNS]`, `[DNS]`, `[NetBIOS]` for each resolved host

## Requirements

- Python 3.10+
- [`zeroconf`](https://pypi.org/project/zeroconf/) — mDNS browsing
- [`mac-vendor-lookup`](https://pypi.org/project/mac-vendor-lookup/) *(optional)* — MAC manufacturer names

## Setup

```bash
# Create and activate the virtual environment
python3 -m venv venv
source venv/bin/activate      # macOS / Linux
# venv\Scripts\activate       # Windows

# Install dependencies
pip install zeroconf mac-vendor-lookup
```

## Usage

```bash
# Full scan: host discovery + port scanning + banner grabbing
venv/bin/python3 netscan.py

# Host discovery only (faster — skips port scanning and banners)
venv/bin/python3 netscan.py --no-ports

# Port scan without banner grabbing
venv/bin/python3 netscan.py --no-banners

# Scan specific ports only
venv/bin/python3 netscan.py --ports 22,80,443,554

# Adjust timeouts
venv/bin/python3 netscan.py --port-timeout 0.3 --banner-timeout 1.5 --mdns-time 3
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--no-ports` | — | Skip port scanning (and banner grabbing) |
| `--no-banners` | — | Skip banner grabbing only |
| `--ports PORT[,PORT...]` | all 63 | Comma-separated list of ports to scan |
| `--port-timeout SEC` | `0.5` | TCP connect timeout per port (seconds) |
| `--banner-timeout SEC` | `2.0` | Banner read timeout per port (seconds) |
| `--mdns-time SEC` | `5.0` | How long to listen for mDNS announcements |

## Sample output

```
Local IP : 192.168.2.120
Network  : 192.168.2.0/24
FD limit : raised 256 → 8192
Ports    : 63 ports (21–51820)  [+banners]

Collecting mDNS/Bonjour announcements (5 s)...
mDNS: 16 name(s) found

Phase 1: Discovering hosts in 192.168.2.0/24 (254 IPs)...

  192.168.2.1        (unresolved)                           [-]
  192.168.2.134      HP28C5C8711735.local                   [mDNS]  Linux/macOS(TTL=64)
  192.168.2.158      mypc.local                             [mDNS]  Windows(TTL=128)
  ...

  → 12 online host(s)

Phase 2: Port scanning 12 hosts × 63 ports = 756 probes...
  → 18 open port(s) found

Phase 3: Grabbing banners on 18 open port(s)...
  → 11 banner(s) captured

════════════════════════════════════════════════════════════════════════════════
  192.168.2.0/24  —  12 online  /  8 resolved  /  63 ports scanned
════════════════════════════════════════════════════════════════════════════════

  192.168.2.1        (unresolved)                           [-]  aa:bb:cc:dd:ee:ff  (Netgear)  53/DNS  80/HTTP[nginx/1.24]  443/HTTPS
  192.168.2.134      HP28C5C8711735.local                   [mDNS]  Linux/macOS  80/HTTP  443/HTTPS  631/IPP  9100/JetDirect
  192.168.2.161      nas.local                              [mDNS]  Linux/macOS  22/SSH[SSH-2.0-OpenSSH_9.3]  80/HTTP  5000/Synology-DSM
  ...
```

## Default port list

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 554 | RTSP |
| 22 | SSH | 631 | IPP (printing) |
| 23 | Telnet | 873 | rsync |
| 25 | SMTP | 1194 | OpenVPN |
| 53 | DNS | 1521 | Oracle DB |
| 67/68 | DHCP | 1723 | PPTP |
| 80 | HTTP | 1883 | MQTT |
| 110 | POP3 | 1900 | UPnP/SSDP |
| 111 | RPCbind | 1935 | RTMP |
| 139 | NetBIOS-SSN | 2049 | NFS |
| 143 | IMAP | 2375/2376 | Docker |
| 161 | SNMP | 3000 | HTTP-dev |
| 443 | HTTPS | 3306 | MySQL |
| 445 | SMB | 3389 | RDP |
| 465 | SMTPS | 4200 | HTTP-dev |
| 515 | LPD | 4343 | HomeAssistant TLS |
| 548 | AFP | 5000 | Synology DSM |
| 587 | SMTP submission | 5001 | Synology HTTPS |
| 993 | IMAPS | 5432 | PostgreSQL |
| 995 | POP3S | 5683 | CoAP |
| 8008 | HTTP-alt (Chromecast) | 5900/5901 | VNC |
| 8080 | HTTP proxy | 6379 | Redis |
| 8096 | Jellyfin | 6443 | Kubernetes API |
| 8123 | Home Assistant | 7000/7100 | AirPlay |
| 8443 | HTTPS-alt | 8554 | RTSP-alt |
| 8883 | MQTT TLS | 8888 | HTTP-dev (Jupyter) |
| 8920 | Jellyfin HTTPS | 9000 | Portainer |
| 9090 | Cockpit | 9100 | JetDirect |
| 27017 | MongoDB | 32400 | Plex |
| 51820 | WireGuard | | |
