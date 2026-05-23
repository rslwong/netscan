#!/usr/bin/env python3
"""Subnet scanner — host discovery, hostname resolution, OS hint, MAC/vendor, port scan, banners.

Resolution order per host:
  1. mDNS    — Bonjour/Avahi service browsing
  2. DNS     — standard reverse PTR via system resolver
  3. NetBIOS — UDP node-status query (port 137)

Port discovery:
  - ICMP ping with TTL capture → OS hint (Linux/macOS / Windows / Network device)
  - TCP fallback for ICMP-blocked hosts
  - Parallel TCP port scan against a catalogue of 63 well-known ports
  - Banner grab on each open port (SSH, HTTP/S, FTP, SMTP, RTSP, generic)

MAC enrichment (post-sweep, from ARP cache):
  - MAC address from system ARP table
  - Manufacturer lookup via IEEE OUI database (mac-vendor-lookup)
"""

import argparse
import ipaddress
import re
import resource
import socket
import ssl
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from zeroconf import ServiceBrowser, ServiceStateChange, Zeroconf

try:
    from mac_vendor_lookup import MacLookup as _MacLookup, VendorNotFoundError as _VendorNotFoundError
    _mac_lookup: _MacLookup | None = _MacLookup()
    # Warm-test so a missing DB is caught here rather than mid-scan
    try:
        _mac_lookup.lookup("00:00:00:00:00:00")
    except _VendorNotFoundError:
        pass
    except Exception:
        print("Downloading MAC vendor database (one-time)...")
        _mac_lookup.update_vendors()
except ImportError:
    _mac_lookup = None


# ---------------------------------------------------------------------------
# Port catalogue
# ---------------------------------------------------------------------------

PORT_NAMES: dict[int, str] = {
    # Remote access
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    3389:  "RDP",
    5900:  "VNC",
    5901:  "VNC-2",
    # Web
    80:    "HTTP",
    443:   "HTTPS",
    8008:  "HTTP-alt",
    8080:  "HTTP-proxy",
    8443:  "HTTPS-alt",
    8888:  "HTTP-dev",
    3000:  "HTTP-dev2",
    4200:  "HTTP-dev3",
    # Email
    25:    "SMTP",
    465:   "SMTPS",
    587:   "SMTP-sub",
    110:   "POP3",
    995:   "POP3S",
    143:   "IMAP",
    993:   "IMAPS",
    # File sharing / storage
    445:   "SMB",
    139:   "NetBIOS-SSN",
    548:   "AFP",
    2049:  "NFS",
    873:   "rsync",
    # Printing
    631:   "IPP",
    9100:  "JetDirect",
    515:   "LPD",
    # Streaming / media
    554:   "RTSP",
    8554:  "RTSP-alt",
    1935:  "RTMP",
    7000:  "AirPlay",
    7100:  "AirPlay-2",
    32400: "Plex",
    8096:  "Jellyfin",
    8920:  "Jellyfin-HTTPS",
    1900:  "UPnP-SSDP",
    # DNS / network infra
    53:    "DNS",
    67:    "DHCP",
    68:    "DHCP-client",
    161:   "SNMP",
    # IoT / smart home
    1883:  "MQTT",
    8883:  "MQTT-TLS",
    8123:  "HomeAssistant",
    4343:  "HomeAssistant-TLS",
    5683:  "CoAP",
    # NAS / management UIs
    5000:  "Synology-DSM",
    5001:  "Synology-HTTPS",
    9000:  "Portainer",
    9090:  "Cockpit",
    # VPN / tunnels
    1194:  "OpenVPN",
    1723:  "PPTP",
    51820: "WireGuard",
    # Databases
    3306:  "MySQL",
    5432:  "PostgreSQL",
    6379:  "Redis",
    27017: "MongoDB",
    1521:  "Oracle",
    # Misc
    111:   "RPCbind",
    2375:  "Docker",
    2376:  "Docker-TLS",
    6443:  "k8s-API",
}

DEFAULT_PORTS = sorted(PORT_NAMES.keys())

# Port sets used during banner grabbing
_HTTPS_PORTS = frozenset({443, 8443, 8920, 4343, 5001, 993, 995, 465})
_HTTP_PORTS  = frozenset({80, 8008, 8080, 8888, 3000, 4200, 5000, 9000, 9090, 8096, 8123, 32400})
_RTSP_PORTS  = frozenset({554, 8554})
_FTP_SMTP    = frozenset({21, 25, 587})


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Host:
    ip: str
    hostname: str | None
    method: str | None
    online: bool
    ttl: int | None = None
    os_hint: str | None = None
    mac: str | None = None
    vendor: str | None = None
    open_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def raise_fd_limit() -> tuple[int, int]:
    """Best-effort raise of the open-file soft limit; return (old_soft, new_soft)."""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(hard, 8192)
        if target > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            return soft, target
        return soft, soft
    except (OSError, ValueError):
        return 0, 0


def get_local_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


def get_subnet(local_ip: str, prefix_len: int = 24) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Interface(f"{local_ip}/{prefix_len}").network


# ---------------------------------------------------------------------------
# Enhancement 2: ping with TTL + OS hint
# ---------------------------------------------------------------------------

def ping(ip: str, timeout: int = 1) -> tuple[bool, int | None]:
    """Ping once; return (reachable, ttl). TTL is None if unparseable."""
    result = subprocess.run(
        ["ping", "-c", "1", "-W", str(timeout), ip],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return False, None
    m = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)
    ttl = int(m.group(1)) if m else None
    return True, ttl


def ttl_to_os(ttl: int | None) -> str | None:
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux/macOS"
    if ttl <= 128:
        return "Windows"
    return "Network device"


# ---------------------------------------------------------------------------
# Enhancement 3: TCP fallback for ICMP-blocked hosts
# ---------------------------------------------------------------------------

_TCP_PROBE_PORTS = [80, 443, 22, 554, 8080, 8443, 8008]


def tcp_probe(ip: str, timeout: float = 0.5) -> bool:
    """Return True if any common TCP port responds (for ICMP-blocked hosts)."""
    for port in _TCP_PROBE_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return True
    return False


# ---------------------------------------------------------------------------
# Enhancement 1: MAC address and vendor lookup
# ---------------------------------------------------------------------------

def get_arp_table() -> dict[str, str]:
    """Return {ip: MAC} from the system ARP cache."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
        table: dict[str, str] = {}
        for line in out.splitlines():
            # macOS / Linux: hostname (1.2.3.4) at aa:bb:cc:dd:ee:ff ...
            m = re.search(
                r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F]{1,2}(?:[:\-][0-9a-fA-F]{1,2}){5})",
                line,
            )
            if m:
                table[m.group(1)] = m.group(2).upper().replace("-", ":")
        return table
    except Exception:
        return {}


def lookup_vendor(mac: str) -> str | None:
    if _mac_lookup is None:
        return None
    try:
        return _mac_lookup.lookup(mac)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Enhancement 4: Banner grabbing
# ---------------------------------------------------------------------------

def _read_bytes(s: socket.socket, max_bytes: int = 512) -> bytes:
    data = b""
    s.settimeout(1.5)
    try:
        while len(data) < max_bytes:
            chunk = s.recv(max_bytes - len(data))
            if not chunk:
                break
            data += chunk
    except (socket.timeout, OSError):
        pass
    return data


def _parse_banner(port: int, data: bytes) -> str | None:
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return None
    first = lines[0].strip()

    # SSH
    if first.startswith("SSH-"):
        return first[:60]

    # FTP / SMTP greeting
    if port in _FTP_SMTP and re.match(r"2[012]\d", first):
        return first[3:].strip()[:60]

    # HTTP(S) — prefer Server header, fall back to status line
    if port in (_HTTP_PORTS | _HTTPS_PORTS) or "HTTP/" in first:
        for line in lines:
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()[:60]
        if "HTTP/" in first:
            return first[:60]

    # RTSP
    if port in _RTSP_PORTS:
        for line in lines:
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()[:60]

    # Generic — first printable line
    printable = "".join(c for c in first if c.isprintable()).strip()
    return printable[:60] if printable else None


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Connect to ip:port and return a short service banner."""
    use_tls = port in _HTTPS_PORTS
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(raw, server_hostname=ip) as s:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    return _parse_banner(port, _read_bytes(s))
            else:
                if port in _HTTP_PORTS:
                    raw.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                elif port in _RTSP_PORTS:
                    raw.sendall(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                return _parse_banner(port, _read_bytes(raw))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Port scanning primitive (called directly from the shared pool in scan_subnet)
# ---------------------------------------------------------------------------

def check_port(ip: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0


# ---------------------------------------------------------------------------
# Hostname resolution (mDNS → DNS → NetBIOS)
# ---------------------------------------------------------------------------

_MDNS_SERVICE_TYPES = [
    "_workstation._tcp.local.",
    "_ssh._tcp.local.",
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_device-info._tcp.local.",
    "_sleep-proxy._udp.local.",
    "_raop._tcp.local.",
    "_airplay._tcp.local.",
    "_ipp._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_companion-link._tcp.local.",
    "_homekit._tcp.local.",
]


def collect_mdns_names(listen_secs: float = 5.0) -> dict[str, str]:
    ip_to_name: dict[str, str] = {}

    def on_change(zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange) -> None:
        if state_change is not ServiceStateChange.Added:
            return
        info = zeroconf.get_service_info(service_type, name)
        if not info or not info.server:
            return
        hostname = info.server.rstrip(".")
        for addr in info.parsed_addresses():
            if addr not in ip_to_name:
                ip_to_name[addr] = hostname

    zc = Zeroconf()
    _browsers = [ServiceBrowser(zc, svc, handlers=[on_change]) for svc in _MDNS_SERVICE_TYPES]
    time.sleep(listen_secs)
    zc.close()
    return ip_to_name


def resolve_dns(ip: str, timeout: float = 2.0) -> str | None:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old)


def _build_nbstat_packet() -> bytes:
    raw = b"\x2a" + b"\x20" * 14 + b"\x00"
    encoded = b"".join(bytes([0x41 | (b >> 4), 0x41 | (b & 0xF)]) for b in raw)
    header = struct.pack("!HHHHHH", 0x8228, 0x0000, 1, 0, 0, 0)
    question = bytes([0x20]) + encoded + b"\x00" + struct.pack("!HH", 0x0021, 0x0001)
    return header + question


_NBSTAT_PACKET = _build_nbstat_packet()


def resolve_netbios(ip: str, timeout: float = 2.0) -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(_NBSTAT_PACKET, (ip, 137))
            data, _ = sock.recvfrom(1024)
        offset = 12
        if len(data) <= offset:
            return None
        offset += 2 if (data[offset] & 0xC0 == 0xC0) else 35
        offset += 10
        if offset >= len(data):
            return None
        num_names = data[offset]
        offset += 1
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            name = data[offset:offset + 15].decode("ascii", errors="ignore").rstrip()
            name_type = data[offset + 15]
            flags = struct.unpack_from("!H", data, offset + 16)[0]
            offset += 18
            if name_type == 0x00 and not (flags & 0x8000) and name:
                return name
        return None
    except Exception:
        return None


def resolve_hostname(ip: str, mdns_map: dict[str, str]) -> tuple[str | None, str | None]:
    if ip in mdns_map:
        return mdns_map[ip], "mDNS"
    name = resolve_dns(ip)
    if name:
        return name, "DNS"
    name = resolve_netbios(ip)
    if name:
        return name, "NetBIOS"
    return None, None


# ---------------------------------------------------------------------------
# Per-host scan
# ---------------------------------------------------------------------------

def discover_host(ip: str, local_ip: str, mdns_map: dict[str, str]) -> Host | None:
    """Phase 1 worker: ping + hostname resolution only (no port scan / banners)."""
    is_local = (ip == local_ip)

    if is_local:
        online, ttl = True, None
    else:
        online, ttl = ping(ip)
        if not online:
            online = tcp_probe(ip)

    if not online:
        return None

    hostname, method = resolve_hostname(ip, mdns_map)
    if is_local:
        hostname = f"{hostname or socket.gethostname()} (this machine)"
        method = method or "local"

    return Host(
        ip=ip,
        hostname=hostname,
        method=method,
        online=True,
        ttl=ttl,
        os_hint=ttl_to_os(ttl),
    )


# ---------------------------------------------------------------------------
# Subnet sweep
# ---------------------------------------------------------------------------

def _fmt_ports(open_ports: list[int], banners: dict[int, str]) -> str:
    parts = []
    for p in open_ports:
        name = PORT_NAMES.get(p, "?")
        banner = banners.get(p)
        parts.append(f"{p}/{name}[{banner}]" if banner else f"{p}/{name}")
    return "  ".join(parts)


def scan_subnet(
    network: ipaddress.IPv4Network,
    local_ip: str,
    mdns_map: dict[str, str],
    ports: list[int],
    do_banners: bool,
    port_timeout: float,
    banner_timeout: float,
    discover_workers: int = 64,
    port_workers: int = 200,
    banner_workers: int = 50,
) -> list[Host]:
    all_ips = [str(ip) for ip in network.hosts()]

    # ── Phase 1: host discovery (ping + hostname) ───────────────────────────
    print(f"Phase 1: Discovering hosts in {network} ({len(all_ips)} IPs)...\n")
    online: dict[str, Host] = {}
    with ThreadPoolExecutor(max_workers=discover_workers) as ex:
        futures = {ex.submit(discover_host, ip, local_ip, mdns_map): ip for ip in all_ips}
        for fut in as_completed(futures):
            host = fut.result()
            if host:
                online[host.ip] = host
                name = host.hostname or "(unresolved)"
                tag = f"[{host.method}]" if host.method else "[-]"
                os_str = f"  {host.os_hint}(TTL={host.ttl})" if host.os_hint else ""
                print(f"  {host.ip:<18} {name:<38} {tag}{os_str}")

    print(f"\n  → {len(online)} online host(s)\n")

    # ── Phase 2: port scan (single shared pool across all hosts × ports) ────
    if ports and online:
        tasks = [(ip, p) for ip in online for p in ports]
        print(f"Phase 2: Port scanning {len(online)} hosts × {len(ports)} ports = {len(tasks)} probes...")
        with ThreadPoolExecutor(max_workers=port_workers) as ex:
            futures = {ex.submit(check_port, ip, p, port_timeout): (ip, p) for ip, p in tasks}
            for fut in as_completed(futures):
                if fut.result():
                    ip, port = futures[fut]
                    online[ip].open_ports.append(port)
        for host in online.values():
            host.open_ports.sort()
        total_open = sum(len(h.open_ports) for h in online.values())
        print(f"  → {total_open} open port(s) found\n")

    # ── Phase 3: banner grab (single shared pool across all open ports) ─────
    if do_banners and ports and online:
        banner_tasks = [(ip, p) for ip, h in online.items() for p in h.open_ports]
        if banner_tasks:
            print(f"Phase 3: Grabbing banners on {len(banner_tasks)} open port(s)...")
            with ThreadPoolExecutor(max_workers=banner_workers) as ex:
                futures = {ex.submit(grab_banner, ip, p, banner_timeout): (ip, p) for ip, p in banner_tasks}
                for fut in as_completed(futures):
                    banner = fut.result()
                    if banner:
                        ip, port = futures[fut]
                        online[ip].banners[port] = banner
            grabbed = sum(len(h.banners) for h in online.values())
            print(f"  → {grabbed} banner(s) captured\n")

    results = sorted(online.values(), key=lambda h: ipaddress.IPv4Address(h.ip))

    # ── Enrich with MAC / vendor from ARP cache (populated by ping sweep) ───
    arp_table = get_arp_table()
    for host in results:
        host.mac = arp_table.get(host.ip)
        if host.mac:
            host.vendor = lookup_vendor(host.mac)

    return results


# ---------------------------------------------------------------------------
# Summary output
# ---------------------------------------------------------------------------

def print_summary(hosts: list[Host], network: ipaddress.IPv4Network, ports: list[int]) -> None:
    resolved = sum(1 for h in hosts if h.hostname)
    print(f"\n{'═' * 80}")
    print(f"  {network}  —  {len(hosts)} online  /  {resolved} resolved  /  {len(ports)} ports scanned")
    print(f"{'═' * 80}\n")

    for h in hosts:
        name  = h.hostname or "(unresolved)"
        meth  = h.method or "—"
        os    = f"  {h.os_hint}" if h.os_hint else ""
        mac   = f"  {h.mac}" if h.mac else ""
        vend  = f"  ({h.vendor})" if h.vendor else ""
        print(f"  {h.ip:<18} {name:<38} [{meth}]{os}{mac}{vend}")
        ports_str = _fmt_ports(h.open_ports, h.banners)
        if ports_str:
            print(f"  {'':18} {ports_str}")
        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scan a /24 subnet for online hosts, resolve hostnames, and check open ports."
    )
    p.add_argument("--no-ports",   action="store_true", help="Skip port scanning (and banners)")
    p.add_argument("--no-banners", action="store_true", help="Skip banner grabbing")
    p.add_argument("--ports", metavar="PORT[,PORT...]", help="Comma-separated list of ports to scan")
    p.add_argument("--port-timeout",   type=float, default=0.5, metavar="SEC")
    p.add_argument("--banner-timeout", type=float, default=2.0, metavar="SEC")
    p.add_argument("--mdns-time",      type=float, default=5.0, metavar="SEC")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if args.no_ports:
        ports: list[int] = []
        do_banners = False
    elif args.ports:
        ports = sorted({int(p.strip()) for p in args.ports.split(",")})
        do_banners = not args.no_banners
    else:
        ports = DEFAULT_PORTS
        do_banners = not args.no_banners

    old_fd, new_fd = raise_fd_limit()
    local_ip = get_local_ip()
    network  = get_subnet(local_ip)

    print(f"Local IP : {local_ip}")
    print(f"Network  : {network}")
    if new_fd and new_fd != old_fd:
        print(f"FD limit : raised {old_fd} → {new_fd}")
    if ports:
        flags = "+banners" if do_banners else "no banners"
        print(f"Ports    : {len(ports)} ports ({ports[0]}–{ports[-1]})  [{flags}]")
    else:
        print("Ports    : skipped")
    print()

    print(f"Collecting mDNS/Bonjour announcements ({args.mdns_time:.0f} s)...")
    mdns_map = collect_mdns_names(listen_secs=args.mdns_time)
    print(f"mDNS: {len(mdns_map)} name(s) found\n")

    online = scan_subnet(
        network, local_ip, mdns_map,
        ports, do_banners,
        args.port_timeout, args.banner_timeout,
    )
    print_summary(online, network, ports)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(1)
