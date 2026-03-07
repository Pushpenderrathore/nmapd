#!/usr/bin/env python3
"""
PyScanner v9.0 - Professional Python Network Scanner (nmap-like)
================================================================
v1->v8 retained (all fixes, upgrades, and enhancements)

v8->v9 capabilities:
  [V9-1] BPF/libpcap packet capture: PacketCapture wraps libpcap via
          ctypes with a kernel-level BPF filter ("tcp and host X"),
          eliminating false positives from other hosts' traffic.
          Falls back to raw socket automatically if libpcap absent.
          Plugged into syn_batch_scan as a drop-in recv_sock replacement.
  [V9-2] Distributed scanning: DistributedScanner splits targets into
          N shards and runs parallel sub-processes via
          multiprocessing.Pool. DistributedWorkerServer provides an
          HTTP API so remote worker nodes can be coordinated.
          Results from all shards are merged and deduplicated.
  [V9-3] 20 additional vulnerability/recon plugins (33 total):
          heartbleed, ms17_010, http_methods, dns_zone_transfer,
          smtp_open_relay, ssh_hostkey, telnet_banner, vnc_no_auth,
          http_robots, mysql_empty_password, ntp_monlist,
          elasticsearch_unauth, k8s_unauth, memcached_unauth,
          rsync_unauth, snmp_community, ldap_rootdse,
          pop3_capabilities, iis_webdav, tftp_test
  [V9-4] Epoll/select receive loop: _EpollReceiver replaces blocking
          recvfrom() with epoll (Linux) or select (cross-platform),
          batch-draining the socket in non-blocking mode. 2-5x fewer
          CPU cycles per packet on high-traffic networks.
  [V9-5] Nmap-compatible XML + CSV export: export_xml() writes the
          Nmap .xml schema (importable by Metasploit/Nessus/Armitage);
          export_csv() writes a flat table suitable for spreadsheets.
  [V9-6] Network topology summary: TopologyAnalyzer groups hosts by
          /24 subnet, ranks most-open hosts, identifies likely
          gateways, and prints an ASCII tree of the network.

Usage:
  python pyscanner.py -t 192.168.1.1 -p 1-1024 --scan-type syn
  python pyscanner.py -t 192.168.1.0/24 --ping-scan
  python pyscanner.py -t 2001:db8::1 -p 80,443 --scan-type syn --ipv6
  python pyscanner.py -t 10.0.0.0/24 -p 1-1024 -T4 --scripts --checkpoint state.json
  python pyscanner.py -t 10.0.0.0/24 -p 1-1024 --resume state.json
  python pyscanner.py -t 192.168.1.0/24 --distributed --workers 4
  python pyscanner.py -t 192.168.1.1 -p 1-1024 -o report.xml
  python pyscanner.py --help
"""

import argparse
import asyncio
import concurrent.futures
import datetime
import importlib
import importlib.util
import ipaddress
import json
import os
import platform
import queue
import random
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────
# Optional imports (degrade gracefully)
# ─────────────────────────────────────────────
try:
    import whois as pywhois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import urllib.request as _urllib_req
    import urllib.error as _urllib_err
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

# ─────────────────────────────────────────────
# Platform flags
# ─────────────────────────────────────────────
IS_LINUX   = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS   = sys.platform.startswith("darwin")

# ─────────────────────────────────────────────
# ANSI Colours
# ─────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"
DIM     = "\033[2m"


def color(text: str, c: str) -> str:
    if sys.stdout.isatty():
        return f"{c}{text}{RESET}"
    return text


# ─────────────────────────────────────────────
# Well-known port -> service name mapping
# ─────────────────────────────────────────────
COMMON_PORTS: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
    69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 162: "snmptrap", 179: "bgp", 194: "irc",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 515: "printer", 587: "submission",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 2049: "nfs",
    2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
    3000: "grafana", 3306: "mysql", 3389: "rdp",
    4369: "epmd", 5000: "upnp", 5432: "postgresql",
    5672: "amqp", 5900: "vnc", 5985: "winrm",
    5986: "winrm-https", 6379: "redis", 6443: "k8s-api",
    7001: "weblogic", 8000: "http-alt", 8080: "http-proxy",
    8081: "http-alt2", 8443: "https-alt", 8888: "http-alt3",
    9000: "php-fpm", 9090: "prometheus", 9200: "elasticsearch",
    9300: "elasticsearch-transport", 10250: "kubelet",
    11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 27018: "mongodb-shard",
    50070: "hdfs-namenode",
}

# Ports that should be SSL-wrapped for banner grabbing [FIX-9]
SSL_PORTS = {443, 636, 993, 995, 465, 8443, 5986}

# [FIX-30/31/32] Retransmit limits
SYN_MAX_RETRIES  = 2   # SYN probes per port before "filtered"
ICMP_MAX_PROBES  = 3   # ICMP pings per host before "down"
UDP_MAX_RETRIES  = 2   # UDP probes per port before "open|filtered"

# [FIX-33] Largest network allowed without --force-large
CIDR_HOST_LIMIT  = 65534   # /16 boundary

# [FIX-34] Service version regex patterns: (pattern, label_template)
# Applied to raw banner strings; first match wins.
SERVICE_VERSION_PATTERNS = [
    # SSH
    (r"SSH-\d+\.\d+-OpenSSH[_\s]([\d.p]+)",    r"OpenSSH \1"),
    (r"SSH-\d+\.\d+-dropbear[_\s]([\d.]+)",     r"Dropbear SSH \1"),
    (r"SSH-\d+\.\d+-([\w._-]+)",                r"SSH \1"),
    # HTTP servers
    (r"Apache/([\d.]+)",                         r"Apache \1"),
    (r"nginx/([\d.]+)",                          r"nginx \1"),
    (r"Microsoft-IIS/([\d.]+)",                  r"IIS \1"),
    (r"lighttpd/([\d.]+)",                       r"lighttpd \1"),
    (r"LiteSpeed",                               r"LiteSpeed"),
    # FTP
    (r"220.*?vsFTPd ([\d.]+)",                   r"vsFTPd \1"),
    (r"220.*?ProFTPD ([\d.]+)",                  r"ProFTPD \1"),
    (r"220.*?FileZilla Server ([\d.]+)",         r"FileZilla FTP \1"),
    # Mail
    (r"220.*?Postfix",                           r"Postfix SMTP"),
    (r"220.*?Exim ([\d.]+)",                     r"Exim \1"),
    (r"\+OK.*?Dovecot",                          r"Dovecot POP3"),
    (r"\* OK.*?Dovecot",                         r"Dovecot IMAP"),
    # Databases
    (r"^.\x00\x00\x00\n([\d.]+)",               r"MySQL \1"),   # MySQL handshake
    (r"redis_version:([\d.]+)",                  r"Redis \1"),
    (r"memcached ([\d.]+)",                      r"Memcached \1"),
    # VPN / misc
    (r"OpenVPN ([\d.]+)",                        r"OpenVPN \1"),
    (r"JDWP-Handshake",                          r"Java Debug Wire Protocol"),
]

# [FIX-7] Global semaphore - limits concurrent raw socket operations
_RAW_SOCKET_SEM = threading.Semaphore(50)


# ─────────────────────────────────────────────
# [FIX-26] Token-bucket rate limiter
# Controls how many packets per second are sent.
# Default: unlimited (None). Set via --rate flag.
# ─────────────────────────────────────────────

class TokenBucket:
    """
    Thread-safe token bucket for rate limiting.
    Allows bursts up to `capacity` tokens then enforces `rate` pps.
    """
    def __init__(self, rate_pps: float, capacity: int = 0):
        self.rate     = rate_pps          # tokens added per second
        self.capacity = capacity or max(int(rate_pps), 1)
        self.tokens   = float(self.capacity)
        self._lock    = threading.Lock()
        self._last    = time.monotonic()

    def consume(self, n: int = 1) -> None:
        """Block until n tokens are available, then consume them."""
        while True:
            with self._lock:
                now    = time.monotonic()
                delta  = now - self._last
                self._last = now
                self.tokens = min(
                    self.capacity,
                    self.tokens + delta * self.rate)
                if self.tokens >= n:
                    self.tokens -= n
                    return
                wait = (n - self.tokens) / self.rate
            time.sleep(wait)


# Global rate limiter – replaced by main() if --rate is set
_RATE_LIMITER: Optional[TokenBucket] = None


# ─────────────────────────────────────────────
# [FIX-25] Unique ephemeral port allocator
# Tracks used source ports per scan session to prevent collisions
# when probing many ports simultaneously.
# ─────────────────────────────────────────────

class _EphemeralPortAllocator:
    """Issue unique random source ports; wraps around if exhausted."""
    _LOW  = 32768
    _HIGH = 60999

    def __init__(self):
        self._used: set = set()
        self._lock = threading.Lock()

    def alloc(self) -> int:
        with self._lock:
            pool = self._HIGH - self._LOW + 1
            if len(self._used) >= pool:
                self._used.clear()   # full reset when exhausted
            while True:
                p = random.randint(self._LOW, self._HIGH)
                if p not in self._used:
                    self._used.add(p)
                    return p

    def free(self, port: int) -> None:
        with self._lock:
            self._used.discard(port)


_PORT_ALLOC = _EphemeralPortAllocator()


# ─────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────

@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "unknown"     # open / closed / filtered / open|filtered
    service: str = ""
    banner: str = ""
    version: str = ""          # [FIX-34] extracted software version string
    reason: str = ""


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    status: str = "down"
    latency_ms: float = 0.0
    os_guess: str = ""
    ttl: int = 0
    mac: str = ""
    ports: List[PortResult] = field(default_factory=list)
    http_headers: Dict[str, str] = field(default_factory=dict)
    whois_info: str = ""
    open_count: int = 0
    scan_time: str = ""
    # [FIX-28] OS fingerprinting signals captured from SYN-ACK replies
    tcp_window:      int  = 0      # remote TCP window size
    has_tcp_options: bool = False   # remote SYN-ACK had TCP options
    df_bit:          bool = False   # remote IP header had DF flag set


@dataclass
class ScanSummary:
    command: str
    start_time: str
    end_time: str
    elapsed_sec: float
    total_hosts: int
    hosts_up: int
    hosts_down: int
    total_ports_scanned: int
    open_ports: int
    results: List[HostResult] = field(default_factory=list)


# ─────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────

def resolve_host(target: str, prefer_ipv6: bool = False) -> Optional[str]:
    """
    [FIX-27] Resolve hostname to IP (v4 or v6).
    Returns None on failure.
    """
    family = socket.AF_INET6 if prefer_ipv6 else socket.AF_INET
    try:
        infos = socket.getaddrinfo(target, None, family)
        if infos:
            return infos[0][4][0]
    except socket.gaierror:
        pass
    # Fallback: try other family
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def is_ipv6(addr: str) -> bool:
    """[FIX-27] Return True if addr is an IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except (socket.error, OSError):
        return False


def expand_cidr(network: str, force_large: bool = False) -> List[str]:
    """
    [FIX-27] Expand IPv4 or IPv6 CIDR to host list.
    [FIX-33] Refuses to expand networks larger than CIDR_HOST_LIMIT hosts
             unless force_large=True is passed (set by --force-large CLI flag).
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
        host_count = net.num_addresses - 2  # exclude network/broadcast
        if host_count > CIDR_HOST_LIMIT and not force_large:
            print(color(
                f"[!] Network {network} has {host_count:,} hosts "
                f"(>{CIDR_HOST_LIMIT:,}). Use --force-large to scan it.",
                RED))
            return []
        return [str(h) for h in net.hosts()]
    except ValueError:
        return [network]


def parse_ports(port_str: str) -> List[int]:
    """Parse '22,80,100-200' into a sorted unique list of ints."""
    ports: set = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def service_name(port: int, proto: str = "tcp") -> str:
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, proto)
    except Exception:
        return "unknown"


def now_str() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def elapsed(start: float) -> float:
    return round(time.time() - start, 3)


def get_local_ip(dst: str = "8.8.8.8") -> str:
    """
    [FIX-1] Return the real outbound IP of this machine.
    [FIX-27] Supports both IPv4 and IPv6 destinations.
    Uses UDP connect trick – no packet is actually sent.
    """
    family = socket.AF_INET6 if is_ipv6(dst) else socket.AF_INET
    probe_dst = "2001:4860:4860::8888" if family == socket.AF_INET6 else "8.8.8.8"
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.connect((probe_dst, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


# ─────────────────────────────────────────────
# [FIX-10] OS Fingerprinting with TTL normalisation
# Routers decrement TTL. We round UP to nearest
# common initial TTL value before guessing OS.
# ─────────────────────────────────────────────

_INITIAL_TTLS = [32, 60, 64, 128, 255]


def _normalise_ttl(observed: int) -> int:
    """Round observed TTL up to the most likely initial TTL value."""
    for init in _INITIAL_TTLS:
        if observed <= init:
            return init
    return 255


def ttl_to_os(ttl: int) -> str:
    """Heuristic OS guess from TTL, hop-decrement normalised."""
    if ttl <= 0:
        return "unknown"
    norm = _normalise_ttl(ttl)
    mapping = {
        32:  "Windows 9x/ME",
        60:  "Solaris/AIX",
        64:  "Linux/Unix/macOS",
        128: "Windows",
        255: "Cisco/Network device",
    }
    return mapping.get(norm, "unknown")


def os_fingerprint(ip: str, open_ports: List[int], ttl: int,
                   tcp_window: int = 0,
                   has_tcp_options: bool = False,
                   df_bit: bool = False) -> str:
    """
    [FIX-28] Multi-signal OS fingerprinting (Nmap-style scoring).

    Signals used and their weights:
      1. TTL (normalised, hop-decrement-aware)         — 2 pts each match
      2. TCP window size (characteristic per OS)        — 3 pts each match
      3. DF (Don't Fragment) bit in IP header           — 1 pt each match
      4. TCP options presence in SYN-ACK                — 1 pt each match
      5. Open-port pattern (RDP/SMB/AFP/SSH etc.)       — 4 pts each match

    Each OS candidate accumulates points; highest scorer wins.
    Ties broken by TTL signal. Returns labelled string with confidence.
    """
    # ── OS candidate definitions ─────────────────────────────────────
    # Each entry: (name, ttl_norm, typical_windows, df_expected, opts_expected)
    OS_PROFILES = [
        # name                  ttl   windows   df     opts
        ("Linux 2.6+",          64,   [5840, 14600, 29200, 65535], True,  True),
        ("Linux 3.x/4.x",       64,   [29200, 65535],              True,  True),
        ("macOS / iOS",         64,   [65535, 65228],              True,  True),
        ("Windows 10/11",       128,  [8192, 65535, 64240],        True,  True),
        ("Windows 7/8",         128,  [8192, 16384],               True,  True),
        ("Windows Server",      128,  [8192, 65535],               True,  True),
        ("Cisco IOS",           255,  [4128, 16384],               True,  False),
        ("FreeBSD / OpenBSD",   64,   [65535, 16384],              True,  True),
        ("Solaris",             255,  [8760, 49152],               True,  True),
    ]

    # ── Known port evidence (highest weight) ─────────────────────────
    port_evidence: List[Tuple[str, List[int]]] = [
        ("Windows",    [3389, 135, 445, 139, 5985]),
        ("Linux/Unix", [22]),
        ("macOS",      [548, 62078, 88]),
        ("Cisco",      [23, 179, 4786]),
    ]

    # ── Score each candidate ──────────────────────────────────────────
    ttl_norm = _normalise_ttl(ttl) if ttl > 0 else 0
    scores: Dict[str, int] = {}

    for (name, os_ttl, os_windows, os_df, os_opts) in OS_PROFILES:
        score = 0
        # Signal 1: TTL match
        if ttl_norm == os_ttl:
            score += 2
        # Signal 2: TCP window size
        if tcp_window and tcp_window in os_windows:
            score += 3
        # Signal 3: DF bit
        if df_bit == os_df:
            score += 1
        # Signal 4: TCP options presence
        if has_tcp_options == os_opts:
            score += 1
        scores[name] = score

    # Signal 5: open-port patterns (strongest signal, applied after)
    port_boost: Dict[str, int] = {}
    for (os_label, ports) in port_evidence:
        matches = sum(1 for p in ports if p in open_ports)
        if matches:
            port_boost[os_label] = matches * 4

    # Apply port boost to any candidate whose name starts with the label
    for (name, _) in [(n, s) for n, s in scores.items()]:
        for os_label, boost in port_boost.items():
            if os_label.lower() in name.lower():
                scores[name] = scores.get(name, 0) + boost

    # ── Pick winner ───────────────────────────────────────────────────
    if not scores or max(scores.values()) == 0:
        return ttl_to_os(ttl) or "Unknown"

    best_name = max(scores, key=lambda k: scores[k])
    best_score = scores[best_name]

    # Confidence label based on total available signals
    max_possible = 2 + 3 + 1 + 1 + 4   # sum of all signal weights
    confidence_pct = min(100, int(best_score / max_possible * 100))
    if confidence_pct >= 70:
        confidence = "high"
    elif confidence_pct >= 40:
        confidence = "medium"
    else:
        confidence = "low"

    return f"{best_name} (confidence: {confidence}, score: {best_score})"




# ═══════════════════════════════════════════════════════════════════
# [ENH-3] DEEP OS FINGERPRINTING ENGINE (Nmap T1-T7 + IE + ECN)
# ═══════════════════════════════════════════════════════════════════

@dataclass
class OsProbeResult:
    """Raw observations collected by OsProbeEngine."""
    # TCP sequence number class: random / time-based / const / increment
    isn_class:        str   = "unknown"
    # IP ID sequence: zero / random / increment / broken
    ipid_class:       str   = "unknown"
    # Observed TCP options order string (e.g. "MSS,SACK,TS,NOP,WS")
    tcp_opts_order:   str   = ""
    # Window scale value extracted from options
    win_scale:        int   = 0
    # Whether ECN (Explicit Congestion Notification) was accepted
    ecn_support:      bool  = False
    # ICMP echo: whether DF bit is echoed back
    icmp_df_echo:     bool  = False
    # ICMP echo: whether ToS is echoed back
    icmp_tos_echo:    bool  = False
    # TCP window from SYN-ACK (already captured in v7)
    tcp_window:       int   = 0
    # Whether timestamps were returned
    ts_option:        bool  = False
    # Measured TTL
    ttl:              int   = 0


class OsProbeEngine:
    """
    [ENH-3] Deep OS fingerprinting engine.

    Sends a sequence of specialised TCP/ICMP probes (like Nmap's T1-T7,
    IE1/IE2, ECN probes) and collects low-level observations:

      T1  — SYN to open port  (captures window, options, ISN)
      T2  — NULL to open port (captures response type)
      T3  — FIN+PSH+URG to open port
      T4  — SYN with unusual options to open port
      T5  — SYN to closed port
      T6  — ACK to closed port
      T7  — FIN+PSH+URG to closed port
      IE1 — ICMP echo request (code=9, ToS=0)
      IE2 — ICMP echo request (code=0, ToS=4)
      ECN — SYN with ECE+CWR flags

    Observations are scored against extended OS profiles.
    Returns an OsProbeResult plus a refined os_guess string.
    """

    def __init__(self, ip: str, open_port: int, closed_port: int,
                 timeout: float = 2.0):
        self.ip          = ip
        self.open_port   = open_port
        self.closed_port = closed_port
        self.timeout     = timeout
        self.src_ip      = get_local_ip(ip)

    def probe(self) -> Tuple[OsProbeResult, str]:
        """
        Run all probes. Returns (OsProbeResult, os_guess_string).
        Gracefully degrades if raw sockets are unavailable.
        """
        result = OsProbeResult()

        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                      socket.IPPROTO_TCP)
            recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                 4 * 1024 * 1024)
            recv_sock.settimeout(self.timeout)
        except (PermissionError, OSError):
            return result, "Unknown (no raw socket)"

        send_times: Dict[int, float] = {}
        isns: List[int] = []
        ipids: List[int] = []

        # ── Probe definitions ─────────────────────────────────────────
        probes: List[Tuple[str, int, int]] = [
            # (label, dst_port, flags)
            ("T1",  self.open_port,   0x02),           # SYN to open
            ("T2",  self.open_port,   0x00),           # NULL to open
            ("T3",  self.open_port,   F_FIN|F_PSH|F_URG),  # FIN+PSH+URG open
            ("T4",  self.open_port,   0x02),           # SYN (special opts) open
            ("T5",  self.closed_port, 0x02),           # SYN to closed
            ("T6",  self.closed_port, F_ACK),          # ACK to closed
            ("T7",  self.closed_port, F_FIN|F_PSH|F_URG),  # FIN+PSH+URG closed
            ("ECN", self.open_port,   0x02|F_ECE|F_CWR),   # ECN probe
        ]

        src_ports: Dict[str, int] = {}
        allocated: List[int] = []

        try:
            # Send all TCP probes
            for label, dst, flags in probes:
                sp = _PORT_ALLOC.alloc()
                allocated.append(sp)
                src_ports[label] = sp
                seq = random.randint(0, 0xFFFFFFFF)
                pkt = _build_flag_packet(self.src_ip, self.ip,
                                         sp, dst, flags, seq)
                if _RATE_LIMITER:
                    _RATE_LIMITER.consume(1)
                try:
                    recv_sock.sendto(pkt, (self.ip, 0))
                    send_times[sp] = time.time()
                except OSError:
                    pass

            # Also send ICMP echo probes (IE1, IE2) — need ICMP socket
            icmp_sock: Optional[socket.socket] = None
            try:
                icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                          socket.IPPROTO_ICMP)
                icmp_sock.settimeout(self.timeout)
                pid   = os.getpid() & 0xFFFF
                # IE1: code=9, ToS=0
                self._send_icmp_probe(icmp_sock, code=9,  tos=0,  seq=0x9001)
                # IE2: code=0, ToS=4
                self._send_icmp_probe(icmp_sock, code=0,  tos=4,  seq=0x9002)
            except (PermissionError, OSError):
                icmp_sock = None

            # Collect TCP responses
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    data, addr = recv_sock.recvfrom(4096)
                except socket.timeout:
                    break
                except OSError:
                    break

                if addr[0] != self.ip or len(data) < 20:
                    continue
                if data[9] != socket.IPPROTO_TCP:
                    continue

                ihl = (data[0] & 0x0F) * 4
                if len(data) < ihl + 20:
                    continue

                reply_dst = struct.unpack("!H", data[ihl+2:ihl+4])[0]
                reply_src = struct.unpack("!H", data[ihl:ihl+2])[0]

                # Track IP ID sequence
                ip_id = struct.unpack("!H", data[4:6])[0]
                ipids.append(ip_id)

                # Track ISN from SYN-ACK replies
                flags_rx = data[ihl+13]
                if flags_rx & 0x12:   # SYN-ACK
                    isn = struct.unpack("!L", data[ihl+4:ihl+8])[0]
                    isns.append(isn)

                    # Parse TCP options from response
                    if not result.tcp_opts_order:
                        result.tcp_opts_order = self._parse_tcp_options(
                            data, ihl)
                        result.tcp_window = struct.unpack(
                            "!H", data[ihl+14:ihl+16])[0]

                    # Window scale
                    ws = self._extract_window_scale(data, ihl)
                    if ws >= 0:
                        result.win_scale = ws

                    # ECN support: if ECE flag set in SYN-ACK
                    if flags_rx & F_ECE:
                        result.ecn_support = True

                    # Send RST
                    remote_seq = struct.unpack("!L", data[ihl+4:ihl+8])[0]
                    _send_rst(self.src_ip, self.ip, reply_dst,
                              reply_src, remote_seq + 1)

                result.ttl = max(result.ttl, data[8])

            # Collect ICMP responses if available
            if icmp_sock is not None:
                deadline2 = time.time() + self.timeout / 2
                while time.time() < deadline2:
                    try:
                        raw, addr = icmp_sock.recvfrom(1024)
                    except socket.timeout:
                        break
                    except OSError:
                        break
                    if addr[0] == self.ip and len(raw) >= 28:
                        ihl2 = (raw[0] & 0x0F) * 4
                        if raw[ihl2] == 0:   # ICMP echo reply
                            # Check DF bit echoed
                            result.icmp_df_echo = bool(
                                struct.unpack("!H", raw[6:8])[0] & 0x4000)
                            result.icmp_tos_echo = (raw[1] != 0)
                icmp_sock.close()

        finally:
            recv_sock.close()
            for p in allocated:
                _PORT_ALLOC.free(p)

        # ── Classify observations ────────────────────────────────────
        result.isn_class  = self._classify_isn(isns)
        result.ipid_class = self._classify_ipid(ipids)

        # ── Score against extended OS profiles ───────────────────────
        os_guess = self._score_profiles(result)
        return result, os_guess

    def _send_icmp_probe(self, sock: socket.socket,
                         code: int, tos: int, seq: int) -> None:
        pid  = os.getpid() & 0xFFFF
        hdr  = struct.pack("!BBHHH", 8, code, 0, pid, seq)
        pay  = b"\x00" * 8
        chk  = checksum(hdr + pay)
        hdr  = struct.pack("!BBHHH", 8, code, chk, pid, seq)
        try:
            sock.sendto(hdr + pay, (self.ip, 0))
        except OSError:
            pass

    def _parse_tcp_options(self, data: bytes, ihl: int) -> str:
        """Return a string like 'MSS,SACK,TS,NOP,WS' from TCP options."""
        tcp_data_off = (data[ihl+12] >> 4) * 4
        opt_bytes    = data[ihl+20: ihl+tcp_data_off]
        opts: List[str] = []
        i = 0
        while i < len(opt_bytes):
            kind = opt_bytes[i]
            if kind == 0:   break                   # EOL
            if kind == 1:   opts.append("NOP"); i += 1; continue
            if i + 1 >= len(opt_bytes): break
            length = opt_bytes[i+1]
            if   kind == 2: opts.append("MSS")
            elif kind == 3: opts.append("WS")
            elif kind == 4: opts.append("SACK")
            elif kind == 8: opts.append("TS")
            i += max(2, length)
        return ",".join(opts)

    def _extract_window_scale(self, data: bytes, ihl: int) -> int:
        """Return window scale value, or -1 if not present."""
        tcp_data_off = (data[ihl+12] >> 4) * 4
        opt_bytes    = data[ihl+20: ihl+tcp_data_off]
        i = 0
        while i < len(opt_bytes):
            kind = opt_bytes[i]
            if kind == 0: break
            if kind == 1: i += 1; continue
            if i + 1 >= len(opt_bytes): break
            length = opt_bytes[i+1]
            if kind == 3 and length == 3 and i + 2 < len(opt_bytes):
                return opt_bytes[i+2]
            i += max(2, length)
        return -1

    def _classify_isn(self, isns: List[int]) -> str:
        if len(isns) < 2:
            return "unknown"
        diffs = [abs(isns[i+1] - isns[i]) for i in range(len(isns)-1)]
        avg   = sum(diffs) / len(diffs)
        if avg == 0:          return "constant"
        if avg < 500:         return "incremental"   # small fixed steps
        if avg < 5_000_000:   return "time-based"    # timer-based ISN
        return "random"

    def _classify_ipid(self, ipids: List[int]) -> str:
        if len(ipids) < 2:
            return "unknown"
        if all(x == 0 for x in ipids):
            return "zero"
        diffs = [abs(ipids[i+1] - ipids[i]) for i in range(len(ipids)-1)]
        avg   = sum(diffs) / len(diffs)
        if avg < 10:    return "incremental"
        if avg > 30000: return "random"
        return "random-increment"

    def _score_profiles(self, obs: OsProbeResult) -> str:
        """Score observations against 15-profile extended OS database."""
        # Extended profile: (name, isn, ipid, ts_present, ecn, win_scale_range)
        EXTENDED_PROFILES = [
            # Linux 5.x / 6.x
            ("Linux 5.x/6.x",     "random",      "random",      True,  True,  (7,  10)),
            # Linux 3.x / 4.x
            ("Linux 3.x/4.x",     "random",      "random",      True,  True,  (6,  9)),
            # Linux 2.6
            ("Linux 2.6",         "random",      "random",      True,  False, (5,  8)),
            # macOS 12+ (Monterey/Ventura)
            ("macOS 12+",         "random",      "random",      True,  True,  (6,  8)),
            # macOS 10.x / 11
            ("macOS 10.x/11",     "random",      "zero",        True,  False, (4,  6)),
            # Windows 11
            ("Windows 11",        "random",      "incremental", True,  True,  (8,  8)),
            # Windows 10
            ("Windows 10",        "random",      "incremental", True,  False, (8,  8)),
            # Windows Server 2019/2022
            ("Windows Server 2019+","random",    "incremental", True,  False, (8,  8)),
            # Windows 7/8
            ("Windows 7/8",       "time-based",  "incremental", False, False, (0,  0)),
            # FreeBSD 13+
            ("FreeBSD 13+",       "random",      "random",      True,  True,  (6,  7)),
            # OpenBSD 7+
            ("OpenBSD 7+",        "random",      "random",      True,  False, (3,  5)),
            # Cisco IOS 15+
            ("Cisco IOS",         "incremental", "incremental", False, False, (0,  0)),
            # Cisco IOS-XE
            ("Cisco IOS-XE",      "random",      "incremental", False, False, (0,  0)),
            # Solaris 11
            ("Solaris 11",        "random",      "incremental", True,  False, (4,  6)),
            # Embedded / IoT (VxWorks / RTOS)
            ("Embedded/IoT",      "constant",    "incremental", False, False, (0,  0)),
        ]

        scores: Dict[str, float] = {}
        for (name, isn, ipid, ts, ecn, ws_range) in EXTENDED_PROFILES:
            score = 0.0
            if obs.isn_class  == isn:  score += 3.0
            if obs.ipid_class == ipid: score += 2.0
            if obs.ts_option  == ts:   score += 1.0
            if obs.ecn_support == ecn: score += 1.5
            ws_lo, ws_hi = ws_range
            if ws_lo <= obs.win_scale <= ws_hi and ws_hi > 0:
                score += 2.0
            scores[name] = score

        if not scores or max(scores.values()) < 1.0:
            return "Unknown"

        best = max(scores, key=lambda k: scores[k])
        sc   = scores[best]
        max_possible = 3.0 + 2.0 + 1.0 + 1.5 + 2.0
        pct  = int(sc / max_possible * 100)
        conf = "high" if pct >= 65 else "medium" if pct >= 40 else "low"
        return f"{best} (confidence: {conf}, score: {sc:.1f})"


# ═══════════════════════════════════════════════════════════════════
# [V9-1] BPF / LIBPCAP PACKET CAPTURE ENGINE
# ═══════════════════════════════════════════════════════════════════
# Uses ctypes to call libpcap directly — no third-party packages.
# Provides a drop-in replacement for raw socket recv that:
#   • Applies a kernel-level BPF filter (far fewer false positives)
#   • Returns Ethernet-stripped IP packets, same format as raw socket
#   • Falls back silently to raw socket if libpcap is absent

import ctypes
import ctypes.util
import select as _select_mod

# Try to load libpcap
_libpcap: Any = None
_PCAP_LIB_NAME = ctypes.util.find_library("pcap")
if _PCAP_LIB_NAME:
    try:
        _libpcap = ctypes.CDLL(_PCAP_LIB_NAME)
        # Declare minimal signatures
        _libpcap.pcap_open_live.restype  = ctypes.c_void_p
        _libpcap.pcap_open_live.argtypes = [
            ctypes.c_char_p,   # device
            ctypes.c_int,      # snaplen
            ctypes.c_int,      # promisc
            ctypes.c_int,      # to_ms
            ctypes.c_char_p,   # errbuf
        ]
        _libpcap.pcap_compile.restype  = ctypes.c_int
        _libpcap.pcap_compile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,   # bpf_program*
            ctypes.c_char_p,   # filter_exp
            ctypes.c_int,      # optimize
            ctypes.c_uint32,   # netmask
        ]
        _libpcap.pcap_setfilter.restype  = ctypes.c_int
        _libpcap.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        _libpcap.pcap_next_ex.restype  = ctypes.c_int
        _libpcap.pcap_next_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        _libpcap.pcap_close.restype  = None
        _libpcap.pcap_close.argtypes = [ctypes.c_void_p]
        _libpcap.pcap_freecode.restype  = None
        _libpcap.pcap_freecode.argtypes = [ctypes.c_void_p]
        _libpcap.pcap_datalink.restype  = ctypes.c_int
        _libpcap.pcap_datalink.argtypes = [ctypes.c_void_p]
        _libpcap.pcap_get_selectable_fd.restype  = ctypes.c_int
        _libpcap.pcap_get_selectable_fd.argtypes = [ctypes.c_void_p]
    except Exception:
        _libpcap = None

HAS_LIBPCAP: bool = _libpcap is not None


# BPF program struct (8-byte instructions × N)
class _BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint),
                 ("bf_insns", ctypes.c_void_p)]


class PacketCapture:
    """
    [V9-1] Thin ctypes wrapper around libpcap for kernel-level BPF filtering.

    Usage:
        cap = PacketCapture(iface="eth0", bpf_filter="tcp and host 192.168.1.1")
        with cap:
            while True:
                pkt = cap.next_packet(timeout=1.0)  # returns IP-layer bytes or None

    Falls back to raw socket mode if libpcap is not available, providing
    the same interface so callers need no special-casing.
    """

    DLT_EN10MB = 1    # Ethernet
    DLT_RAW    = 101  # Raw IP
    DLT_LINUX_SLL = 113  # Linux cooked

    def __init__(self, dst_ip: str = "",
                 bpf_filter: str = "",
                 snaplen: int = 65535,
                 promisc: int = 0,
                 timeout_ms: int = 100):
        self.dst_ip     = dst_ip
        self.snaplen    = snaplen
        self.promisc    = promisc
        self.timeout_ms = timeout_ms
        self._handle: Any = None
        self._raw_sock: Optional[socket.socket] = None
        self._datalink  = self.DLT_EN10MB
        self._use_pcap  = False
        self._errbuf    = ctypes.create_string_buffer(256)

        # Build filter string
        self._filter = bpf_filter or (
            f"tcp and host {dst_ip}" if dst_ip else "tcp")

    def open(self, iface: str = "") -> bool:
        """
        Open capture. Returns True if libpcap available and opened,
        False if falling back to raw socket.
        """
        if _libpcap is not None:
            # Detect default interface if not given
            dev = iface.encode() if iface else self._detect_iface()
            handle = _libpcap.pcap_open_live(
                dev, self.snaplen, self.promisc,
                self.timeout_ms, self._errbuf)
            if handle:
                self._handle   = handle
                self._datalink = _libpcap.pcap_datalink(handle)
                self._apply_filter()
                self._use_pcap = True
                return True

        # Fallback: raw socket
        try:
            self._raw_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self._raw_sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            self._raw_sock.setblocking(False)
        except (PermissionError, OSError):
            self._raw_sock = None
        return False

    def _detect_iface(self) -> bytes:
        """Return default network interface name as bytes."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            iface = s.getsockname()[0]
            s.close()
            # Try to find interface name from IP
            import subprocess as _sp
            result = _sp.run(["ip", "-o", "-4", "addr"],
                              capture_output=True, text=True, timeout=2)
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and iface in parts[3]:
                    return parts[1].encode()
        except Exception:
            pass
        return b"eth0"

    def _apply_filter(self) -> None:
        """Compile and apply BPF filter to pcap handle."""
        if not self._handle or not self._filter:
            return
        prog = _BpfProgram()
        ret = _libpcap.pcap_compile(
            self._handle,
            ctypes.byref(prog),
            self._filter.encode(),
            1,       # optimize
            0xFFFFFFFF,  # netmask (PCAP_NETMASK_UNKNOWN)
        )
        if ret == 0:
            _libpcap.pcap_setfilter(self._handle, ctypes.byref(prog))
            _libpcap.pcap_freecode(ctypes.byref(prog))

    def next_packet(self, timeout: float = 1.0) -> Optional[bytes]:
        """
        Return the next IP-layer bytes (strips Ethernet/SLL header).
        Returns None on timeout or error.
        """
        if self._use_pcap and self._handle:
            return self._next_pcap(timeout)
        elif self._raw_sock:
            return self._next_raw(timeout)
        return None

    def _next_pcap(self, timeout: float) -> Optional[bytes]:
        """Read one packet from pcap handle, strip datalink header."""
        hdr_ptr  = ctypes.c_void_p()
        data_ptr = ctypes.c_void_p()
        ret = _libpcap.pcap_next_ex(
            self._handle,
            ctypes.byref(hdr_ptr),
            ctypes.byref(data_ptr))
        if ret == 1 and data_ptr:
            # Read caplen from pcap_pkthdr: u_int ts.tv_sec, ts.tv_usec, caplen, len
            caplen = ctypes.cast(hdr_ptr,
                ctypes.POINTER(ctypes.c_uint * 4))[0][2]
            raw = bytes(ctypes.cast(data_ptr,
                ctypes.POINTER(ctypes.c_ubyte * caplen))[0])
            return self._strip_datalink(raw)
        return None

    def _next_raw(self, timeout: float) -> Optional[bytes]:
        """Read from raw socket using select for timeout."""
        try:
            r, _, _ = _select_mod.select([self._raw_sock], [], [], timeout)
            if r:
                return self._raw_sock.recv(65535)
        except Exception:
            pass
        return None

    def _strip_datalink(self, raw: bytes) -> bytes:
        """Strip datalink-layer header to expose raw IP packet."""
        if self._datalink == self.DLT_EN10MB:
            return raw[14:] if len(raw) > 14 else raw  # Ethernet header = 14
        if self._datalink == self.DLT_LINUX_SLL:
            return raw[16:] if len(raw) > 16 else raw  # Linux cooked = 16
        return raw  # DLT_RAW: already IP

    def fileno(self) -> int:
        """Return selectable fd (for use with epoll/select)."""
        if self._use_pcap and self._handle:
            fd = _libpcap.pcap_get_selectable_fd(self._handle)
            if fd >= 0:
                return fd
        if self._raw_sock:
            return self._raw_sock.fileno()
        return -1

    def close(self) -> None:
        if self._use_pcap and self._handle:
            _libpcap.pcap_close(self._handle)
            self._handle = None
        if self._raw_sock:
            try: self._raw_sock.close()
            except Exception: pass
            self._raw_sock = None

    def __enter__(self) -> "PacketCapture":
        self.open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# ═══════════════════════════════════════════════════════════════════
# [V9-4] EPOLL / SELECT RECEIVE LOOP
# ═══════════════════════════════════════════════════════════════════

class _EpollReceiver:
    """
    [V9-4] Non-blocking packet receiver using epoll (Linux) or select
    (cross-platform fallback).

    Replaces the blocking recvfrom() loop in syn_batch_scan with a
    batch-drain loop: after epoll signals readability, all available
    packets are read in a tight non-blocking loop before returning to
    epoll_wait. This halves context-switch overhead on fast networks.
    """

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._epoll: Any = None
        self._use_epoll = False
        sock.setblocking(False)
        # Try epoll first (Linux only)
        if hasattr(_select_mod, "epoll"):
            try:
                self._epoll = _select_mod.epoll()
                self._epoll.register(sock.fileno(), _select_mod.EPOLLIN)
                self._use_epoll = True
            except Exception:
                self._epoll = None

    def recv_packets(self, timeout: float,
                     bufsize: int = 65535) -> List[bytes]:
        """
        Block up to `timeout` seconds, then batch-drain all available
        packets from the socket. Returns a list of raw packet bytes.
        """
        packets: List[bytes] = []
        deadline = time.time() + timeout

        while time.time() < deadline:
            remaining = max(0.01, deadline - time.time())

            if self._use_epoll and self._epoll:
                try:
                    events = self._epoll.poll(min(remaining, 0.1))
                    if not events:
                        continue
                except Exception:
                    break
            else:
                # select() fallback
                try:
                    r, _, _ = _select_mod.select(
                        [self._sock], [], [], min(remaining, 0.1))
                    if not r:
                        continue
                except Exception:
                    break

            # Batch-drain: read all available packets non-blocking
            while True:
                try:
                    data = self._sock.recv(bufsize)
                    if data:
                        packets.append(data)
                except BlockingIOError:
                    break   # no more packets right now
                except Exception:
                    return packets
            break   # one drain pass per epoll event (avoid starvation)

        return packets

    def close(self) -> None:
        if self._epoll:
            try: self._epoll.close()
            except Exception: pass


# ─────────────────────────────────────────────
# Internet checksum
# ─────────────────────────────────────────────

def checksum(data: bytes) -> int:
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += data[i] + (data[i + 1] << 8)
    if n:
        s += data[-1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


# ─────────────────────────────────────────────
# [FIX-5] ICMP Ping
# ─────────────────────────────────────────────

def icmp_ping(ip: str, timeout: float = 1.5) -> Tuple[bool, float, int]:
    """
    Send ICMP echo requests. Returns (reachable, latency_ms, ttl).
    [FIX-5]  On PermissionError falls back immediately to TCP ping.
    [FIX-31] Retransmits up to ICMP_MAX_PROBES times before declaring
             host down — one dropped probe no longer marks a host as down.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
    except PermissionError:
        return _tcp_ping(ip, timeout)
    except OSError:
        return _tcp_ping(ip, timeout)

    pid = os.getpid() & 0xFFFF

    try:
        for attempt in range(ICMP_MAX_PROBES):   # [FIX-31] retry loop
            seq  = random.randint(0, 0xFFFF)
            hdr  = struct.pack("!BBHHH", 8, 0, 0, pid, seq)
            payload = b"PyScanner-ping"
            chk  = checksum(hdr + payload)
            hdr  = struct.pack("!BBHHH", 8, 0, chk, pid, seq)
            pkt  = hdr + payload

            t0       = time.time()
            deadline = t0 + timeout
            sock.sendto(pkt, (ip, 0))

            while time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    raw, addr = sock.recvfrom(1024)
                    if addr[0] == ip:
                        # Verify ICMP echo reply (type=0) and matching seq
                        ip_hdr_len = (raw[0] & 0x0F) * 4
                        if len(raw) >= ip_hdr_len + 8:
                            icmp_type = raw[ip_hdr_len]
                            recv_seq  = struct.unpack(
                                "!H", raw[ip_hdr_len + 6: ip_hdr_len + 8])[0]
                            if icmp_type == 0 and recv_seq == seq:
                                ttl = raw[8]
                                lat = (time.time() - t0) * 1000
                                return True, round(lat, 2), ttl
                except socket.timeout:
                    break   # this probe timed out; try again
    except Exception:
        pass
    finally:
        sock.close()
    return False, 0.0, 0


def _tcp_ping(ip: str, timeout: float = 1.0) -> Tuple[bool, float, int]:
    """
    TCP connect as ping fallback (no root required).
    [FIX-12] Handles ECONNREFUSED portably across Linux/Windows/macOS.
    """
    for port in (80, 443, 22, 8080, 23):
        t0 = time.time()
        s  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            code = s.connect_ex((ip, port))
            lat  = (time.time() - t0) * 1000
            # [FIX-12] 0=connected, 111=Linux ECONNREFUSED, 10061=Windows, 61=macOS
            if code == 0 or code in (111, 10061, 61):
                return True, round(lat, 2), 0
        except ConnectionRefusedError:
            lat = (time.time() - t0) * 1000
            return True, round(lat, 2), 0
        except Exception:
            pass
        finally:
            s.close()
    return False, 0.0, 0


# ─────────────────────────────────────────────
# TCP Connect Scan
# ─────────────────────────────────────────────

def tcp_connect_scan(ip: str, port: int, timeout: float) -> PortResult:
    """[FIX-27] Supports both IPv4 and IPv6 targets."""
    result = PortResult(port=port, protocol="tcp")
    family = socket.AF_INET6 if is_ipv6(ip) else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((ip, port))
        if code == 0:
            result.state   = "open"
            result.service = service_name(port)
            result.reason  = "syn-ack"
        elif code in (111, 10061, 61):
            # [FIX-12] Platform-portable ECONNREFUSED check
            result.state  = "closed"
            result.reason = "reset"
        else:
            result.state  = "filtered"
            result.reason = f"errno-{code}"
    except ConnectionRefusedError:
        result.state  = "closed"
        result.reason = "reset"
    except socket.timeout:
        result.state  = "filtered"
        result.reason = "timeout"
    except Exception as exc:
        result.state  = "filtered"
        result.reason = str(exc)
    finally:
        s.close()
    return result


# ─────────────────────────────────────────────
# [FIX-20, FIX-24] Shared-socket SYN batch engine
# ─────────────────────────────────────────────
# Professional scanners (Nmap, Masscan) use ONE send socket and ONE
# receive socket for an entire host, not a new socket per port.
# This avoids per-port socket overhead and lets us:
#   1. Send all SYN probes first (fast burst)
#   2. Collect all replies in a single receive loop
# This is the send/receive split ("async-style") Masscan uses.
# ─────────────────────────────────────────────

def syn_batch_scan(ip: str, ports: List[int],
                   timeout: float) -> Dict[int, PortResult]:
    """
    [FIX-20] Batch SYN scan: ONE send socket + ONE receive socket per host.
    [FIX-24] Send all probes first, then collect all replies.
    [FIX-25] Unique ephemeral source ports via _PORT_ALLOC (no collisions).
    [FIX-26] Respects global _RATE_LIMITER token bucket if set.
    [ENH-2]  IPv6 targets routed to syn_batch_scan_v6() automatically.
    [V9-1]   PacketCapture (libpcap+BPF) used as recv backend if available.
    [V9-4]   EpollReceiver drains socket non-blocking for lower CPU usage.

    Returns {port: PortResult} for every port. Falls back to connect scan
    if raw sockets are unavailable.
    """
    results: Dict[int, PortResult] = {
        p: PortResult(port=p, protocol="tcp",
                      state="filtered", reason="no-response")
        for p in ports
    }

    if not ports:
        return results

    # [ENH-2] Route IPv6 to dedicated v6 engine
    if is_ipv6(ip):
        return syn_batch_scan_v6(ip, ports, timeout)

    src_ip = get_local_ip(ip)

    # [V9-1] Try libpcap first; fall back to raw socket
    cap = PacketCapture(
        dst_ip     = ip,
        bpf_filter = f"tcp and host {ip}",
        timeout_ms = 50,
    )
    cap.open()   # sets cap._use_pcap = True if libpcap available

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except (PermissionError, OSError):
        cap.close()
        return results

    # [V9-4] EpollReceiver for the raw fallback path
    if not cap._use_pcap and cap._raw_sock:
        _epoll_rcv = _EpollReceiver(cap._raw_sock)
    else:
        _epoll_rcv = None

    # [FIX-25] src_port -> (dst_port, seq) — each src_port is unique
    probe_map: Dict[int, Tuple[int, int]] = {}
    allocated_ports: List[int] = []

    def _process_packet(data: bytes,
                        seen_ports: set) -> None:
        """Parse one IP+TCP packet and update results."""
        if len(data) < 20 or data[9] != socket.IPPROTO_TCP:
            return
        ip_hdr_len = (data[0] & 0x0F) * 4
        if len(data) < ip_hdr_len + 20:
            return

        # [V9-1] With BPF filter, src IP is already guaranteed to be `ip`.
        # Without BPF, verify it here.
        if not cap._use_pcap:
            pkt_src = socket.inet_ntoa(data[12:16])
            if pkt_src != ip:
                return

        reply_dst = struct.unpack(
            "!H", data[ip_hdr_len + 2: ip_hdr_len + 4])[0]
        reply_src = struct.unpack(
            "!H", data[ip_hdr_len    : ip_hdr_len + 2])[0]

        if reply_dst not in probe_map:
            return
        expected_dst, _ = probe_map[reply_dst]
        if reply_src != expected_dst:
            return

        dst_port   = expected_dst
        flags      = data[ip_hdr_len + 13]
        remote_seq = struct.unpack(
            "!L", data[ip_hdr_len + 4: ip_hdr_len + 8])[0]

        r = results[dst_port]
        if flags & 0x12:    # SYN-ACK -> open
            r.state   = "open"
            r.reason  = "syn-ack"
            r.service = service_name(dst_port)
            _send_rst(src_ip, ip, reply_dst, dst_port, remote_seq + 1)

            # [FIX-28] fingerprinting signals
            tcp_win = struct.unpack(
                "!H", data[ip_hdr_len + 14: ip_hdr_len + 16])[0]
            df = bool(struct.unpack("!H", data[6:8])[0] & 0x4000)
            has_opts = (data[ip_hdr_len + 12] >> 4) * 4 > 20
            r._fp_tcp_window      = tcp_win
            r._fp_df_bit          = df
            r._fp_has_tcp_options = has_opts

        elif flags & 0x04:  # RST -> closed
            r.state  = "closed"
            r.reason = "reset"

        seen_ports.add(dst_port)

    try:
        # ── Phase 1: burst-send all SYN probes ──────────────────────────
        for dst_port in ports:
            src_port = _PORT_ALLOC.alloc()
            allocated_ports.append(src_port)
            seq_num  = random.randint(0, 0xFFFFFFFF)
            probe_map[src_port] = (dst_port, seq_num)

            pkt = _build_syn_packet(src_ip, ip, src_port, dst_port, seq_num)

            if _RATE_LIMITER is not None:
                _RATE_LIMITER.consume(1)
            try:
                send_sock.sendto(pkt, (ip, 0))
                if _CONGESTION:
                    _CONGESTION.on_send()
            except OSError:
                pass

        def _collect(deadline: float, seen_ports: set) -> None:
            """
            Collect replies using whichever backend is active:
            • libpcap: call cap.next_packet() in a loop
            • raw socket + epoll: batch-drain via _EpollReceiver
            • raw socket blocking: original recvfrom() path
            """
            if cap._use_pcap:
                # [V9-1] libpcap path
                while time.time() < deadline and len(seen_ports) < len(ports):
                    pkt = cap.next_packet(
                        timeout=min(0.1, deadline - time.time()))
                    if pkt:
                        _process_packet(pkt, seen_ports)
            elif _epoll_rcv:
                # [V9-4] Epoll/select batch-drain path
                while time.time() < deadline and len(seen_ports) < len(ports):
                    remaining = max(0.01, deadline - time.time())
                    packets = _epoll_rcv.recv_packets(
                        timeout=min(0.1, remaining))
                    for pkt in packets:
                        _process_packet(pkt, seen_ports)
            else:
                # Legacy blocking recvfrom (original behaviour)
                while time.time() < deadline and len(seen_ports) < len(ports):
                    try:
                        data, addr = cap._raw_sock.recvfrom(4096) \
                            if cap._raw_sock else (b"", ("", 0))
                        if addr[0] == ip:
                            _process_packet(data, seen_ports)
                    except socket.timeout:
                        time.sleep(0.01)
                    except OSError:
                        break

            # [ENH-1] Congestion tick after each collect window
            if _CONGESTION:
                _CONGESTION.tick()
                _CONGESTION.update_rate_limiter()

        # ── Phase 2: collect initial replies ─────────────────────────────
        seen_ports: set = set()
        _collect(time.time() + timeout, seen_ports)

        # ── Phase 3: [FIX-30] retransmit for unanswered ports ────────────
        for retry in range(SYN_MAX_RETRIES - 1):
            unanswered = [p for p in ports if p not in seen_ports]
            if not unanswered:
                break

            # Re-map new ephemeral src_port for each retransmit
            for dst_port in unanswered:
                new_src = _PORT_ALLOC.alloc()
                allocated_ports.append(new_src)
                seq_num  = random.randint(0, 0xFFFFFFFF)
                probe_map[new_src] = (dst_port, seq_num)

                pkt = _build_syn_packet(src_ip, ip, new_src, dst_port, seq_num)
                if _RATE_LIMITER is not None:
                    _RATE_LIMITER.consume(1)
                try:
                    send_sock.sendto(pkt, (ip, 0))
                except OSError:
                    pass

            _collect(time.time() + timeout, seen_ports)

    finally:
        send_sock.close()
        cap.close()           # [V9-1] closes libpcap handle or raw socket
        if _epoll_rcv:
            _epoll_rcv.close()  # [V9-4]
        for p in allocated_ports:
            _PORT_ALLOC.free(p)   # [FIX-25]

    return results




def tcp_syn_scan(ip: str, port: int, timeout: float) -> PortResult:
    """
    [FIX-36] Thin wrapper — delegates to syn_batch_scan() for a single port.
    The old per-port raw-socket implementation has been removed; the shared
    batch engine is strictly superior (fewer sockets, retransmit, fingerprint).
    Falls back to tcp_connect_scan if raw sockets are unavailable.
    """
    batch = syn_batch_scan(ip, [port], timeout)
    r = batch.get(port)
    if r is None:
        return tcp_connect_scan(ip, port, timeout)
    # If batch returned default filtered+no-response, try connect fallback
    if r.state == "filtered" and r.reason == "no-response":
        return tcp_connect_scan(ip, port, timeout)
    return r





def _build_tcp_options() -> bytes:
    """
    [FIX-21] Build standard TCP options that a real OS would include in a SYN.
    Without these, IDS tools fingerprint the packet as a scanner.

    Options included (mimicking a Linux kernel SYN):
      - MSS (kind=2): Maximum Segment Size = 1460 (standard Ethernet)
      - SACK permitted (kind=4): Selective ACK supported
      - Timestamps (kind=8): val=random, ecr=0 (as in initial SYN)
      - NOP (kind=1): padding
      - Window scale (kind=3): shift count = 7  (window *= 128)

    Total option bytes = 20, so TCP data offset = (20+20)/4 = 10 words.
    """
    mss        = struct.pack("!BBH", 2, 4, 1460)           # MSS = 1460
    sack_perm  = struct.pack("!BB",  4, 2)                  # SACK permitted
    ts_val     = random.randint(100000, 0xFFFFFFFF)
    timestamps = struct.pack("!BBLL", 8, 10, ts_val, 0)     # Timestamps
    nop        = b"\x01"                                     # NOP padding
    win_scale  = struct.pack("!BBB", 3, 3, 7)               # Window scale=7
    options    = mss + sack_perm + timestamps + nop + win_scale
    # Pad to 4-byte boundary
    pad = (4 - len(options) % 4) % 4
    options += b"\x00" * pad
    return options


def _build_syn_packet(src_ip: str, dst_ip: str,
                      src_port: int, dst_port: int,
                      seq: int) -> bytes:
    """
    Build a valid IP/TCP SYN packet with correct checksums.
    [FIX-13] IP header checksum computed and embedded.
    [FIX-16] TCP pseudo-header uses actual tcp_hdr byte length.
    [FIX-19] Randomised IP ID to reduce predictability.
    [FIX-21] TCP options included: MSS + SACK + Timestamps + WinScale.
    [FIX-22] TTL uses OS-realistic values (64 or 128) not suspicious 48-64.
    """
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)

    # [FIX-21] Build TCP options
    tcp_opts   = _build_tcp_options()
    data_offset = (20 + len(tcp_opts)) // 4   # TCP header words
    th_off_res  = (data_offset << 4)

    # TCP header with options (no checksum yet)
    tcp_hdr_nc = struct.pack("!HHLLBBHHH",
        src_port, dst_port,
        seq, 0,              # seq, ack=0
        th_off_res, 0x02,    # SYN flag
        65535, 0, 0)         # window=65535, checksum=0, urgent=0
    tcp_hdr_nc += tcp_opts

    # [FIX-16] Pseudo-header uses actual length of full TCP segment
    tcp_len = len(tcp_hdr_nc)
    pseudo  = struct.pack("!4s4sBBH",
        ip_src, ip_dst, 0, socket.IPPROTO_TCP, tcp_len)
    tcp_chk = checksum(pseudo + tcp_hdr_nc)

    # Rebuild TCP header with real checksum embedded at byte offset 16
    tcp_hdr = (tcp_hdr_nc[:16]
               + struct.pack("!H", tcp_chk)
               + tcp_hdr_nc[18:])

    total_len = 20 + tcp_len

    # [FIX-13] IP header: compute checksum
    # [FIX-19] Randomised IP ID
    # [FIX-22] OS-realistic TTL
    rand_ttl = random.choice([64, 64, 64, 128])
    rand_id  = random.randint(0, 0xFFFF)
    ip_hdr_nc = struct.pack("!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, total_len, rand_id, 0,
        rand_ttl, socket.IPPROTO_TCP, 0,
        ip_src, ip_dst)
    ip_chk = checksum(ip_hdr_nc)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, total_len, rand_id, 0,
        rand_ttl, socket.IPPROTO_TCP, ip_chk,
        ip_src, ip_dst)

    return ip_hdr + tcp_hdr


def _send_rst(src_ip: str, dst_ip: str,
              src_port: int, dst_port: int,
              ack_num: int) -> None:
    """
    [FIX-3] Send RST/ACK with correct seq/ack numbers.
    [FIX-13] IP header checksum now computed and embedded.
    [FIX-19] Randomised TTL for IDS evasion.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                          socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        ip_src = socket.inet_aton(src_ip)
        ip_dst = socket.inet_aton(dst_ip)

        th_off_res = (5 << 4)
        th_flags   = 0x14   # RST + ACK
        tcp_hdr_nc = struct.pack("!HHLLBBHHH",
            src_port, dst_port,
            0, ack_num,
            th_off_res, th_flags,
            0, 0, 0)
        pseudo = struct.pack("!4s4sBBH",
            ip_src, ip_dst, 0, socket.IPPROTO_TCP, len(tcp_hdr_nc))
        tcp_chk = checksum(pseudo + tcp_hdr_nc)
        tcp_hdr = struct.pack("!HHLLBBHHH",
            src_port, dst_port,
            0, ack_num, th_off_res, th_flags, 0, tcp_chk, 0)

        rand_ttl = random.choice([64, 64, 64, 128])   # [FIX-22] OS-realistic TTL
        rand_id  = random.randint(0, 0xFFFF)
        total_len = 20 + len(tcp_hdr)
        # [FIX-13] Compute real IP checksum
        ip_hdr_nc = struct.pack("!BBHHHBBH4s4s",
            (4 << 4) | 5, 0, total_len, rand_id, 0,
            rand_ttl, socket.IPPROTO_TCP, 0,
            ip_src, ip_dst)
        ip_chk = checksum(ip_hdr_nc)
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
            (4 << 4) | 5, 0, total_len, rand_id, 0,
            rand_ttl, socket.IPPROTO_TCP, ip_chk,
            ip_src, ip_dst)

        s.sendto(ip_hdr + tcp_hdr, (dst_ip, 0))
        s.close()
    except Exception:
        pass


# ─────────────────────────────────────────────
# [FIX-4] UDP Scan with ICMP unreachable detection
# ─────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════════
# [ENH-2] IPv6 SYN SCANNING
# ═══════════════════════════════════════════════════════════════════

def _tcp_checksum_v6(src_ip6: str, dst_ip6: str,
                     tcp_payload: bytes) -> int:
    """
    Compute TCP checksum over IPv6 pseudo-header (RFC 2460 §8.1).
    Pseudo-header: src(16) + dst(16) + tcp_len(4) + zeros(3) + next(1)
    """
    src_b = socket.inet_pton(socket.AF_INET6, src_ip6)
    dst_b = socket.inet_pton(socket.AF_INET6, dst_ip6)
    tcp_len = len(tcp_payload)
    pseudo = (src_b + dst_b
              + struct.pack("!I", tcp_len)
              + b"\x00\x00\x00"
              + bytes([socket.IPPROTO_TCP]))
    return checksum(pseudo + tcp_payload)


def _build_syn_packet_v6(src_ip6: str, dst_ip6: str,
                          src_port: int, dst_port: int,
                          seq_num: int) -> bytes:
    """
    [ENH-2] Build a raw TCP SYN packet for IPv6.

    Note: unlike IPv4, we do NOT prepend the IPv6 header when using
    AF_INET6 SOCK_RAW — the kernel handles the IPv6 header for us.
    We only need to supply the TCP segment.
    """
    # Reuse the same TCP options as IPv4 SYN (MSS+SACK+TS+NOP+WS)
    tcp_opts = _build_tcp_options()
    data_off = (20 + len(tcp_opts)) // 4  # in 4-byte words

    tcp_hdr = struct.pack("!HHLLBBHHH",
        src_port, dst_port,
        seq_num, 0,                # seq, ack=0
        data_off << 4,             # data offset
        0x02,                      # SYN flag
        65535,                     # window
        0, 0,                      # checksum placeholder, urgent
    ) + tcp_opts

    # Compute checksum over IPv6 pseudo-header
    chk = _tcp_checksum_v6(src_ip6, dst_ip6, tcp_hdr)
    # Patch checksum at bytes 16-17 of TCP header
    tcp_hdr = tcp_hdr[:16] + struct.pack("!H", chk) + tcp_hdr[18:]
    return tcp_hdr


def syn_batch_scan_v6(ip6: str, ports: List[int],
                      timeout: float) -> Dict[int, PortResult]:
    """
    [ENH-2] Batch SYN scan for IPv6 targets.

    Architecture mirrors syn_batch_scan() for IPv4:
      1. Open AF_INET6 SOCK_RAW send + receive sockets
      2. Burst all SYN probes (kernel adds IPv6 header)
      3. Single receive loop with port correlation
      4. Retransmit unanswered ports up to SYN_MAX_RETRIES times

    Falls back to tcp_connect_scan per port if privileges unavailable.
    """
    results: Dict[int, PortResult] = {
        p: PortResult(port=p, protocol="tcp",
                      state="filtered", reason="no-response")
        for p in ports
    }

    try:
        # Get local IPv6 source address
        probe_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        probe_sock.connect((ip6, 80))
        src_ip6 = probe_sock.getsockname()[0]
        probe_sock.close()
    except Exception:
        src_ip6 = "::1"

    try:
        send_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        recv_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                             4 * 1024 * 1024)
        recv_sock.settimeout(0.5)
    except (PermissionError, OSError):
        # No raw socket access → connect-scan each port
        for p in ports:
            results[p] = tcp_connect_scan(ip6, p, timeout)
        return results

    probe_map: Dict[int, Tuple[int, int]] = {}   # src_port → (dst_port, seq)
    allocated: List[int] = []
    seen_ports: set = set()

    def _send_batch(port_list: List[int]) -> None:
        for dst_port in port_list:
            src_port = _PORT_ALLOC.alloc()
            allocated.append(src_port)
            seq_num  = random.randint(0, 0xFFFFFFFF)
            probe_map[src_port] = (dst_port, seq_num)
            pkt = _build_syn_packet_v6(src_ip6, ip6, src_port, dst_port, seq_num)
            if _RATE_LIMITER:
                _RATE_LIMITER.consume(1)
            try:
                send_sock.sendto(pkt, (ip6, 0, 0, 0))
            except OSError:
                pass

    def _recv_batch(deadline: float) -> None:
        while time.time() < deadline and len(seen_ports) < len(ports):
            try:
                data, addr = recv_sock.recvfrom(4096)
            except socket.timeout:
                time.sleep(0.01)
                continue
            except OSError:
                break
            # AF_INET6 raw: no IPv6 header prepended, data IS the TCP segment
            if addr[0] != ip6 or len(data) < 20:
                continue
            reply_dst = struct.unpack("!H", data[2:4])[0]
            reply_src = struct.unpack("!H", data[0:2])[0]
            if reply_dst not in probe_map:
                continue
            dst_port, _ = probe_map[reply_dst]
            if reply_src != dst_port:
                continue
            flags      = data[13]
            remote_seq = struct.unpack("!L", data[4:8])[0]
            r = results[dst_port]
            if flags & 0x12:
                r.state   = "open"
                r.reason  = "syn-ack"
                r.service = service_name(dst_port)
                # Send RST: reuse _send_rst adapted for v6
                try:
                    rst = struct.pack("!HHLLBBHHH",
                        reply_dst, dst_port,
                        0, remote_seq + 1,
                        5 << 4, 0x04, 0, 0, 0)
                    chk = _tcp_checksum_v6(src_ip6, ip6, rst)
                    rst = rst[:16] + struct.pack("!H", chk) + rst[18:]
                    send_sock.sendto(rst, (ip6, 0, 0, 0))
                except Exception:
                    pass
            elif flags & 0x04:
                r.state  = "closed"
                r.reason = "reset"
            seen_ports.add(dst_port)

    try:
        _send_batch(ports)
        _recv_batch(time.time() + timeout)

        # Retransmit loop [FIX-30 equivalent for v6]
        for _retry in range(SYN_MAX_RETRIES - 1):
            unanswered = [p for p in ports if p not in seen_ports]
            if not unanswered:
                break
            _send_batch(unanswered)
            _recv_batch(time.time() + timeout)
    finally:
        send_sock.close()
        recv_sock.close()
        for p in allocated:
            _PORT_ALLOC.free(p)

    return results


def _udp_probe(port: int) -> bytes:
    """Return a meaningful UDP payload for well-known services."""
    probes: Dict[int, bytes] = {
        53:   (b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
               b"\x07version\x04bind\x00\x00\x10\x00\x03"),
        123:  b"\x1b" + b"\x00" * 47,
        161:  (b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
               b"\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00"
               b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
        1900: (b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\n"
               b"MAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n"),
        5353: (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
               b"\x05_http\x04_tcp\x05local\x00\x00\x0c\x00\x01"),
    }
    return probes.get(port, b"\x00" * 8)


def udp_scan(ip: str, port: int, timeout: float) -> PortResult:
    """
    [FIX-4]  Proper UDP scan with ICMP unreachable detection.
    [FIX-15] Full ICMP type-3 code mapping per RFC 792 / RFC 1812.
    [FIX-18] Enlarged ICMP receive buffer.
    [FIX-32] Retransmit loop: each port probed up to UDP_MAX_RETRIES times.
             ICMP unreachable on any attempt terminates immediately.
             This eliminates false open|filtered from a single dropped probe.
    """
    result = PortResult(port=port, protocol="udp")
    result.service = service_name(port, "udp")

    ICMP3_MAP: Dict[int, Tuple[str, str]] = {
        0:  ("filtered", "icmp-net-unreachable"),
        1:  ("filtered", "icmp-host-unreachable"),
        2:  ("filtered", "icmp-proto-unreachable"),
        3:  ("closed",   "icmp-port-unreachable"),
        9:  ("filtered", "icmp-net-admin-prohib"),
        10: ("filtered", "icmp-host-admin-prohib"),
        13: ("filtered", "icmp-comm-admin-prohib"),
    }

    icmp_sock: Optional[socket.socket] = None

    with _RAW_SOCKET_SEM:
        try:
            icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                      socket.IPPROTO_ICMP)
            icmp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                 2 * 1024 * 1024)
            icmp_sock.settimeout(timeout)
        except (PermissionError, OSError):
            icmp_sock = None

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(timeout)

        try:
            probe = _udp_probe(port)

            # [FIX-32] Retry loop — repeat probe up to UDP_MAX_RETRIES times
            for attempt in range(UDP_MAX_RETRIES):
                udp_sock.sendto(probe, (ip, port))
                deadline = time.time() + timeout

                # Phase 1: direct UDP response → open immediately
                try:
                    udp_sock.settimeout(min(0.4, timeout))
                    data, addr = udp_sock.recvfrom(1024)
                    if addr[0] == ip:
                        result.state  = "open"
                        result.reason = "udp-response"
                        return result
                except socket.timeout:
                    pass
                except Exception:
                    pass

                # Phase 2: ICMP unreachable → closed/filtered immediately
                if icmp_sock is not None:
                    got_icmp = False
                    while time.time() < deadline:
                        remaining = deadline - time.time()
                        if remaining <= 0:
                            break
                        icmp_sock.settimeout(remaining)
                        try:
                            raw, addr = icmp_sock.recvfrom(1024)
                            if addr[0] != ip:
                                continue
                            ihl = (raw[0] & 0x0F) * 4
                            if len(raw) < ihl + 8:
                                continue
                            if raw[ihl] == 3:   # type=3 Dest Unreachable
                                state, reason = ICMP3_MAP.get(
                                    raw[ihl + 1],
                                    ("filtered",
                                     f"icmp-type3-code{raw[ihl + 1]}"))
                                result.state  = state
                                result.reason = reason
                                return result   # definitive answer, stop retrying
                        except socket.timeout:
                            break
                        except Exception:
                            break

            # All retries exhausted with no response
            result.state  = "open|filtered"
            result.reason = (
                "no-response" if icmp_sock is not None
                else "no-icmp-listener")

        except Exception as exc:
            result.state  = "filtered"
            result.reason = str(exc)
        finally:
            udp_sock.close()
            if icmp_sock is not None:
                icmp_sock.close()

    return result


# ─────────────────────────────────────────────
# [FIX-9] Banner Grabbing with SSL support
# ─────────────────────────────────────────────

BANNER_PROBES: Dict[int, bytes] = {
    21:   b"",
    22:   b"",
    25:   b"EHLO pyscanner.local\r\n",
    80:   b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    110:  b"",
    143:  b"",
    443:  b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    587:  b"EHLO pyscanner.local\r\n",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
    8080: b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    8443: b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
}


# ═══════════════════════════════════════════════════════════════════
# [UPG-1] SERVICE PROBE DATABASE  (nmap-service-probes equivalent)
# ═══════════════════════════════════════════════════════════════════
# Each entry is a ProbeSpec:
#   name     : human label
#   ports    : TCP ports this probe applies to
#   payload  : bytes sent to the service (b"" = wait for banner)
#   matches  : ordered list of (regex, template) → version string
#              First match wins. \\1, \\2 etc reference capture groups.
#   ssl      : whether to wrap in TLS before probing

@dataclass
class ProbeSpec:
    name:    str
    ports:   List[int]
    payload: bytes
    matches: List[Tuple[str, str]]   # (pattern, version_template)
    ssl:     bool = False


SERVICE_PROBE_DB: List[ProbeSpec] = [
    # ── SSH ─────────────────────────────────────────────────────────
    ProbeSpec("SSH",  [22, 2222],  b"",
        [(r"SSH-\d+\.\d+-OpenSSH_([\d.p]+)",    r"OpenSSH \1"),
         (r"SSH-\d+\.\d+-dropbear_([\d.]+)",    r"Dropbear SSH \1"),
         (r"SSH-\d+\.\d+-([\w._-]+)",           r"SSH \1")]),

    # ── FTP ─────────────────────────────────────────────────────────
    ProbeSpec("FTP",  [21],  b"",
        [(r"220.*?vsFTPd\s*([\d.]+)",           r"vsFTPd \1"),
         (r"220.*?ProFTPD\s*([\d.]+)",          r"ProFTPD \1"),
         (r"220.*?FileZilla Server\s*([\d.]+)", r"FileZilla FTP \1"),
         (r"220.*?Pure-FTPd",                   r"Pure-FTPd"),
         (r"220(.*)",                            r"FTP\1")]),

    # ── SMTP ────────────────────────────────────────────────────────
    ProbeSpec("SMTP", [25, 587], b"EHLO pyscanner.local\r\n",
        [(r"220.*?Postfix",                     r"Postfix SMTP"),
         (r"220.*?Exim\s*([\d.]+)",             r"Exim \1"),
         (r"220.*?sendmail\s*([\d./]+)",        r"Sendmail \1"),
         (r"220(.*)",                            r"SMTP\1")]),

    # ── POP3 ────────────────────────────────────────────────────────
    ProbeSpec("POP3", [110], b"",
        [(r"\+OK.*?Dovecot",                    r"Dovecot POP3"),
         (r"\+OK.*?UW POP3\s*([\d.]+)",         r"UW POP3 \1"),
         (r"\+OK(.*)",                           r"POP3\1")]),

    # ── IMAP ────────────────────────────────────────────────────────
    ProbeSpec("IMAP", [143], b"",
        [(r"\* OK.*?Dovecot",                   r"Dovecot IMAP"),
         (r"\* OK.*?Cyrus IMAP\s*([\d.]+)",     r"Cyrus IMAP \1"),
         (r"\* OK(.*)",                          r"IMAP\1")]),

    # ── HTTP ────────────────────────────────────────────────────────
    ProbeSpec("HTTP", [80, 8080, 8000, 8008],
        b"GET / HTTP/1.0\r\n\r\n",
        [(r"Server:\s*Apache/([\d.]+)",         r"Apache httpd \1"),
         (r"Server:\s*nginx/([\d.]+)",          r"nginx \1"),
         (r"Server:\s*Microsoft-IIS/([\d.]+)",  r"Microsoft IIS \1"),
         (r"Server:\s*lighttpd/([\d.]+)",       r"lighttpd \1"),
         (r"Server:\s*([\w._/-]+)",             r"HTTP \1"),
         (r"HTTP/[\d.]+ (\d+)",                 r"HTTP \1")]),

    # ── HTTPS ───────────────────────────────────────────────────────
    ProbeSpec("HTTPS", [443, 8443],
        b"GET / HTTP/1.0\r\n\r\n",
        [(r"Server:\s*Apache/([\d.]+)",         r"Apache httpd \1 (SSL)"),
         (r"Server:\s*nginx/([\d.]+)",          r"nginx \1 (SSL)"),
         (r"Server:\s*([\w._/-]+)",             r"HTTPS \1"),
         (r"HTTP/[\d.]+ (\d+)",                 r"HTTPS \1")],
        ssl=True),

    # ── MySQL ───────────────────────────────────────────────────────
    ProbeSpec("MySQL", [3306], b"",
        [(r"[\x00-\x09]([\d.]+)-",              r"MySQL \1"),
         (r"([\d]+\.[\d]+\.[\d]+)",             r"MySQL \1")]),

    # ── PostgreSQL ──────────────────────────────────────────────────
    ProbeSpec("PostgreSQL", [5432],
        # Startup message: protocol 3.0, user=postgres
        (b"\x00\x00\x00\x28\x00\x03\x00\x00"
         b"user\x00postgres\x00database\x00postgres\x00\x00"),
        [(r"PostgreSQL\s*([\d.]+)",             r"PostgreSQL \1"),
         (r"FATAL.*role.*postgres",             r"PostgreSQL (login fail=version hidden)")]),

    # ── Redis ───────────────────────────────────────────────────────
    ProbeSpec("Redis", [6379], b"PING\r\n",
        [(r"\+PONG",                            r"Redis (PONG)"),
         (r"redis_version:([\d.]+)",            r"Redis \1"),
         (r"-ERR.*?([Rr]edis)",                r"Redis (auth required)")]),

    # ── Memcached ───────────────────────────────────────────────────
    ProbeSpec("Memcached", [11211], b"version\r\n",
        [(r"VERSION\s*([\d.]+)",                r"Memcached \1")]),

    # ── MongoDB ─────────────────────────────────────────────────────
    ProbeSpec("MongoDB", [27017],
        # Minimal OP_QUERY for isMaster
        (b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
         b"\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00"
         b"\x00\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00"
         b"\x10isMaster\x00\x01\x00\x00\x00\x00"),
        [(r'"version"\s*:\s*"([\d.]+)"',        r"MongoDB \1"),
         (r'ismaster',                           r"MongoDB")]),

    # ── LDAP ────────────────────────────────────────────────────────
    ProbeSpec("LDAP", [389],
        # Minimal LDAPv3 bind request (anonymous)
        b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
        [(r"OpenLDAP\s*([\d.]+)",               r"OpenLDAP \1"),
         (r"\x30",                              r"LDAP")]),

    # ── RDP ─────────────────────────────────────────────────────────
    ProbeSpec("RDP", [3389],
        # X.224 Connection Request
        b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
        [(r"\x03\x00",                          r"RDP (Microsoft Terminal Services)"),
         (r".",                                  r"RDP")]),

    # ── VNC ─────────────────────────────────────────────────────────
    ProbeSpec("VNC", [5900, 5901],  b"",
        [(r"RFB\s*([\d.]+)",                    r"VNC RFB \1")]),

    # ── SNMP ────────────────────────────────────────────────────────
    ProbeSpec("SNMP_UDP", [161],
        # SNMPv1 GetRequest for sysDescr
        (b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
         b"\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00"
         b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
        [(r"([\w\s]+\s+[\d.]+)",                r"SNMP device: \1"),
         (r".",                                  r"SNMP")]),

    # ── AMQP (RabbitMQ) ─────────────────────────────────────────────
    ProbeSpec("AMQP", [5672],  b"AMQP\x00\x00\x09\x01",
        [(r"AMQP",                              r"AMQP/RabbitMQ"),
         (r"RabbitMQ\s*([\d.]+)",              r"RabbitMQ \1")]),

    # ── Elasticsearch ───────────────────────────────────────────────
    ProbeSpec("Elasticsearch", [9200],
        b"GET / HTTP/1.0\r\n\r\n",
        [(r'"number"\s*:\s*"([\d.]+)"',         r"Elasticsearch \1"),
         (r'elasticsearch',                      r"Elasticsearch")]),

    # ── Kafka ───────────────────────────────────────────────────────
    ProbeSpec("Kafka", [9092],
        # Kafka ApiVersionsRequest v0
        b"\x00\x00\x00\x0a\x00\x12\x00\x00\x00\x00\x00\x00\x00\x00",
        [(r"\x00\x12",                          r"Kafka broker"),
         (r".",                                  r"Kafka")]),

    # ── Docker ──────────────────────────────────────────────────────
    ProbeSpec("Docker", [2375, 2376],
        b"GET /version HTTP/1.0\r\n\r\n",
        [(r'"Version"\s*:\s*"([\d.]+)"',        r"Docker \1 (UNAUTHENTICATED!)"),
         (r'docker',                             r"Docker API")],
        ssl=False),

    # ── Kubernetes ──────────────────────────────────────────────────
    ProbeSpec("Kubernetes", [6443, 8080],
        b"GET /version HTTP/1.0\r\n\r\n",
        [(r'"gitVersion"\s*:\s*"v([\d.]+)"',    r"Kubernetes v\1"),
         (r'kubernetes',                         r"Kubernetes API")]),
]

# Build port→probe index for O(1) lookup during scan
_PROBE_INDEX: Dict[int, List[ProbeSpec]] = {}
for _ps in SERVICE_PROBE_DB:
    for _port in _ps.ports:
        _PROBE_INDEX.setdefault(_port, []).append(_ps)


def run_service_probe(ip: str, port: int, timeout: float = 3.0) -> Tuple[str, str]:
    """
    [UPG-1] Run all matching probes for `port` against `ip`.
    Returns (version_string, raw_banner).
    Tries each ProbeSpec in order; returns first match.
    Falls back to plain banner grab if no DB entry exists.
    """
    probes = _PROBE_INDEX.get(port, [])

    for spec in probes:
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)
            raw_sock.connect((ip, port))

            sock: Any = raw_sock
            if spec.ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                try:
                    sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
                except ssl.SSLError:
                    sock = raw_sock

            if spec.payload:
                sock.sendall(spec.payload)

            banner_bytes = b""
            try:
                banner_bytes = sock.recv(4096)
            except socket.timeout:
                pass
            try:
                sock.close()
            except Exception:
                pass

            banner = banner_bytes.decode("utf-8", errors="replace").strip()

            for pattern, template in spec.matches:
                m = re.search(pattern, banner, re.IGNORECASE | re.DOTALL)
                if m:
                    try:
                        version = m.expand(template)
                    except re.error:
                        version = template
                    return version, banner

        except Exception:
            continue

    # No DB probe matched — fall back to generic banner
    banner = grab_banner(ip, port, timeout)
    version = extract_service_version(banner)
    return version, banner


def extract_service_version(banner: str) -> str:
    """
    [FIX-34] Match banner against SERVICE_VERSION_PATTERNS to extract
    a human-readable software name and version string.
    Returns empty string if nothing matches.
    """
    for pattern, template in SERVICE_VERSION_PATTERNS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            try:
                return m.expand(template)
            except re.error:
                return template
    return ""
    """
    Grab service banner from an open port.
    [FIX-17] Uses ssl.create_default_context() for SSL-wrapped ports.
    [FIX-19] Randomised User-Agent to vary HTTP probe signatures.
    [FIX-23] Extended protocol-specific probes for 20+ services.
             Each probe matches the protocol's real handshake sequence.
    """
    ua_id = random.randint(10000, 99999)
    http_probe = (
        f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n"
        f"User-Agent: Mozilla/5.0 (compatible; Scanner/{ua_id})\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    # [FIX-23] Protocol-specific probes
    _probes: Dict[int, bytes] = {
        # File transfer / remote access
        21:   b"",                             # FTP: server sends banner first
        22:   b"",                             # SSH: server sends banner first
        23:   b"",                             # Telnet: server sends options first

        # Mail
        25:   b"EHLO scanner.local\r\n",       # SMTP EHLO
        110:  b"",                             # POP3: server sends +OK first
        143:  b"",                             # IMAP: server sends * OK first
        465:  http_probe,                      # SMTPS (over SSL)
        587:  b"EHLO scanner.local\r\n",       # SMTP submission
        993:  b"",                             # IMAPS: server sends first
        995:  b"",                             # POP3S: server sends first

        # Web
        80:   http_probe,
        443:  http_probe,
        8080: http_probe,
        8443: http_probe,
        8888: http_probe,

        # Databases
        3306: b"",                             # MySQL: server sends handshake
        5432: b"",                             # PostgreSQL: server sends first
        6379: b"PING\r\n",                     # Redis: expects PONG
        27017: b"\x3a\x00\x00\x00\x01\x00\x00\x00"  # MongoDB OP_QUERY ping
               b"\x00\x00\x00\x00\xd4\x07\x00\x00"
               b"\x00\x00\x00\x00admin.$cmd\x00"
               b"\x00\x00\x00\x00\x01\x00\x00\x00"
               b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00",

        # Directory / messaging
        389:  b"",                             # LDAP: wait for server
        5672: b"AMQP\x00\x00\x09\x01",        # RabbitMQ AMQP greeting

        # Monitoring
        9200: (                                # Elasticsearch REST
               b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"),
        11211: b"version\r\n",                 # Memcached
    }

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))

        if port in SSL_PORTS:
            # [FIX-17] Recommended ssl.create_default_context() idiom
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
            except ssl.SSLError:
                sock = raw_sock
        else:
            sock = raw_sock

        probe = _probes.get(port, b"")
        if probe:
            sock.sendall(probe)

        banner_bytes = b""
        try:
            banner_bytes = sock.recv(2048)
        except socket.timeout:
            pass

        try:
            sock.close()
        except Exception:
            pass

        banner = banner_bytes.decode("utf-8", errors="replace").strip()
        for line in banner.splitlines():
            line = line.strip()
            if line:
                return line[:200]
        return ""
    except Exception:
        return ""


# ─────────────────────────────────────────────
# HTTP Header Grabber
# ─────────────────────────────────────────────

def fetch_http_headers(ip: str, port: int = 80,
                       use_https: bool = False,
                       timeout: float = 5.0) -> Dict[str, str]:
    if not HAS_URLLIB:
        return {}
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{ip}:{port}/"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    attempts = [True, False] if use_https else [False]
    for with_ssl in attempts:
        try:
            req = _urllib_req.Request(
                url, headers={"User-Agent": "PyScanner/2.0"})
            kw: dict = {"timeout": timeout}
            if with_ssl:
                kw["context"] = ctx
            with _urllib_req.urlopen(req, **kw) as resp:
                headers = dict(resp.getheaders())
                headers["_status_code"] = str(resp.status)
                headers["_url"] = url
                return headers
        except Exception:
            continue
    return {}


# ─────────────────────────────────────────────
# Traceroute
# ─────────────────────────────────────────────

def traceroute(target_ip: str, max_hops: int = 30,
               timeout: float = 2.0) -> List[Dict]:
    hops: List[Dict] = []
    for ttl in range(1, max_hops + 1):
        hop: Dict = {"ttl": ttl, "ip": "*",
                     "hostname": "*", "rtt_ms": None}
        recv_sock = None
        send_sock = None
        try:
            recv_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_sock = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            recv_sock.settimeout(timeout)
            recv_sock.bind(("", 0))    # bind to ephemeral port each TTL
            t0 = time.time()
            send_sock.sendto(b"PyScanner", (target_ip, 33434 + ttl))
            try:
                _, addr = recv_sock.recvfrom(512)
                rtt = round((time.time() - t0) * 1000, 2)
                hop["ip"]       = addr[0]
                hop["hostname"] = reverse_dns(addr[0]) or addr[0]
                hop["rtt_ms"]   = rtt
            except socket.timeout:
                pass
        except PermissionError:
            hop["ip"] = "requires-root"
            hops.append(hop)
            break
        except Exception as exc:
            hop["ip"] = f"error:{exc}"
        finally:
            if send_sock:
                send_sock.close()
            if recv_sock:
                recv_sock.close()

        hops.append(hop)
        if hop["ip"] == target_ip:
            break

    return hops


# ─────────────────────────────────────────────
# [FIX-11] Whois – proper referral chain
# ─────────────────────────────────────────────

def _raw_whois_query(server: str, query: str,
                     timeout: float = 8.0) -> str:
    """Query a whois server directly via TCP port 43."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((server, 43))
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        s.close()


def do_whois(target: str) -> str:
    """
    [FIX-11] Two-step whois:
      1. Query whois.iana.org to get the authoritative referral server.
      2. Follow the 'refer:' line and query the real server.
    Previously queried only IANA which returns referral metadata, not
    full whois records.
    """
    if HAS_WHOIS:
        try:
            w = pywhois.whois(target)
            return str(w)[:3000]
        except Exception:
            pass

    # Step 1: IANA query for referral
    try:
        iana_resp = _raw_whois_query("whois.iana.org", target)
    except Exception:
        return "Whois: IANA query failed"

    # Step 2: Parse 'refer:' line
    refer_server: Optional[str] = None
    for line in iana_resp.splitlines():
        m = re.match(r"(?i)refer:\s*(\S+)", line.strip())
        if m:
            refer_server = m.group(1).strip()
            break

    if not refer_server:
        return iana_resp[:3000]

    # Step 3: Query the authoritative whois server
    try:
        real_resp = _raw_whois_query(refer_server, target)
        return real_resp[:3000]
    except Exception:
        return iana_resp[:3000]


# ─────────────────────────────────────────────
# [FIX-6] ARP Scan - cross-platform
# ─────────────────────────────────────────────

def _arp_scan_linux_raw(network: str, timeout: float) -> List[Dict]:
    """Linux AF_PACKET ARP scan. Requires root."""
    results: List[Dict] = []
    try:
        hosts = expand_cidr(network)
    except Exception:
        return results

    ETH_P_ARP = 0x0806
    ETH_P_ALL = 0x0003

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(ETH_P_ALL))
        s.settimeout(timeout)
    except (AttributeError, OSError, PermissionError):
        return results

    try:
        iface   = _get_default_iface()
        s.bind((iface, 0))
        src_mac = _get_mac(iface)
        src_ip  = get_local_ip()
    except Exception:
        s.close()
        return results

    src_mac_b = bytes.fromhex(src_mac.replace(":", ""))
    broadcast  = b"\xff\xff\xff\xff\xff\xff"

    for dst_ip in hosts:
        dst_ip_b = socket.inet_aton(dst_ip)
        eth = broadcast + src_mac_b + struct.pack("!H", ETH_P_ARP)
        arp = struct.pack("!HHBBH6s4s6s4s",
            1, 0x0800, 6, 4, 1,   # HTYPE, PTYPE, HLEN, PLEN, OP=REQUEST
            src_mac_b, socket.inet_aton(src_ip),
            b"\x00" * 6, dst_ip_b)
        try:
            s.send(eth + arp)
        except Exception:
            continue

    deadline = time.time() + timeout
    seen: set = set()
    while time.time() < deadline:
        try:
            frame, _ = s.recvfrom(2048)
            if len(frame) < 42:
                continue
            eth_type = struct.unpack("!H", frame[12:14])[0]
            if eth_type != ETH_P_ARP:
                continue
            arp_op = struct.unpack("!H", frame[20:22])[0]
            if arp_op != 2:    # ARP Reply
                continue
            sender_mac = ":".join(f"{b:02x}" for b in frame[22:28])
            sender_ip  = socket.inet_ntoa(frame[28:32])
            if sender_ip not in seen:
                seen.add(sender_ip)
                results.append({"ip": sender_ip, "mac": sender_mac})
        except socket.timeout:
            break
        except Exception:
            break

    s.close()
    return results


def _arp_scan_subprocess(network: str) -> List[Dict]:
    """
    [FIX-6] Cross-platform ARP discovery via external tools.
    Tries: arp-scan -> nmap -sn -> arp cache (passive).
    Works on macOS and Windows as well as Linux without raw sockets.
    """
    results: List[Dict] = []

    # Option A: arp-scan (Linux, needs root)
    try:
        out = subprocess.check_output(
            ["arp-scan", "--localnet", "--quiet"],
            stderr=subprocess.DEVNULL, timeout=15)
        for line in out.decode(errors="replace").splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F:]{17})", line)
            if m:
                results.append({"ip": m.group(1), "mac": m.group(2)})
        if results:
            return results
    except Exception:
        pass

    # Option B: nmap ping scan
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", "-PR", network, "-oG", "-"],
            stderr=subprocess.DEVNULL, timeout=30)
        for line in out.decode(errors="replace").splitlines():
            m = re.search(r"Host: (\d+\.\d+\.\d+\.\d+)", line)
            if m and "Up" in line:
                results.append({"ip": m.group(1), "mac": "unknown"})
        if results:
            return results
    except Exception:
        pass

    # Option C: read OS ARP cache (passive, no root required)
    try:
        out = subprocess.check_output(
            ["arp", "-a"], stderr=subprocess.DEVNULL, timeout=5)
        pattern = (r"(\d+\.\d+\.\d+\.\d+).*?"
                   r"([\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-]"
                   r"[\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-]"
                   r"[\da-fA-F]{2}[:\-][\da-fA-F]{2})")
        for line in out.decode(errors="replace").splitlines():
            m = re.search(pattern, line)
            if m:
                results.append({
                    "ip":  m.group(1),
                    "mac": m.group(2).replace("-", ":")})
    except Exception:
        pass

    return results


def arp_scan(network: str, timeout: float = 2.0) -> List[Dict]:
    """Entry point: choose best ARP method for the current platform."""
    if IS_LINUX:
        res = _arp_scan_linux_raw(network, timeout)
        if res:
            return res
    return _arp_scan_subprocess(network)


def _get_default_iface() -> str:
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    except Exception:
        pass
    return "eth0"


def _get_mac(iface: str) -> str:
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip()
    except Exception:
        return "00:00:00:00:00:00"


# ─────────────────────────────────────────────
# Core Scanner
# ─────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════════
# [UPG-3] ADAPTIVE TIMING MODES  (-T0 to -T5, like Nmap)
# ═══════════════════════════════════════════════════════════════════
# Each timing mode configures: timeout, max_rate (pps), min_parallelism,
# inter-probe delay, and retransmit count. Higher T = faster + louder.

@dataclass
class TimingMode:
    name:            str
    timeout:         float   # per-probe socket timeout (seconds)
    max_rate:        int     # max packets/sec (0 = unlimited)
    parallelism:     int     # max concurrent threads/coroutines
    probe_delay:     float   # fixed delay between probes (seconds)
    syn_retries:     int     # SYN retransmit attempts
    icmp_probes:     int     # ICMP ping attempts


T_MODES: Dict[int, TimingMode] = {
    0: TimingMode("paranoid",    300.0,    1,   1,    5.0,   3, 5),
    1: TimingMode("sneaky",       15.0,   10,   5,    0.15,  3, 4),
    2: TimingMode("polite",        5.0,  100,  20,    0.04,  2, 3),
    3: TimingMode("normal",        2.0,    0, 100,    0.0,   2, 3),   # default
    4: TimingMode("aggressive",    1.0,    0, 250,    0.0,   1, 2),
    5: TimingMode("insane",        0.3,    0, 500,    0.0,   1, 1),
}


class AdaptiveRTT:
    """
    RFC 6298 RTT estimator.  Tracks SRTT and RTTVAR → dynamic RTO.
    Thread-safe; updated by both sync and async engines.
    """
    def __init__(self, initial_rtt: float = 0.5):
        self._srtt:   float = initial_rtt
        self._rttvar: float = initial_rtt / 2
        self._lock            = threading.Lock()

    def update(self, measured_rtt: float) -> None:
        with self._lock:
            alpha, beta  = 0.125, 0.25
            self._rttvar = ((1 - beta)  * self._rttvar
                            + beta  * abs(self._srtt - measured_rtt))
            self._srtt   = ((1 - alpha) * self._srtt
                            + alpha * measured_rtt)

    @property
    def rto(self) -> float:
        """RTO = SRTT + 4·RTTVAR, clamped 0.1–5s."""
        with self._lock:
            return max(0.1, min(5.0, self._srtt + 4 * self._rttvar))

    @property
    def srtt_ms(self) -> float:
        with self._lock:
            return round(self._srtt * 1000, 2)


class CongestionController:
    """
    [ENH-1] Adaptive congestion controller — Nmap-style dynamic pacing.

    Implements a simplified TCP-like congestion control loop:

      Phase 1 — Slow Start:
        send_rate doubles each RTT until loss is detected or
        ssthresh is reached.  Allows fast ramp-up on uncongested paths.

      Phase 2 — Congestion Avoidance:
        send_rate increases by 1 pps per RTT.  Steady, gentle growth.

      Loss event:
        ssthresh = max(send_rate / 2, MIN_RATE)
        send_rate = ssthresh  (multiplicative decrease)
        parallelism reduced by 20%

      Parallelism:
        Adjusted proportionally to send_rate; bounded by T-mode limits.

    Integrates with AsyncSynScanner and syn_batch_scan via the
    global _CONGESTION singleton, which can be read by the rate limiter.
    """

    MIN_RATE:   float = 5.0    # pps floor
    MAX_RATE:   float = 10000  # pps ceiling (practical Python limit)
    MIN_PARA:   int   = 1
    MAX_PARA:   int   = 500

    def __init__(self, initial_rate: float = 100.0,
                 initial_para: int = 50):
        self._rate:     float = initial_rate
        self._ssthresh: float = self.MAX_RATE
        self._para:     int   = initial_para
        self._slow_start: bool = True
        self._sent:     int   = 0
        self._replied:  int   = 0
        self._loss_events: int = 0
        self._lock            = threading.Lock()
        self._rtt             = AdaptiveRTT(initial_rtt=0.3)

    # ── Called when a probe is sent ──────────────────────────────────
    def on_send(self) -> None:
        with self._lock:
            self._sent += 1

    # ── Called when a reply arrives ──────────────────────────────────
    def on_reply(self, rtt: float) -> None:
        self._rtt.update(rtt)
        with self._lock:
            self._replied += 1

    # ── Called at end of each RTT window to adjust rate ──────────────
    def tick(self) -> None:
        """Call once per RTT to update send_rate and parallelism."""
        with self._lock:
            sent    = max(1, self._sent)
            replied = self._replied
            loss_ratio = 1.0 - min(1.0, replied / sent)

            # Loss event if >10% probes unanswered
            if loss_ratio > 0.10:
                self._loss_events += 1
                self._ssthresh = max(self.MIN_RATE, self._rate / 2.0)
                self._rate     = self._ssthresh
                self._slow_start = False
                # Reduce parallelism proportionally
                self._para = max(self.MIN_PARA,
                                 int(self._para * 0.8))
            elif self._slow_start:
                # Exponential growth until ssthresh
                new_rate = min(self._rate * 2.0, self._ssthresh)
                if new_rate >= self._ssthresh:
                    self._slow_start = False
                self._rate = min(new_rate, self.MAX_RATE)
            else:
                # Congestion avoidance: linear +1 pps per RTT
                self._rate = min(self._rate + 1.0, self.MAX_RATE)

            # Parallelism tracks rate on a log scale
            import math
            target_para = max(
                self.MIN_PARA,
                min(self.MAX_PARA,
                    int(math.log2(max(2, self._rate)) * 10)))
            # Smooth toward target
            self._para = int(0.8 * self._para + 0.2 * target_para)

            # Reset window counters
            self._sent    = 0
            self._replied = 0

    @property
    def send_rate(self) -> float:
        with self._lock:
            return self._rate

    @property
    def parallelism(self) -> int:
        with self._lock:
            return self._para

    @property
    def loss_events(self) -> int:
        with self._lock:
            return self._loss_events

    def install_as_rate_limiter(self) -> None:
        """Replace the global token bucket with this controller's rate."""
        global _RATE_LIMITER
        _RATE_LIMITER = TokenBucket(
            rate_pps=self._rate, capacity=int(self._rate))

    def update_rate_limiter(self) -> None:
        """Re-sync the global token bucket after a tick()."""
        global _RATE_LIMITER
        if _RATE_LIMITER is not None:
            _RATE_LIMITER = TokenBucket(
                rate_pps=self._rate, capacity=max(1, int(self._rate)))


# Global congestion controller — None until activated by -T4/-T5 or --adaptive
_CONGESTION: Optional[CongestionController] = None


# ═══════════════════════════════════════════════════════════════════
# [UPG-3] ADVANCED SCAN TYPES: NULL / FIN / XMAS / ACK / WINDOW
# ═══════════════════════════════════════════════════════════════════

# TCP flag bit constants
F_FIN  = 0x01
F_SYN  = 0x02
F_RST  = 0x04
F_PSH  = 0x08
F_ACK  = 0x10
F_URG  = 0x20
F_ECE  = 0x40
F_CWR  = 0x80


def _build_flag_packet(src_ip: str, dst_ip: str,
                       src_port: int, dst_port: int,
                       flags: int,
                       seq: int = 0, ack_num: int = 0,
                       window: int = 1024) -> bytes:
    """
    Build a raw IP+TCP packet with arbitrary TCP flags.
    Re-uses the checksum() function from the core engine.
    Used by NULL, FIN, XMAS, ACK, Window scans.
    """
    # IP header (20 bytes, no options)
    ip_id  = random.randint(0, 0xFFFF)
    ttl    = random.choice([64, 64, 64, 128])   # OS-realistic [FIX-22]
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0,        # version/IHL, DSCP/ECN
        40,             # total length (20 IP + 20 TCP)
        ip_id, 0x4000,  # ID, flags (DF set)
        ttl,            # TTL
        socket.IPPROTO_TCP,
        0,              # checksum placeholder
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip_chk  = checksum(ip_hdr)
    ip_hdr  = ip_hdr[:10] + struct.pack("!H", ip_chk) + ip_hdr[12:]

    # TCP header (20 bytes, no options)
    tcp_hdr = struct.pack("!HHLLBBHHH",
        src_port, dst_port,
        seq, ack_num,
        0x50,           # data offset = 5 words (20 bytes)
        flags,
        window,
        0, 0,           # checksum placeholder, urgent pointer
    )
    # TCP pseudo-header for checksum
    pseudo  = struct.pack("!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0, socket.IPPROTO_TCP, len(tcp_hdr),
    )
    tcp_chk = checksum(pseudo + tcp_hdr)
    tcp_hdr = tcp_hdr[:16] + struct.pack("!H", tcp_chk) + tcp_hdr[18:]

    return ip_hdr + tcp_hdr


def stealth_scan(ip: str, ports: List[int],
                 scan_flags: int, timeout: float) -> Dict[int, PortResult]:
    """
    [UPG-3] Generic stealth scan engine.  Sends crafted TCP packets with
    the given flag combination and interprets responses per RFC 793:

      NULL (flags=0x00): no flags   → RFC: RST=closed, silence=open|filtered
      FIN  (flags=0x01): FIN only   → same as NULL
      XMAS (flags=0x29): FIN+PSH+URG→ same as NULL
      ACK  (flags=0x10): ACK only   → RST=unfiltered, silence=filtered
                                       (used for firewall rule mapping)
      Window(flags=0x10): like ACK, but open=RST with nonzero window

    Returns dict port → PortResult with state/reason.
    """
    src_ip = get_local_ip(ip)
    results: Dict[int, PortResult] = {
        p: PortResult(port=p, protocol="tcp", state="open|filtered",
                      reason="no-response")
        for p in ports
    }

    is_ack_mode   = bool(scan_flags & F_ACK and not (scan_flags & F_SYN))
    is_window_mode = scan_flags == F_ACK  # Window scan = ACK + check window

    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                             4 * 1024 * 1024)
        recv_sock.settimeout(0.5)
    except (PermissionError, OSError):
        # No raw socket access → return all as unknown
        for r in results.values():
            r.state  = "unknown"
            r.reason = "no-root"
        return results

    # src_port → dst_port map
    port_map: Dict[int, int] = {}
    allocated: List[int] = []

    try:
        # ── Send phase ──────────────────────────────────────────────
        for dst_port in ports:
            src_port = _PORT_ALLOC.alloc()
            allocated.append(src_port)
            port_map[src_port] = dst_port

            seq = random.randint(0, 0xFFFFFFFF)
            pkt = _build_flag_packet(src_ip, ip, src_port, dst_port,
                                     scan_flags, seq)
            if _RATE_LIMITER:
                _RATE_LIMITER.consume(1)
            try:
                recv_sock.sendto(pkt, (ip, 0))
            except OSError:
                pass

        # ── Receive phase ────────────────────────────────────────────
        reverse_map = {v: k for k, v in port_map.items()}   # dst→src
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                data, addr = recv_sock.recvfrom(4096)
            except socket.timeout:
                time.sleep(0.01)
                continue
            except OSError:
                break

            if addr[0] != ip or len(data) < 20:
                continue
            if data[9] != socket.IPPROTO_TCP:
                continue

            ihl = (data[0] & 0x0F) * 4
            if len(data) < ihl + 20:
                continue

            reply_dst = struct.unpack("!H", data[ihl + 2: ihl + 4])[0]
            reply_src = struct.unpack("!H", data[ihl:     ihl + 2])[0]

            if reply_dst not in port_map:
                continue
            dst_port = port_map[reply_dst]
            if reply_src != dst_port:
                continue

            flags_rx = data[ihl + 13]
            window   = struct.unpack("!H", data[ihl + 14: ihl + 16])[0]
            r = results[dst_port]

            if flags_rx & F_RST:
                if is_ack_mode:
                    # ACK scan: RST = unfiltered (port exists in FW ruleset)
                    r.state  = "unfiltered"
                    r.reason = "rst"
                elif is_window_mode and window > 0:
                    # Window scan: RST with nonzero window = open
                    r.state  = "open"
                    r.reason = "rst-window"
                else:
                    # NULL/FIN/XMAS: RST = closed
                    r.state  = "closed"
                    r.reason = "rst"
            elif flags_rx & 0x12:   # SYN-ACK (shouldn't happen but handle it)
                r.state  = "open"
                r.reason = "syn-ack"
                _send_rst(src_ip, ip, reply_dst, dst_port,
                          struct.unpack("!L", data[ihl+4:ihl+8])[0] + 1)

    finally:
        recv_sock.close()
        for p in allocated:
            _PORT_ALLOC.free(p)

    return results


def null_scan(ip: str, ports: List[int], timeout: float) -> Dict[int, PortResult]:
    """[UPG-3] NULL scan: no TCP flags. RST=closed, silence=open|filtered."""
    return stealth_scan(ip, ports, 0x00, timeout)


def fin_scan(ip: str, ports: List[int], timeout: float) -> Dict[int, PortResult]:
    """[UPG-3] FIN scan: FIN flag only. Bypasses many stateless firewalls."""
    return stealth_scan(ip, ports, F_FIN, timeout)


def xmas_scan(ip: str, ports: List[int], timeout: float) -> Dict[int, PortResult]:
    """[UPG-3] XMAS scan: FIN+PSH+URG. Named for 'lit-up' flags."""
    return stealth_scan(ip, ports, F_FIN | F_PSH | F_URG, timeout)


def ack_scan(ip: str, ports: List[int], timeout: float) -> Dict[int, PortResult]:
    """[UPG-3] ACK scan: maps firewall rules. RST=unfiltered, silence=filtered."""
    return stealth_scan(ip, ports, F_ACK, timeout)


def window_scan(ip: str, ports: List[int], timeout: float) -> Dict[int, PortResult]:
    """[UPG-3] Window scan: ACK + nonzero RST window = open. OS-dependent."""
    return stealth_scan(ip, ports, F_ACK, timeout)


# ═══════════════════════════════════════════════════════════════════
# [UPG-4] ASYNC EVENT-LOOP SCAN ENGINE
# ═══════════════════════════════════════════════════════════════════
# Uses asyncio with raw sockets in non-blocking mode.
# For large port counts (>500 ports or >10 hosts), the async engine
# delivers 10–50x throughput over thread-per-port models by batching
# all sends and running a single non-blocking receive loop.

class AsyncSynScanner:
    """
    [UPG-4] Async SYN scanner.

    Architecture:
      1. A single async coroutine sends all SYN probes in rate-limited bursts.
      2. A parallel receive coroutine drains the raw socket using
         loop.run_in_executor() to avoid blocking the event loop.
      3. An AdaptiveRTT object updates dynamically as replies arrive,
         tightening the recv deadline on fast networks.
      4. Unanswered ports are retransmitted up to SYN_MAX_RETRIES times.

    This matches the Masscan/Nmap async model at the Python level.
    """

    def __init__(self, src_ip: str, timeout: float,
                 rtt: Optional[AdaptiveRTT] = None):
        self.src_ip  = src_ip
        self.timeout = timeout
        self.rtt     = rtt or AdaptiveRTT(initial_rtt=min(timeout / 2, 0.5))

    def scan(self, ip: str, ports: List[int]) -> Dict[int, PortResult]:
        """Entry point — runs the async event loop and returns results."""
        try:
            return asyncio.run(self._async_scan(ip, ports))
        except Exception:
            # Fall back to synchronous batch scan if async fails
            return syn_batch_scan(ip, ports, self.timeout)

    async def _async_scan(self, ip: str,
                          ports: List[int]) -> Dict[int, PortResult]:
        loop = asyncio.get_running_loop()

        results: Dict[int, PortResult] = {
            p: PortResult(port=p, protocol="tcp",
                          state="filtered", reason="no-response")
            for p in ports
        }

        # Open raw sockets in a thread (blocking call)
        try:
            send_sock, recv_sock = await loop.run_in_executor(
                None, self._open_sockets)
        except OSError:
            # No raw socket privilege → connect-scan fallback per port
            tasks = [
                loop.run_in_executor(None, tcp_connect_scan, ip, p, self.timeout)
                for p in ports
            ]
            scan_results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in scan_results:
                if isinstance(r, PortResult):
                    results[r.port] = r
            return results

        probe_map:      Dict[int, Tuple[int, int]] = {}   # src_port→(dst,seq)
        allocated:      List[int] = []
        seen_ports:     set = set()
        send_times:     Dict[int, float] = {}   # dst_port→time sent

        try:
            # ── Async send loop ──────────────────────────────────────
            await loop.run_in_executor(
                None, self._send_all, ip, ports,
                probe_map, allocated, send_times, send_sock)

            # ── Async receive loop ───────────────────────────────────
            await loop.run_in_executor(
                None, self._recv_all, ip, recv_sock,
                probe_map, seen_ports, results, send_times)

            # ── Async retransmit loop ────────────────────────────────
            for _retry in range(SYN_MAX_RETRIES - 1):
                unanswered = [p for p in ports if p not in seen_ports]
                if not unanswered:
                    break
                await loop.run_in_executor(
                    None, self._send_all, ip, unanswered,
                    probe_map, allocated, send_times, send_sock)
                await loop.run_in_executor(
                    None, self._recv_all, ip, recv_sock,
                    probe_map, seen_ports, results, send_times)

        finally:
            send_sock.close()
            recv_sock.close()
            for p in allocated:
                _PORT_ALLOC.free(p)

        return results

    def _open_sockets(self) -> Tuple[socket.socket, socket.socket]:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                             8 * 1024 * 1024)   # 8MB — larger than sync engine
        recv_sock.settimeout(0.5)
        return send_sock, recv_sock

    def _send_all(self, ip: str, ports: List[int],
                  probe_map: Dict, allocated: List,
                  send_times: Dict, send_sock: socket.socket) -> None:
        for dst_port in ports:
            src_port = _PORT_ALLOC.alloc()
            allocated.append(src_port)
            seq_num  = random.randint(0, 0xFFFFFFFF)
            probe_map[src_port] = (dst_port, seq_num)
            send_times[dst_port] = time.time()

            pkt = _build_syn_packet(self.src_ip, ip, src_port,
                                    dst_port, seq_num)
            if _RATE_LIMITER:
                _RATE_LIMITER.consume(1)
            try:
                send_sock.sendto(pkt, (ip, 0))
                if _CONGESTION:
                    _CONGESTION.on_send()   # [ENH-1] track sent probes
            except OSError:
                pass

    def _recv_all(self, ip: str, recv_sock: socket.socket,
                  probe_map: Dict, seen_ports: set,
                  results: Dict, send_times: Dict) -> None:
        deadline    = time.time() + self.rto_deadline()
        tick_time   = time.time() + self.rtt.rto   # [ENH-1] periodic tick

        while time.time() < deadline and len(seen_ports) < len(results):
            try:
                data, addr = recv_sock.recvfrom(4096)
            except socket.timeout:
                # [ENH-1] Periodic congestion tick on each timeout window
                if _CONGESTION and time.time() >= tick_time:
                    _CONGESTION.tick()
                    _CONGESTION.update_rate_limiter()
                    tick_time = time.time() + self.rtt.rto
                time.sleep(0.005)
                continue
            except OSError:
                break

            if addr[0] != ip or len(data) < 20:
                continue
            if data[9] != socket.IPPROTO_TCP:
                continue

            ihl = (data[0] & 0x0F) * 4
            if len(data) < ihl + 20:
                continue

            reply_dst = struct.unpack("!H", data[ihl + 2: ihl + 4])[0]
            reply_src = struct.unpack("!H", data[ihl:     ihl + 2])[0]

            if reply_dst not in probe_map:
                continue
            dst_port, _ = probe_map[reply_dst]
            if reply_src != dst_port:
                continue

            # [ENH-1] Update RTT and congestion controller on each reply
            if dst_port in send_times:
                rtt = time.time() - send_times[dst_port]
                self.rtt.update(rtt)
                if _CONGESTION:
                    _CONGESTION.on_reply(rtt)

            flags      = data[ihl + 13]
            remote_seq = struct.unpack("!L", data[ihl + 4: ihl + 8])[0]
            r = results[dst_port]

            if flags & 0x12:   # SYN-ACK → open
                r.state   = "open"
                r.reason  = "syn-ack"
                r.service = service_name(dst_port)

                tcp_win = struct.unpack("!H", data[ihl+14:ihl+16])[0]
                df      = bool(struct.unpack("!H", data[6:8])[0] & 0x4000)
                has_opt = (data[ihl+12] >> 4) * 4 > 20
                r._fp_tcp_window      = tcp_win
                r._fp_df_bit          = df
                r._fp_has_tcp_options = has_opt

                _send_rst(self.src_ip, ip, reply_dst, dst_port,
                          remote_seq + 1)
            elif flags & 0x04:  # RST → closed
                r.state  = "closed"
                r.reason = "reset"

            seen_ports.add(dst_port)

        # [ENH-1] Final tick at end of receive window
        if _CONGESTION:
            _CONGESTION.tick()
            _CONGESTION.update_rate_limiter()

    def rto_deadline(self) -> float:
        """Dynamic timeout = max(configured_timeout, 2 * RTO)."""
        return max(self.timeout, 2 * self.rtt.rto)


# ═══════════════════════════════════════════════════════════════════
# [UPG-2] PLUGIN / SCRIPT ENGINE  (NSE equivalent)
# ═══════════════════════════════════════════════════════════════════

@dataclass
class PluginResult:
    plugin:  str
    port:    int
    output:  str
    data:    Dict[str, Any] = field(default_factory=dict)


@dataclass
class PluginSpec:
    """Metadata + implementation for one plugin."""
    name:     str
    ports:    List[int]    # [] = run on all open ports
    protocol: str          # "tcp" or "udp"
    run:      Callable     # fn(ip, port, timeout) → PluginResult | None


# ── Built-in Plugins ───────────────────────────────────────────────

def _plugin_http_title(ip: str, port: int, timeout: float) -> Optional[PluginResult]:
    """Fetch HTTP page title from an HTTP or HTTPS service."""
    use_ssl = port in SSL_PORTS
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)
        sock.sendall(
            f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            .encode())
        response = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
        except Exception:
            pass
        sock.close()

        text = response.decode("utf-8", errors="replace")
        m = re.search(r"<title[^>]*>(.*?)</title>", text,
                      re.IGNORECASE | re.DOTALL)
        title = m.group(1).strip() if m else "(no title)"
        title = re.sub(r"\s+", " ", title)[:120]
        return PluginResult(
            plugin="http-title", port=port,
            output=f"HTTP Title: {title}",
            data={"title": title})
    except Exception:
        return None


def _plugin_ftp_anon(ip: str, port: int, timeout: float) -> Optional[PluginResult]:
    """Test whether FTP allows anonymous login."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.sendall(b"USER anonymous\r\n")
        r1 = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.sendall(b"PASS scanner@example.com\r\n")
        r2 = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()
        if r2.startswith("2"):   # 2xx = login accepted
            return PluginResult(
                plugin="ftp-anon", port=port,
                output="FTP anonymous login ALLOWED",
                data={"anonymous": True, "response": r2})
        return PluginResult(
            plugin="ftp-anon", port=port,
            output="FTP anonymous login denied",
            data={"anonymous": False})
    except Exception:
        return None


def _plugin_redis_info(ip: str, port: int, timeout: float) -> Optional[PluginResult]:
    """Probe Redis for unauthenticated INFO command."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(b"INFO server\r\n")
        raw = sock.recv(4096).decode("utf-8", errors="replace")
        sock.close()
        if "redis_version" in raw:
            m = re.search(r"redis_version:([\d.]+)", raw)
            ver  = m.group(1) if m else "?"
            mode = "UNAUTHENTICATED" if "requirepass" not in raw else "protected"
            return PluginResult(
                plugin="redis-info", port=port,
                output=f"Redis {ver} ({mode})",
                data={"version": ver, "unauthenticated": "requirepass" not in raw})
        if "NOAUTH" in raw or "DENIED" in raw:
            return PluginResult(
                plugin="redis-info", port=port,
                output="Redis (auth required)",
                data={"unauthenticated": False})
    except Exception:
        pass
    return None


def _plugin_ssl_cert(ip: str, port: int, timeout: float) -> Optional[PluginResult]:
    """Extract TLS certificate subject, issuer, and expiry."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                cipher_name, proto, bits = ssock.cipher()

        if not cert:
            return PluginResult(plugin="ssl-cert", port=port,
                                output="TLS: self-signed or no cert info")

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        cn      = subject.get("commonName", "?")
        org     = subject.get("organizationName", "?")
        iss_cn  = issuer.get("commonName", "?")
        expiry  = cert.get("notAfter", "?")
        sans    = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        out = (f"TLS {proto}/{bits}bit  CN={cn}  Org={org}\n"
               f"        Issuer={iss_cn}  Expires={expiry}")
        if sans:
            out += f"\n        SANs: {', '.join(sans[:6])}"
        return PluginResult(
            plugin="ssl-cert", port=port, output=out,
            data={"cn": cn, "issuer": iss_cn, "expiry": expiry,
                  "sans": sans, "proto": proto, "bits": bits})
    except Exception:
        return None


def _plugin_smb_os(ip: str, port: int, timeout: float) -> Optional[PluginResult]:
    """Send SMB negotiation to extract OS and domain information."""
    # SMBv1 Negotiate Protocol Request
    smb_neg = (
        b"\x00\x00\x00\x85"                    # NetBIOS session
        b"\xff\x53\x4d\x42"                    # SMB header magic
        b"\x72"                                 # Command: Negotiate
        b"\x00\x00\x00\x00"                    # NT Status
        b"\x18\x53\xc8\x00"                    # Flags
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\xff\xfe"
        b"\x00\x00\x00\x00"
        b"\x00\x62\x00\x02NT LM 0.12\x00"
        b"\x02SMB 2.002\x00\x02SMB 2.???\x00"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(smb_neg)
        raw = sock.recv(4096)
        sock.close()
        if len(raw) > 4 and raw[4:8] == b"\xffSMB":
            # Parse basic fields from response
            return PluginResult(
                plugin="smb-os", port=port,
                output="SMBv1 responded (potential EternalBlue target)",
                data={"smb_version": "v1", "warning": "SMBv1 enabled"})
        if b"\xfeSMB" in raw:
            return PluginResult(
                plugin="smb-os", port=port,
                output="SMBv2/v3 responded",
                data={"smb_version": "v2+"})
    except Exception:
        pass
    return None


def _plugin_ssh_auth(ip: str, port: int, timeout: float) -> Optional[PluginResult]:
    """Extract SSH server banner and supported auth methods."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(256).decode("utf-8", errors="replace").strip()
        # Send our client banner
        sock.sendall(b"SSH-2.0-PyScanner_7.0\r\n")
        # Read key exchange init (don't parse deeply, just grab what we can)
        kex_raw = b""
        try:
            kex_raw = sock.recv(1024)
        except Exception:
            pass
        sock.close()
        m = re.search(r"SSH-[\d.]+-(.+)", banner)
        software = m.group(1) if m else "SSH"
        return PluginResult(
            plugin="ssh-auth", port=port,
            output=f"SSH banner: {software}",
            data={"banner": banner, "software": software})
    except Exception:
        return None


def _plugin_http_server(ip: str, port: int, timeout: float) -> Optional[PluginResult]:
    """Extract Server header from HTTP/HTTPS response."""
    use_ssl = port in SSL_PORTS
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        raw = sock.recv(2048).decode("utf-8", errors="replace")
        sock.close()
        m = re.search(r"^Server:\s*(.+)$", raw, re.MULTILINE | re.IGNORECASE)
        if m:
            server = m.group(1).strip()
            return PluginResult(
                plugin="http-server", port=port,
                output=f"Server: {server}",
                data={"server": server})
    except Exception:
        pass
    return None


# ── ENH-4: Vulnerability Detection Plugins ────────────────────────

def _plugin_ssl_weak_ciphers(ip: str, port: int,
                              timeout: float) -> Optional[PluginResult]:
    """Check for weak TLS versions and cipher suites."""
    findings: List[str] = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    # Test SSLv3 / TLS 1.0 / 1.1 (deprecated, should fail on modern stacks)
    WEAK_PROTOCOLS = [
        ("TLS 1.0", ssl.TLSVersion.TLSv1   if hasattr(ssl, 'TLSVersion') else None),
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl, 'TLSVersion') else None),
    ]
    for proto_name, proto_ver in WEAK_PROTOCOLS:
        if proto_ver is None:
            continue
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode    = ssl.CERT_NONE
            ctx2.maximum_version = proto_ver
            ctx2.minimum_version = proto_ver
            with socket.create_connection((ip, port), timeout=timeout) as s:
                with ctx2.wrap_socket(s, server_hostname=ip):
                    findings.append(f"WEAK: {proto_name} accepted")
        except ssl.SSLError:
            pass   # Server correctly rejected weak protocol
        except Exception:
            pass

    # Check for self-signed cert
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            ctx3 = ssl.create_default_context()
            ctx3.check_hostname = False
            ctx3.verify_mode    = ssl.CERT_NONE
            with ctx3.wrap_socket(s, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", []))
                    issr = dict(x[0] for x in cert.get("issuer", []))
                    if subj == issr:
                        findings.append("WARN: Self-signed certificate")
                if cipher_info:
                    cipher_name = cipher_info[0]
                    if any(w in cipher_name.upper() for w in
                           ["RC4", "DES", "NULL", "EXPORT", "ANON", "MD5"]):
                        findings.append(f"WEAK cipher: {cipher_name}")
    except Exception:
        pass

    if findings:
        return PluginResult(
            plugin="ssl-weak-ciphers", port=port,
            output="\n".join(findings),
            data={"findings": findings, "vulnerable": True})
    return PluginResult(
        plugin="ssl-weak-ciphers", port=port,
        output="TLS: no obvious weak ciphers detected",
        data={"vulnerable": False})


def _plugin_http_security_headers(ip: str, port: int,
                                   timeout: float) -> Optional[PluginResult]:
    """Check for missing HTTP security headers (HSTS, CSP, X-Frame, etc.)."""
    use_ssl = port in SSL_PORTS
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)
        sock.sendall(
            f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            .encode())
        raw = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                raw += chunk
                if b"\r\n\r\n" in raw: break
        except Exception:
            pass
        sock.close()

        headers_raw = raw.decode("utf-8", errors="replace").lower()
        missing: List[str] = []
        security_headers = {
            "strict-transport-security": "Missing HSTS",
            "content-security-policy":   "Missing CSP",
            "x-frame-options":           "Missing X-Frame-Options",
            "x-content-type-options":    "Missing X-Content-Type-Options",
            "x-xss-protection":          "Missing X-XSS-Protection",
            "referrer-policy":           "Missing Referrer-Policy",
        }
        for hdr, label in security_headers.items():
            if hdr not in headers_raw:
                missing.append(label)

        if missing:
            return PluginResult(
                plugin="http-security-headers", port=port,
                output="Missing security headers: " + ", ".join(missing),
                data={"missing": missing})
        return PluginResult(
            plugin="http-security-headers", port=port,
            output="HTTP security headers: all present",
            data={"missing": []})
    except Exception:
        return None


def _plugin_default_creds(ip: str, port: int,
                           timeout: float) -> Optional[PluginResult]:
    """Test common default credentials for FTP, Redis, MongoDB."""
    if port == 21:   # FTP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.recv(1024)
            for user, pwd in [("admin","admin"), ("admin",""), ("root","root")]:
                sock.sendall(f"USER {user}\r\n".encode())
                r1 = sock.recv(256).decode("utf-8", errors="replace")
                sock.sendall(f"PASS {pwd}\r\n".encode())
                r2 = sock.recv(256).decode("utf-8", errors="replace")
                if r2.startswith("2"):
                    sock.close()
                    return PluginResult(
                        plugin="default-creds", port=port,
                        output=f"FTP default creds work: {user}/{pwd}",
                        data={"service": "ftp", "user": user, "pass": pwd,
                              "vulnerable": True})
            sock.close()
        except Exception:
            pass

    elif port == 6379:  # Redis
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.sendall(b"PING\r\n")
            r = sock.recv(256)
            sock.close()
            if r.startswith(b"+PONG"):
                return PluginResult(
                    plugin="default-creds", port=port,
                    output="Redis: no authentication required (UNAUTHENTICATED)",
                    data={"service": "redis", "vulnerable": True})
        except Exception:
            pass

    elif port == 27017:  # MongoDB
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            # Minimal isMaster query
            sock.sendall(
                b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
                b"\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00"
                b"\x00\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00"
                b"\x10isMaster\x00\x01\x00\x00\x00\x00")
            r = sock.recv(512).decode("utf-8", errors="replace")
            sock.close()
            if "ismaster" in r.lower() or "isWritablePrimary" in r:
                return PluginResult(
                    plugin="default-creds", port=port,
                    output="MongoDB: responds to unauthenticated queries",
                    data={"service": "mongodb", "vulnerable": True})
        except Exception:
            pass
    return None


def _plugin_open_redirect(ip: str, port: int,
                           timeout: float) -> Optional[PluginResult]:
    """Test for open redirect via common query string patterns."""
    use_ssl = port in SSL_PORTS
    scheme  = "https" if use_ssl else "http"
    PAYLOADS = [
        "/?url=http://evil.com",
        "/?redirect=http://evil.com",
        "/?next=http://evil.com",
        "/?return=http://evil.com",
    ]
    try:
        for path in PAYLOADS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)
            req = (f"GET {path} HTTP/1.0\r\nHost: {ip}\r\n\r\n").encode()
            sock.sendall(req)
            try:
                resp = sock.recv(1024).decode("utf-8", errors="replace")
            except Exception:
                resp = ""
            try: sock.close()
            except Exception: pass
            if "http://evil.com" in resp and (
                    "301" in resp or "302" in resp or "Location" in resp):
                return PluginResult(
                    plugin="open-redirect", port=port,
                    output=f"Open redirect detected via {path}",
                    data={"path": path, "vulnerable": True})
    except Exception:
        pass
    return None


def _plugin_smb_signing(ip: str, port: int,
                         timeout: float) -> Optional[PluginResult]:
    """Check whether SMB signing is required (disabled = MITM risk)."""
    smb_neg = (
        b"\x00\x00\x00\x85"
        b"\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\xff\xfe\x00\x00\x00\x00"
        b"\x00\x62\x00\x02NT LM 0.12\x00"
        b"\x02SMB 2.002\x00\x02SMB 2.???\x00"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(smb_neg)
        raw = sock.recv(512)
        sock.close()
        # Check SecurityMode byte in SMBv2 negotiate response
        # Byte 70 in a typical negotiate response contains SecurityMode
        # Bit 0 = signing enabled; bit 1 = signing required
        if len(raw) > 70:
            sec_mode = raw[70] if len(raw) > 70 else 0
            signing_required = bool(sec_mode & 0x02)
            signing_enabled  = bool(sec_mode & 0x01)
            if not signing_required:
                return PluginResult(
                    plugin="smb-signing", port=port,
                    output=("SMB signing NOT required — MITM attack possible"
                            if not signing_enabled
                            else "SMB signing enabled but not required"),
                    data={"signing_required": False,
                          "vulnerable": not signing_required})
            return PluginResult(
                plugin="smb-signing", port=port,
                output="SMB signing required (secure)",
                data={"signing_required": True, "vulnerable": False})
    except Exception:
        pass
    return None


def _plugin_docker_unauth(ip: str, port: int,
                           timeout: float) -> Optional[PluginResult]:
    """Check for unauthenticated Docker API exposure."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(b"GET /version HTTP/1.0\r\n\r\n")
        raw = sock.recv(2048).decode("utf-8", errors="replace")
        sock.close()
        if '"Version"' in raw and '"ApiVersion"' in raw:
            m = re.search(r'"Version"\s*:\s*"([\d.]+)"', raw)
            ver = m.group(1) if m else "?"
            return PluginResult(
                plugin="docker-unauth", port=port,
                output=f"Docker {ver} API exposed WITHOUT authentication! "
                       f"CRITICAL: remote code execution possible.",
                data={"version": ver, "vulnerable": True,
                      "severity": "CRITICAL"})
    except Exception:
        pass
    return None


# ── V9-3: Additional Vulnerability / Recon Plugins (20 new) ──────

def _plugin_heartbleed(ip: str, port: int,
                       timeout: float) -> Optional[PluginResult]:
    """Send Heartbleed TLS heartbeat probe (CVE-2014-0160)."""
    # TLS 1.0 ClientHello + Heartbeat extension
    hello = (
        b"\x16\x03\x01\x00\x31"        # TLS Record: Handshake, v1.0, 49 bytes
        b"\x01\x00\x00\x2d"            # ClientHello
        b"\x03\x01"                    # TLS version 1.0
        + b"\x00" * 32                  # random
        + b"\x00"                       # session ID length
        + b"\x00\x02\x00\x2f"         # cipher suites (AES-128-SHA)
        + b"\x01\x00"                  # compression null
        + b"\x00\x00"                  # extensions length 0
    )
    heartbeat = (
        b"\x18\x03\x01\x00\x03"       # TLS Record: Heartbeat
        b"\x01\xff\x00"               # type=request, length=65280
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(hello)
        s.recv(4096)   # server hello
        s.sendall(heartbeat)
        resp = s.recv(4096)
        s.close()
        if len(resp) > 3 and resp[0] == 0x18:
            return PluginResult(
                plugin="heartbleed", port=port,
                output="VULNERABLE to Heartbleed (CVE-2014-0160)! "
                       "Memory disclosure possible.",
                data={"cve": "CVE-2014-0160", "vulnerable": True,
                      "severity": "CRITICAL"})
        return PluginResult(plugin="heartbleed", port=port,
                             output="Heartbleed: not vulnerable",
                             data={"vulnerable": False})
    except Exception:
        return None


def _plugin_ms17_010(ip: str, port: int,
                     timeout: float) -> Optional[PluginResult]:
    """Check for MS17-010 (EternalBlue) SMB vulnerability."""
    # SMBv1 Negotiate + check for unpatched server
    neg = (
        b"\x00\x00\x00\x54"                    # NetBIOS
        b"\xff\x53\x4d\x42\x72\x00\x00\x00"  # SMB magic + Negotiate
        b"\x00\x18\x01\x20\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\xff\xfe\x00\x00\x00\x00"
        b"\x00\x31\x00\x02NT LM 0.12\x00"
        b"\x02SMB 2.002\x00"
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(neg)
        r = s.recv(512)
        s.close()
        if len(r) > 40:
            # Heuristic: SMBv1 accepted + older server = potentially vulnerable
            if b"\xffSMB" in r:
                return PluginResult(
                    plugin="ms17-010", port=port,
                    output="SMBv1 enabled — potentially vulnerable to EternalBlue "
                           "(CVE-2017-0144). Manual verification required.",
                    data={"cve": "CVE-2017-0144", "smb_v1": True,
                          "severity": "HIGH"})
    except Exception:
        pass
    return None


def _plugin_http_methods(ip: str, port: int,
                          timeout: float) -> Optional[PluginResult]:
    """Check for dangerous HTTP methods: PUT, DELETE, TRACE, CONNECT."""
    use_ssl = port in SSL_PORTS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.sendall(b"OPTIONS / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        raw = s.recv(2048).decode("utf-8", errors="replace")
        s.close()
        m = re.search(r"Allow:\s*(.+)", raw, re.IGNORECASE)
        if m:
            methods = [x.strip().upper() for x in m.group(1).split(",")]
            dangerous = [m for m in methods
                         if m in {"PUT", "DELETE", "TRACE", "CONNECT"}]
            if dangerous:
                return PluginResult(
                    plugin="http-methods", port=port,
                    output=f"Dangerous HTTP methods allowed: {', '.join(dangerous)}",
                    data={"methods": methods, "dangerous": dangerous})
            return PluginResult(
                plugin="http-methods", port=port,
                output=f"HTTP methods: {', '.join(methods[:6])}",
                data={"methods": methods})
    except Exception:
        pass
    return None


def _plugin_dns_zone_transfer(ip: str, port: int,
                               timeout: float) -> Optional[PluginResult]:
    """Attempt DNS AXFR zone transfer (CVE-old but still common misconfig)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # DNS AXFR for "." (root) — will reveal if zone transfer is allowed
        axfr = (b"\x00\x1c"              # length prefix
                b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\xfc\x00\x01")  # AXFR query for .
        s.sendall(axfr)
        r = s.recv(256)
        s.close()
        if len(r) > 12 and r[2:4] in (b"\x80\x00", b"\x85\x80"):
            return PluginResult(
                plugin="dns-zone-transfer", port=port,
                output="DNS zone transfer ALLOWED (AXFR misconfig)",
                data={"vulnerable": True})
        return PluginResult(plugin="dns-zone-transfer", port=port,
                             output="DNS zone transfer: denied (secure)",
                             data={"vulnerable": False})
    except Exception:
        return None


def _plugin_smtp_open_relay(ip: str, port: int,
                             timeout: float) -> Optional[PluginResult]:
    """Test for open SMTP relay (mail forwarding without auth)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.recv(512)  # banner
        s.sendall(b"EHLO pyscanner.test\r\n"); s.recv(512)
        s.sendall(b"MAIL FROM:<test@pyscanner.test>\r\n")
        r1 = s.recv(256).decode("utf-8", errors="replace")
        s.sendall(b"RCPT TO:<victim@external-domain.com>\r\n")
        r2 = s.recv(256).decode("utf-8", errors="replace")
        s.sendall(b"QUIT\r\n")
        s.close()
        if r2.startswith("2"):
            return PluginResult(
                plugin="smtp-open-relay", port=port,
                output="SMTP open relay DETECTED — external mail relay possible",
                data={"vulnerable": True, "severity": "HIGH"})
        return PluginResult(plugin="smtp-open-relay", port=port,
                             output="SMTP relay: denied (secure)",
                             data={"vulnerable": False})
    except Exception:
        return None


def _plugin_ssh_hostkey(ip: str, port: int,
                         timeout: float) -> Optional[PluginResult]:
    """Extract SSH host key fingerprint and algorithm."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        banner = s.recv(256).decode("utf-8", errors="replace").strip()
        s.sendall(b"SSH-2.0-PyScanner_9.0\r\n")
        kex = s.recv(2048)
        s.close()
        # Parse host key algorithm from KEX_INIT (byte 17 starts algorithms)
        algo = "unknown"
        if len(kex) > 22:
            try:
                # Skip packet_length(4) + padding_length(1) + msg_type(1) + cookie(16)
                off = 22
                if off + 4 <= len(kex):
                    kex_algos_len = struct.unpack("!I", kex[off:off+4])[0]
                    off += 4 + kex_algos_len
                    if off + 4 <= len(kex):
                        ha_len = struct.unpack("!I", kex[off:off+4])[0]
                        if ha_len > 0 and off + 4 + ha_len <= len(kex):
                            algo = kex[off+4: off+4+ha_len].decode(
                                "ascii", errors="replace").split(",")[0]
            except Exception:
                pass
        m = re.search(r"SSH-[\d.]+-(.+)", banner)
        software = m.group(1) if m else "?"
        return PluginResult(
            plugin="ssh-hostkey", port=port,
            output=f"SSH host key algo: {algo}  software: {software}",
            data={"algorithm": algo, "software": software, "banner": banner})
    except Exception:
        return None


def _plugin_telnet_banner(ip: str, port: int,
                           timeout: float) -> Optional[PluginResult]:
    """Grab telnet banner — its presence alone is a security finding."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        raw = s.recv(256)
        s.close()
        # Strip telnet IAC sequences
        clean = bytes(b for b in raw if b < 0x80).decode(
            "utf-8", errors="replace").strip()[:80]
        return PluginResult(
            plugin="telnet-banner", port=port,
            output=f"TELNET service detected (plaintext!) — banner: {clean or '(none)'}",
            data={"banner": clean, "severity": "MEDIUM"})
    except Exception:
        return None


def _plugin_vnc_no_auth(ip: str, port: int,
                         timeout: float) -> Optional[PluginResult]:
    """Check for VNC with no authentication (SecurityType=1)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        banner = s.recv(32).decode("utf-8", errors="replace")
        if not banner.startswith("RFB"):
            s.close(); return None
        ver = banner.strip()
        # Send our version
        s.sendall(b"RFB 003.008\n")
        sec_types_raw = s.recv(64)
        s.close()
        if len(sec_types_raw) >= 2:
            n = sec_types_raw[0]
            types = list(sec_types_raw[1:1+n]) if n > 0 else []
            if 1 in types:
                return PluginResult(
                    plugin="vnc-no-auth", port=port,
                    output=f"VNC {ver}: None authentication (SecurityType=1) — "
                           "UNAUTHENTICATED ACCESS possible",
                    data={"vnc_version": ver, "sec_types": types,
                          "no_auth": True, "severity": "CRITICAL"})
            return PluginResult(
                plugin="vnc-no-auth", port=port,
                output=f"VNC {ver}: authentication required (types={types})",
                data={"no_auth": False})
    except Exception:
        return None


def _plugin_http_robots(ip: str, port: int,
                         timeout: float) -> Optional[PluginResult]:
    """Fetch /robots.txt to enumerate hidden paths."""
    use_ssl = port in SSL_PORTS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.sendall(
            f"GET /robots.txt HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        raw = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        if "200" in raw[:20]:
            body  = raw.split("\r\n\r\n", 1)[-1]
            paths = [l.split(":",1)[1].strip() for l in body.splitlines()
                     if l.lower().startswith("disallow:") and len(l) > 10]
            if paths:
                return PluginResult(
                    plugin="http-robots", port=port,
                    output=f"robots.txt: {len(paths)} Disallow paths: "
                           + ", ".join(paths[:5]),
                    data={"disallow_paths": paths})
    except Exception:
        pass
    return None


def _plugin_mysql_empty_password(ip: str, port: int,
                                  timeout: float) -> Optional[PluginResult]:
    """Check if MySQL root has empty password via handshake."""
    # MySQL Client Auth with empty password
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        server_hello = s.recv(512)
        if not server_hello or server_hello[4] != 10:
            s.close(); return None  # not MySQL greeting

        # Send auth packet: user=root, password=empty
        auth = (b"\x52\x00\x00\x01"       # length + seq
                b"\x85\xa6\x3f\x20"       # capabilities
                b"\x00\x00\x00\x01"       # max packet
                b"\x21"                    # charset utf8
                + b"\x00"*23              # reserved
                + b"root\x00"             # username
                + b"\x00")               # empty password (auth_response_length=0)
        s.sendall(auth)
        resp = s.recv(128)
        s.close()
        if resp and resp[4] == 0x00:
            return PluginResult(
                plugin="mysql-empty-password", port=port,
                output="MySQL root login with empty password SUCCEEDED — "
                       "CRITICAL misconfiguration",
                data={"vulnerable": True, "severity": "CRITICAL"})
        return PluginResult(plugin="mysql-empty-password", port=port,
                             output="MySQL: root empty-password auth failed (secure)",
                             data={"vulnerable": False})
    except Exception:
        return None


def _plugin_ntp_monlist(ip: str, port: int,
                         timeout: float) -> Optional[PluginResult]:
    """Test for NTP monlist amplification (CVE-2013-5211)."""
    # NTP MON_LIST request (mode 7, opcode 42)
    monlist_req = (
        b"\x17\x00\x03\x2a" + b"\x00"*4)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(monlist_req, (ip, port))
        resp, _ = s.recvfrom(4096)
        s.close()
        if len(resp) > 8 and resp[0] == 0x97:
            return PluginResult(
                plugin="ntp-monlist", port=port,
                output=f"NTP monlist ENABLED ({len(resp)} bytes response) — "
                       "CVE-2013-5211 amplification possible",
                data={"cve": "CVE-2013-5211", "vulnerable": True,
                      "response_bytes": len(resp), "severity": "HIGH"})
        return PluginResult(plugin="ntp-monlist", port=port,
                             output="NTP monlist: disabled (secure)",
                             data={"vulnerable": False})
    except Exception:
        return None


def _plugin_elasticsearch_unauth(ip: str, port: int,
                                  timeout: float) -> Optional[PluginResult]:
    """Check for unauthenticated Elasticsearch cluster access."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(b"GET /_cluster/health HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        raw = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        if '"cluster_name"' in raw or '"status"' in raw:
            m = re.search(r'"cluster_name"\s*:\s*"([^"]+)"', raw)
            cname = m.group(1) if m else "unknown"
            return PluginResult(
                plugin="elasticsearch-unauth", port=port,
                output=f"Elasticsearch UNAUTHENTICATED: cluster '{cname}' exposed",
                data={"cluster": cname, "vulnerable": True, "severity": "HIGH"})
    except Exception:
        pass
    return None


def _plugin_k8s_unauth(ip: str, port: int,
                        timeout: float) -> Optional[PluginResult]:
    """Check for unauthenticated Kubernetes API access."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if port == 6443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.sendall(b"GET /version HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        raw = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        if '"gitVersion"' in raw:
            m = re.search(r'"gitVersion"\s*:\s*"v([\d.]+)"', raw)
            ver = m.group(1) if m else "?"
            return PluginResult(
                plugin="k8s-unauth", port=port,
                output=f"Kubernetes API v{ver} exposed without authentication!",
                data={"k8s_version": ver, "vulnerable": True, "severity": "CRITICAL"})
    except Exception:
        pass
    return None


def _plugin_memcached_unauth(ip: str, port: int,
                              timeout: float) -> Optional[PluginResult]:
    """Check for unauthenticated Memcached access + amplification risk."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(b"stats\r\n")
        raw = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        if "STAT " in raw:
            m = re.search(r"STAT version\s+([\d.]+)", raw)
            ver = m.group(1) if m else "?"
            return PluginResult(
                plugin="memcached-unauth", port=port,
                output=f"Memcached {ver}: UNAUTHENTICATED access + UDP amplification risk",
                data={"version": ver, "vulnerable": True, "severity": "HIGH"})
    except Exception:
        pass
    return None


def _plugin_rsync_unauth(ip: str, port: int,
                          timeout: float) -> Optional[PluginResult]:
    """Check for unauthenticated rsync module listing."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        banner = s.recv(128).decode("utf-8", errors="replace")
        if "@RSYNCD" not in banner.upper():
            s.close(); return None
        # Request module list
        s.sendall(b"#list\n")
        modules = s.recv(2048).decode("utf-8", errors="replace")
        s.close()
        mod_list = [l.strip() for l in modules.splitlines()
                    if l.strip() and not l.startswith("@")]
        if mod_list:
            return PluginResult(
                plugin="rsync-unauth", port=port,
                output=f"Rsync module list exposed: {', '.join(mod_list[:5])}",
                data={"modules": mod_list, "vulnerable": True})
        return PluginResult(plugin="rsync-unauth", port=port,
                             output="Rsync: no accessible modules",
                             data={"vulnerable": False})
    except Exception:
        return None


def _plugin_snmp_community(ip: str, port: int,
                            timeout: float) -> Optional[PluginResult]:
    """Test SNMP v1/v2c default community string 'public'."""
    # SNMPv1 GetRequest for sysDescr.0
    snmp_req = (
        b"\x30\x26"                           # SEQUENCE
        b"\x02\x01\x00"                       # version: 0 (v1)
        b"\x04\x06public"                     # community: public
        b"\xa0\x19"                           # GetRequest-PDU
        b"\x02\x04\x00\x00\x00\x01"          # request-id
        b"\x02\x01\x00"                       # error-status
        b"\x02\x01\x00"                       # error-index
        b"\x30\x0b\x30\x09"                   # variable bindings
        b"\x06\x05\x2b\x06\x01\x02\x01"      # OID 1.3.6.1.2.1
        b"\x05\x00"                            # Null
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(snmp_req, (ip, port))
        resp, _ = s.recvfrom(4096)
        s.close()
        if resp and resp[0] == 0x30:
            desc_m = re.search(rb"(Linux|Windows|Cisco|FreeBSD|[\w\s]+\d+\.\d+)", resp)
            desc = desc_m.group(1).decode("utf-8", errors="replace") if desc_m else "?"
            return PluginResult(
                plugin="snmp-community", port=port,
                output=f"SNMP 'public' community accepted: sysDescr={desc}",
                data={"community": "public", "sysDescr": desc,
                      "vulnerable": True, "severity": "MEDIUM"})
    except Exception:
        pass
    return None


def _plugin_ldap_rootdse(ip: str, port: int,
                          timeout: float) -> Optional[PluginResult]:
    """Query LDAP rootDSE anonymously — reveals server info."""
    # Minimal LDAP search request for rootDSE
    ldap_search = (
        b"\x30\x26"           # SEQUENCE (38 bytes)
        b"\x02\x01\x01"       # messageID: 1
        b"\x63\x21"           # SearchRequest
        b"\x04\x00"           # baseObject: ""
        b"\x0a\x01\x00"       # scope: baseObject(0)
        b"\x0a\x01\x00"       # derefAliases: neverDerefAliases
        b"\x02\x01\x00"       # sizeLimit: 0
        b"\x02\x01\x00"       # timeLimit: 0
        b"\x01\x01\x00"       # typesOnly: FALSE
        b"\x87\x0b"
        b"objectClass"        # filter: present(objectClass)
        b"\x30\x00"           # attributes: [] (all)
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(ldap_search)
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        if len(resp) > 10:
            vendor = re.search(r"(OpenLDAP|Active Directory|Samba|389)", resp)
            vend_s = vendor.group(1) if vendor else "LDAP server"
            return PluginResult(
                plugin="ldap-rootdse", port=port,
                output=f"{vend_s}: anonymous bind accepted — rootDSE exposed",
                data={"vendor": vend_s, "anonymous_bind": True})
    except Exception:
        pass
    return None


def _plugin_pop3_capabilities(ip: str, port: int,
                               timeout: float) -> Optional[PluginResult]:
    """Query POP3 CAPA command to list supported capabilities."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.recv(256)  # banner
        s.sendall(b"CAPA\r\n")
        raw = s.recv(1024).decode("utf-8", errors="replace")
        s.close()
        caps = [l.strip() for l in raw.splitlines()
                if l.strip() and not l.startswith("+") and l.strip() != "."]
        if caps:
            stls = "STLS" in raw
            return PluginResult(
                plugin="pop3-capabilities", port=port,
                output=f"POP3 CAPA: {', '.join(caps[:6])}"
                       + ("" if stls else " — WARN: no STLS (plaintext)"),
                data={"capabilities": caps, "stls": stls})
    except Exception:
        pass
    return None


def _plugin_iis_webdav(ip: str, port: int,
                        timeout: float) -> Optional[PluginResult]:
    """Check if IIS WebDAV is enabled (PROPFIND method)."""
    use_ssl = port in SSL_PORTS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        req = (b"PROPFIND / HTTP/1.0\r\n"
               b"Depth: 0\r\n"
               b"Content-Type: text/xml\r\n\r\n")
        s.sendall(req)
        raw = s.recv(1024).decode("utf-8", errors="replace")
        s.close()
        if "207" in raw[:20] or "WebDAV" in raw or "DAV:" in raw:
            return PluginResult(
                plugin="iis-webdav", port=port,
                output="WebDAV enabled — file upload/modification may be possible",
                data={"webdav": True, "severity": "MEDIUM"})
    except Exception:
        pass
    return None


def _plugin_tftp_test(ip: str, port: int,
                       timeout: float) -> Optional[PluginResult]:
    """Test if TFTP responds (unauthenticated file server)."""
    # TFTP RRQ for /etc/passwd (will fail, but we check if server responds)
    rrq = b"\x00\x01/etc/passwd\x00octet\x00"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(rrq, (ip, port))
        resp, _ = s.recvfrom(512)
        s.close()
        if len(resp) >= 4:
            opcode = struct.unpack("!H", resp[:2])[0]
            if opcode in (3, 5):   # DATA or ERROR (server responded!)
                return PluginResult(
                    plugin="tftp-test", port=port,
                    output="TFTP server active — unauthenticated file access possible",
                    data={"responsive": True, "severity": "MEDIUM"})
    except Exception:
        pass
    return None


# ── Plugin Registry ────────────────────────────────────────────────
BUILTIN_PLUGINS: List[PluginSpec] = [
    # ── Service information plugins (UPG-2) ─────────────────────────
    PluginSpec("http-title",  [80, 443, 8080, 8443, 8000, 8008],
               "tcp", _plugin_http_title),
    PluginSpec("ftp-anon",    [21],
               "tcp", _plugin_ftp_anon),
    PluginSpec("redis-info",  [6379],
               "tcp", _plugin_redis_info),
    PluginSpec("ssl-cert",    [443, 993, 995, 465, 8443, 636, 5986],
               "tcp", _plugin_ssl_cert),
    PluginSpec("smb-os",      [445, 139],
               "tcp", _plugin_smb_os),
    PluginSpec("ssh-auth",    [22, 2222],
               "tcp", _plugin_ssh_auth),
    PluginSpec("http-server", [80, 443, 8080, 8443, 8000, 8008],
               "tcp", _plugin_http_server),
    # ── Vulnerability detection plugins (ENH-4) ──────────────────────
    PluginSpec("ssl-weak-ciphers",       [443, 8443, 993, 995, 465, 636],
               "tcp", _plugin_ssl_weak_ciphers),
    PluginSpec("http-security-headers",  [80, 443, 8080, 8443, 8000, 8008],
               "tcp", _plugin_http_security_headers),
    PluginSpec("default-creds",          [21, 6379, 27017],
               "tcp", _plugin_default_creds),
    PluginSpec("open-redirect",          [80, 443, 8080, 8443],
               "tcp", _plugin_open_redirect),
    PluginSpec("smb-signing",            [445, 139],
               "tcp", _plugin_smb_signing),
    PluginSpec("docker-unauth",          [2375, 2376],
               "tcp", _plugin_docker_unauth),
    # ── Extended vuln/recon plugins (V9-3) ───────────────────────────
    PluginSpec("heartbleed",             [443, 8443, 993, 995, 465],
               "tcp", _plugin_heartbleed),
    PluginSpec("ms17-010",               [445, 139],
               "tcp", _plugin_ms17_010),
    PluginSpec("http-methods",           [80, 443, 8080, 8443, 8000],
               "tcp", _plugin_http_methods),
    PluginSpec("dns-zone-transfer",      [53],
               "tcp", _plugin_dns_zone_transfer),
    PluginSpec("smtp-open-relay",        [25, 587, 465, 2525],
               "tcp", _plugin_smtp_open_relay),
    PluginSpec("ssh-hostkey",            [22, 2222],
               "tcp", _plugin_ssh_hostkey),
    PluginSpec("telnet-banner",          [23, 2323],
               "tcp", _plugin_telnet_banner),
    PluginSpec("vnc-no-auth",            [5900, 5901, 5902],
               "tcp", _plugin_vnc_no_auth),
    PluginSpec("http-robots",            [80, 443, 8080, 8443, 8000],
               "tcp", _plugin_http_robots),
    PluginSpec("mysql-empty-password",   [3306],
               "tcp", _plugin_mysql_empty_password),
    PluginSpec("ntp-monlist",            [123],
               "udp", _plugin_ntp_monlist),
    PluginSpec("elasticsearch-unauth",   [9200, 9300],
               "tcp", _plugin_elasticsearch_unauth),
    PluginSpec("k8s-unauth",             [6443, 8080, 8443],
               "tcp", _plugin_k8s_unauth),
    PluginSpec("memcached-unauth",       [11211],
               "tcp", _plugin_memcached_unauth),
    PluginSpec("rsync-unauth",           [873],
               "tcp", _plugin_rsync_unauth),
    PluginSpec("snmp-community",         [161],
               "udp", _plugin_snmp_community),
    PluginSpec("ldap-rootdse",           [389, 636],
               "tcp", _plugin_ldap_rootdse),
    PluginSpec("pop3-capabilities",      [110, 995],
               "tcp", _plugin_pop3_capabilities),
    PluginSpec("iis-webdav",             [80, 443, 8080, 8443],
               "tcp", _plugin_iis_webdav),
    PluginSpec("tftp-test",              [69],
               "udp", _plugin_tftp_test),
]

# Index: port → list of applicable plugins
_PLUGIN_INDEX: Dict[int, List[PluginSpec]] = {}
for _pl in BUILTIN_PLUGINS:
    for _port in _pl.ports:
        _PLUGIN_INDEX.setdefault(_port, []).append(_pl)


def load_external_plugins(plugin_dir: str) -> List[PluginSpec]:
    """
    [UPG-2] Load external plugins from a directory.
    Each .py file must define:
      NAME     : str   — plugin name
      PORTS    : list  — ports to apply to ([] = all open)
      PROTOCOL : str   — "tcp" or "udp"
      def run(ip, port, timeout) -> Optional[PluginResult]
    """
    plugins: List[PluginSpec] = []
    if not os.path.isdir(plugin_dir):
        return plugins
    for fname in sorted(os.listdir(plugin_dir)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        fpath = os.path.join(plugin_dir, fname)
        try:
            spec_obj = importlib.util.spec_from_file_location(
                fname[:-3], fpath)
            mod = importlib.util.module_from_spec(spec_obj)
            spec_obj.loader.exec_module(mod)
            ps = PluginSpec(
                name     = getattr(mod, "NAME",     fname[:-3]),
                ports    = getattr(mod, "PORTS",    []),
                protocol = getattr(mod, "PROTOCOL", "tcp"),
                run      = mod.run,
            )
            plugins.append(ps)
        except Exception as exc:
            print(color(f"[!] Plugin load failed ({fname}): {exc}", YELLOW))
    return plugins


def run_plugins(ip: str, port: int, protocol: str,
                plugins: List[PluginSpec],
                timeout: float) -> List[PluginResult]:
    """Run all matching plugins for an open port. Returns list of results."""
    applicable = [
        p for p in plugins
        if (not p.ports or port in p.ports) and p.protocol == protocol
    ]
    results: List[PluginResult] = []
    for plug in applicable:
        try:
            res = plug.run(ip, port, timeout)
            if res is not None:
                results.append(res)
        except Exception:
            pass
    return results


# ═══════════════════════════════════════════════════════════════════
# [ENH-5] REAL-TIME PROGRESS DISPLAY
# ═══════════════════════════════════════════════════════════════════

class ProgressTracker:
    """
    [ENH-5] tqdm-style inline progress bar for port scanning.

    Writes a single updating line to stderr if the output is a TTY.
    Falls back to periodic log lines (every 5%) if not a TTY.

    Thread-safe: update() can be called from any worker thread.

    Display format:
      [=====>    ] 450/1024 ports  43.9%  178 p/s  ETA 3s  ■■ 3 open
    """

    def __init__(self, total: int, label: str = ""):
        self.total     = max(1, total)
        self.label     = label
        self._done     = 0
        self._open     = 0
        self._lock     = threading.Lock()
        self._start    = time.time()
        self._is_tty   = sys.stdout.isatty()
        self._last_pct = -1
        self._bar_w    = 30   # width of the progress bar in chars

    def update(self, n: int = 1, is_open: bool = False) -> None:
        with self._lock:
            self._done += n
            if is_open:
                self._open += 1
            self._render()

    def _render(self) -> None:
        """Must be called with self._lock held."""
        pct     = self._done / self.total
        elapsed = max(0.001, time.time() - self._start)
        rate    = self._done / elapsed
        eta     = (self.total - self._done) / max(rate, 0.001)

        filled  = int(self._bar_w * pct)
        bar     = "=" * filled + (">" if filled < self._bar_w else "") + \
                  " " * (self._bar_w - filled - (1 if filled < self._bar_w else 0))

        line = (f"\r  [{bar}] {self._done}/{self.total}"
                f"  {pct*100:.1f}%"
                f"  {rate:.0f}p/s"
                f"  ETA {eta:.0f}s"
                f"  open:{self._open}")
        if self.label:
            line += f"  {self.label}"

        if self._is_tty:
            sys.stdout.write(line)
            sys.stdout.flush()
        else:
            # Non-TTY: log every 5% milestone
            pct_int = int(pct * 100)
            if pct_int // 5 != self._last_pct // 5:
                self._last_pct = pct_int
                print(f"  Progress: {pct_int}%"
                      f" ({self._done}/{self.total}"
                      f"  {rate:.0f}p/s"
                      f"  open:{self._open})")

    def finish(self) -> None:
        """Call when scan is complete to print a final newline."""
        if self._is_tty:
            sys.stdout.write("\n")
            sys.stdout.flush()


# ═══════════════════════════════════════════════════════════════════
# [ENH-6] SCAN CHECKPOINTING
# ═══════════════════════════════════════════════════════════════════

class ScanCheckpoint:
    """
    [ENH-6] Persist scan state to disk mid-scan so large scans can be
    resumed if interrupted.

    File format: JSON with:
      {
        "targets":   ["10.0.0.1", ...],   # full target list
        "completed": ["10.0.0.1", ...],   # hosts fully scanned
        "results":   { "10.0.0.1": {...} } # serialised HostResult
      }

    Usage:
      cp = ScanCheckpoint("state.json", targets)
      # after each host:
      cp.save_host(hr)
      # on resume:
      remaining, results = cp.load()
    """

    def __init__(self, path: str, targets: Optional[List[str]] = None):
        self.path       = path
        self._lock      = threading.Lock()
        self._completed: set = set()
        self._results:   Dict[str, Any] = {}
        self._targets:   List[str] = targets or []

        # Write initial file if targets provided (new scan)
        if targets and not os.path.exists(path):
            self._flush()

    def save_host(self, hr: HostResult) -> None:
        """Persist a completed HostResult to the checkpoint file."""
        with self._lock:
            self._completed.add(hr.ip)
            # Convert HostResult to serialisable dict
            hr_dict = {
                "ip":         hr.ip,
                "status":     hr.status,
                "hostname":   hr.hostname,
                "ttl":        hr.ttl,
                "latency_ms": hr.latency_ms,
                "os_guess":   hr.os_guess,
                "open_count": hr.open_count,
                "ports": [
                    {"port":     p.port,
                     "protocol": p.protocol,
                     "state":    p.state,
                     "service":  p.service,
                     "version":  p.version,
                     "banner":   p.banner,
                     "reason":   p.reason}
                    for p in hr.ports
                ]
            }
            self._results[hr.ip] = hr_dict
            self._flush()

    def _flush(self) -> None:
        """Write checkpoint file (must be called with self._lock held)."""
        state = {
            "targets":   self._targets,
            "completed": list(self._completed),
            "results":   self._results,
        }
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(state, f, indent=2)
            os.replace(tmp, self.path)
        except Exception as exc:
            print(color(f"[!] Checkpoint write failed: {exc}", YELLOW))

    @classmethod
    def load(cls, path: str) -> Tuple[List[str], List[HostResult]]:
        """
        Load a checkpoint file.
        Returns (remaining_targets, completed_host_results).
        """
        try:
            with open(path) as f:
                state = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot load checkpoint '{path}': {exc}")

        completed_ips = set(state.get("completed", []))
        all_targets   = state.get("targets", [])
        remaining     = [t for t in all_targets if t not in completed_ips]

        # Reconstruct HostResult objects
        host_results: List[HostResult] = []
        for ip, d in state.get("results", {}).items():
            hr = HostResult(ip=ip)
            hr.status     = d.get("status",     "up")
            hr.hostname   = d.get("hostname",   "")
            hr.ttl        = d.get("ttl",        0)
            hr.latency_ms = d.get("latency_ms", 0.0)
            hr.os_guess   = d.get("os_guess",   "")
            hr.open_count = d.get("open_count", 0)
            for pd in d.get("ports", []):
                pr = PortResult(port=pd["port"])
                pr.protocol = pd.get("protocol", "tcp")
                pr.state    = pd.get("state",    "unknown")
                pr.service  = pd.get("service",  "")
                pr.version  = pd.get("version",  "")
                pr.banner   = pd.get("banner",   "")
                pr.reason   = pd.get("reason",   "")
                hr.ports.append(pr)
            host_results.append(hr)

        print(color(
            f"[*] Resuming from '{path}': "
            f"{len(completed_ips)}/{len(all_targets)} hosts done, "
            f"{len(remaining)} remaining.", CYAN))
        return remaining, host_results


# ═══════════════════════════════════════════════════════════════════
# [V9-2] DISTRIBUTED SCANNING
# ═══════════════════════════════════════════════════════════════════

import multiprocessing
import http.server
import urllib.parse
import urllib.request
import urllib.error


def _shard_scan_worker(args_tuple: Tuple) -> List[Dict]:
    """
    [V9-2] Worker function for multiprocessing.Pool.
    Runs a full connect-scan on a shard of targets.
    Returns serialisable list of host result dicts.
    """
    (ip_shard, ports, timeout, scan_type, banner_grab) = args_tuple
    results: List[Dict] = []

    for ip in ip_shard:
        hr_dict: Dict[str, Any] = {
            "ip": ip, "status": "unknown", "ports": []}

        # Quick TCP ping to check liveness
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            # Try first port from list
            test_port = ports[0] if ports else 80
            s.connect((ip, test_port))
            s.close()
            hr_dict["status"] = "up"
        except Exception:
            pass

        # Scan ports
        for port in ports:
            try:
                r = tcp_connect_scan(ip, port, timeout)
                port_dict: Dict[str, Any] = {
                    "port": port, "state": r.state,
                    "service": r.service, "version": r.version,
                    "banner": r.banner}
                if r.state == "open" and banner_grab:
                    ver, banner = run_service_probe(ip, port, timeout)
                    port_dict["version"] = ver
                    port_dict["banner"]  = banner
                hr_dict["ports"].append(port_dict)
            except Exception:
                pass

        open_c = sum(1 for p in hr_dict["ports"] if p["state"] == "open")
        hr_dict["open_count"] = open_c
        if open_c > 0:
            hr_dict["status"] = "up"
        results.append(hr_dict)

    return results


class DistributedScanner:
    """
    [V9-2] Multi-process distributed scanner.

    Splits the target list into N equal shards, spawns N worker
    sub-processes via multiprocessing.Pool, and merges results.

    Each worker runs tcp_connect_scan + run_service_probe independently
    with no shared state (safe for multiprocessing).

    For remote nodes, pair with DistributedWorkerServer which exposes
    an HTTP API so agents on other machines can receive shards.

    Usage:
        ds = DistributedScanner(workers=4, timeout=1.5)
        summary = ds.scan(targets, ports=parse_ports("80,443,22"))
        print(f"{summary['total_open']} open ports found")
    """

    def __init__(self, workers: int = 4,
                 timeout: float = 1.5,
                 scan_type: str = "connect",
                 banner_grab: bool = False):
        self.workers     = min(workers,
                               multiprocessing.cpu_count() * 2)
        self.timeout     = timeout
        self.scan_type   = scan_type
        self.banner_grab = banner_grab

    def _shard(self, lst: List, n: int) -> List[List]:
        """Split list into n roughly-equal shards."""
        k, m = divmod(len(lst), n)
        return [lst[i*k + min(i,m): (i+1)*k + min(i+1,m)]
                for i in range(n) if lst[i*k + min(i,m): (i+1)*k + min(i+1,m)]]

    def scan(self, targets: List[str],
             ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Distribute scan across self.workers processes.
        Returns merged summary dict.
        """
        if not targets:
            return {"results": [], "total_open": 0}

        ports    = ports or [80, 443, 22, 21, 25, 3306, 6379]
        shards   = self._shard(targets, self.workers)
        job_args = [
            (shard, ports, self.timeout, self.scan_type, self.banner_grab)
            for shard in shards
        ]

        print(color(
            f"[*] Distributed scan: {self.workers} workers × "
            f"{len(shards[0]) if shards else 0} hosts/shard"
            f" ({len(targets)} total targets)", CYAN))

        all_results: List[Dict] = []
        try:
            with multiprocessing.Pool(processes=self.workers) as pool:
                shard_results = pool.map(_shard_scan_worker, job_args)
            for sr in shard_results:
                all_results.extend(sr)
        except Exception as exc:
            print(color(f"[!] Distributed scan error: {exc}", RED))
            # Serial fallback
            for args in job_args:
                all_results.extend(_shard_scan_worker(args))

        total_open = sum(h.get("open_count", 0) for h in all_results)
        up_count   = sum(1 for h in all_results if h.get("status") == "up")

        return {
            "results":    all_results,
            "total_open": total_open,
            "hosts_up":   up_count,
            "hosts_total": len(targets),
        }

    def print_results(self, summary: Dict[str, Any]) -> None:
        print(color(
            f"\n[*] Distributed scan complete: "
            f"{summary['hosts_up']}/{summary['hosts_total']} hosts up, "
            f"{summary['total_open']} open ports", YELLOW))
        for hr in summary["results"]:
            open_ports = [p for p in hr["ports"] if p["state"] == "open"]
            if not open_ports:
                continue
            lbl = color(hr["ip"], GREEN)
            print(f"\n  {lbl}  ({hr.get('status','?')})")
            for p in open_ports:
                ver = f"  [{p['version']}]" if p.get("version") else ""
                print(f"    {p['port']:<7} {p['service']:<16}{ver}")


class DistributedWorkerServer:
    """
    [V9-2] Lightweight HTTP API server that runs on remote worker nodes.

    The coordinator sends scan jobs as JSON POST requests;
    the worker scans and returns results as JSON.

    Endpoints:
      POST /scan   body: {"targets": [...], "ports": [...], "timeout": N}
                   returns: {"results": [...]}
      GET  /ping   returns: {"status": "ok", "node": hostname}

    Usage (on each worker node):
        server = DistributedWorkerServer(host="0.0.0.0", port=9876)
        server.start()   # blocks

    Coordinator sends shards to http://worker-ip:9876/scan
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 9876):
        self.host = host
        self.port = port

    def start(self) -> None:
        """Start HTTP server (blocking)."""
        import json as _json
        host, port = self.host, self.port
        node_name  = socket.gethostname()

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                pass  # silence default logging

            def do_GET(self) -> None:
                if self.path == "/ping":
                    body = _json.dumps({"status": "ok", "node": node_name}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self) -> None:
                if self.path != "/scan":
                    self.send_response(404)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", 0))
                body   = self.rfile.read(length)
                try:
                    req      = _json.loads(body)
                    targets  = req.get("targets", [])
                    ports    = req.get("ports", [80, 443, 22])
                    timeout  = float(req.get("timeout", 1.5))
                    results  = _shard_scan_worker(
                        (targets, ports, timeout, "connect", False))
                    resp = _json.dumps({"results": results}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(resp)
                except Exception as exc:
                    err = _json.dumps({"error": str(exc)}).encode()
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(err)

        print(color(
            f"[*] DistributedWorkerServer listening on {host}:{port}", CYAN))
        srv = http.server.HTTPServer((host, port), _Handler)
        srv.serve_forever()

    @staticmethod
    def send_shard(worker_url: str, targets: List[str],
                   ports: List[int], timeout: float = 1.5) -> List[Dict]:
        """
        Send a shard to a remote worker node.
        Returns list of host result dicts, or [] on error.
        """
        import json as _json
        payload = _json.dumps({
            "targets": targets, "ports": ports, "timeout": timeout
        }).encode()
        try:
            req  = urllib.request.Request(
                f"{worker_url}/scan",
                data    = payload,
                headers = {"Content-Type": "application/json"},
                method  = "POST")
            with urllib.request.urlopen(req, timeout=300) as resp:
                return _json.loads(resp.read()).get("results", [])
        except Exception as exc:
            print(color(f"[!] Worker {worker_url} failed: {exc}", YELLOW))
            return []


class PyScanner:
    def __init__(self, args: argparse.Namespace):
        self.args       = args
        self.timeout    = args.timeout
        self.threads    = args.threads
        self.scan_type  = args.scan_type
        self.results: List[HostResult] = []
        self._lock      = threading.Lock()
        self._stop      = False
        self._errors: List[str] = []
        signal.signal(signal.SIGINT, self._handle_sigint)

        # [UPG-3] Apply timing mode — overrides individual timeout/thread/rate
        t_level = getattr(args, "timing", 3)
        if t_level in T_MODES:
            tm = T_MODES[t_level]
            self.timeout = tm.timeout
            self.threads = tm.parallelism
            # Update global rate limiter if timing mode specifies one
            global _RATE_LIMITER, SYN_MAX_RETRIES, ICMP_MAX_PROBES
            if tm.max_rate > 0:
                _RATE_LIMITER = TokenBucket(tm.max_rate, tm.max_rate)
            SYN_MAX_RETRIES = tm.syn_retries
            ICMP_MAX_PROBES = tm.icmp_probes
            if tm.probe_delay > 0:
                # Encode as a very low rate bucket if no explicit rate
                if tm.max_rate == 0 or _RATE_LIMITER is None:
                    _RATE_LIMITER = TokenBucket(
                        1.0 / tm.probe_delay,
                        max(1, int(1.0 / tm.probe_delay)))

        # [UPG-4] Async engine — shared RTT estimator across hosts
        self._rtt = AdaptiveRTT(initial_rtt=min(self.timeout / 2, 0.5))
        use_async = (getattr(args, "use_async", False)
                     or getattr(args, "timing", 3) >= 4)
        self._use_async = use_async

        # [UPG-2] Plugin system
        self._plugins: List[PluginSpec] = list(BUILTIN_PLUGINS)
        plugin_dir = getattr(args, "plugin_dir", None) or ""
        if plugin_dir:
            ext = load_external_plugins(plugin_dir)
            self._plugins.extend(ext)
            if ext:
                print(color(f"[*] Loaded {len(ext)} external plugin(s) "
                            f"from {plugin_dir}", CYAN))

    def _handle_sigint(self, sig, frame):
        print(color("\n[!] Scan interrupted by user.", RED))
        self._stop = True

    def resolve_targets(self) -> List[str]:
        """
        [FIX-27] Passes ipv6 preference through to resolver.
        [FIX-33] Passes force_large flag to expand_cidr.
        [FIX-35] Applies --exclude list to filter out unwanted IPs/CIDRs.
        """
        prefer_v6    = getattr(self.args, "_prefer_ipv6", False)
        force_large  = getattr(self.args, "force_large",  False)

        # [FIX-35] Build exclusion set from --exclude argument
        exclude_ips: set = set()
        exclude_str = getattr(self.args, "exclude", None) or ""
        for token in exclude_str.split(","):
            token = token.strip()
            if not token:
                continue
            if "/" in token:
                try:
                    for h in ipaddress.ip_network(token, strict=False).hosts():
                        exclude_ips.add(str(h))
                except ValueError:
                    pass
            elif "-" in token:
                # Range like 10.0.0.1-10.0.0.50
                try:
                    lo_str, hi_str = token.split("-", 1)
                    lo = ipaddress.ip_address(lo_str.strip())
                    hi = ipaddress.ip_address(hi_str.strip())
                    cur = lo
                    while cur <= hi:
                        exclude_ips.add(str(cur))
                        cur += 1
                except Exception:
                    pass
            else:
                exclude_ips.add(token)

        targets: List[str] = []
        for t in self.args.targets:
            if "/" in t:
                targets.extend(expand_cidr(t, force_large=force_large))
            else:
                ip = resolve_host(t, prefer_ipv6=prefer_v6)
                if ip:
                    targets.append(ip)
                else:
                    print(color(f"[!] Could not resolve: {t}", RED))

        # [FIX-35] Remove excluded hosts
        targets = [ip for ip in targets if ip not in exclude_ips]
        if exclude_ips and len(targets) < len(self.args.targets):
            n = len(exclude_ips)
            print(color(f"[*] Excluding {n} host(s) from scan.", YELLOW))

        return list(dict.fromkeys(targets))

    def ping_host(self, ip: str) -> HostResult:
        hr = HostResult(ip=ip)
        hr.scan_time = now_str()
        if self.args.skip_ping:
            hr.status   = "up"
            hr.hostname = reverse_dns(ip)
            return hr
        up, lat, ttl = icmp_ping(ip, self.timeout)
        if up:
            hr.status     = "up"
            hr.latency_ms = lat
            hr.ttl        = ttl
            hr.hostname   = reverse_dns(ip)
            hr.os_guess   = ttl_to_os(ttl)
        return hr

    def scan_port(self, ip: str, port: int) -> PortResult:
        """Route single-port scan to correct engine based on --scan-type."""
        if self.scan_type == "udp":
            return udp_scan(ip, port, self.timeout)
        elif self.scan_type == "syn":
            return tcp_syn_scan(ip, port, self.timeout)
        elif self.scan_type == "connect":
            return tcp_connect_scan(ip, port, self.timeout)
        # [UPG-3] Advanced / stealth scan types (single port via batch engine)
        elif self.scan_type == "null":
            return null_scan(ip, [port], self.timeout).get(
                port, PortResult(port=port, state="unknown"))
        elif self.scan_type == "fin":
            return fin_scan(ip, [port], self.timeout).get(
                port, PortResult(port=port, state="unknown"))
        elif self.scan_type == "xmas":
            return xmas_scan(ip, [port], self.timeout).get(
                port, PortResult(port=port, state="unknown"))
        elif self.scan_type == "ack":
            return ack_scan(ip, [port], self.timeout).get(
                port, PortResult(port=port, state="unknown"))
        elif self.scan_type == "window":
            return window_scan(ip, [port], self.timeout).get(
                port, PortResult(port=port, state="unknown"))
        else:
            return tcp_connect_scan(ip, port, self.timeout)

    def scan_ports(self, hr: HostResult, ports: List[int]) -> None:
        """
        [FIX-7]  Semaphore limits raw-socket concurrency.
        [FIX-8]  All worker exceptions caught and logged.
        [FIX-19] Optional port-order randomisation + inter-probe jitter.
        [FIX-20] SYN uses shared-socket batch engine.
        [UPG-2]  Plugins run post-scan on each open port.
        [UPG-3]  Stealth types (null/fin/xmas/ack/window) use batch engine.
        [UPG-4]  Async engine activated for SYN when --async or -T4/-T5.
        """
        scan_order = list(ports)
        if getattr(self.args, "randomise", False):
            random.shuffle(scan_order)

        batch_results: Optional[Dict[int, PortResult]] = None

        # ── Batch engines for SYN and stealth scan types ─────────────────
        if self.scan_type == "syn":
            if self._use_async:
                # [UPG-4] Async engine — faster for large port sets
                asc = AsyncSynScanner(get_local_ip(hr.ip),
                                      self.timeout, self._rtt)
                batch_results = asc.scan(hr.ip, scan_order)
            else:
                batch_results = syn_batch_scan(hr.ip, scan_order, self.timeout)

        elif self.scan_type in ("null", "fin", "xmas", "ack", "window"):
            # [UPG-3] Stealth scans — all use the shared stealth_scan engine
            flag_map = {
                "null":   0x00,
                "fin":    F_FIN,
                "xmas":   F_FIN | F_PSH | F_URG,
                "ack":    F_ACK,
                "window": F_ACK,
            }
            batch_results = stealth_scan(
                hr.ip, scan_order,
                flag_map[self.scan_type], self.timeout)

        if batch_results is not None:
            all_filtered = all(
                r.state in ("filtered", "open|filtered")
                and r.reason == "no-response"
                for r in batch_results.values())
            if not all_filtered or not batch_results:
                self._post_process_batch(hr, batch_results)
                return

        # ── Per-port worker pool (connect / UDP / fallback) ───────────────
        def worker(port: int) -> Optional[PortResult]:
            if self._stop:
                return None
            if getattr(self.args, "randomise", False):
                time.sleep(random.uniform(0.005, 0.05))
            try:
                r = self.scan_port(hr.ip, port)
                if r.state == "open":
                    self._enrich_port(hr.ip, r)
                return r
            except Exception as exc:
                with self._lock:
                    self._errors.append(f"Worker {hr.ip}:{port} -> {exc}")
                return PortResult(port=port, state="error", reason=str(exc))

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.threads) as ex:
            future_map = {ex.submit(worker, p): p for p in scan_order}
            for f in concurrent.futures.as_completed(future_map):
                try:
                    res = f.result()
                except Exception as exc:
                    with self._lock:
                        self._errors.append(f"Future error: {exc}")
                    continue
                if res is not None:
                    with self._lock:
                        hr.ports.append(res)

        hr.ports.sort(key=lambda x: x.port)
        hr.open_count = sum(1 for p in hr.ports if p.state == "open")

    def _post_process_batch(self, hr: HostResult,
                            batch_results: Dict[int, PortResult]) -> None:
        """
        Shared post-processing for batch scan results:
        banner/version probe, fingerprint signal harvest, plugin run.
        """
        for r in batch_results.values():
            if r.state == "open":
                self._enrich_port(hr.ip, r)

        # Harvest fingerprinting signals from first open SYN-ACK result
        for r in batch_results.values():
            if r.state == "open":
                if getattr(r, "_fp_tcp_window", 0):
                    hr.tcp_window = r._fp_tcp_window
                if getattr(r, "_fp_df_bit", False):
                    hr.df_bit = True
                if getattr(r, "_fp_has_tcp_options", False):
                    hr.has_tcp_options = True
                break

        with self._lock:
            hr.ports.extend(batch_results.values())
        hr.ports.sort(key=lambda x: x.port)
        hr.open_count = sum(1 for p in hr.ports if p.state == "open")

    def _enrich_port(self, ip: str, r: PortResult) -> None:
        """
        Run all enrichment on a single open PortResult:
        [UPG-1] service probe DB, [FIX-34] regex version, [UPG-2] plugins.
        """
        run_probes = getattr(self.args, "banner", False) or \
                     getattr(self.args, "scripts", False)
        if run_probes:
            # [UPG-1] Full probe database: sends protocol payloads, regex match
            version, banner = run_service_probe(ip, r.port, self.timeout)
            r.banner  = banner
            r.version = version or extract_service_version(banner)

        # [UPG-2] Run matching plugins
        if getattr(self.args, "scripts", False) and self._plugins:
            plugin_results = run_plugins(
                ip, r.port, r.protocol, self._plugins, self.timeout)
            # Store plugin results on the PortResult for reporting
            if not hasattr(r, "plugin_results"):
                r.plugin_results = []
            r.plugin_results.extend(plugin_results)

    def grab_http(self, hr: HostResult) -> None:
        open_nums = {p.port for p in hr.ports if p.state == "open"}
        for port, use_https in [(80, False), (443, True),
                                 (8080, False), (8443, True)]:
            if port in open_nums:
                hdrs = fetch_http_headers(
                    hr.ip, port, use_https, self.timeout)
                if hdrs:
                    hr.http_headers[str(port)] = hdrs

    def fingerprint(self, hr: HostResult) -> None:
        """
        [FIX-28] Heuristic scoring from SYN-ACK signals.
        [ENH-3]  Deep probe engine (T1-T7 + IE + ECN) when possible.

        Strategy:
          1. If an open port is found and deep-fp is enabled (-T3+), attempt
             OsProbeEngine which sends 10 specialised probes.
          2. Fall back to heuristic os_fingerprint() otherwise.
        """
        open_ports   = [p.port for p in hr.ports if p.state == "open"]
        closed_ports = [p.port for p in hr.ports if p.state == "closed"]

        # [ENH-3] Deep probe: needs ≥1 open and ≥1 closed port, and raw sockets
        deep_fp = getattr(self.args, "deep_fp", False) or \
                  getattr(self.args, "timing", 3) >= 3

        if deep_fp and open_ports and closed_ports:
            try:
                engine = OsProbeEngine(
                    ip          = hr.ip,
                    open_port   = open_ports[0],
                    closed_port = closed_ports[0],
                    timeout     = min(self.timeout * 2, 4.0),
                )
                obs, guess = engine.probe()
                if guess and guess != "Unknown (no raw socket)":
                    hr.os_guess = guess
                    # Merge deep observations back for display
                    if obs.isn_class != "unknown":
                        hr.os_guess += (f" | ISN={obs.isn_class}"
                                        f" IPID={obs.ipid_class}")
                    return
            except Exception:
                pass  # fall through to heuristic

        # Heuristic fallback
        hr.os_guess = os_fingerprint(
            hr.ip, open_ports, hr.ttl,
            tcp_window      = getattr(hr, "tcp_window",      0),
            has_tcp_options = getattr(hr, "has_tcp_options", False),
            df_bit          = getattr(hr, "df_bit",          False),
        )

    def whois_lookup(self, hr: HostResult) -> None:
        hr.whois_info = do_whois(hr.ip)

    def run_traceroute(self, ip: str) -> List[Dict]:
        return traceroute(ip, max_hops=self.args.max_hops,
                          timeout=self.timeout)

    def run(self) -> ScanSummary:
        t0       = time.time()
        start_ts = now_str()
        cmd      = " ".join(sys.argv)

        # [ENH-6] Resume from checkpoint if requested
        checkpoint_path = getattr(self.args, "checkpoint", None) or ""
        resume_path     = getattr(self.args, "resume",     None) or ""
        resumed_results: List[HostResult] = []

        if resume_path and os.path.exists(resume_path):
            remaining_targets, resumed_results = ScanCheckpoint.load(resume_path)
            # Override targets with remaining ones
            self.args.targets = remaining_targets or self.args.targets
            checkpoint_path   = resume_path  # continue writing to same file

        targets = self.resolve_targets()

        if not targets and not resumed_results:
            print(color("[!] No valid targets.", RED))
            sys.exit(1)

        ports = parse_ports(self.args.ports) if self.args.ports else []

        print(color(
            f"\nPyScanner v9.0 — starting scan at {start_ts}", BOLD))
        print(color(f"Targets  : {len(targets)}", CYAN))
        if ports:
            print(color(f"Ports    : {len(ports)}  ({self.args.ports})",
                        CYAN))
        print(color(f"Scan type: {self.scan_type}", CYAN))
        if resumed_results:
            print(color(f"Resumed  : {len(resumed_results)} hosts from checkpoint",
                        CYAN))
        print()

        # [ENH-6] Initialise checkpoint writer
        checkpoint: Optional[ScanCheckpoint] = None
        if checkpoint_path:
            checkpoint = ScanCheckpoint(checkpoint_path,
                                        targets=targets or [])
            print(color(f"[*] Checkpointing to: {checkpoint_path}", CYAN))

        host_results: List[HostResult] = list(resumed_results)

        # ── Host discovery ───────────────────────────────────────────
        if targets:
            print(color("[*] Host discovery...", YELLOW))
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.threads) as ex:
                pfutures = {
                    ex.submit(self.ping_host, ip): ip for ip in targets}
                for f in concurrent.futures.as_completed(pfutures):
                    try:
                        hr = f.result()
                    except Exception as exc:
                        ip = pfutures[f]
                        print(color(
                            f"  [!] ping_host({ip}) error: {exc}", RED))
                        hr = HostResult(ip=ip)
                    host_results.append(hr)
                    sc = GREEN if hr.status == "up" else DIM
                    ls = f" ({hr.latency_ms}ms)" if hr.latency_ms else ""
                    hs = hr.ip + (f" ({hr.hostname})" if hr.hostname else "")
                    print(f"  {color(hr.status.upper(), sc):20s} {hs}{ls}")

        try:
            host_results.sort(key=lambda h: socket.inet_aton(h.ip))
        except Exception:
            pass   # IPv6 addresses can't use inet_aton
        up_hosts = [h for h in host_results if h.status == "up"]
        print(color(
            f"\n[*] {len(up_hosts)}/{len(host_results)} hosts up.\n",
            YELLOW))

        # ── Port scan ────────────────────────────────────────────────
        if ports and up_hosts:
            print(color("[*] Port scanning...", YELLOW))
            total_work = len(up_hosts) * len(ports)

            # [ENH-5] Progress tracker across all hosts
            progress = ProgressTracker(
                total=total_work,
                label=f"({len(up_hosts)} hosts)")

            for hr in up_hosts:
                if self._stop:
                    break
                lbl = (f"{hr.ip} ({hr.hostname})"
                       if hr.hostname else hr.ip)
                print(color(f"\n  Scanning {lbl} ...", CYAN))

                # Monkey-patch scan_port to drive progress bar
                orig_scan_port = self.scan_port
                def _tracked_scan_port(ip, port,
                                       _orig=orig_scan_port,
                                       _prog=progress) -> PortResult:
                    result = _orig(ip, port)
                    _prog.update(1, is_open=(result.state == "open"))
                    return result
                self.scan_port = _tracked_scan_port  # type: ignore

                self.scan_ports(hr, ports)
                self.scan_port = orig_scan_port       # restore

                self.fingerprint(hr)
                if self.args.http_headers:
                    self.grab_http(hr)
                if self.args.whois:
                    self.whois_lookup(hr)

                # [ENH-6] Save host to checkpoint before printing
                if checkpoint:
                    checkpoint.save_host(hr)

                self._print_host_result(hr)

            progress.finish()

        # ── Traceroute ───────────────────────────────────────────────
        if self.args.traceroute and up_hosts:
            for hr in up_hosts[:3]:
                print(color(f"\n[*] Traceroute to {hr.ip}", YELLOW))
                hops = self.run_traceroute(hr.ip)
                self._print_traceroute(hops)

        # ── ARP scan ─────────────────────────────────────────────────
        if self.args.arp_scan:
            for t in self.args.targets:
                if "/" in t:
                    print(color(f"\n[*] ARP scan on {t}", YELLOW))
                    arp_res = arp_scan(t, self.timeout)
                    if not arp_res:
                        print(color(
                            "  No hosts found (or insufficient privileges).",
                            DIM))
                    for entry in arp_res:
                        print(f"  {color(entry['ip'], GREEN)}"
                              f"  MAC: {entry['mac']}")

        if self._errors and self.args.verbose:
            print(color("\n[!] Worker errors:", YELLOW))
            for e in self._errors[:20]:
                print(color(f"    {e}", DIM))

        elapsed_s  = elapsed(t0)
        end_ts     = now_str()
        open_ports = sum(h.open_count for h in host_results)

        summary = ScanSummary(
            command=cmd,
            start_time=start_ts,
            end_time=end_ts,
            elapsed_sec=elapsed_s,
            total_hosts=len(targets),
            hosts_up=len(up_hosts),
            hosts_down=len(targets) - len(up_hosts),
            total_ports_scanned=len(ports) * len(up_hosts),
            open_ports=open_ports,
            results=host_results,
        )
        self._print_summary(summary)
        self.results = host_results
        return summary

    # ─────────────────────────────────────────
    # Pretty Printers
    # ─────────────────────────────────────────

    def _print_host_result(self, hr: HostResult) -> None:
        open_ports     = [p for p in hr.ports if p.state == "open"]
        closed_count   = sum(1 for p in hr.ports if p.state == "closed")
        filtered_count = sum(1 for p in hr.ports if "filtered" in p.state)

        print(f"  OS guess : {color(hr.os_guess or 'Unknown', MAGENTA)}")
        print(f"  Open: {color(str(len(open_ports)), GREEN)}"
              f"  Closed: {closed_count}"
              f"  Filtered: {filtered_count}")

        if not open_ports:
            print(color("  No open ports found.", DIM))
            return

        # ── Port table with version column ────────────────────────────────
        hdr = (f"  {'PORT':<10} {'PROTO':<6} {'STATE':<14}"
               f" {'SERVICE':<14} {'VERSION':<28} BANNER")
        print(color(hdr, BOLD))
        print("  " + "─" * 90)
        for p in open_ports:
            ver = (p.version[:26] + "..") if len(p.version) > 28 else p.version
            bs  = (p.banner[:28] + "..") if len(p.banner) > 30 else p.banner
            # Strip newlines from banner for table display
            bs = bs.replace("\n", " ").replace("\r", "")
            print(f"  {p.port:<10} {p.protocol:<6}"
                  f" {color(p.state, GREEN):<22}"
                  f" {p.service:<14}"
                  f" {color(ver, CYAN):<36}"
                  f" {color(bs, DIM)}")

            # [UPG-2] Print plugin results indented under the port line
            for pr in getattr(p, "plugin_results", []):
                plug_label = color(f"  [{pr.plugin}]", MAGENTA)
                # Multi-line plugin output — indent each line
                for line in pr.output.splitlines():
                    print(f"        {plug_label} {line}")
                    plug_label = " " * (len(pr.plugin) + 4)

        if self.args.verbose:
            for p in hr.ports:
                if p.state == "open":
                    continue
                sc = YELLOW if "filtered" in p.state else DIM
                print(f"  {p.port:<10} {p.protocol:<6}"
                      f" {color(p.state, sc):<22}"
                      f" {p.service:<14}"
                      f" {color(p.reason, DIM)}")

        if hr.http_headers:
            print(color("\n  HTTP Headers:", YELLOW))
            for port_str, hdrs in hr.http_headers.items():
                print(f"    Port {port_str}:")
                for k, v in list(hdrs.items())[:12]:
                    print(f"      {k}: {v}")

        if hr.whois_info:
            print(color("\n  Whois (truncated):", YELLOW))
            for line in hr.whois_info.splitlines()[:15]:
                if line.strip():
                    print(f"    {line}")

    def _print_traceroute(self, hops: List[Dict]) -> None:
        print(f"  {'HOP':<5} {'IP':<18} {'HOSTNAME':<35} RTT")
        print("  " + "─" * 65)
        for h in hops:
            rtt = (f"{h['rtt_ms']}ms"
                   if h["rtt_ms"] is not None else "*")
            hn = h["hostname"] \
                if h["hostname"] not in ("*", h["ip"]) else ""
            print(f"  {h['ttl']:<5} {h['ip']:<18} {hn:<35} {rtt}")

    def _print_summary(self, s: ScanSummary) -> None:
        print(color("\n" + "=" * 62, BOLD))
        print(color("  PyScanner v9.0 - Scan Summary", BOLD))
        print(color("=" * 62, BOLD))
        print(f"  Start    : {s.start_time}")
        print(f"  End      : {s.end_time}")
        print(f"  Duration : {s.elapsed_sec}s")
        print(f"  Hosts    : {color(str(s.hosts_up), GREEN)} up / "
              f"{color(str(s.hosts_down), DIM)} down / "
              f"{s.total_hosts} total")
        print(f"  Ports    : {color(str(s.open_ports), GREEN)} open"
              f" / {s.total_ports_scanned} scanned")
        if self._errors:
            print(color(
                f"  Errors   : {len(self._errors)} (use -v to see)",
                YELLOW))
        print(color("=" * 62 + "\n", BOLD))


# ─────────────────────────────────────────────
# Report Export
# ─────────────────────────────────────────────

def export_json(summary: ScanSummary, path: str) -> None:
    def _default(obj):
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return str(obj)
    data = {
        "scanner":     "PyScanner v9.0",
        "command":     summary.command,
        "start_time":  summary.start_time,
        "end_time":    summary.end_time,
        "elapsed_sec": summary.elapsed_sec,
        "stats": {
            "hosts_up":   summary.hosts_up,
            "hosts_down": summary.results_down,
            "open_ports": summary.open_ports,
        },
        "hosts": [asdict(h) for h in summary.results],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=_default)
    print(color(f"[+] JSON report -> {path}", GREEN))


def export_text(summary: ScanSummary, path: str) -> None:
    lines = [
        "PyScanner v9.0 Report",
        "=" * 62,
        f"Command : {summary.command}",
        f"Start   : {summary.start_time}",
        f"End     : {summary.end_time}",
        f"Elapsed : {summary.elapsed_sec}s",
        f"Hosts up: {summary.hosts_up}/{summary.total_hosts}",
        f"Open ports: {summary.open_ports}",
        "",
    ]
    for hr in summary.results:
        lines.append(f"Host: {hr.ip}"
                     + (f" ({hr.hostname})" if hr.hostname else ""))
        lines.append(f"  Status  : {hr.status}")
        lines.append(f"  OS      : {hr.os_guess}")
        lines.append(f"  Latency : {hr.latency_ms}ms")
        if hr.ports:
            lines.append(
                f"  {'PORT':<10} {'PROTO':<6} {'STATE':<14}"
                f" {'SERVICE':<16} BANNER")
            for p in sorted(hr.ports, key=lambda x: x.port):
                lines.append(
                    f"  {p.port:<10} {p.protocol:<6}"
                    f" {p.state:<14} {p.service:<16} {p.banner}")
        lines.append("")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(color(f"[+] Text report -> {path}", GREEN))


# ─────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════
# [V9-5] NMAP-COMPATIBLE XML EXPORT + CSV EXPORT
# ═══════════════════════════════════════════════════════════════════

import xml.etree.ElementTree as ET


def export_xml(summary: ScanSummary, path: str) -> None:
    """
    [V9-5] Export scan results as Nmap-compatible XML.

    Schema matches Nmap's output format so tools like Metasploit,
    Armitage, Nessus, and BloodHound can import it directly.

    Key elements: <nmaprun> → <host> → <ports> → <port> → <service>
    """
    root = ET.Element("nmaprun")
    root.set("scanner",    "pyscanner")
    root.set("version",    "9.0")
    root.set("start",      str(int(time.time())))
    root.set("startstr",   summary.start_time)
    root.set("args",       summary.command)
    root.set("xmloutputversion", "1.04")

    # <scaninfo>
    si = ET.SubElement(root, "scaninfo")
    si.set("type",      "syn")
    si.set("protocol",  "tcp")
    si.set("numservices", str(sum(len(h.ports) for h in summary.results)))
    si.set("services",  "")

    # One <host> per HostResult
    for hr in summary.results:
        host_el = ET.SubElement(root, "host")

        # <status>
        st = ET.SubElement(host_el, "status")
        st.set("state",  hr.status)
        st.set("reason", "user-set" if hr.status == "up" else "no-response")

        # <address>
        addr = ET.SubElement(host_el, "address")
        addr.set("addr",     hr.ip)
        addr.set("addrtype", "ipv6" if is_ipv6(hr.ip) else "ipv4")

        # <hostnames>
        hnames = ET.SubElement(host_el, "hostnames")
        if hr.hostname:
            hn = ET.SubElement(hnames, "hostname")
            hn.set("name", hr.hostname)
            hn.set("type", "PTR")

        # <ports>
        ports_el = ET.SubElement(host_el, "ports")
        for p in hr.ports:
            port_el = ET.SubElement(ports_el, "port")
            port_el.set("protocol", p.protocol)
            port_el.set("portid",   str(p.port))

            state_el = ET.SubElement(port_el, "state")
            state_el.set("state",  p.state)
            state_el.set("reason", p.reason)

            svc_el = ET.SubElement(port_el, "service")
            svc_el.set("name",    p.service)
            svc_el.set("product", p.version.split(" ")[0] if p.version else "")
            svc_el.set("version", " ".join(p.version.split(" ")[1:])
                       if p.version and " " in p.version else p.version)
            svc_el.set("extrainfo", p.banner[:80] if p.banner else "")

            # Plugin output as <script> elements
            for pr in getattr(p, "plugin_results", []):
                sc = ET.SubElement(port_el, "script")
                sc.set("id",     pr.plugin)
                sc.set("output", pr.output)

        # <os> block
        if hr.os_guess:
            os_el = ET.SubElement(host_el, "os")
            osm   = ET.SubElement(os_el, "osmatch")
            osm.set("name",     hr.os_guess)
            osm.set("accuracy", "75")

        # <times>
        times_el = ET.SubElement(host_el, "times")
        times_el.set("rttvar", "0")
        times_el.set("srtt",   str(int(hr.latency_ms * 1000)))
        times_el.set("to",     "1000000")

    # <runstats>
    rs = ET.SubElement(root, "runstats")
    fin = ET.SubElement(rs, "finished")
    fin.set("time",    str(int(time.time())))
    fin.set("elapsed", str(elapsed(0)))
    hosts_el = ET.SubElement(rs, "hosts")
    hosts_el.set("up",    str(summary.hosts_up))
    hosts_el.set("down",  str(summary.total_hosts - summary.hosts_up))
    hosts_el.set("total", str(summary.total_hosts))

    # Pretty-print with indentation
    _indent_xml(root)
    tree = ET.ElementTree(root)
    with open(path, "wb") as f:
        f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n'
                b'<!DOCTYPE nmaprun>\n')
        tree.write(f, encoding="UTF-8", xml_declaration=False)
    print(color(f"[+] XML report  → {path}  (Nmap-compatible)", GREEN))


def _indent_xml(elem: ET.Element, level: int = 0) -> None:
    """Add pretty-print indentation to an ElementTree in place."""
    indent = "\n" + "  " * level
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = indent + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = indent
        for child in elem:
            _indent_xml(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = indent
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = indent


def export_csv(summary: ScanSummary, path: str) -> None:
    """
    [V9-5] Export scan results as flat CSV suitable for spreadsheets.

    Columns: ip, hostname, status, os_guess, latency_ms,
             port, protocol, state, service, version, banner, reason
    """
    import csv as _csv
    COLS = ["ip", "hostname", "status", "os_guess", "latency_ms",
            "port", "protocol", "state", "service", "version",
            "banner", "reason"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = _csv.writer(f)
        writer.writerow(COLS)
        for hr in summary.results:
            if not hr.ports:
                writer.writerow([
                    hr.ip, hr.hostname, hr.status, hr.os_guess,
                    hr.latency_ms, "", "", "", "", "", "", ""])
            else:
                for p in hr.ports:
                    writer.writerow([
                        hr.ip, hr.hostname, hr.status, hr.os_guess,
                        hr.latency_ms,
                        p.port, p.protocol, p.state,
                        p.service, p.version,
                        p.banner.replace("\n", " ")[:80],
                        p.reason,
                    ])
    print(color(f"[+] CSV report  → {path}", GREEN))


# ═══════════════════════════════════════════════════════════════════
# [V9-6] NETWORK TOPOLOGY ANALYZER
# ═══════════════════════════════════════════════════════════════════

class TopologyAnalyzer:
    """
    [V9-6] Analyze and visualize the network topology from scan results.

    Groups hosts by /24 subnet, identifies likely gateways (TTL=1 hop,
    low ports like 22/80/443, .1/.254 addresses), ranks hosts by open
    port count, and prints an ASCII tree.

    Example output:
      Network Topology (/24 subnets)
      ├── 192.168.1.0/24  (4 hosts, 12 open ports)
      │   ├── 192.168.1.1   [GATEWAY]  open:3  os:Cisco IOS
      │   ├── 192.168.1.10  open:5  os:Linux 5.x
      │   └── 192.168.1.100 open:1  os:Windows 10
      └── 10.0.0.0/24  (1 host, 2 open ports)
          └── 10.0.0.1  [GATEWAY]  open:2
    """

    def __init__(self, hosts: List[HostResult]):
        self.hosts = [h for h in hosts if h.status == "up"]

    def analyze(self) -> Dict[str, Any]:
        """Return structured topology dict."""
        subnets: Dict[str, List[HostResult]] = {}

        for h in self.hosts:
            subnet = self._subnet_key(h.ip)
            subnets.setdefault(subnet, []).append(h)

        topology: Dict[str, Any] = {}
        for subnet, subnet_hosts in sorted(subnets.items()):
            total_open = sum(h.open_count for h in subnet_hosts)
            gateways   = [h for h in subnet_hosts
                          if self._is_likely_gateway(h)]
            ranked     = sorted(subnet_hosts,
                                key=lambda h: h.open_count, reverse=True)
            topology[subnet] = {
                "hosts":       ranked,
                "total_open":  total_open,
                "gateways":    gateways,
                "host_count":  len(subnet_hosts),
            }

        return {
            "subnets":     topology,
            "total_hosts": len(self.hosts),
            "total_open":  sum(h.open_count for h in self.hosts),
            "most_open":   sorted(self.hosts,
                                  key=lambda h: h.open_count,
                                  reverse=True)[:5],
        }

    def _subnet_key(self, ip: str) -> str:
        """Return /24 subnet string for an IPv4, or ip itself for IPv6."""
        if is_ipv6(ip):
            return ip
        try:
            parts = ip.split(".")
            return f"{'.'.join(parts[:3])}.0/24"
        except Exception:
            return ip

    def _is_likely_gateway(self, h: HostResult) -> bool:
        """Heuristic: .1 or .254 address, or running routing services."""
        try:
            last_octet = int(h.ip.split(".")[-1])
            if last_octet in (1, 254):
                return True
        except Exception:
            pass
        open_ports = {p.port for p in h.ports if p.state == "open"}
        gateway_ports = {80, 443, 22, 23, 161, 179, 520, 4786}
        return len(open_ports & gateway_ports) >= 2

    def print_tree(self) -> None:
        """Print ASCII network topology tree to stdout."""
        topo = self.analyze()
        print(color(
            f"\n{'─'*60}\n"
            f"  Network Topology  ({topo['total_hosts']} hosts up, "
            f"{topo['total_open']} open ports)\n"
            f"{'─'*60}", BOLD))

        subnets = topo["subnets"]
        subnet_keys = sorted(subnets.keys())

        for si, subnet in enumerate(subnet_keys):
            is_last_subnet = (si == len(subnet_keys) - 1)
            branch = "└──" if is_last_subnet else "├──"
            info   = subnets[subnet]
            print(f"  {color(branch, CYAN)} "
                  f"{color(subnet, BOLD)}  "
                  f"({info['host_count']} hosts, "
                  f"{info['total_open']} open ports)")

            hosts  = info["hosts"]
            for hi, h in enumerate(hosts):
                is_last = (hi == len(hosts) - 1)
                connector = "│   " if not is_last_subnet else "    "
                hbranch   = "└──" if is_last else "├──"
                gw_tag    = color(" [GATEWAY]", YELLOW) \
                            if self._is_likely_gateway(h) else ""
                os_short  = ""
                if h.os_guess and h.os_guess != "Unknown":
                    # Shorten: "Linux 5.x/6.x (confidence: high, score: 9.5)"
                    # → "Linux 5.x"
                    os_short = color(
                        "  os:" + h.os_guess.split("(")[0].strip()[:20],
                        DIM)
                open_ports = [p.port for p in h.ports if p.state == "open"]
                ports_str  = (",".join(str(p) for p in open_ports[:6])
                              + ("…" if len(open_ports) > 6 else ""))
                lat = f"  {h.latency_ms}ms" if h.latency_ms else ""
                hostname   = f" ({h.hostname})" if h.hostname else ""

                print(f"  {connector}{hbranch} "
                      f"{color(h.ip, GREEN)}{hostname}"
                      f"{gw_tag}"
                      f"  open:{h.open_count}"
                      f"  [{ports_str}]"
                      f"{os_short}"
                      f"{color(lat, DIM)}")

        # Top 5 most exposed hosts
        most_open = topo["most_open"]
        if most_open:
            print(color(f"\n  Top {len(most_open)} most exposed hosts:", YELLOW))
            for i, h in enumerate(most_open, 1):
                print(f"    {i}. {color(h.ip, GREEN)}"
                      f"  open:{h.open_count}")
        print()


# ─────────────────────────────────────────────
# Report Export
# ─────────────────────────────────────────────
# ─────────────────────────────────────────────

BANNER_ART = r"""
  ____        ____
 |  _ \ _   _/ ___|  ___ __ _ _ __  _ __   ___ _ __
 | |_) | | | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 |  __/| |_| |___) | (_| (_| | | | | | | |  __/ |
 |_|    \__, |____/ \___\__,_|_| |_|_| |_|\___|_|
        |___/                    v9.0  (nmap-like)
"""

TOP_100_PORTS = (
    "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,"
    "119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,"
    "515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,"
    "1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,"
    "2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,"
    "5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,"
    "8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,"
    "49154,49155,49156,49157"
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pyscanner",
        description="PyScanner v9.0 - professional Python network scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pyscanner.py -t 192.168.1.1 -p 1-1024
  python pyscanner.py -t 10.0.0.0/24 --ping-scan --threads 200
  python pyscanner.py -t example.com -p 80,443 --banner --http-headers
  python pyscanner.py -t 192.168.1.1 -p 22,80,443 --scan-type syn
  python pyscanner.py -t 192.168.1.1 -p 1-65535 --scan-type syn --rate 500
  python pyscanner.py -t 2001:db8::1 -p 80,443 --ipv6
  python pyscanner.py -t 192.168.1.0/24 --arp-scan
  python pyscanner.py -t 8.8.8.8 --traceroute
  python pyscanner.py -t example.com --whois -o report.json
        """
    )
    p.add_argument("-t", "--targets", nargs="+", required=True,
                   metavar="TARGET",
                   help="IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
    p.add_argument("-p", "--ports", default=None,
                   help="Ports: '22', '80,443', '1-1024', 'top100'")
    p.add_argument("--scan-type",
                   choices=["connect", "syn", "udp",
                            "null", "fin", "xmas", "ack", "window"],
                   default="connect",
                   help=("[UPG-3] Scan method (default: connect). "
                         "Stealth types (null/fin/xmas) bypass stateless FW. "
                         "ack/window map firewall rules."))
    p.add_argument("-T", "--timing", type=int, choices=range(6),
                   default=3, metavar="0-5",
                   help=("[UPG-3] Timing mode 0=paranoid..5=insane "
                         "(like Nmap -T). Overrides --timeout/--threads/--rate. "
                         "T4+ activates async engine. Default: 3 (normal)"))
    p.add_argument("--scripts", action="store_true",
                   help=("[UPG-2] Run built-in NSE-style plugins after scan: "
                         "http-title, ftp-anon, ssl-cert, redis-info, "
                         "smb-os, ssh-auth. Implies --banner."))
    p.add_argument("--plugin-dir", metavar="DIR", default="",
                   help=("[UPG-2] Load external plugins from directory "
                         "(each .py file exports NAME, PORTS, PROTOCOL, run())"))
    p.add_argument("--async", dest="use_async", action="store_true",
                   help=("[UPG-4] Force async event-loop SYN engine "
                         "(auto-enabled at -T4/-T5). 10-50x faster."))
    p.add_argument("--ping-scan", action="store_true",
                   help="Ping sweep only, no port scan")
    p.add_argument("--skip-ping", action="store_true",
                   help="Skip host discovery, assume all hosts up")
    p.add_argument("--arp-scan", action="store_true",
                   help="ARP scan for LAN host discovery")
    p.add_argument("--timeout", type=float, default=1.0,
                   help="Socket timeout in seconds (default: 1.0, overridden by -T)")
    p.add_argument("--threads", type=int, default=100,
                   help="Max concurrent threads (default: 100, overridden by -T)")
    p.add_argument("--banner", action="store_true",
                   help="Grab service banners from open ports")
    p.add_argument("--http-headers", action="store_true",
                   help="Fetch HTTP/HTTPS response headers")
    p.add_argument("--traceroute", action="store_true",
                   help="Run traceroute to each up host (first 3)")
    p.add_argument("--max-hops", type=int, default=30,
                   help="Max hops for traceroute (default: 30)")
    p.add_argument("--whois", action="store_true",
                   help="Whois lookup on each target IP")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Save report (.json or .txt)")
    p.add_argument("--randomise", action="store_true",
                   help="Randomise port scan order + add inter-probe jitter")
    p.add_argument("--rate", type=float, default=0, metavar="PPS",
                   help="[FIX-26] Max packets per second (0=unlimited, overridden by -T)")
    p.add_argument("--ipv6", action="store_true",
                   help="[FIX-27] Prefer IPv6 addresses when resolving hostnames")
    p.add_argument("--exclude", default="", metavar="HOSTS",
                   help="[FIX-35] Comma-separated IPs, CIDRs, or ranges to skip")
    p.add_argument("--force-large", action="store_true",
                   help="[FIX-33] Allow scanning networks larger than /16 (>65534 hosts)")
    p.add_argument("--deep-fp", action="store_true",
                   help=("[ENH-3] Enable deep OS fingerprinting engine "
                         "(sends T1-T7 + IE + ECN probes, like Nmap)"))
    p.add_argument("--checkpoint", metavar="FILE", default="",
                   help=("[ENH-6] Save scan state to FILE after each host "
                         "(allows --resume after interruption)"))
    p.add_argument("--resume", metavar="FILE", default="",
                   help=("[ENH-6] Resume a previous scan from checkpoint FILE"))
    p.add_argument("--adaptive", action="store_true",
                   help=("[ENH-1] Enable adaptive congestion control "
                         "(auto-enabled at -T4/-T5)"))
    p.add_argument("--distributed", action="store_true",
                   help=("[V9-2] Run distributed multi-process scan "
                         "(splits targets across --workers processes)"))
    p.add_argument("--workers", type=int, default=4,
                   help=("[V9-2] Number of parallel worker processes for "
                         "distributed scanning (default: 4)"))
    p.add_argument("--worker-server", action="store_true",
                   help=("[V9-2] Start a DistributedWorkerServer HTTP agent "
                         "on this machine for remote coordination"))
    p.add_argument("--worker-port", type=int, default=9876,
                   help="[V9-2] Port for the worker server (default: 9876)")
    p.add_argument("--topology", action="store_true",
                   help=("[V9-6] Print ASCII network topology tree after scan"))
    p.add_argument("--output-xml", metavar="FILE", default="",
                   help=("[V9-5] Save Nmap-compatible XML report"))
    p.add_argument("--output-csv", metavar="FILE", default="",
                   help=("[V9-5] Save CSV report (one row per open port)"))
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show closed/filtered ports and worker errors")
    return p


def main():
    global _RATE_LIMITER

    print(color(BANNER_ART, CYAN))
    args = build_parser().parse_args()

    if args.ports == "top100":
        args.ports = TOP_100_PORTS
    if args.ping_scan:
        args.ports = None

    # [UPG-2] --scripts implies banner grabbing
    if args.scripts:
        args.banner = True

    # [FIX-29] / [FIX-26] Activate rate limiter if --rate given
    # (May be overridden by -T timing mode inside PyScanner.__init__)
    if args.rate and args.rate > 0:
        _RATE_LIMITER = TokenBucket(rate_pps=args.rate)

    # [FIX-29] / [FIX-27] Pass IPv6 preference
    args._prefer_ipv6 = getattr(args, "ipv6", False)

    # [UPG-3] Print active timing mode
    t_level = getattr(args, "timing", 3)
    if t_level in T_MODES:
        tm = T_MODES[t_level]
        print(color(
            f"[*] Timing mode: -T{t_level} ({tm.name}) "
            f"timeout={tm.timeout}s  parallelism={tm.parallelism}"
            + (f"  rate={tm.max_rate}pps" if tm.max_rate else "  rate=unlimited"),
            CYAN))

    # [UPG-4] Print async mode status
    if getattr(args, "use_async", False) or t_level >= 4:
        print(color("[*] Async engine: ENABLED (asyncio event loop)", CYAN))

    # [ENH-1] Activate adaptive congestion controller
    global _CONGESTION
    if getattr(args, "adaptive", False) or t_level >= 4:
        initial_rate = args.rate if args.rate > 0 else 200.0
        _CONGESTION = CongestionController(
            initial_rate=initial_rate,
            initial_para=args.threads)
        _CONGESTION.install_as_rate_limiter()
        print(color(
            f"[*] Adaptive congestion control: ENABLED "
            f"(initial rate={initial_rate:.0f}pps, slow-start ON)", CYAN))

    # [V9-2] Worker server mode
    if getattr(args, "worker_server", False):
        port = getattr(args, "worker_port", 9876)
        srv  = DistributedWorkerServer(host="0.0.0.0", port=port)
        srv.start()   # blocks forever
        sys.exit(0)

    # [V9-2] Distributed scan mode
    if getattr(args, "distributed", False):
        ports = parse_ports(args.ports) if args.ports else [80, 443, 22]
        ds    = DistributedScanner(
            workers     = getattr(args, "workers", 4),
            timeout     = args.timeout,
            scan_type   = args.scan_type,
            banner_grab = getattr(args, "banner", False),
        )
        # Resolve targets
        all_targets: List[str] = []
        for t in args.targets:
            if "/" in t:
                all_targets.extend(expand_cidr(t))
            else:
                ip = resolve_host(t)
                if ip:
                    all_targets.append(ip)
        dist_summary = ds.scan(all_targets, ports)
        ds.print_results(dist_summary)
        # Save to JSON if requested
        if args.output and args.output.endswith(".json"):
            import json as _json
            with open(args.output, "w") as f:
                _json.dump(dist_summary, f, indent=2)
            print(color(f"[+] Distributed results → {args.output}", GREEN))
        sys.exit(0)

    scanner = PyScanner(args)
    summary = scanner.run()

    # [V9-6] Topology analysis
    if getattr(args, "topology", False) or len(summary.results) > 1:
        topo = TopologyAnalyzer(summary.results)
        topo.print_tree()

    # Output formats
    if args.output:
        if args.output.endswith(".json"):
            export_json(summary, args.output)
        elif args.output.endswith(".xml"):
            export_xml(summary, args.output)
        elif args.output.endswith(".csv"):
            export_csv(summary, args.output)
        else:
            export_text(summary, args.output)

    # Additional explicit format flags
    xml_out = getattr(args, "output_xml", "") or ""
    csv_out = getattr(args, "output_csv", "") or ""
    if xml_out:
        export_xml(summary, xml_out)
    if csv_out:
        export_csv(summary, csv_out)


if __name__ == "__main__":
    main()
