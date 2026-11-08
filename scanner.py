"""
Scanning Engine
---------------
Supports three scan types:
  * tcp_connect - Full TCP connect scan (always available, uses sockets)
  * tcp_syn     - TCP SYN (half-open) scan (needs Nmap or Scapy + admin/Npcap)
  * udp         - UDP scan (Nmap if installed, otherwise socket probe)

Engine selection order: Nmap (python-nmap) -> Scapy -> built-in sockets.
"""
import socket
import shutil
import ipaddress
from concurrent.futures import ThreadPoolExecutor

try:
    import nmap  # python-nmap
except ImportError:  # pragma: no cover
    nmap = None

try:
    from scapy.all import IP, TCP, sr1, conf  # noqa: F401
    conf.verb = 0
    SCAPY_OK = True
except Exception:  # pragma: no cover
    SCAPY_OK = False

COMMON_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1900: "ssdp",
    3306: "mysql", 3389: "rdp", 5353: "mdns", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

# Simple knowledge base of risky services -> possible vulnerability notes
VULN_HINTS = {
    "ftp": "FTP sends credentials in clear text; check for anonymous login.",
    "telnet": "Telnet is unencrypted - replace with SSH.",
    "smtp": "Check for open relay configuration.",
    "netbios-ssn": "NetBIOS exposure can leak host/share information.",
    "microsoft-ds": "SMB exposed - ensure patched against EternalBlue (MS17-010).",
    "msrpc": "RPC exposed - restrict to trusted networks.",
    "rdp": "RDP exposed - brute-force / BlueKeep risk; use VPN + NLA.",
    "vnc": "VNC often weakly authenticated.",
    "mysql": "Database port exposed publicly.",
    "mssql": "Database port exposed publicly.",
    "postgresql": "Database port exposed publicly.",
    "mongodb": "MongoDB may allow unauthenticated access.",
    "redis": "Redis often has no authentication by default.",
    "elasticsearch": "Elasticsearch may expose data without auth.",
    "snmp": "SNMP v1/v2 uses community strings ('public') in clear text.",
    "http": "Unencrypted HTTP - prefer HTTPS.",
    "tftp": "TFTP has no authentication.",
}


def service_name(port, proto="tcp"):
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


def parse_ports(spec):
    """'22,80,100-110' -> sorted list of ints (max 2048 ports)."""
    ports = set()
    for part in str(spec).replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            ports.update(range(max(1, a), min(65535, b) + 1))
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    ports = sorted(ports)
    if not ports:
        raise ValueError("No valid ports given")
    if len(ports) > 2048:
        raise ValueError("Too many ports (max 2048 per scan)")
    return ports


def resolve_targets(target):
    """Accept IP, hostname, or small CIDR (/24 or smaller) for local network scans."""
    target = target.strip()
    if not target:
        raise ValueError("Target is required")
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 256:
            raise ValueError("Network too large (max /24)")
        hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
        return hosts
    return [socket.gethostbyname(target)]


def nmap_available():
    return nmap is not None and shutil.which("nmap") is not None


# ---------------------------------------------------------------- engines
def _tcp_connect(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((ip, port))
        if code == 0:
            return "open"
        # 10061 / 111 = connection refused -> closed; timeout -> filtered
        if code in (10061, 111):
            return "closed"
        return "filtered"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "filtered"
    finally:
        s.close()


def _udp_probe(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b"\x00", (ip, port))
        s.recvfrom(1024)
        return "open"
    except socket.timeout:
        return "open|filtered"
    except ConnectionResetError:  # ICMP port unreachable on Windows
        return "closed"
    except OSError:
        return "closed"
    finally:
        s.close()


def _scapy_syn(ip, port, timeout):
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout)
    if resp is None:
        return "filtered"
    if resp.haslayer(TCP):
        flags = int(resp[TCP].flags)
        if flags & 0x12 == 0x12:  # SYN-ACK
            sr1(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=0.5)
            return "open"
        if flags & 0x04:  # RST
            return "closed"
    return "filtered"


def _nmap_scan(ip, ports, scan_type):
    flag = {"tcp_syn": "-sS", "tcp_connect": "-sT", "udp": "-sU"}[scan_type]
    nm = nmap.PortScanner()
    nm.scan(ip, ",".join(map(str, ports)), arguments=f"{flag} -sV -T4")
    rows = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port, info in sorted(nm[host][proto].items()):
                svc = info.get("name") or service_name(port, proto)
                rows.append({
                    "ip": host, "port": port, "protocol": proto,
                    "service": svc,
                    "version": " ".join(filter(None, [info.get("product"), info.get("version")])),
                    "status": info.get("state", "unknown"),
                })
    return rows


def run_scan(target, ports_spec="1-1024", scan_type="tcp_connect", timeout=0.5, show_closed=False):
    if scan_type not in ("tcp_connect", "tcp_syn", "udp"):
        raise ValueError("Unknown scan type")
    hosts = resolve_targets(target)
    ports = parse_ports(ports_spec)
    proto = "udp" if scan_type == "udp" else "tcp"
    notes = []
    rows = []

    if nmap_available():
        engine = "nmap"
        for ip in hosts:
            rows.extend(_nmap_scan(ip, ports, scan_type))
    else:
        if scan_type == "tcp_syn":
            if SCAPY_OK:
                engine = "scapy"
                fn = _scapy_syn
            else:
                engine = "socket"
                fn = _tcp_connect
                notes.append("SYN scan needs Nmap or Scapy+Npcap; fell back to Full Connect.")
        elif scan_type == "udp":
            engine, fn = "socket", _udp_probe
        else:
            engine, fn = "socket", _tcp_connect

        jobs = [(ip, p) for ip in hosts for p in ports]
        fallback = []

        def work(job):
            ip, p = job
            try:
                st = fn(ip, p, timeout)
            except Exception:
                # e.g. scapy without Npcap / admin rights
                fallback.append(1)
                st = _tcp_connect(ip, p, timeout) if proto == "tcp" else "error"
            return {"ip": ip, "port": p, "protocol": proto,
                    "service": service_name(p, proto), "version": "", "status": st}

        with ThreadPoolExecutor(max_workers=200) as ex:
            rows = list(ex.map(work, jobs))
        if fallback:
            engine = "socket"
            notes.append("Raw SYN packets need Npcap + Administrator rights; used Full Connect instead.")

    for r in rows:
        r["vulnerability"] = VULN_HINTS.get(r["service"], "") if r["status"].startswith("open") else ""

    if not show_closed:
        rows = [r for r in rows if r["status"].startswith("open")]
    rows.sort(key=lambda r: (ipaddress.ip_address(r["ip"]), r["port"]))

    return {
        "target": target, "hosts_scanned": len(hosts), "ports_scanned": len(ports),
        "scan_type": scan_type, "engine": engine, "notes": notes, "results": rows,
    }


def format_report(scan):
    """Readable text report of a scan."""
    lines = [f"Scan of {scan['target']} ({scan['scan_type']}, engine={scan['engine']})",
             f"{'IP':<16}{'PORT':<8}{'PROTO':<7}{'SERVICE':<16}STATUS"]
    for r in scan["results"]:
        lines.append(f"{r['ip']:<16}{r['port']:<8}{r['protocol']:<7}{r['service']:<16}{r['status']}")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    t = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(format_report(run_scan(t, "1-1024")))
