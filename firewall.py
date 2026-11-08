"""
Firewall Simulation Logic
-------------------------
Rules are evaluated in priority order (lowest number = highest priority).
The first matching rule decides the action (first-match rule chaining,
like iptables / Windows Firewall). If no rule matches, the default
policy is applied.

Rule format:
  {"id": 1, "priority": 10, "action": "allow"|"deny",
   "src_ip": "any" | "192.168.1.5" | "10.0.0.0/8",
   "dst_ip": "any" | ip | cidr,
   "port": "any" | "80" | "1000-2000" | "22,80,443",
   "protocol": "any" | "tcp" | "udp" | "icmp",
   "direction": "inbound"|"outbound"|"any"}
"""
import ipaddress


def _ip_match(rule_ip, ip):
    if not rule_ip or rule_ip == "any":
        return True
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(rule_ip, strict=False)
    except ValueError:
        return rule_ip == ip


def _port_match(rule_port, port):
    if rule_port in (None, "", "any"):
        return True
    if port in (None, ""):
        return False
    port = int(port)
    for part in str(rule_port).replace(" ", "").split(","):
        if "-" in part:
            a, b = map(int, part.split("-", 1))
            if a <= port <= b:
                return True
        elif part and int(part) == port:
            return True
    return False


def rule_matches(rule, pkt):
    proto = rule.get("protocol", "any")
    direction = rule.get("direction", "any")
    return (
        (proto == "any" or proto == pkt.get("protocol"))
        and (direction == "any" or direction == pkt.get("direction", "inbound"))
        and _ip_match(rule.get("src_ip", "any"), pkt.get("src_ip"))
        and _ip_match(rule.get("dst_ip", "any"), pkt.get("dst_ip"))
        and _port_match(rule.get("port", "any"), pkt.get("port"))
    )


def evaluate(rules, packet, default_policy="deny"):
    """Return decision for a single packet + trace of rules checked."""
    ordered = sorted(rules, key=lambda r: (int(r.get("priority", 100)), r.get("id", 0)))
    trace = []
    for r in ordered:
        m = rule_matches(r, packet)
        trace.append({"rule_id": r.get("id"), "matched": m})
        if m:
            return {"action": r["action"], "rule_id": r.get("id"), "trace": trace}
    return {"action": default_policy, "rule_id": None, "trace": trace}


def simulate(rules, packets, default_policy="deny"):
    out = []
    for p in packets:
        d = evaluate(rules, p, default_policy)
        out.append({**p, **d})
    summary = {
        "allowed": sum(1 for o in out if o["action"] == "allow"),
        "blocked": sum(1 for o in out if o["action"] == "deny"),
    }
    return {"results": out, "summary": summary}
