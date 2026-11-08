"""
Network Security Scanner & Firewall Visualizer - Flask backend
Run:  python app.py   then open http://127.0.0.1:5000
"""
import io
from flask import Flask, jsonify, request, render_template, send_file

import scanner
import firewall

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def status():
    return jsonify({
        "nmap": scanner.nmap_available(),
        "scapy": scanner.SCAPY_OK,
    })


@app.post("/api/scan")
def scan():
    data = request.get_json(force=True) or {}
    try:
        result = scanner.run_scan(
            target=data.get("target", ""),
            ports_spec=data.get("ports", "1-1024"),
            scan_type=data.get("scan_type", "tcp_connect"),
            timeout=float(data.get("timeout", 0.5)),
            show_closed=bool(data.get("show_closed", False)),
        )
        result["report"] = scanner.format_report(result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/firewall/simulate")
def simulate():
    data = request.get_json(force=True) or {}
    try:
        return jsonify(firewall.simulate(
            data.get("rules", []), data.get("packets", []),
            data.get("default_policy", "deny")))
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/firewall/chart")
def chart():
    """matplotlib bar chart of allowed vs blocked traffic per port."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    data = request.get_json(force=True) or {}
    sim = firewall.simulate(data.get("rules", []), data.get("packets", []),
                            data.get("default_policy", "deny"))
    labels, allowed, blocked = [], [], []
    for r in sim["results"]:
        lab = f"{r.get('protocol')}/{r.get('port')}"
        if lab not in labels:
            labels.append(lab); allowed.append(0); blocked.append(0)
        i = labels.index(lab)
        if r["action"] == "allow":
            allowed[i] += 1
        else:
            blocked[i] += 1
    fig, ax = plt.subplots(figsize=(8, 3.5))
    x = range(len(labels))
    ax.bar(x, allowed, color="#22a06b", label="Allowed")
    ax.bar(x, blocked, bottom=allowed, color="#d9534f", label="Blocked")
    ax.set_xticks(list(x)); ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.set_ylabel("Packets"); ax.set_title("Firewall decisions by protocol/port")
    ax.legend(); fig.tight_layout()
    buf = io.BytesIO(); fig.savefig(buf, format="png", dpi=110); plt.close(fig)
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
