const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

let rules = [];
let packets = [];
let ruleSeq = 1;
let lastScan = null;

async function api(url, body) {
  const r = await fetch(url, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

// ---------------- engine status ----------------
fetch("/api/status").then(r => r.json()).then(s => {
  $("engine").textContent = "Engine: " + (s.nmap ? "Nmap" : s.scapy ? "Scapy + sockets" : "Python sockets");
});

// ---------------- scanner ----------------
$("portPreset").onchange = e => $("customWrap").classList.toggle("hidden", e.target.value !== "custom");

$("scanBtn").onclick = async () => {
  const ports = $("portPreset").value === "custom" ? $("customPorts").value : $("portPreset").value;
  $("scanBtn").disabled = true;
  $("scanMsg").textContent = "Scanning…";
  const t0 = performance.now();
  try {
    const res = await api("/api/scan", {
      target: $("target").value, ports, scan_type: $("scanType").value,
      timeout: $("timeout").value, show_closed: $("showClosed").checked,
    });
    lastScan = res;
    renderScan(res, ((performance.now() - t0) / 1000).toFixed(1));
    $("scanMsg").textContent = "";
  } catch (e) {
    $("scanMsg").textContent = "Error: " + e.message;
  } finally {
    $("scanBtn").disabled = false;
  }
};

function renderScan(res, secs) {
  const open = res.results.filter(r => r.status.startsWith("open")).length;
  $("summary").innerHTML = `Target <b>${esc(res.target)}</b> · ${res.hosts_scanned} host(s) · ${res.ports_scanned} port(s) · engine <b>${res.engine}</b> · <b>${open}</b> open · ${secs}s`
    + res.notes.map(n => `<br>⚠ ${esc(n)}`).join("");
  const tb = $("results").querySelector("tbody");
  if (!res.results.length) { tb.innerHTML = `<tr><td colspan="7" class="empty">No open ports found.</td></tr>`; }
  else tb.innerHTML = res.results.map((r, i) => `<tr>
      <td>${esc(r.ip)}</td><td>${r.port}</td><td>${r.protocol.toUpperCase()}</td>
      <td>${esc(r.service)} ${r.version ? `<small>(${esc(r.version)})</small>` : ""}</td>
      <td class="st-${esc(r.status)}">${esc(r.status)}</td>
      <td class="vuln">${esc(r.vulnerability)}</td>
      <td>${r.status.startsWith("open") ? `<button class="secondary" onclick="testFromScan(${i})">Test</button>` : ""}</td></tr>`).join("");
  $("report").textContent = res.report;
}

window.testFromScan = i => {
  const r = lastScan.results[i];
  packets.push({src_ip: $("pSrc").value || "203.0.113.7", dst_ip: r.ip, port: r.port, protocol: r.protocol, direction: "inbound"});
  renderPackets();
};

// ---------------- rules ----------------
function addRule(r) { rules.push({id: ruleSeq++, ...r}); renderRules(); }

$("addRule").onclick = () => addRule({
  priority: +$("rPriority").value || 100, action: $("rAction").value, direction: $("rDir").value,
  src_ip: $("rSrc").value.trim() || "any", dst_ip: $("rDst").value.trim() || "any",
  port: $("rPort").value.trim() || "any", protocol: $("rProto").value,
});

$("sampleRules").onclick = () => {
  rules = []; ruleSeq = 1;
  addRule({priority: 1, action: "deny", direction: "inbound", src_ip: "203.0.113.0/24", dst_ip: "any", port: "any", protocol: "any"});
  addRule({priority: 5, action: "allow", direction: "inbound", src_ip: "192.168.1.0/24", dst_ip: "any", port: "22", protocol: "tcp"});
  addRule({priority: 10, action: "allow", direction: "inbound", src_ip: "any", dst_ip: "any", port: "80,443", protocol: "tcp"});
  addRule({priority: 20, action: "deny", direction: "any", src_ip: "any", dst_ip: "any", port: "3389", protocol: "tcp"});
  addRule({priority: 30, action: "allow", direction: "outbound", src_ip: "any", dst_ip: "any", port: "53", protocol: "udp"});
};

window.delRule = id => { rules = rules.filter(r => r.id !== id); renderRules(); };
window.movePrio = (id, d) => { const r = rules.find(x => x.id === id); r.priority = Math.max(0, r.priority + d); renderRules(); };

function renderRules() {
  const sorted = [...rules].sort((a, b) => a.priority - b.priority || a.id - b.id);
  $("rulesTable").querySelector("tbody").innerHTML = sorted.map(r => `<tr>
    <td>R${r.id}</td>
    <td>${r.priority} <button class="del" title="higher priority" onclick="movePrio(${r.id},-1)">▲</button><button class="del" title="lower priority" onclick="movePrio(${r.id},1)">▼</button></td>
    <td><span class="tag ${r.action}">${r.action.toUpperCase()}</span></td>
    <td>${r.direction}</td><td>${esc(r.src_ip)}</td><td>${esc(r.dst_ip)}</td><td>${esc(r.port)}</td><td>${r.protocol}</td>
    <td><button class="del" onclick="delRule(${r.id})">✕</button></td></tr>`).join("")
    || `<tr><td colspan="9" class="empty">No rules — default policy applies to everything.</td></tr>`;
}

// ---------------- packets ----------------
$("addPkt").onclick = () => {
  packets.push({src_ip: $("pSrc").value.trim(), dst_ip: $("pDst").value.trim(), port: +$("pPort").value,
                protocol: $("pProto").value, direction: $("pDir").value});
  renderPackets();
};
$("clearPkts").onclick = () => { packets = []; renderPackets(); };
$("fromScan").onclick = () => {
  if (!lastScan || !lastScan.results.length) return alert("Run a scan with open ports first.");
  lastScan.results.filter(r => r.status.startsWith("open")).forEach(r =>
    packets.push({src_ip: $("pSrc").value || "203.0.113.7", dst_ip: r.ip, port: r.port, protocol: r.protocol, direction: "inbound"}));
  renderPackets();
};
$("samplePkts").onclick = () => {
  packets = [
    {src_ip: "203.0.113.7", dst_ip: "192.168.1.10", port: 80, protocol: "tcp", direction: "inbound"},
    {src_ip: "192.168.1.25", dst_ip: "192.168.1.10", port: 22, protocol: "tcp", direction: "inbound"},
    {src_ip: "8.8.4.4", dst_ip: "192.168.1.10", port: 22, protocol: "tcp", direction: "inbound"},
    {src_ip: "8.8.4.4", dst_ip: "192.168.1.10", port: 443, protocol: "tcp", direction: "inbound"},
    {src_ip: "10.0.0.5", dst_ip: "192.168.1.10", port: 3389, protocol: "tcp", direction: "inbound"},
    {src_ip: "192.168.1.10", dst_ip: "1.1.1.1", port: 53, protocol: "udp", direction: "outbound"},
    {src_ip: "198.51.100.3", dst_ip: "192.168.1.10", port: 445, protocol: "tcp", direction: "inbound"},
  ];
  renderPackets();
};
window.delPkt = i => { packets.splice(i, 1); renderPackets(); };
function renderPackets() {
  $("pktList").innerHTML = packets.map((p, i) =>
    `<li>${esc(p.src_ip)} → ${esc(p.dst_ip)}:${p.port} ${p.protocol}/${p.direction} <button class="del" onclick="delPkt(${i})">✕</button></li>`).join("");
}

// ---------------- simulation ----------------
$("simulate").onclick = async () => {
  if (!packets.length) return alert("Add some traffic first (or load sample traffic).");
  const body = {rules, packets, default_policy: $("defaultPolicy").value};
  try {
    const sim = await api("/api/firewall/simulate", body);
    renderSim(sim);
    const r = await fetch("/api/firewall/chart", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
    if (r.ok) $("chart").src = URL.createObjectURL(await r.blob());
  } catch (e) { alert(e.message); }
};

function renderSim(sim) {
  $("simSummary").innerHTML = `<b style="color:var(--allow)">${sim.summary.allowed} allowed</b> · <b style="color:var(--deny)">${sim.summary.blocked} blocked</b> · default policy <b>${$("defaultPolicy").value.toUpperCase()}</b>`;
  $("simTable").querySelector("tbody").innerHTML = sim.results.map(r => `<tr>
    <td>${esc(r.src_ip)}</td><td>${esc(r.dst_ip)}</td><td>${r.port}</td><td>${r.protocol}</td><td>${r.direction}</td>
    <td><span class="tag ${r.action}">${r.action === "allow" ? "ALLOWED" : "BLOCKED"}</span></td>
    <td>${r.rule_id ? "R" + r.rule_id : "default policy"}</td>
    <td>${r.trace.map(t => (t.matched ? "<b>" : "") + "R" + t.rule_id + (t.matched ? "✓</b>" : "✗")).join(" → ") || "—"}</td></tr>`).join("");
  drawFlow(sim.results);
}

// SVG flow diagram: Sources -> Firewall (rule chain) -> Destinations
function drawFlow(results) {
  const NS = "http://www.w3.org/2000/svg";
  const srcs = [...new Set(results.map(r => r.src_ip))];
  const dsts = [...new Set(results.map(r => `${r.dst_ip}:${r.port}/${r.protocol}`))];
  const sorted = [...rules].sort((a, b) => a.priority - b.priority || a.id - b.id);
  const rowH = 46, top = 50;
  const H = Math.max(srcs.length, dsts.length, sorted.length + 2) * rowH + top + 20;
  const W = 1000, xS = 20, wS = 170, xF = 400, wF = 200, xD = 810, wD = 170;
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("width", "100%");
  const el = (tag, attrs, text) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); if (text != null) e.textContent = text; svg.appendChild(e); return e; };

  el("text", {x: xS, y: 28, fill: "#94a3b8", "font-size": 13}, "SOURCES");
  el("text", {x: xF, y: 28, fill: "#94a3b8", "font-size": 13}, "FIREWALL (rule chain)");
  el("text", {x: xD, y: 28, fill: "#94a3b8", "font-size": 13}, "DESTINATIONS");

  const sy = i => top + i * rowH + 16;
  const dy = i => top + i * rowH + 16;
  const fTop = top, fH = H - top - 20, fMid = fTop + fH / 2;

  // lines first (under boxes)
  results.forEach(r => {
    const y1 = sy(srcs.indexOf(r.src_ip));
    const y2 = dy(dsts.indexOf(`${r.dst_ip}:${r.port}/${r.protocol}`));
    const allow = r.action === "allow";
    const color = allow ? "#22c55e" : "#ef4444";
    const entryY = fTop + 20 + ((y1 + y2) / 2 - top) / (H - top) * (fH - 40);
    const tip = `${r.src_ip} → ${r.dst_ip}:${r.port}/${r.protocol} — ${allow ? "ALLOWED" : "BLOCKED"} by ${r.rule_id ? "R" + r.rule_id : "default policy"}`;
    const p1 = el("path", {d: `M${xS + wS},${y1} C${xS + wS + 110},${y1} ${xF - 110},${entryY} ${xF},${entryY}`, stroke: color, "stroke-width": 2.5, fill: "none", opacity: .85});
    p1.appendChild(Object.assign(document.createElementNS(NS, "title"), {textContent: tip}));
    if (allow) {
      const p2 = el("path", {d: `M${xF + wF},${entryY} C${xF + wF + 110},${entryY} ${xD - 110},${y2} ${xD},${y2}`, stroke: color, "stroke-width": 2.5, fill: "none", opacity: .85});
      p2.appendChild(Object.assign(document.createElementNS(NS, "title"), {textContent: tip}));
    } else {
      el("text", {x: xF - 18, y: entryY + 6, fill: color, "font-size": 18, "font-weight": 700}, "✖");
    }
  });

  // source boxes
  srcs.forEach((s, i) => {
    el("rect", {x: xS, y: sy(i) - 16, width: wS, height: 32, rx: 6, fill: "#1e293b", stroke: "#475569"});
    el("text", {x: xS + 10, y: sy(i) + 5, fill: "#e2e8f0", "font-size": 13}, s);
  });
  // firewall box with rule chain
  el("rect", {x: xF, y: fTop, width: wF, height: fH, rx: 10, fill: "#172033", stroke: "#38bdf8", "stroke-width": 2});
  sorted.forEach((r, i) => {
    const y = fTop + 14 + i * 26;
    el("rect", {x: xF + 10, y, width: wF - 20, height: 22, rx: 4, fill: r.action === "allow" ? "rgba(34,197,94,.18)" : "rgba(239,68,68,.18)"});
    el("text", {x: xF + 16, y: y + 15, fill: r.action === "allow" ? "#22c55e" : "#ef4444", "font-size": 11},
      `P${r.priority} R${r.id} ${r.action.toUpperCase()} ${r.protocol}:${r.port}`.slice(0, 30));
  });
  el("text", {x: xF + 16, y: fTop + fH - 12, fill: "#94a3b8", "font-size": 11}, `default: ${$("defaultPolicy").value.toUpperCase()}`);
  // destination boxes
  dsts.forEach((d, i) => {
    el("rect", {x: xD, y: dy(i) - 16, width: wD, height: 32, rx: 6, fill: "#1e293b", stroke: "#475569"});
    el("text", {x: xD + 10, y: dy(i) + 5, fill: "#e2e8f0", "font-size": 12}, d);
  });

  $("flow").innerHTML = "";
  $("flow").appendChild(svg);
}

renderRules();
