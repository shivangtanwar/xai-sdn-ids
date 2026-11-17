/* XAI-SDN-IDS live dashboard client. Data arrives over SSE from /api/stream. */
(() => {
  "use strict";

  const HOSTS = [
    { name: "h1", ip: "10.0.0.1", role: "user", sw: "s2" },
    { name: "h2", ip: "10.0.0.2", role: "user", sw: "s2" },
    { name: "h3", ip: "10.0.0.3", role: "user", sw: "s2" },
    { name: "h4", ip: "10.0.0.4", role: "attacker", sw: "s2" },
    { name: "h5", ip: "10.0.0.5", role: "web server", sw: "s3" },
    { name: "h6", ip: "10.0.0.6", role: "DNS server", sw: "s3" },
    { name: "h7", ip: "10.0.0.7", role: "attacker", sw: "s3" },
    { name: "h8", ip: "10.0.0.8", role: "user", sw: "s3" },
  ];
  const COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"];
  const NAME = Object.fromEntries(HOSTS.map(h => [h.ip, h.name]));
  const CLASSES = ["benign", "icmp_flood", "syn_flood", "udp_flood", "port_scan"];
  const TYPES = {
    syn_flood: "SYN flood", udp_flood: "UDP flood", icmp_flood: "ICMP flood",
    port_scan: "Port scan", heavy_benign: "Heavy benign transfer",
  };
  const ACTION_TEXT = { BLOCK: "BLOCK", RATE_LIMIT: "RATE LIMIT", ALERT: "ALERT", NONE: "NO ACTION" };
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const S = {
    rounds: [], decisions: [], status: {}, mitigations: {}, episodes: [], health: {},
    demoRunning: false, authed: false, selected: "10.0.0.4", follow: true,
    lastAttackOnSelected: 0, view: null, resultsLoaded: false, seenDecisions: new Set(),
  };

  // ---------------------------------------------------------------- helpers
  const $ = id => document.getElementById(id);
  function el(tag, props = {}, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k === "style") n.style.cssText = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) n.setAttribute(k, v === true ? "" : v);
    }
    for (const k of kids.flat()) if (k != null) n.append(k instanceof Node ? k : document.createTextNode(k));
    return n;
  }
  const SVG = "http://www.w3.org/2000/svg";
  function sv(tag, attrs = {}, text) {
    const n = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (text != null) n.textContent = text;
    return n;
  }
  const clock = ts => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
  function rate(v) {
    if (v == null) return "–";
    if (v >= 1e6) return (v / 1e6).toFixed(1) + "M";
    if (v >= 1e3) return (v / 1e3).toFixed(1) + "k";
    return v >= 10 ? v.toFixed(0) : v.toFixed(1);
  }
  const num = v => (Math.abs(v) >= 1000 ? rate(v) : Math.abs(v) >= 10 ? v.toFixed(0) : v.toFixed(2));
  const lastRound = () => S.rounds[S.rounds.length - 1];
  function hostState(ip) {
    const r = lastRound();
    return (r && r.hosts[ip]) || { pkt_rate: 0, in_rate: 0, label: "idle", state: "NONE" };
  }
  async function api(path, opts = {}) {
    const r = await fetch(path, {
      method: opts.method || "GET", credentials: "same-origin",
      headers: opts.body ? { "Content-Type": "application/json" } : {},
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.detail || data.error || `Request failed (${r.status})`);
    return data;
  }

  // ---------------------------------------------------------------- stream
  function connect() {
    const es = new EventSource("/api/stream");
    es.onopen = () => setLive(true);
    es.onerror = () => setLive(false);
    es.addEventListener("snapshot", e => {
      const d = JSON.parse(e.data);
      S.rounds = d.rounds; S.decisions = d.decisions;
      d.decisions.forEach(x => S.seenDecisions.add(key(x)));
      applyStatus(d);
      const recent = d.decisions[d.decisions.length - 1];
      if (S.follow && recent && Date.now() / 1000 - recent.ts < 60) {
        S.selected = recent.src_ip; S.lastAttackOnSelected = recent.ts;
      }
      renderFeed(true); renderAll(); fetchView();
    });
    es.addEventListener("round", e => {
      S.rounds.push(JSON.parse(e.data));
      if (S.rounds.length > 300) S.rounds.shift();
      renderAll(); fetchView();
    });
    es.addEventListener("decision", e => {
      const d = JSON.parse(e.data);
      if (S.seenDecisions.has(key(d))) return;
      S.seenDecisions.add(key(d));
      S.decisions.push(d);
      if (S.decisions.length > 600) S.decisions.shift();
      maybeFollow(d);
      renderFeed(false);
    });
    es.addEventListener("status", e => { applyStatus(JSON.parse(e.data)); renderSide(); });
  }
  const key = d => `${d.ts}|${d.src_ip}`;
  // A window that passes the gates while its source is already mitigated gets action NONE
  // (no duplicate rule). Show it as "already blocked/limited", not as "no action".
  const already = d => d && d.action === "NONE" && d.active && d.active !== "NONE";

  function setLive(ok) {
    $("h-live").className = "dot live " + (ok ? "ok" : "bad");
    $("h-live-t").textContent = ok ? "Live" : "Reconnecting…";
  }

  function applyStatus(d) {
    S.status = d.status || S.status;
    S.mitigations = d.mitigations || {};
    S.episodes = d.episodes || [];
    S.health = d.health || {};
    S.demoRunning = !!d.demo_running;
    S.mitReceived = Date.now();
    refreshHeader();
  }

  function refreshHeader() {
    if (!S.health || !Object.keys(S.health).length) {   // nothing received yet: don't raise alarms
      $("h-sw").textContent = "– switches";
      $("banner").hidden = true;
      $("protect").disabled = !S.authed;
      return;
    }
    $("h-ctrl").className = "dot " + (S.health.controller ? "ok" : "bad");
    $("h-bed").className = "dot " + (S.health.testbed ? "ok" : "bad");
    const sw = (S.status.switches || []).length;
    $("h-sw").textContent = `${sw}/3 switches`;
    const prot = $("protect");
    prot.setAttribute("aria-checked", S.status.mode === "detect" ? "true" : "false");
    prot.disabled = !S.authed;
    prot.title = S.authed ? "" : "Sign in to change protection";
    const msgs = [];
    if (!S.health.controller) msgs.push("The Ryu controller is not reachable, so live data is paused until it reconnects.");
    if (!S.health.testbed) msgs.push("The Mininet testbed is not reachable, so traffic controls are unavailable.");
    if (S.status.mode === "monitor") msgs.push("Automatic protection is off: attacks are detected and explained but not mitigated.");
    $("banner").hidden = !msgs.length;
    $("banner").textContent = msgs.join(" ");
  }

  function maybeFollow(d) {
    if (d.src_ip === S.selected) S.lastAttackOnSelected = d.ts;
    if (!S.follow || d.src_ip === S.selected) return;
    if (d.ts - S.lastAttackOnSelected < 6) return;   // don't flip between two active attackers
    S.selected = d.src_ip;
    S.lastAttackOnSelected = d.ts;
    renderChips(); renderTopo(); fetchView();
  }

  // ---------------------------------------------------------------- pipeline
  let viewSeq = 0;
  async function fetchView() {
    const seq = ++viewSeq;
    try {
      const v = await api(`/api/explain/${S.selected}`);
      if (seq === viewSeq) { S.view = v; renderPipeline(); }
    } catch {
      if (seq === viewSeq) { S.view = null; renderPipeline(); }
    }
  }

  function renderChips() {
    const box = $("host-chips");
    box.replaceChildren(...HOSTS.map((h, i) => {
      const hs = hostState(h.ip);
      let st = null;
      if (hs.state === "BLOCK") st = el("span", { class: "st pill BLOCK", text: "BLOCKED" });
      else if (hs.state === "RATE_LIMIT") st = el("span", { class: "st pill RATE_LIMIT", text: "LIMITED" });
      else if (hs.label && !["benign", "idle"].includes(hs.label)) st = el("span", { class: "st pill ALERT", text: "SUSPECT" });
      return el("button", {
        class: "chip", "aria-pressed": h.ip === S.selected ? "true" : "false",
        onclick: () => select(h.ip),
      }, el("span", { class: "key", style: `background:${COLORS[i]}` }), `${h.name} · ${h.role}`, st);
    }));
  }

  function select(ip) {
    S.selected = ip;
    S.lastAttackOnSelected = Date.now() / 1000;
    renderChips(); renderTopo(); fetchView();
  }

  function railState(v) {
    // Per-segment / per-node state of the signal for the selected host's latest window.
    const segs = Array(5).fill(""), nodes = Array(6).fill("");
    if (!v) return { segs, nodes, end: -1 };
    if (v.label === "benign") {            // explained, but nothing to gate
      segs.fill("on", 0, 3); nodes.fill("on", 0, 4); nodes[5] = "on";
      return { segs, nodes, end: 3 };
    }
    segs.fill("on", 0, 4); nodes.fill("on", 0, 5);
    const d = v.decision;
    const action = already(d) ? d.active : d ? d.action : "NONE";
    if (action === "BLOCK" || action === "RATE_LIMIT") {
      segs[4] = "on"; nodes[5] = "act-" + action;
      return { segs, nodes, end: 5 };
    }
    segs[4] = "cut"; nodes[4] = "stop";
    nodes[5] = action === "ALERT" ? "act-ALERT" : "on";
    return { segs, nodes, end: 4 };
  }

  function renderRail(v) {
    const rail = $("rail");
    const stations = [...document.querySelectorAll(".station")];
    if (new Set(stations.map(s => s.offsetTop)).size > 1) { rail.hidden = true; return; }
    rail.hidden = false;
    const base = rail.getBoundingClientRect().left;
    const xs = stations.map(s => { const r = s.getBoundingClientRect(); return r.left + r.width / 2 - base; });
    const st = railState(v);
    const kids = st.segs.map((c, i) => el("div", { class: "seg " + c, style: `left:${xs[i]}px;width:${xs[i + 1] - xs[i]}px` }));
    st.nodes.forEach((c, i) => kids.push(el("div", { class: "node " + c, style: `left:${xs[i]}px`, text: c === "stop" ? "!" : String(i + 1) })));
    const pulse = el("div", { class: "pulse", style: `left:${xs[0]}px` });
    kids.push(pulse);
    rail.replaceChildren(...kids);
    if (!reduceMotion && st.end >= 0) {
      const endX = xs[st.end];
      pulse.animate([{ left: `${xs[0]}px`, opacity: 1 }, { left: `${endX}px`, opacity: 1 }, { left: `${endX}px`, opacity: 0 }],
        { duration: 1100, easing: "cubic-bezier(.3,.7,.4,1)" });
    }
  }

  function renderPipeline() {
    const v = S.view;
    const name = NAME[S.selected];
    renderRail(v);
    if (!v) {
      $("pipe-when").textContent = `No analysed traffic from ${name} yet. Hosts sending fewer than 5 packets/s are not analysed.`;
      ["st-1-body", "st-2-body", "st-3-body", "st-4-body", "st-5-body", "st-6-body"].forEach(id => $(id).replaceChildren());
      document.querySelectorAll(".station").forEach(s => s.classList.add("dim"));
      return;
    }
    document.querySelectorAll(".station").forEach(s => s.classList.remove("dim"));
    const age = Math.max(0, Date.now() / 1000 - v.ts);
    $("pipe-when").textContent = `${name} (${v.ip}) · window ending ${clock(v.ts)}` + (age > 5 ? ` · ${age.toFixed(0)} s ago (no new traffic since)` : "");
    const f = v.features;
    const hs = hostState(v.ip);

    // 1 counters
    $("st-1-body").replaceChildren(...kv([
      ["Packets/s sent", rate(f.pkt_rate)], ["Bytes/s sent", rate(f.byte_rate)],
      ["Packets/s received", rate(hs.in_rate)], ["Active flow rules", num(f.n_flows)],
      ["New flow rules", num(f.new_flows)], ["Packet-Ins/s", num(f.pktin_rate)],
    ]));

    // 2 features
    const shapSorted = Object.entries(v.shap).sort((a, b) => b[1] - a[1]);
    const top = new Set(shapSorted.slice(0, 3).filter(([, x]) => x > 0).map(([k]) => k));
    $("st-2-body").replaceChildren(...Object.entries(f).flatMap(([k, val]) => [
      el("dt", { class: top.has(k) ? "hot" : "", text: k }), el("dd", { class: top.has(k) ? "hot" : "", text: num(val) }),
    ]));

    // 3 probabilities
    $("st-3-body").replaceChildren(...CLASSES.map(c => {
      const p = v.probs[c] || 0;
      const win = c === v.label;
      const track = el("div", { class: "track" }, el("div", { class: "fill" + (win ? " win" : ""), style: `width:${p * 100}%` }));
      if (win && c !== "benign") {
        track.append(el("div", { class: "tick", style: "left:70%" }), el("div", { class: "tick", style: "left:90%" }));
      }
      return el("div", { class: "bar" }, el("span", { class: "lbl" + (win ? " win" : ""), text: c }), track,
        el("span", { class: "val", text: p.toFixed(2) }));
    }));

    // 4 SHAP
    $("st-4-lead").textContent = `Feature contributions towards “${v.label}”.`;
    const byMag = Object.entries(v.shap).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1])).slice(0, 6);
    const maxAbs = Math.max(1e-6, ...byMag.map(([, x]) => Math.abs(x)));
    $("st-4-body").replaceChildren(...byMag.map(([k, x]) => {
      const w = Math.abs(x) / maxAbs * 50;
      const style = x >= 0 ? `left:50%;width:${w}%` : `left:${50 - w}%;width:${w}%`;
      return el("div", { class: "bar" }, el("span", { class: "lbl", text: k }),
        el("div", { class: "track" }, el("div", { class: "fill " + (x >= 0 ? "sup" : "opp"), style })),
        el("span", { class: "val", text: (x >= 0 ? "+" : "") + x.toFixed(2) }));
    }));

    // 5 gates
    renderGates(v);
    // 6 decision
    renderDecision(v);
  }

  function kv(rows) {
    return rows.flatMap(([k, val]) => [el("dt", { text: k }), el("dd", { text: val })]);
  }

  function renderGates(v) {
    const box = $("st-5-body");
    const st5 = $("st-5");
    if (v.label === "benign") {
      st5.classList.add("dim");
      box.replaceChildren(el("p", { class: "empty", text: "Not evaluated. The window was classified benign, so there is nothing to gate." }));
      return;
    }
    const d = v.decision;
    if (!d || !d.gates || !Object.keys(d.gates).length) {
      box.replaceChildren(el("p", { class: "empty", text: "Waiting for this window's gate results." }));
      return;
    }
    const g = d.gates;
    const tl = S.status.tau_limit ?? 0.7, tb = S.status.tau_block ?? 0.9;
    const topF = (d.explanation || []).map(e => e.feature);
    const name = NAME[v.ip];
    const rows = [
      ["G1", "Confidence", g.G1_limit,
        g.G1_block ? `p = ${d.confidence.toFixed(2)} ≥ ${tb}: may block` :
          g.G1_limit ? `p = ${d.confidence.toFixed(2)} ≥ ${tl}: may rate-limit, not block` :
            `p = ${d.confidence.toFixed(2)} < ${tl}: too uncertain to act`],
      ["G2", "Persistence", g.G2,
        g.G2 ? "Flagged in at least 2 of the last 3 windows" : "First suspicious window, so it waits for a second"],
      ["G3", "Explanation", g.G3,
        g.G3 ? `${topF.join(", ")} match the ${v.label} signature` : `${topF.join(", ")} don't match the ${v.label} signature`],
      ["G4", "Asset safety", g.G4,
        g.G4 ? `${name} is not a protected server` : `${name} is a protected server, so alert only`],
    ];
    box.replaceChildren(...rows.map(([id, title, ok, text]) =>
      el("div", { class: "gate " + (ok ? "pass" : "fail") },
        el("span", { class: "mark", text: ok ? "✓" : "✕", "aria-label": ok ? "passed" : "failed" }),
        el("div", {}, el("b", { text: `${id} ${title}` }), el("span", { text }))),
    ));
  }

  function renderDecision(v) {
    const d = v.decision;
    const box = $("st-6-body");
    let action = d ? d.action : "NONE";
    let reason = d ? d.reason : "Classified benign, so no action is needed.";
    const active = S.mitigations[v.ip];
    if (already(d)) {
      action = d.active;
      reason = `Gates passed, but ${NAME[v.ip]} was already ${d.active === "BLOCK" ? "blocked" : "rate-limited"}, so no duplicate rule was installed.`;
    }
    const kids = [el("div", { class: "stamp " + action, text: ACTION_TEXT[action] || action }), el("p", { class: "reason", text: reason })];
    if (action === "BLOCK") kids.push(el("p", { class: "reason", text: `Drop rule in table 0 for all IPv4 from ${v.ip}, priority 1000.` }));
    if (action === "RATE_LIMIT") kids.push(el("p", { class: "reason", text: `OpenFlow meter caps ${v.ip} at ${S.status.rate_limit_kbps || 1000} kbps.` }));
    if (active) kids.push(el("p", { class: "reason mono", text: `Expires in ${Math.max(0, active.expires_in).toFixed(0)} s` }));
    if (d) kids.push(el("p", { class: "reason mono", text: `Inference ${d.infer_ms} ms · SHAP ${d.explain_ms} ms` }));
    box.replaceChildren(...kids);
  }

  // ---------------------------------------------------------------- topology
  const POS = {
    ctrl: [360, 34], s1: [360, 118], s2: [177, 206], s3: [543, 206],
    h1: [48, 318], h2: [134, 318], h3: [220, 318], h4: [306, 318],
    h5: [414, 318], h6: [500, 318], h7: [586, 318], h8: [672, 318],
  };
  function renderTopo() {
    const svg = sv("svg", { viewBox: "0 0 720 392", role: "img", "aria-label": "Network topology with live host states" });
    const link = (a, b, cls, w = 2) => svg.append(sv("line", { x1: POS[a][0], y1: POS[a][1], x2: POS[b][0], y2: POS[b][1], class: cls, "stroke-width": w }));
    ["s1", "s2", "s3"].forEach(s => link("ctrl", s, "t-ctrl", 1.2));
    const swLoad = { s2: 0, s3: 0 };
    HOSTS.forEach(h => { const hs = hostState(h.ip); swLoad[h.sw] += (hs.pkt_rate || 0) + (hs.in_rate || 0); });
    ["s2", "s3"].forEach(s => link("s1", s, "t-link" + (swLoad[s] > 40 ? " busy" : ""), 3));
    HOSTS.forEach(h => {
      const hs = hostState(h.ip);
      const load = (hs.pkt_rate || 0) + (hs.in_rate || 0);
      const w = 1.5 + Math.min(4, Math.log10(1 + load));
      link(h.sw, h.name, "t-link" + (hs.state === "BLOCK" ? " cut" : load > 20 ? " busy" : ""), w);
    });
    const node = (id, cls, lines, w, hgt) => {
      const [x, y] = POS[id];
      const g = sv("g", { class: "t-node " + cls, transform: `translate(${x - w / 2},${y - hgt / 2})` });
      g.append(sv("rect", { width: w, height: hgt, rx: 7 }));
      lines.forEach(([text, c, dy]) => g.append(sv("text", { x: w / 2, y: dy, "text-anchor": "middle", class: c }, text)));
      svg.append(g);
      return g;
    };
    node("ctrl", "ctrl", [["Ryu controller", "", 22]], 130, 34);
    node("s1", "sw", [["s1 core", "", 20]], 90, 32);
    node("s2", "sw", [["s2 edge", "", 20]], 90, 32);
    node("s3", "sw", [["s3 edge", "", 20]], 90, 32);
    HOSTS.forEach(h => {
      const hs = hostState(h.ip);
      const cls = `host st-${hs.state || "NONE"}` + (h.ip === S.selected ? " sel" : "") +
        (hs.state === "NONE" && !["benign", "idle"].includes(hs.label) ? " st-ALERT" : "");
      const g = node(h.name, cls, [[h.name, "", 17], [h.ip, "small", 31], [h.role, "role", 44]], 80, 54);
      g.setAttribute("tabindex", "0");
      g.setAttribute("aria-label", `${h.name} ${h.role}, ${hs.state === "NONE" ? "no mitigation" : hs.state}`);
      g.addEventListener("click", () => select(h.ip));
      g.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(h.ip); } });
      const [x, y] = POS[h.name];
      svg.append(sv("text", { x, y: y + 44, "text-anchor": "middle", class: "t-rate" }, `↑${rate(hs.pkt_rate)} ↓${rate(hs.in_rate)}`));
      let badge = null, color = null;
      const m = S.mitigations[h.ip];
      if (hs.state === "BLOCK") { badge = `BLOCKED${m ? " " + Math.max(0, m.expires_in).toFixed(0) + "s" : ""}`; color = "#d03b3b"; }
      else if (hs.state === "RATE_LIMIT") { badge = "RATE-LIMITED"; color = "#ec835a"; }
      else if (!["benign", "idle"].includes(hs.label)) { badge = `SUSPECT ${hs.label}`; color = "#b07a00"; }
      if (badge) {
        const bw = badge.length * 6.4 + 12;
        const bg = sv("g", { class: "t-badge", transform: `translate(${x - bw / 2},${y - 44})` });
        bg.append(sv("rect", { width: bw, height: 15, rx: 3, fill: color }), sv("text", { x: bw / 2, y: 11, "text-anchor": "middle" }, badge));
        svg.append(bg);
      }
    });
    $("topo").replaceChildren(svg);
  }

  // ---------------------------------------------------------------- traffic chart
  let chart = null;
  function chartData() {
    const xs = S.rounds.map(r => r.ts);
    const ys = HOSTS.map(h => S.rounds.map(r => Math.max(1, (r.hosts[h.ip] || {}).pkt_rate || 0)));
    return [xs, ...ys];
  }
  function bandsPlugin() {
    return {
      hooks: {
        drawClear: u => {
          const { ctx } = u;
          const { left, top, width, height } = u.bbox;
          const [x0, x1] = [u.scales.x.min, u.scales.x.max];
          ctx.save();
          ctx.beginPath(); ctx.rect(left, top, width, height); ctx.clip();
          for (const ep of S.episodes) {
            const end = ep.end ?? Date.now() / 1000;
            if (end < x0 || ep.start > x1) continue;
            const a = u.valToPos(Math.max(ep.start, x0), "x", true), b = u.valToPos(Math.min(end, x1), "x", true);
            ctx.fillStyle = ep.type === "heavy_benign" ? "rgba(27,175,122,.08)" : "rgba(11,11,11,.055)";
            ctx.fillRect(a, top, b - a, height);
            ctx.fillStyle = "#52514e";
            ctx.font = `${11 * devicePixelRatio}px "IBM Plex Mono", monospace`;
            ctx.fillText(`${ep.type} ${ep.src}→${ep.dst}`, a + 4 * devicePixelRatio, top + 13 * devicePixelRatio);
          }
          ctx.restore();
        },
        draw: u => {
          const { ctx } = u;
          const { top, height } = u.bbox;
          ctx.save();
          let lastX = -1e9, level = 0;
          for (const d of S.decisions) {
            if (!d.mitigation_ts || d.mitigation_ts < u.scales.x.min) continue;
            const x = u.valToPos(d.mitigation_ts, "x", true);
            level = x - lastX < 70 * devicePixelRatio ? level + 1 : 0;   // stagger close labels
            lastX = x;
            ctx.strokeStyle = "#d03b3b"; ctx.lineWidth = 2 * devicePixelRatio;
            ctx.beginPath(); ctx.moveTo(x, top); ctx.lineTo(x, top + height); ctx.stroke();
            ctx.fillStyle = "#d03b3b";
            ctx.font = `600 ${10.5 * devicePixelRatio}px "IBM Plex Mono", monospace`;
            ctx.fillText(`${d.action === "BLOCK" ? "BLOCK" : "LIMIT"} ${NAME[d.src_ip]}`, x + 4 * devicePixelRatio,
              top + height - (6 + level * 14) * devicePixelRatio);
          }
          ctx.restore();
        },
      },
    };
  }
  function renderChart() {
    const box = $("traffic");
    const width = Math.max(300, box.clientWidth);
    if (!chart) {
      chart = new uPlot({
        width, height: 300, plugins: [bandsPlugin()],
        cursor: { points: { size: 8 }, drag: { x: false, y: false } },
        legend: { live: true },
        scales: { x: { time: true }, y: { distr: 3, range: (u, mn, mx) => [1, Math.max(100, mx * 1.6)] } },
        axes: [
          { stroke: "#898781", grid: { stroke: "#e1e0d9", width: 1 }, ticks: { stroke: "#c3c2b7" } },
          { stroke: "#898781", grid: { stroke: "#e1e0d9", width: 1 }, ticks: { stroke: "#c3c2b7" }, size: 56,
            values: (u, vals) => vals.map(v => rate(v)), label: "packets/s", labelSize: 18 },
        ],
        series: [{ value: (u, v) => v == null ? "–" : clock(v) },
          ...HOSTS.map((h, i) => ({ label: `${h.name} ${h.role}`, stroke: COLORS[i], width: 2, points: { show: false },
            value: (u, v) => v == null ? "–" : (v <= 1 ? "≤1" : rate(v)) }))],
      }, chartData(), box);
      new ResizeObserver(() => chart.setSize({ width: Math.max(300, box.clientWidth), height: 300 })).observe(box);
    } else {
      chart.setData(chartData());
    }
    const r = lastRound();
    if (r) {
      const flows = Object.entries(r.flows || {}).sort();
      const total = flows.reduce((s, [, n]) => s + n, 0);
      $("flows-line").replaceChildren(el("span", {}, "Forwarding rules in switches: ", el("b", { text: String(total) })),
        ...flows.map(([d, n]) => el("span", {}, `s${d} `, el("b", { text: String(n) }))));
    }
  }

  // ---------------------------------------------------------------- feed / side panels
  function feedRow(d, fresh) {
    const gates = d.gates || {};
    const gc = (id, ok) => el("i", { class: ok === false ? "x" : "", text: `${id}${ok === false ? "✕" : "✓"}` });
    const why = el("span", { class: "why" }, ...(d.explanation || []).flatMap((e, i) => [
      i ? " · " : "", el("b", { text: e.feature }), `=${num(e.value)} (${e.shap >= 0 ? "+" : ""}${e.shap.toFixed(2)})`]));
    return el("tr", { class: fresh ? "new" : "" },
      el("td", { class: "mono", text: clock(d.ts) }),
      el("td", {}, el("a", { href: "#", onclick: e => { e.preventDefault(); select(d.src_ip); }, text: NAME[d.src_ip] || d.src_ip })),
      el("td", {}, d.label, " ", el("span", { class: "mono", text: d.confidence.toFixed(2) })),
      el("td", {}, why),
      el("td", {}, Object.keys(gates).length ? el("span", { class: "gchips" }, gc("G1", gates.G1_limit), gc("G2", gates.G2), gc("G3", gates.G3), gc("G4", gates.G4)) : "–"),
      el("td", {}, already(d)
        ? [el("span", { class: "pill " + d.active, text: "ALREADY " + (d.active === "BLOCK" ? "BLOCKED" : "LIMITED") }),
           el("div", { class: "why", text: "rule still active" })]
        : [el("span", { class: "pill " + d.action, text: d.action === "NONE" ? "none" : ACTION_TEXT[d.action] }),
           el("div", { class: "why", text: d.reason })]));
  }
  function renderFeed(full) {
    const body = $("feed");
    const list = S.decisions.slice(-80).reverse();
    $("feed-empty").hidden = list.length > 0;
    if (full) { body.replaceChildren(...list.map(d => feedRow(d, false))); return; }
    body.prepend(feedRow(list[0], true));
    while (body.children.length > 80) body.lastChild.remove();
  }

  function renderMitigations() {
    const box = $("mitig");
    const entries = Object.entries(S.mitigations);
    if (!entries.length) {
      box.replaceChildren(el("p", { class: "empty", text: "No host is blocked or rate-limited right now." }));
      return;
    }
    const elapsed = (Date.now() - (S.mitReceived || Date.now())) / 1000;
    box.replaceChildren(...entries.map(([ip, m]) => el("div", { class: "row" },
      el("span", { class: "pill " + m.action, text: ACTION_TEXT[m.action] }),
      el("span", {}, `${NAME[ip] || ip} `, el("span", { class: "mono why", text: ip })),
      el("span", { class: "count", text: `${Math.max(0, m.expires_in - elapsed).toFixed(0)} s left` }),
      S.authed ? el("button", { class: "btn", onclick: () => release(ip), text: "Release now" }) : el("span"),
    )));
  }

  function renderEpisodes() {
    const rows = S.episodes.slice(-12).reverse();
    $("ep-empty").hidden = rows.length > 0;
    $("episodes").replaceChildren(...rows.map(ep => {
      let result;
      if (ep.type === "heavy_benign") {
        result = ep.action ? el("span", { class: "pill BLOCK", text: "WRONGLY MITIGATED" })
          : el("span", { class: "pill ok", text: ep.status === "running" ? "not blocked" : "correctly ignored" });
      } else if (ep.action) {
        result = el("span", { class: "pill " + ep.action, text: ACTION_TEXT[ep.action] });
      } else {
        result = el("span", { class: "pill", text: ep.status === "running" ? "running" : ep.detected_s != null ? "detected only" : "not detected" });
      }
      const s = v => v == null ? "–" : `${v.toFixed(1)} s`;
      return el("tr", {},
        el("td", { class: "mono", text: clock(ep.start) }),
        el("td", {}, `${TYPES[ep.type] || ep.type} `, el("span", { class: "why", text: `${ep.src}→${ep.dst} · ${ep.duration}s · ${ep.status}` })),
        el("td", { class: "num", text: ep.type === "heavy_benign" ? "–" : s(ep.detected_s) }),
        el("td", { class: "num", text: s(ep.mitigated_s) }),
        el("td", {}, result));
    }));
  }

  function renderControls() {
    $("locked").hidden = S.authed;
    $("controls").hidden = !S.authed;
    $("auth-btn").textContent = S.authed ? "Sign out" : "Sign in";
    $("protect").disabled = !S.authed;
    $("c-demo").disabled = S.demoRunning;
    $("c-demo").textContent = S.demoRunning ? "Guided demo running…" : "Run guided demo";
  }

  function renderSide() { renderMitigations(); renderEpisodes(); renderControls(); }
  function renderAll() { renderChips(); renderTopo(); renderChart(); renderSide(); }

  // ---------------------------------------------------------------- actions
  function say(text, err = false) { const m = $("c-msg"); m.textContent = text; m.className = "msg" + (err ? " err" : ""); }
  async function release(ip) {
    try { await api(`/api/release/${ip}`, { method: "POST" }); say(`Released ${NAME[ip]}. Traffic from it is forwarded again.`); }
    catch (e) { say(e.message, true); }
  }
  function setupControls() {
    const t = $("c-type"), s = $("c-src"), d = $("c-dst");
    Object.entries(TYPES).forEach(([k, v]) => t.append(el("option", { value: k, text: v })));
    HOSTS.forEach(h => { s.append(el("option", { value: h.name, text: `${h.name} · ${h.role}` })); d.append(el("option", { value: h.name, text: `${h.name} · ${h.role}` })); });
    s.value = "h4"; d.value = "h5";
    $("c-launch").onclick = async () => {
      try {
        const ep = await api("/api/attack", { method: "POST", body: { type: t.value, src: s.value, dst: d.value, duration: +$("c-dur").value } });
        say(`Launched ${TYPES[ep.type]} from ${ep.src} to ${ep.dst} for ${ep.duration} s.`);
        if (S.follow) select(HOSTS.find(h => h.name === ep.src).ip);
      } catch (e) { say(e.message, true); }
    };
    $("c-demo").onclick = async () => {
      try { const r = await api("/api/demo", { method: "POST" }); say(`Guided demo started: ${r.steps.length} episodes of ${r.duration} s each.`); }
      catch (e) { say(e.message, true); }
    };
    $("c-stop").onclick = async () => {
      try { const r = await api("/api/stop", { method: "POST" }); say(`Stopped ${r.stopped} running episode(s).`); }
      catch (e) { say(e.message, true); }
    };
    $("protect").onclick = async () => {
      const next = S.status.mode === "detect" ? "monitor" : "detect";
      try { await api("/api/mode", { method: "POST", body: { mode: next } }); S.status.mode = next; refreshHeader(); }
      catch (e) { say(e.message, true); }
    };
    $("follow").onchange = e => { S.follow = e.target.checked; };
  }

  function setupAuth() {
    const dlg = $("login");
    const open = () => { $("pw").value = ""; $("pw-msg").textContent = ""; dlg.showModal(); };
    $("auth-btn").onclick = async () => {
      if (S.authed) { await api("/api/logout", { method: "POST" }); S.authed = false; renderSide(); refreshHeader(); }
      else open();
    };
    document.querySelectorAll("[data-signin]").forEach(b => b.onclick = open);
    $("pw-cancel").onclick = () => dlg.close();
    $("login-form").onsubmit = async e => {
      e.preventDefault();
      try {
        await api("/api/login", { method: "POST", body: { password: $("pw").value } });
        S.authed = true; dlg.close(); renderSide(); refreshHeader();
      } catch (err) { $("pw-msg").textContent = err.message; }
    };
    api("/api/me").then(r => { S.authed = r.authenticated; renderSide(); refreshHeader(); }).catch(() => {});
  }

  // ---------------------------------------------------------------- results tab
  async function loadResults() {
    if (S.resultsLoaded) return;
    S.resultsLoaded = true;
    const r = await api("/api/results");
    const f = v => (+v).toFixed(3);
    const table = (id, head, rows, numCols, bestRow) => {
      $(id).replaceChildren(
        el("thead", {}, el("tr", {}, ...head.map((h, i) => el("th", { class: numCols.includes(i) ? "num" : "", text: h })))),
        el("tbody", {}, ...rows.map((row, ri) => el("tr", { class: ri === bestRow ? "best" : "" },
          ...row.map((c, i) => el("td", { class: numCols.includes(i) ? "num" : "", text: c }))))));
    };
    table("r-models", ["Model", "Accuracy", "Precision", "Recall", "F1", "FPR", "FNR"],
      r.models.map(m => [m.model, f(m.accuracy), f(m.precision), f(m.recall), f(m.f1), f(m.fpr), f(m.fnr)]), [1, 2, 3, 4, 5, 6], 0);
    table("r-class", ["Class", "Precision", "Recall", "F1", "Windows"],
      r.per_class.map(c => [c.class, f(c.precision), f(c.recall), f(c.f1), c.support]), [1, 2, 3, 4], -1);
    const innocent = src => (src || "").split(" ").filter(ip => ip && !["10.0.0.4", "10.0.0.7"].includes(ip));
    table("r-ablation", ["Policy", "Innocent hosts hit", "Attacks stopped", "Time to mitigate"],
      r.ablation.map(a => [a.variant, innocent(a.sources).map(ip => NAME[ip]).join(", ") || "none",
        a.attacks_mitigated, `${(+a.mean_time_to_mitigate_s).toFixed(1)} s`]), [3], -1);
  }
  function setupTabs() {
    document.querySelectorAll("[data-tab]").forEach(b => b.onclick = () => {
      document.querySelectorAll("[data-tab]").forEach(x => x.setAttribute("aria-selected", String(x === b)));
      $("tab-live").hidden = b.dataset.tab !== "live";
      $("tab-results").hidden = b.dataset.tab !== "results";
      history.replaceState(null, "", b.dataset.tab === "results" ? "#results" : location.pathname);
      if (b.dataset.tab === "results") loadResults().catch(() => { S.resultsLoaded = false; });
      else { renderChart(); renderRail(S.view); }
    });
  }

  // ---------------------------------------------------------------- boot
  setupControls(); setupAuth(); setupTabs();
  if (location.hash === "#results") document.querySelector('[data-tab="results"]').click();
  renderChips(); renderTopo(); renderPipeline(); renderSide();
  connect();
  setInterval(renderMitigations, 1000);
  addEventListener("resize", () => renderRail(S.view));
})();
