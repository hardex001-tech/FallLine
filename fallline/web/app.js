"use strict";
// All scan data is inserted with textContent (never innerHTML): banners and
// titles come from the network and must be treated as untrusted.
const $ = (id) => document.getElementById(id);
const state = {
  demo: false,
  data: null,
  simKeys: new Set(),
  simMode: false,
  angles: [],
  steps: [],
  color: "#f85149",
  hasAutoPlayed: false,
};

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
  const r = await fetch(path, opt);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || r.statusText);
  return j;
}

function say(msg) {
  const m = $("message");
  if (!m) return;
  m.textContent = msg;
  m.classList.toggle("hidden", !msg);
}

const perspective = () => $("perspective").value;

async function refresh() {
  try {
    state.data = state.simMode
      ? await api("/api/simulate", { fixed: [...state.simKeys], perspective: perspective() })
      : await api("/api/state?perspective=" + perspective());
  } catch (e) {
    say("Error: " + e.message);
    return;
  }
  render();
}

function copyCommand(cmd, btn) {
  if (!cmd) return;
  const prev = btn.textContent;
  if (typeof navigator !== "undefined" && navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(cmd).catch(() => {});
  }
  btn.textContent = "Copied!";
  say("Copied remediation command: " + cmd);
  setTimeout(() => {
    btn.textContent = prev;
  }, 1400);
}

function render() {
  const d = state.data;
  if (!d) return;

  $("sim-banner").classList.toggle("hidden", !state.simMode);
  $("report-link").href = "/api/report?perspective=" + perspective();
  if ($("pdf-link")) $("pdf-link").href = "/api/report.pdf?perspective=" + perspective();
  if ($("sarif-link")) $("sarif-link").href = "/api/report.sarif?perspective=" + perspective();
  if ($("csv-link")) $("csv-link").href = "/api/report.csv?perspective=" + perspective();

  // Summary cards
  const totalCount = d.records ? d.records.length : (d.counts.open + d.counts.fixed_verified + d.counts.accepted_risk);
  if ($("stat-total")) $("stat-total").textContent = String(totalCount);
  if ($("stat-open")) {
    $("stat-open").textContent = String(d.counts.open);
    $("stat-open").className = "mono " + (d.counts.open > 0 ? "val-red" : "val-green");
  }
  if ($("stat-fixed")) $("stat-fixed").textContent = String(d.counts.fixed_verified);
  if ($("stat-accepted")) $("stat-accepted").textContent = String(d.counts.accepted_risk);

  const ttc = $("ttc");
  const isSafe = d.ttc_minutes === null && (d.counts.open > 0 || d.counts.fixed_verified > 0);
  ttc.textContent = d.ttc_minutes === null
    ? (d.counts.open || d.counts.fixed_verified ? "No path (blocked)" : "No scan data")
    : d.ttc_human;
  ttc.className = "mono ttc" + (isSafe ? " safe" : "") + (state.simMode ? " sim" : "");

  if ($("sys-engine")) {
    $("sys-engine").textContent = state.simMode
      ? "What-if simulation"
      : `Active (${perspective()})`;
    $("sys-engine").className = "mono " + (state.simMode ? "val-amber" : "val-green");
  }
  if ($("sys-fixes")) {
    $("sys-fixes").textContent = d.fix_plan.length
      ? `${d.fix_plan.length} priority fix${d.fix_plan.length > 1 ? "es" : ""}`
      : "0 (path blocked)";
    $("sys-fixes").className = "mono " + (d.fix_plan.length ? "val-amber" : "val-green");
  }

  $("ttc-sub").textContent = `${d.counts.open} open · ${d.counts.fixed_verified} verified fixed · ${d.counts.accepted_risk} accepted`;

  if ($("live-intel")) {
    $("live-intel").textContent = d.intel.available
      ? `KEV/EPSS (${d.intel.kev_entries} KEV)`
      : "Offline rules";
    $("live-intel").className = "mono " + (d.intel.available ? "val-green" : "val-blue");
  }

  // Attack path status line
  const surv = $("hud-surveillance-status");
  if (surv) {
    if (state.simMode) {
      surv.textContent = `Simulated breach time: ${ttc.textContent}`;
      surv.className = "path-status-text sim";
    } else if (d.ttc_minutes !== null) {
      surv.textContent = `Active path found — estimated time to compromise: ${d.ttc_human}`;
      surv.className = "path-status-text threat";
    } else if (d.baseline_path && d.baseline_path.length) {
      surv.textContent = "Attack chain blocked — verified by re-scan";
      surv.className = "path-status-text safe";
    } else {
      surv.textContent = "Ready — run a scan to compute shortest path";
      surv.className = "path-status-text";
    }
  }

  const ba = $("before-after");
  ba.replaceChildren();
  const mk = (label, val) => {
    const b = el("div", undefined, "box");
    b.append(el("span", label + ":", "muted"), el("strong", val));
    return b;
  };
  if (d.counts.fixed_verified || state.simMode) {
    ba.append(
      mk("Baseline", d.baseline_ttc_human),
      el("span", "\u2192"),
      mk(state.simMode ? "Simulated" : "Verified", d.ttc_minutes === null ? "No path" : d.ttc_human)
    );
  }

  drawPath(d);
  renderStory(d);
  renderPlan(d);
  renderTable(d);
  renderMitre(d);
  loadSnapshots();

  if (!state.hasAutoPlayed && state.steps.length && state.color !== "#3fb950") {
    state.hasAutoPlayed = true;
    setTimeout(() => play(), 250);
  }
}

let animating = false;
let animGen = 0;

function layoutDominoes(c, n) {
  const cw = c ? c.width : 1120;
  const w = n > 7 ? Math.max(28, Math.floor(340 / n)) : 44;
  const h = 112;
  const minStartX = 140;
  const maxLastX = cw - 210 - w;
  const idealSpan = (n - 1) * 165;
  const startX = n <= 1
    ? Math.floor((cw - w) / 2)
    : Math.max(minStartX, Math.min(280, Math.floor((cw - idealSpan - w) / 2)));
  const availSpan = Math.max(60, maxLastX - startX);
  const gap = n > 1 ? Math.min(210, availSpan / (n - 1)) : 0;
  const lastX = startX + (n - 1) * gap;
  const attX = Math.max(68, startX - 85);
  const goalX = Math.min(cw - 62, Math.max(lastX + w + 138, cw / 2 + 160));
  return { startX, gap, w, h, lastX, attX, goalX };
}

function drawPath(d) {
  animGen++;
  animating = false;
  let steps = d.path;
  let color = state.simMode ? "#d29922" : "#f85149";
  let cap = "";
  if (!steps.length && d.baseline_path.length) {
    steps = d.baseline_path;
    color = "#3fb950";
    cap = "Path blocked" + (state.simMode ? " (simulated)" : " (verified by re-scan)");
  } else if (steps.length) {
    cap = `${steps.length} step${steps.length > 1 ? "s" : ""} from entry to target data`;
  }
  state.steps = steps;
  state.color = color;
  state.angles = steps.map(() => 0);
  $("path-caption").textContent = cap;
  paint();
}

const trunc = (t, n) => (t && t.length > n ? t.slice(0, n - 1) + "\u2026" : (t || ""));

function paint() {
  const c = $("dominoes");
  if (!c) return;
  const g = c.getContext("2d");
  g.clearRect(0, 0, c.width, c.height);

  const steps = state.steps;
  if (!steps.length) {
    g.save();
    g.fillStyle = "#8b949e";
    g.font = '13px -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif';
    g.textAlign = "center";
    g.fillText("No active attack path — run a scan or select another perspective", c.width / 2, c.height / 2);
    g.restore();
    return;
  }

  const baseY = 165;
  // Clean matte baseline track
  g.save();
  g.strokeStyle = "#30363d";
  g.lineWidth = 1.5;
  g.beginPath();
  g.moveTo(40, baseY);
  g.lineTo(c.width - 40, baseY);
  g.stroke();
  g.restore();

  const n = steps.length;
  const { startX, gap, w, h, lastX, attX, goalX } = layoutDominoes(c, n);

  // Left marker: Entry
  g.save();
  g.fillStyle = "#161b22";
  g.strokeStyle = "#30363d";
  g.lineWidth = 1.5;
  g.beginPath();
  g.arc(attX, baseY - 46, 22, 0, Math.PI * 2);
  g.fill();
  g.stroke();
  g.fillStyle = "#e6edf3";
  g.font = '600 10px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
  g.textAlign = "center";
  g.fillText("Entry", attX, baseY - 43);
  g.fillStyle = "#8b949e";
  g.font = '10px "JetBrains Mono", Consolas, monospace';
  g.fillText(perspective(), attX, baseY - 10);
  g.restore();

  // Right marker: Target Data
  const goalSafe = state.color === "#3fb950";
  const goalCol = goalSafe ? "#3fb950" : "#58a6ff";
  g.save();
  g.fillStyle = "#161b22";
  g.strokeStyle = goalCol;
  g.lineWidth = 1.5;
  g.beginPath();
  g.arc(goalX, baseY - 46, 24, 0, Math.PI * 2);
  g.fill();
  g.stroke();
  g.fillStyle = "#e6edf3";
  g.font = '600 10px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
  g.textAlign = "center";
  g.fillText("Target", goalX, baseY - 49);
  g.fillText("Data", goalX, baseY - 37);
  g.fillStyle = goalCol;
  g.font = '10px "JetBrains Mono", Consolas, monospace';
  g.fillText(goalSafe ? "protected" : "at risk", goalX, baseY - 10);
  g.restore();

  // Subtle dashed connectors anchored to current domino edge positions
  const firstRad = ((state.angles[0] || 0) * Math.PI) / 180;
  const firstLeftX = startX + w - w * Math.cos(firstRad) + (h / 2) * Math.sin(firstRad);
  const firstLeftY = baseY - w * Math.sin(firstRad) - (h / 2) * Math.cos(firstRad);
  const lastRad = ((state.angles[n - 1] || 0) * Math.PI) / 180;
  const lastRightX = lastX + w + (h / 2) * Math.sin(lastRad);
  const lastRightY = baseY - (h / 2) * Math.cos(lastRad);

  g.save();
  g.setLineDash([4, 4]);
  g.strokeStyle = "#30363d";
  g.lineWidth = 1;
  g.beginPath();
  g.moveTo(attX + 24, baseY - 46);
  g.lineTo(firstLeftX, firstLeftY);
  g.stroke();
  g.beginPath();
  g.moveTo(lastRightX, lastRightY);
  g.lineTo(goalX - 26, baseY - 46);
  g.stroke();
  g.restore();

  const maxChars = n > 1 ? Math.max(15, Math.min(26, Math.floor(gap / 5.2))) : 26;
  const lblFontPx = n >= 7 ? 10 : 11;

  // Render clean matte domino cards
  steps.forEach((s, i) => {
    const x = startX + i * gap;
    const a = state.angles[i] || 0;
    const techId = (s.technique || "").split(" ")[0] || `Step ${i + 1}`;

    // MITRE technique ID above domino
    g.save();
    g.fillStyle = "#8b949e";
    g.font = '10px "JetBrains Mono", Consolas, monospace';
    g.textAlign = "center";
    g.fillText(techId, x + w / 2, baseY - h - 10);
    g.restore();

    // Rotated domino card
    g.save();
    g.translate(x + w, baseY);
    g.rotate((a * Math.PI) / 180);
    g.translate(-w, 0);

    // Matte card body with 1.5px semantic border
    g.fillStyle = "#161b22";
    g.strokeStyle = state.color;
    g.lineWidth = 1.5;
    g.beginPath();
    g.roundRect(0, -h, w, h, 4);
    g.fill();
    g.stroke();

    // Subtle top color bar on domino
    g.fillStyle = state.color;
    g.fillRect(2, -h + 2, w - 4, 4);

    // Center divider line
    g.strokeStyle = "#30363d";
    g.lineWidth = 1;
    g.beginPath();
    g.moveTo(5, -h / 2);
    g.lineTo(w - 5, -h / 2);
    g.stroke();

    // Top half: step index
    g.fillStyle = "#e6edf3";
    g.font = '600 11px "JetBrains Mono", Consolas, monospace';
    g.textAlign = "center";
    g.fillText(String(i + 1), w / 2, -h + 26);

    g.fillStyle = "#8b949e";
    g.font = '9px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
    g.fillText((s.kind || "step").slice(0, 6), w / 2, -h + 42);

    // Bottom half: effort minutes
    g.fillStyle = "#e6edf3";
    g.font = '600 10px "JetBrains Mono", Consolas, monospace';
    g.fillText(`${Math.round(s.minutes)}m`, w / 2, -24);
    g.fillStyle = "#8b949e";
    g.font = '9px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
    g.fillText("est.", w / 2, -10);

    g.restore();

    // Clean labels below the baseline
    const where = s.port ? `${s.host}:${s.port}` : s.host;
    g.save();
    g.font = `600 ${lblFontPx}px "JetBrains Mono", Consolas, monospace`;
    g.fillStyle = "#e6edf3";
    g.fillText(trunc(where, maxChars), x - 6, baseY + 18);

    g.font = `${lblFontPx}px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`;
    g.fillStyle = "#8b949e";
    g.fillText(trunc(s.title, maxChars), x - 6, baseY + 34);

    g.font = '10px "JetBrains Mono", Consolas, monospace';
    g.fillStyle = state.color;
    g.fillText(trunc(`~${Math.round(s.minutes)}m (${s.from}\u2192${s.to})`, maxChars), x - 6, baseY + 49);
    g.restore();
  });
}

function play() {
  if (animating || !state.steps.length || state.color === "#3fb950") return;
  const myGen = ++animGen;
  animating = true;
  state.angles = state.steps.map(() => 0);
  let i = 0;

  const tick = () => {
    if (myGen !== animGen) return;
    if (i < state.steps.length) {
      state.angles[i] += 6;
      if (state.angles[i] >= 72) {
        state.angles[i] = 72;
        i++;
      }
    }
    paint();
    if (i < state.steps.length) {
      requestAnimationFrame(tick);
    } else {
      animating = false;
    }
  };
  requestAnimationFrame(tick);
}

function renderStory(d) {
  const ol = $("story");
  ol.replaceChildren();
  if (!d.path.length) {
    const li = el("li");
    li.style.borderLeftColor = "#3fb950";
    li.textContent = d.counts.open
      ? "No complete attack path reaches target data from this perspective."
      : "No active path steps. Run a scan to populate findings.";
    ol.append(li);
    return;
  }
  d.path.forEach((s, idx) => {
    const li = el("li");
    const head = el(
      "span",
      `Step ${idx + 1} · ${s.technique} (~${Math.round(s.minutes)} min)`,
      "step-head"
    );
    const hostLine = el(
      "div",
      `${s.from} \u2192 ${s.to}${s.port ? " (port " + s.port + ")" : ""}: ${s.title}`,
      "step-host"
    );
    const whyLine = el("div", s.why || "Post-exploitation data access on controlled host.", "muted");
    li.append(head, hostLine, whyLine);
    ol.append(li);
  });
}

function renderPlan(d) {
  const box = $("plan");
  box.replaceChildren();
  if (!d.fix_plan.length) {
    box.append(
      el(
        "p",
        d.counts.open
          ? "Attack path blocked — no remaining choke-point fixes required."
          : "No findings yet.",
        "muted"
      )
    );
    return;
  }
  d.fix_plan.forEach((p, i) => {
    const item = el("div", undefined, "plan-item");
    const headB = el("b");
    headB.append(
      el("span", `${i + 1}. ${p.title} on `),
      el("span", `${p.host}${p.port ? ":" + p.port : ""}`, "mono"),
      el("span", " ("),
      el("span", p.technique, "tech-badge"),
      el("span", ")")
    );
    item.append(headB);
    item.append(el("div", p.remediation));
    if (p.fix_command) {
      const cmdBox = el("div", undefined, "cmd-box");
      const cmdCode = el("code", p.fix_command, "cmd-text");
      const copyBtn = el("button", "Copy Command", "secondary btn-sm copy-btn");
      copyBtn.onclick = () => copyCommand(p.fix_command, copyBtn);
      cmdBox.append(cmdCode, copyBtn);
      item.append(cmdBox);
    }
    item.append(
      el(
        "div",
        `Est. fix time: ~${Math.round(p.fix_minutes)} min · Breach time after fix: ` +
          (p.ttc_after === null ? "No path (blocks chain)" : `~${Math.round(p.ttc_after)} min`),
        "muted"
      )
    );
    const act = el("div", undefined, "actions");
    if (!state.simMode) {
      const v = el("button", "Verify fix (re-scan)", "btn-sm");
      const msg = el("span", "", "vmsg");
      if (state.demo) {
        const d2 = el("button", "Apply demo patch", "secondary btn-sm");
        d2.onclick = async () => {
          await api("/api/demo/fix", { key: p.key });
          msg.textContent = "Demo patch applied — click Verify fix to re-scan.";
        };
        act.append(d2);
      }
      v.onclick = () => verify(p.key, v, msg);
      act.append(v, msg);
    }
    item.append(act);
    box.append(item);
  });
}

async function verify(key, btn, msg) {
  btn.disabled = true;
  if (msg) msg.textContent = "Re-scanning single port/check...";
  try {
    const r = await api("/api/verify", { key });
    say(r.message);
    await refresh();
  } catch (e) {
    if (msg) msg.textContent = e.message;
  }
  btn.disabled = false;
}

function renderTable(d) {
  const tb = document.querySelector("#findings tbody");
  tb.replaceChildren();
  d.records.forEach((r) => {
    const tr = el("tr");

    // 1. SIM checkbox
    const sim = el("td");
    if (r.status === "OPEN" && r.classified) {
      const cb = el("input");
      cb.type = "checkbox";
      cb.checked = state.simKeys.has(r.key);
      cb.title = "Include in what-if simulation";
      cb.onchange = () => (cb.checked ? state.simKeys.add(r.key) : state.simKeys.delete(r.key));
      sim.append(cb);
    }

    // 2. Host
    const hostTd = el("td", r.host, "col-host");

    // 3. Port
    const portTd = el("td", r.port ? String(r.port) : "-", "col-port");

    // 4. Protocol / Service
    const protoText = `${(r.protocol || "tcp").toUpperCase()}${r.service ? " / " + r.service : ""}`;
    const protoTd = el("td", protoText, "col-proto");

    // 5. Status
    let statusLabel = "Open";
    if (r.status === "OPEN") {
      statusLabel = `Open (${(r.severity || "info").toUpperCase()})`;
    } else if (r.status === "FIXED_VERIFIED") {
      statusLabel = "Verified Fixed";
    } else if (r.status === "ACCEPTED_RISK") {
      statusLabel = "Accepted Risk";
    } else {
      statusLabel = (r.status || "").replace(/_/g, " ");
    }
    const statusTd = el("td", statusLabel, "st-" + r.status);

    // 6. Finding / MITRE ATT&CK
    const prodSuffix = r.product ? ` (${r.product}${r.version ? " " + r.version : ""})` : "";
    const noteSuffix = r.note ? ` \u2014 ${r.note}` : "";
    const expTd = el("td");
    if (r.technique && r.technique !== "-") {
      expTd.append(el("span", `[${r.technique.split(" ")[0]}]`, "tech-badge"), el("span", " "));
    }
    expTd.append(el("span", `${r.title}${prodSuffix}${noteSuffix}`));

    // 7. Actions
    const act = el("td");
    const actWrap = el("div", undefined, "row");
    actWrap.style.margin = "0";
    if (r.status === "OPEN") {
      if (r.fix_command) {
        const copyBtn = el("button", "Copy Cmd", "secondary btn-sm");
        copyBtn.title = r.fix_command;
        copyBtn.onclick = () => copyCommand(r.fix_command, copyBtn);
        actWrap.append(copyBtn);
      }
      if (state.demo) {
        const cp = el("button", "Close Port", "secondary btn-sm");
        cp.title = "Demo: close port / patch check in fake network";
        cp.onclick = async () => {
          cp.disabled = true;
          try {
            await api("/api/demo/fix", { key: r.key });
            say("Demo patch applied — click Verify to re-scan.");
          } catch (e) {
            say(e.message);
          }
          cp.disabled = false;
        };
        actWrap.append(cp);
      }
      const vBtn = el("button", "Verify", "btn-sm");
      vBtn.title = "Re-scan this single port/check to verify remediation";
      vBtn.onclick = () => verify(r.key, vBtn);
      actWrap.append(vBtn);
      if (state.demo && r.classified) {
        const dp = el("button", "Patch+Verify", "secondary btn-sm");
        dp.title = "Demo shortcut: patch in fake lab and immediately run single-finding verification";
        dp.onclick = async () => {
          dp.disabled = true;
          try {
            await api("/api/demo/fix", { key: r.key });
            const vr = await api("/api/verify", { key: r.key });
            say(vr.message);
            await refresh();
          } catch (e) {
            say(e.message);
          }
          dp.disabled = false;
        };
        actWrap.append(dp);
      }
      const a = el("button", "Accept", "secondary btn-sm");
      a.onclick = async () => {
        const reason = prompt("Why is this risk accepted? (required for audit log)");
        if (!reason) return;
        try {
          await api("/api/accept", { key: r.key, reason });
          await refresh();
        } catch (e) {
          say(e.message);
        }
      };
      actWrap.append(a);
    } else {
      const o = el("button", "Reopen", "secondary btn-sm");
      o.onclick = async () => {
        await api("/api/reopen", { key: r.key });
        await refresh();
      };
      actWrap.append(o);
    }
    act.append(actWrap);

    tr.append(sim, hostTd, portTd, protoTd, statusTd, expTd, act);
    tb.append(tr);
  });
}

function renderMitre(d) {
  const grid = $("mitre-matrix");
  if (!grid || !d.mitre_matrix) return;
  grid.replaceChildren();
  let activeTactics = 0;
  let openTotal = 0;
  d.mitre_matrix.forEach((col) => {
    if (col.open_count > 0) activeTactics++;
    openTotal += col.open_count;
    const card = el(
      "div",
      undefined,
      "mitre-col" + (col.open_count > 0 ? " has-open" : col.fixed_count > 0 ? " all-fixed" : "")
    );
    const head = el("div", undefined, "mitre-col-head");
    const countTxt = col.accepted_count > 0
      ? `${col.open_count} open · ${col.fixed_count} fixed · ${col.accepted_count} acc`
      : `${col.open_count} open · ${col.fixed_count} fixed`;
    head.append(
      el("span", col.tactic, "mitre-tactic-name"),
      el("span", countTxt, "mitre-counts")
    );
    card.append(head);

    if (!col.findings.length) {
      card.append(el("span", `${col.rules_count} rules monitored · 0 findings`, "muted"));
    } else {
      col.findings.slice(0, 5).forEach((f) => {
        const chipCls = f.status === "OPEN"
          ? "chip-open"
          : f.status === "ACCEPTED_RISK"
            ? "chip-accepted"
            : "chip-fixed";
        const chip = el("div", undefined, "mitre-finding-chip " + chipCls);
        chip.append(
          el("span", `[${f.technique_id}] `, "tech-badge"),
          el("span", `${f.title} (${f.host}${f.port ? ":" + f.port : ""})`)
        );
        card.append(chip);
      });
      if (col.findings.length > 5) {
        card.append(el("span", `+${col.findings.length - 5} more in this tactic`, "muted"));
      }
    }
    grid.append(card);
  });
  if ($("mitre-summary")) {
    $("mitre-summary").textContent = `${activeTactics} of ${d.mitre_matrix.length} tactics with open exposures (${openTotal} open findings)`;
  }
}

async function loadSnapshots() {
  const sel = $("snapshot-select");
  if (!sel) return;
  const targetSel = $("snapshot-target-select");
  try {
    const res = await api("/api/snapshots");
    const snaps = res.snapshots || [];
    const currentVal = sel.value;
    const currentTargetVal = targetSel ? targetSel.value : "";
    sel.replaceChildren();
    if (targetSel) {
      targetSel.replaceChildren();
      const curOpt = el("option", "Current State");
      curOpt.value = "";
      targetSel.append(curOpt);
    }
    if (!snaps.length) {
      const opt = el("option", "No snapshots saved");
      opt.value = "";
      sel.append(opt);
      return;
    }
    snaps.forEach((s) => {
      const label = `#${s.id} ${s.name} (open: ${s.counts.open}, ext TTC: ${s.ttc_external === null ? "blocked" : s.ttc_external + "m"})`;
      const opt = el("option", label);
      opt.value = String(s.id);
      sel.append(opt);
      if (targetSel) {
        const topt = el("option", label);
        topt.value = String(s.id);
        targetSel.append(topt);
      }
    });
    const chosen = snaps.some((s) => String(s.id) === currentVal) ? currentVal : String(snaps[0].id);
    sel.value = chosen;
    const chosenTarget = targetSel && snaps.some((s) => String(s.id) === currentTargetVal) ? currentTargetVal : "";
    if (targetSel) targetSel.value = chosenTarget;
    await runSnapshotDiff(chosen, chosenTarget);
  } catch (_) {
    // Ignore snapshot fetch errors during offline/mock runs
  }
}

async function runSnapshotDiff(baseId, targetId) {
  const view = $("snapshot-diff-view");
  if (!view || !baseId) return;
  try {
    let url = "/api/snapshots/diff?base_id=" + encodeURIComponent(baseId);
    if (targetId) {
      url += "&target_id=" + encodeURIComponent(targetId);
    }
    const diff = await api(url);
    if (!diff || !diff.base) return;
    view.replaceChildren();

    const metrics = el("div", undefined, "diff-metrics");
    const mkCard = (title, body, cls) => {
      const c = el("div", undefined, "diff-card");
      c.append(el("div", title, "muted"), el("strong", body, "mono " + (cls || "")));
      return c;
    };
    const extDeltaTxt = diff.path_blocked_external
      ? "Path blocked!"
      : diff.ttc_external_delta !== null
        ? (diff.ttc_external_delta >= 0 ? `+${diff.ttc_external_delta}m` : `${diff.ttc_external_delta}m`)
        : "n/a";
    const intDeltaTxt = diff.path_blocked_internal
      ? "Path blocked!"
      : diff.ttc_internal_delta !== null
        ? (diff.ttc_internal_delta >= 0 ? `+${diff.ttc_internal_delta}m` : `${diff.ttc_internal_delta}m`)
        : "n/a";
    metrics.append(
      mkCard(
        "External TTC (Before \u2192 After)",
        `${diff.base.ttc_external_human} \u2192 ${diff.target.ttc_external_human} (${extDeltaTxt})`,
        diff.path_blocked_external || (diff.ttc_external_delta || 0) > 0 ? "val-green" : ""
      ),
      mkCard(
        "Internal TTC (Before \u2192 After)",
        `${diff.base.ttc_internal_human} \u2192 ${diff.target.ttc_internal_human} (${intDeltaTxt})`,
        diff.path_blocked_internal || (diff.ttc_internal_delta || 0) > 0 ? "val-green" : ""
      ),
      mkCard(
        "Domino Chain Length",
        `${diff.chain_length_before} \u2192 ${diff.chain_length_after} steps (${diff.chain_length_delta >= 0 ? "+" : ""}${diff.chain_length_delta})`
      ),
      mkCard(
        "Finding Deltas",
        `+${diff.counts_diff.new} new · -${diff.counts_diff.fixed} fixed · ${diff.counts_diff.accepted} accepted`,
        diff.counts_diff.fixed > 0 ? "val-green" : ""
      )
    );
    view.append(metrics);

    const hasFixed = diff.fixed_findings && diff.fixed_findings.length > 0;
    const hasNew = diff.new_findings && diff.new_findings.length > 0;
    const hasAccepted = diff.accepted_findings && diff.accepted_findings.length > 0;
    if (hasFixed || hasNew || hasAccepted) {
      const lists = el("div", undefined, "diff-lists");
      const fixedCol = el("div", undefined, "diff-list-col");
      fixedCol.append(el("b", `Resolved & Verified (-${(diff.fixed_findings || []).length})`));
      if (!hasFixed) {
        fixedCol.append(el("div", "No findings verified fixed since this snapshot.", "muted"));
      } else {
        diff.fixed_findings.forEach((f) => {
          fixedCol.append(el("div", `\u2713 ${f.title} on ${f.host}:${f.port || "-"}`, "val-green mono"));
        });
      }
      const newCol = el("div", undefined, "diff-list-col");
      newCol.append(el("b", `Newly Introduced (+${(diff.new_findings || []).length})`));
      if (!hasNew) {
        newCol.append(el("div", "No new exposures introduced since this snapshot.", "muted"));
      } else {
        diff.new_findings.forEach((f) => {
          newCol.append(el("div", `+ ${f.title} on ${f.host}:${f.port || "-"}`, "val-red mono"));
        });
      }
      const accCol = el("div", undefined, "diff-list-col");
      accCol.append(el("b", `Accepted Risk (${(diff.accepted_findings || []).length})`));
      if (!hasAccepted) {
        accCol.append(el("div", "No risk-accepted findings in target state.", "muted"));
      } else {
        diff.accepted_findings.forEach((f) => {
          accCol.append(el("div", `~ ${f.title} on ${f.host}:${f.port || "-"}`, "val-amber mono"));
        });
      }
      lists.append(fixedCol, newCol, accCol);
      view.append(lists);
    }
  } catch (e) {
    say(e.message);
  }
}

function renderDiscoveredHosts(res) {
  const box = $("discovered-hosts");
  if (!box) return;
  box.replaceChildren();
  const hosts = res.hosts || [];
  box.classList.toggle("hidden", false);
  const header = el(
    "div",
    `Discovered ${hosts.length} live host${hosts.length === 1 ? "" : "s"} on ${res.target} (${res.engine}):`,
    "muted"
  );
  box.append(header);
  hosts.forEach((h) => {
    const card = el("div", undefined, "host-card");
    const meta = el("div", undefined, "host-meta");
    meta.append(
      el("strong", h.host, "mono"),
      h.hostname ? el("span", `(${h.hostname})`, "muted") : el("span", ""),
      el("span", `${(h.open_ports || []).length} open ports: ${(h.open_ports || []).slice(0, 8).join(", ")}`, "mono muted")
    );
    const scanHostBtn = el("button", "Scan host", "secondary btn-sm");
    scanHostBtn.onclick = () => {
      $("target").value = h.host;
      $("scan-btn").onclick();
    };
    card.append(meta, scanHostBtn);
    box.append(card);
  });
}

async function pollJob(id) {
  for (;;) {
    const j = await api("/api/jobs/" + id);
    if (j.status === "running") {
      await new Promise((r) => setTimeout(r, 1200));
      continue;
    }
    return j;
  }
}

async function loadTargets() {
  try {
    const t = await api("/api/targets");
    state.demo = !!t.demo;
    const badge = $("mode-badge");
    if (badge) {
      badge.textContent = t.demo ? "Demo Lab" : "Live Scope";
      badge.classList.toggle("demo", !!t.demo);
    }
    if ($("demo-reset-btn")) {
      $("demo-reset-btn").classList.toggle("hidden", !t.demo);
    }
    if ($("live-scope")) {
      $("live-scope").textContent = t.demo ? "Demo sandbox" : "Enforced";
    }
    if (t.demo) {
      say("Demo mode active: 23 sample lab findings loaded on 192.168.56.0/24.");
    }
    const verified = t.verified_public && t.verified_public.length
      ? ` · Verified public: ${t.verified_public.join(", ")}`
      : "";
    $("scope-info").textContent = `Authorized Scope (${t.authorized_by}): ${t.targets.join(", ")}${verified}`;
    if (!$("target").value && t.targets.length) $("target").value = t.targets[0];
  } catch (e) {
    say("Scope error: " + e.message);
  }
}

$("scan-btn").onclick = async () => {
  const btn = $("scan-btn");
  btn.disabled = true;
  say("Scanning authorized target...");
  try {
    const { job } = await api("/api/scan", { target: $("target").value.trim(), web: $("web").checked });
    const j = await pollJob(job);
    if (j.status === "error") {
      say("Scan failed: " + j.error);
    } else {
      say(
        `Scan complete: ${j.result.found} findings (${j.result.new} new, ${j.result.reopened} reopened).` +
          (j.result.warnings.length ? " Notes: " + j.result.warnings.join("; ") : "")
      );
      state.hasAutoPlayed = false;
    }
    await refresh();
  } catch (e) {
    say("Refused/failed: " + e.message);
  }
  btn.disabled = false;
};

if ($("discover-btn")) {
  $("discover-btn").onclick = async () => {
    const btn = $("discover-btn");
    btn.disabled = true;
    say("Discovering live hosts on authorized subnet...");
    try {
      const res = await api("/api/discover", { target: $("target").value.trim() });
      renderDiscoveredHosts(res);
      say(`Host discovery complete: ${res.count} live host(s) found on ${res.target}.`);
    } catch (e) {
      say("Discovery refused/failed: " + e.message);
    }
    btn.disabled = false;
  };
}

if ($("snapshot-save-btn")) {
  $("snapshot-save-btn").onclick = async () => {
    const nameInput = $("snapshot-name");
    const label = (nameInput && nameInput.value.trim()) || "Assessment Snapshot";
    try {
      const snap = await api("/api/snapshots", { name: label });
      if (nameInput) nameInput.value = "";
      say(`Saved snapshot #${snap.id}: ${snap.name}`);
      await loadSnapshots();
    } catch (e) {
      say(e.message);
    }
  };
}

if ($("snapshot-diff-btn")) {
  $("snapshot-diff-btn").onclick = () => {
    const sel = $("snapshot-select");
    const targetSel = $("snapshot-target-select");
    if (sel && sel.value) runSnapshotDiff(sel.value, targetSel ? targetSel.value : "");
  };
}

if ($("snapshot-select")) {
  $("snapshot-select").onchange = () => {
    const sel = $("snapshot-select");
    const targetSel = $("snapshot-target-select");
    if (sel && sel.value) runSnapshotDiff(sel.value, targetSel ? targetSel.value : "");
  };
}

if ($("snapshot-target-select")) {
  $("snapshot-target-select").onchange = () => {
    const sel = $("snapshot-select");
    const targetSel = $("snapshot-target-select");
    if (sel && sel.value) runSnapshotDiff(sel.value, targetSel ? targetSel.value : "");
  };
}

$("intel-btn").onclick = async () => {
  try {
    say((await api("/api/intel/update", {})).message);
    await refresh();
  } catch (e) {
    say(e.message);
  }
};

if ($("demo-reset-btn")) {
  $("demo-reset-btn").onclick = async () => {
    try {
      await api("/api/demo/reset", {});
      state.simMode = false;
      state.simKeys.clear();
      state.hasAutoPlayed = false;
      say("Demo lab reset: all 23 sample findings restored to OPEN.");
      await refresh();
    } catch (e) {
      say(e.message);
    }
  };
}

$("aws-btn").onclick = async () => {
  try {
    const r = await api("/api/aws-audit", {
      profile: $("aws-profile").value || null,
      region: $("aws-region").value || null,
    });
    say(`AWS audit: ${r.found} findings.` + (r.warnings.length ? " " + r.warnings.join("; ") : ""));
    await refresh();
  } catch (e) {
    say(e.message);
  }
};

if ($("add-private-btn")) {
  $("add-private-btn").onclick = async () => {
    try {
      const r = await api("/api/targets/add", {
        target: $("new-private-target").value.trim(),
        confirm_authorization: $("confirm-auth").checked,
      });
      say(`Added authorized private target: ${r.added}`);
      await loadTargets();
    } catch (e) {
      say(e.message);
    }
  };
  $("challenge-btn").onclick = async () => {
    try {
      const r = await api("/api/targets/challenge", { target: $("public-target").value.trim() });
      $("challenge-info").textContent = `Token: ${r.token} \u2014 place at ${r.http_url} or in DNS TXT record`;
    } catch (e) {
      say(e.message);
    }
  };
  const verifyPub = async (method) => {
    try {
      const r = await api("/api/targets/verify-ownership", {
        target: $("public-target").value.trim(),
        method,
      });
      say(`Ownership verified for ${r.target} via ${r.method}.`);
      await loadTargets();
    } catch (e) {
      say(e.message);
    }
  };
  $("verify-http-btn").onclick = () => verifyPub("http");
  $("verify-dns-btn").onclick = () => verifyPub("dns");
}

if ($("scope-manager") && $("aws-drawer")) {
  $("scope-manager").ontoggle = () => {
    if ($("scope-manager").open) $("aws-drawer").open = false;
  };
  $("aws-drawer").ontoggle = () => {
    if ($("aws-drawer").open) $("scope-manager").open = false;
  };
}

$("sim-btn").onclick = () => {
  state.simMode = true;
  refresh();
};
$("sim-clear").onclick = () => {
  state.simMode = false;
  state.simKeys.clear();
  refresh();
};
$("play").onclick = play;
if ($("dominoes")) $("dominoes").onclick = play;
$("perspective").onchange = () => {
  state.hasAutoPlayed = false;
  refresh();
};

loadTargets().then(() => refresh());

