/* SOC Console — logique d'affichage.
   Aucune dependance : fetch + DOM. Les donnees viennent des routes /api de app.py. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const el = (t, a = {}, html = "") => {
  const n = document.createElement(t);
  for (const [k, v] of Object.entries(a)) {
    if (k === "class") n.className = v; else if (k === "html") n.innerHTML = v;
    else n.setAttribute(k, v);
  }
  if (html) n.innerHTML = html;
  return n;
};
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (n) => (n === null || n === undefined || n === "" ? "—" : Number(n).toLocaleString("fr-FR"));
const pad = (n) => String(n).padStart(2, "0");

/* ------------------------------------------------------------------ etat */
const S = {
  token: "", overview: null, lab: null, alerts: [], playbooks: [], pbKey: null,
  q: "", fSev: "", fAgent: "", sessions: [], curSess: 0, red: null, rev: null,
  view: "dash", loaded: {},
};

/* ------------------------------------------------------------- transport */
function api(path, opts = {}) {
  const headers = Object.assign({ "X-SOC-Token": S.token }, opts.headers || {});
  return fetch(path, Object.assign({}, opts, { headers })).then(async (r) => {
    if (r.status === 401) { openToken(); throw new Error("401"); }
    const txt = await r.text();
    let data; try { data = JSON.parse(txt); } catch (e) { data = { raw: txt }; }
    if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    return data;
  });
}

/* --------------------------------------------------------------- format */
const SEV = {
  crit: { label: "Critique", icon: "warn" }, high: { label: "Élevé", icon: "warn" },
  med: { label: "Moyen", icon: "dot" }, low: { label: "Faible", icon: "dot" },
  info: { label: "Info", icon: "dot" },
};
const sevOf = (level) => (level >= 12 ? "crit" : level >= 8 ? "high" : level >= 4 ? "med" : "low");
const ICONS = {
  warn: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2 1.5 21h21L12 2Zm0 6 6.4 11H5.6L12 8Zm-1 3v4h2v-4h-2Zm0 5v2h2v-2h-2Z"/></svg>',
  dot: '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="7"/></svg>',
  flash: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13 2 3 14h7l-1 8 10-12h-7l1-8Z"/></svg>',
  eye: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 5C6.5 5 2.3 9.4 1 12c1.3 2.6 5.5 7 11 7s9.7-4.4 11-7c-1.3-2.6-5.5-7-11-7Zm0 11a4 4 0 1 1 0-8 4 4 0 0 1 0 8Z"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2 4 5v7c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5l-8-3Z"/></svg>',
  bolt: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M11 2 4 13h6l-1 9 8-12h-6l1-8Z"/></svg>',
  warn2: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm-1 5h2v6h-2V7Zm0 8h2v2h-2v-2Z"/></svg>',
};
const sevCell = (level) => {
  const k = sevOf(level), s = SEV[k];
  return `<span class="sev ${k}">${ICONS[s.icon]} ${s.label}</span>`;
};
const confCell = (level) => {
  const filled = Math.max(1, Math.min(5, Math.round(level / 3)));
  return `<span class="conf">${[1, 2, 3, 4, 5].map((i) => `<b class="${i <= filled ? "f" : ""}"></b>`).join("")}` +
    `<em>${Math.round((level / 15) * 100)}%</em></span>`;
};
const timeOf = (ts) => {
  if (!ts) return "—";
  const d = new Date(String(ts).replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
  if (isNaN(d)) return String(ts).slice(11, 19);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};
const ago = (sec) => {
  if (sec === null || sec === undefined) return "inconnu";
  if (sec < 60) return Math.round(sec) + " s";
  if (sec < 3600) return Math.round(sec / 60) + " min";
  if (sec < 86400) return Math.round(sec / 3600) + " h";
  return Math.round(sec / 86400) + " j";
};
const md = (txt) => {
  let s = esc(txt || "");
  s = s.replace(/^### (.*)$/gm, "<h4>$1</h4>").replace(/^## (.*)$/gm, "<h4>$1</h4>");
  s = s.replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
  s = s.replace(/^- (.*)$/gm, "<li>$1</li>");
  s = s.replace(/(<li>[\s\S]*?<\/li>)(?!\s*<li>)/g, "<ul>$1</ul>");
  s = s.replace(/\n{2,}/g, "</p><p>").replace(/\n/g, "<br>");
  return "<p>" + s + "</p>";
};

/* ------------------------------------------------------------------ jeton */
function openToken() { $("#tokenModal").classList.add("open"); $("#tokenInput").focus(); }
function saveToken(t) { S.token = t; try { localStorage.setItem("soc_token", t); } catch (e) {} }
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.add("on");
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("on"), 2200);
}

/* ------------------------------------------------------------------ routes */
const VIEWS = {
  dash: ["Tableau de bord", "vue d'ensemble"],
  assistant: ["Assistant", "questions sur le snapshot"],
  alerts: ["Alertes", "banque d'alertes"],
  incidents: ["Incidents", "file de travail"],
  investigations: ["Investigations", "playbooks"],
  assets: ["Ressources", "agents et postes"],
  reverse: ["Ingénierie inverse", "analyse d'échantillon"],
  redteam: ["Red Team", "exposition locale"],
  reports: ["Analytique", "bilan et constats"],
  settings: ["Paramètres", "configuration"],
};
function route() {
  const h = (location.hash || "#dash").replace("#", "").split("?")[0];
  const v = VIEWS[h] ? h : "dash";
  S.view = v;
  $$(".view").forEach((n) => n.classList.toggle("on", n.id === "v-" + v));
  $$(".item").forEach((n) => n.classList.toggle("on", n.dataset.view === v));
  $$(".top .pill").forEach((n) => n.classList.toggle("on", n.dataset.view === v));
  $("#pageTitle").textContent = VIEWS[v][0];
  $("#pageCrumb").textContent = VIEWS[v][1];
  render(v);
}

/* ============================================================ rendu global */
function render(v) {
  if (!S.overview) return;
  if (v === "dash") renderDash();
  if (v === "alerts") renderAlerts();
  if (v === "incidents") renderIncidents();
  if (v === "investigations") renderInvestigations();
  if (v === "assets") renderAssets();
  if (v === "reports") renderReports();
  if (v === "settings") renderSettings();
  if (v === "assistant") renderChat();
  if (v === "alerts" && location.hash.includes("drawer") && S.alerts.length && !$("#drawer").classList.contains("open")) {
    openAlert(S.alerts[0]);
  }
  if (v === "redteam" && !S.red) $("#btnRed").click();
}

function renderCounters() {
  const o = S.overview || {};
  const bank = o.alert_bank || {};
  const total = bank.total ?? (o.recent_alerts || []).length;
  $("#nAlerts").textContent = num(total);
  const inc = (o.recent_alerts || []).filter((a) => a.level >= 8).length;
  $("#nIncidents").textContent = num(inc);
  const lab = S.lab || {};
  const on = (lab.agents || []).filter((a) => a.status === "ONLINE").length;
  $("#nAgents").textContent = lab.available === false ? "!" : `${on}/${(lab.agents || []).length}`;
  $("#liveState").textContent = lab.available === false ? "ORCH. INJOIGNABLE" : "LOCAL";
}

/* ============================================================== tableau de bord */
function renderDash() {
  const o = S.overview, k = o.kpi || {};
  const bank = o.alert_bank || {};
  const timeline = o.timeline || [];
  const recent = o.recent_alerts || [];
  $("#dashSub").textContent = o.ready
    ? `collecte ${ago(o.age_seconds)} · ${o.stale ? "snapshot ancien" : "snapshot frais"} · ${o.errors?.length || 0} erreur(s) de collecte`
    : (o.message || "aucune donnée");

  const niveaux = (o.by_level && Object.keys(o.by_level).length) ? o.by_level : countLevels(S.alerts);
  const totalLocal = S.alerts.length;
  const alertsTotal = bank.total ?? totalLocal;
  const crit = k.alerts_critique ?? Number(niveaux.crit || 0);
  const high = k.alerts_eleve ?? Number(niveaux.high || 0);
  const fenetre = timeline.length ? num(k.alerts_24h) : num(totalLocal);

  $("#kpis").innerHTML = [
    ["POSTURE", k.score ?? "—", "100 = rien à signaler", "score"],
    [timeline.length ? "ALERTES 24 H" : "ALERTES EN BANQUE", fenetre,
     timeline.length ? `banque : ${num(alertsTotal)} alertes` : `${num(alertsTotal)} alertes · indexeur muet`, "alerts"],
    ["CRITIQUES", num(crit), `dont ${num(high)} élevées`, "crit"],
  ].map(([lab, val, sub]) => `
    <div class="kpi"><div class="lab">${lab}</div><div class="val">${val}</div><div class="sub">${esc(sub)}</div></div>`).join("");

  /* volume : timeline si dispo, sinon les dernieres alertes locales */
  const source = timeline.length ? "indexeur" : "banque locale";
  const points = timeline.length ? timeline : (S.alerts.length ? S.alerts : recent).map((a) => ({ ts: a.ts, level: a.level }));
  $("#volTotal").textContent = `${num(points.length)} points · ${source}`;
  $("#volChart").innerHTML = stackedBars(points, 24);

  /* donut severites */
  const byLevel = niveaux;
  const sevTot = Object.values(byLevel).reduce((a, b) => a + Number(b || 0), 0);
  $("#sevTotal").textContent = num(sevTot) + " alertes";
  $("#sevDonut").innerHTML = donut(byLevel, sevTot, "ALERTES");

  /* regles / mitre / collecte */
  let rules = (o.top_rules || []).slice(0, 6);
  if (!rules.length) {
    const agg = new Map();
    S.alerts.forEach((a) => {
      const key = a.rule_id || "?";
      const cur = agg.get(key) || { rule_id: a.rule_id, description: a.description, count: 0 };
      cur.count++;
      agg.set(key, cur);
    });
    rules = Array.from(agg.values()).sort((x, y) => y.count - x.count).slice(0, 6);
  }
  $("#topRules").innerHTML = rules.length
    ? bars(rules.map((r) => ({ label: (r.rule_id ? r.rule_id + " · " : "") + (r.description || "règle"), n: r.count })))
    : '<div class="empty">Aucune agrégation de règles disponible.</div>';

  let mitre = (o.top_mitre || []).slice(0, 6);
  if (!mitre.length) {
    const agg = new Map();
    S.alerts.forEach((a) => (a.mitre_ids || []).forEach((m) => agg.set(m, (agg.get(m) || 0) + 1)));
    mitre = Array.from(agg.entries()).map(([technique, count]) => ({ technique, count }))
      .sort((x, y) => y.count - x.count).slice(0, 6);
  }
  $("#mitreList").innerHTML = mitre.length
    ? bars(mitre.map((m) => ({ label: m.technique || m.id || "—", n: m.count })), "var(--med)")
    : '<div class="empty">Aucune technique MITRE remontée.</div>';

  const errs = o.errors || [];
  $("#collState").textContent = o.stale ? "ANCIEN" : "À JOUR";
  $("#collState").className = "tag " + (o.stale ? "badge-warn" : "badge-ok");
  $("#collInfo").innerHTML = `
    <div class="kv" style="grid-template-columns:96px 1fr">
      <dt>collecté</dt><dd>${o.collected_at ? esc(o.collected_at.slice(0, 19).replace("T", " ")) : "—"}</dd>
      <dt>âge</dt><dd>${ago(o.age_seconds)}</dd>
      <dt>manager</dt><dd>${esc(o.manager?.version || o.manager?.url || "—")}</dd>
      <dt>postes</dt><dd>${num(k.agents_active)}/${num(k.agents_total)} actifs</dd>
      <dt>erreurs</dt><dd class="clamp2">${errs.length ? errs.map((e) => `<span class="badge-bad">${esc(String(e).slice(0, 90))}</span>`).join("<br>") : '<span class="badge-ok">aucune</span>'}</dd>
    </div>`;

  /* alertes recentes */
  const t = $("#recentTable");
  t.innerHTML = `<thead><tr><th>Heure</th><th>Règle</th><th>Sévérité</th><th>Agent</th><th>MITRE</th></tr></thead><tbody>` +
    recent.slice(0, 7).map((a) => `<tr data-alert="${esc(a.fingerprint || a.rule_id)}">
      <td class="id">${timeOf(a.ts)}</td>
      <td class="name">${esc(a.rule_id || "—")} <span>${esc((a.description || "").slice(0, 62))}</span></td>
      <td>${sevCell(a.level)}</td>
      <td class="mono">${esc(a.agent || "—")}</td>
      <td class="mono">${esc((a.mitre_ids || []).join(", ") || "—")}</td></tr>`).join("") +
    (recent.length ? "" : '<tr><td colspan="5" class="empty">Aucune alerte en base.</td></tr>') + "</tbody>";

  /* constats */
  const finds = o.findings || [];
  $("#findCount").textContent = finds.length + " constats";
  $("#findList").innerHTML = finds.length ? finds.slice(0, 6).map((f) => `
    <div class="find ${esc(f.level || "info")}"><span class="bar"></span>
      <div style="min-width:0">
        <h4>${esc(f.title)}</h4><p>${esc(f.detail)}</p>
        ${f.evidence ? `<div class="ev">${esc(f.evidence)}</div>` : ""}
      </div></div>`).join("") : '<div class="empty">Aucun constat.</div>';

  bindAlertRows();
}

function countLevels(alerts) {
  const out = { crit: 0, high: 0, med: 0, low: 0 };
  alerts.forEach((a) => { out[sevOf(a.level)]++; });
  return out;
}

/* barres empilees par heure, 24 tranches */
function stackedBars(points, buckets) {
  const H = 168, W = 640, padB = 18, padT = 8;
  const now = Date.now();
  const step = (24 * 3600 * 1000) / buckets;
  const zero = now - 24 * 3600 * 1000;
  const data = Array.from({ length: buckets }, () => ({ crit: 0, high: 0, med: 0, low: 0 }));
  points.forEach((p) => {
    const t = new Date(String(p.ts).replace(/([+-]\d{2})(\d{2})$/, "$1:$2")).getTime();
    if (isNaN(t) || t < zero) return;
    const i = Math.min(buckets - 1, Math.floor((t - zero) / step));
    data[i][sevOf(p.level)]++;
  });
  const max = Math.max(1, ...data.map((d) => d.crit + d.high + d.med + d.low));
  const bw = W / buckets, gap = Math.max(1, bw * 0.22);
  const colors = { crit: "#ef4444", high: "#f59e0b", med: "#3b82f6", low: "#22c55e" };
  let bars = "";
  data.forEach((d, i) => {
    const total = d.crit + d.high + d.med + d.low;
    const x = i * bw + gap / 2, w = bw - gap;
    let y = H - padB;
    if (!total) { bars += `<rect x="${x}" y="${H - padB - 1}" width="${w}" height="1" fill="#161e19"/>`; return; }
    ["low", "med", "high", "crit"].forEach((k) => {
      const h = (d[k] / max) * (H - padB - padT);
      if (!h) return;
      y -= h;
      bars += `<rect x="${x}" y="${y.toFixed(1)}" width="${w}" height="${h.toFixed(1)}" fill="${colors[k]}" opacity=".92" rx="1"/>`;
    });
  });
  let grid = "";
  for (let i = 0; i <= 3; i++) {
    const y = padT + ((H - padB - padT) / 3) * i;
    grid += `<line x1="0" y1="${y.toFixed(1)}" x2="${W}" y2="${y.toFixed(1)}" stroke="#141b16"/>`;
  }
  const ticks = [0, 6, 12, 18, 23].map((i) => {
    const d = new Date(zero + i * step);
    return `<text x="${(i * bw + bw / 2).toFixed(1)}" y="${H - 5}" fill="#5c6a61" font-size="9" text-anchor="middle" font-family="ui-monospace,monospace">${pad(d.getHours())}h</text>`;
  }).join("");
  const legend = `<div class="legend">
    <span><i style="background:${colors.crit}"></i>critique</span>
    <span><i style="background:${colors.high}"></i>élevé</span>
    <span><i style="background:${colors.med}"></i>moyen</span>
    <span><i style="background:${colors.low}"></i>faible</span></div>`;
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" height="${H}">${grid}${bars}${ticks}</svg>${legend}`;
}

function bars(items, color = "var(--green)") {
  const max = Math.max(1, ...items.map((i) => Number(i.n) || 0));
  return items.map((i) => `<div class="row2"><span class="name" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(i.label)}</span>
    <span class="n">${num(i.n)}</span>
    <span class="track"><span class="fill" style="width:${Math.max(2, (Number(i.n) / max) * 100)}%;background:${color}"></span></span></div>`).join("");
}

function donut(byLevel, total, label) {
  const order = [["crit", "#ef4444"], ["high", "#f59e0b"], ["med", "#3b82f6"], ["low", "#22c55e"]];
  const R = 44, C = 2 * Math.PI * R;
  let off = 0, arcs = "";
  order.forEach(([k, c]) => {
    const v = Number(byLevel[k] || 0);
    if (!v || !total) return;
    const len = (v / total) * C;
    arcs += `<circle cx="54" cy="54" r="${R}" fill="none" stroke="${c}" stroke-width="13"
      stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}"
      transform="rotate(-90 54 54)" opacity=".92"/>`;
    off += len;
  });
  if (!arcs) arcs = `<circle cx="54" cy="54" r="${R}" fill="none" stroke="#161e19" stroke-width="13"/>`;
  const rows = order.map(([k, c]) => {
    const v = Number(byLevel[k] || 0);
    return `<div class="row2"><span><i style="display:inline-block;width:6px;height:6px;border-radius:2px;background:${c};margin-right:6px"></i>${SEV[k].label}</span>
      <span class="n">${num(v)}${total ? ` · ${Math.round((v / total) * 100)}%` : ""}</span></div>`;
  }).join("");
  return `<svg class="donut" viewBox="0 0 108 108">${arcs}
      <text class="mid" x="54" y="55" text-anchor="middle">${num(total)}</text>
      <text class="midl" x="54" y="68" text-anchor="middle">${label}</text></svg>
    <div class="rows">${rows}</div>`;
}

/* ================================================================== alertes */
function alertRows(list, withState = true) {
  return list.map((a) => `<tr data-alert="${esc(a.fingerprint || a.rule_id)}">
    <td class="id">${esc(a.rule_id || "—")}</td>
    <td class="name">${esc(a.description || "sans description")}</td>
    <td>${sevCell(a.level)}</td>
    ${withState ? `<td>${confCell(a.level)}</td>` : ""}
    <td><span class="state ${a.state === "traite" ? "closed" : ""}"><i></i>${esc(a.state || "nouveau")}</span></td>
    <td class="mono">${esc(a.agent || "—")}</td>
    <td class="mono">${esc((a.mitre_ids || []).join(", ") || "—")}</td>
    <td class="id">${timeOf(a.ts)}</td></tr>`).join("");
}

function renderAlerts() {
  const o = S.overview;
  const all = S.alerts;
  const bank = o.alert_bank || {};
  const counts = countLevels(all);
  $("#alertsSub").textContent = `${num(all.length)} alertes chargées · banque ${num(bank.total ?? all.length)} · ${o.stale ? "snapshot ancien" : "collecte fraîche"}`;

  $("#alertTiles").innerHTML = [
    ["crit", "critique", counts.crit], ["high", "élevé", counts.high],
    ["med", "moyen", counts.med], ["low", "faible", counts.low],
  ].map(([k, l, v]) => `<div class="tile ${k}"><div class="v">${num(v)}</div><div class="l">${l}</div></div>`).join("");

  const agents = Array.from(new Set(all.map((a) => a.agent).filter(Boolean))).sort();
  const sel = $("#fAgent");
  if (sel.options.length <= 1) sel.innerHTML = '<option value="">Tous les agents</option>' + agents.map((a) => `<option>${esc(a)}</option>`).join("");

  const q = S.q.toLowerCase();
  const list = all.filter((a) => {
    if (S.fSev && sevOf(a.level) !== S.fSev) return false;
    if (S.fAgent && a.agent !== S.fAgent) return false;
    if (!q) return true;
    return [a.rule_id, a.description, a.agent, (a.mitre_ids || []).join(" "), a.playbook].join(" ").toLowerCase().includes(q);
  });

  $("#filterCount").textContent = `${num(list.length)} / ${num(all.length)}`;
  $("#alertsTable").innerHTML = `<thead><tr><th>Règle</th><th>Description</th><th>Sévérité</th><th>Confiance</th>
      <th>État</th><th>Agent</th><th>MITRE</th><th>Heure</th></tr></thead>
    <tbody>${alertRows(list.slice(0, 300), true) || '<tr><td colspan="8" class="empty">Aucune alerte ne correspond.</td></tr>'}</tbody>`;
  bindAlertRows();
}

/* ================================================================ incidents */
function incidentsFrom(alerts) {
  const map = new Map();
  alerts.forEach((a) => {
    const k = (a.rule_id || "?") + "|" + (a.agent || "?");
    let it = map.get(k);
    if (!it) {
      it = { rule_id: a.rule_id, description: a.description, agent: a.agent, level: a.level,
             n: 0, first: a.ts, last: a.ts, playbook: a.playbook, mitre: a.mitre_ids || [], sample: a };
      map.set(k, it);
    }
    it.n++;
    if (a.level > it.level) { it.level = a.level; it.sample = a; }
    if ((a.ts || "") > (it.last || "")) it.last = a.ts;
    if ((a.ts || "") < (it.first || "")) it.first = a.ts;
  });
  return Array.from(map.values()).sort((x, y) => y.level - x.level || y.n - x.n);
}

function renderIncidents() {
  const inc = incidentsFrom(S.alerts);
  const c = { crit: 0, high: 0, med: 0, low: 0 };
  inc.forEach((i) => { c[sevOf(i.level)]++; });
  $("#incTiles").innerHTML = [
    ["crit", "critiques", c.crit], ["high", "élevés", c.high],
    ["med", "moyens", c.med], ["low", "faibles", c.low],
  ].map(([k, l, v]) => `<div class="tile ${k}"><div class="v">${num(v)}</div><div class="l">${l}</div></div>`).join("");

  const sub = $("#v-incidents .vhead p");
  if (sub) sub.textContent = `${num(S.alerts.length)} alertes regroupées en ${num(inc.length)} incidents — une ligne par règle et par poste`;

  $("#incTable").innerHTML = `<thead><tr><th>Règle</th><th>Incident</th><th>Sévérité</th><th>Confiance</th>
      <th>Alertes</th><th>Agent</th><th>Playbook</th><th>Dernière vue</th></tr></thead>
    <tbody>${inc.slice(0, 200).map((i) => `<tr data-rule="${esc(i.rule_id)}" data-agent="${esc(i.agent)}">
      <td class="id">${esc(i.rule_id || "—")}</td>
      <td class="name">${esc(i.description || "—")}</td>
      <td>${sevCell(i.level)}</td>
      <td>${confCell(i.level)}</td>
      <td class="id">${num(i.n)}</td>
      <td class="mono">${esc(i.agent || "—")}</td>
      <td><span class="chip ghost">${esc(i.playbook || "—")}</span></td>
      <td class="id">${timeOf(i.last)}</td></tr>`).join("")
      || '<tr><td colspan="8" class="empty">Aucune alerte en base.</td></tr>'}</tbody>`;

  $$("#incTable [data-rule]").forEach((tr) => tr.onclick = () => {
    const row = inc.find((i) => String(i.rule_id) === tr.dataset.rule && String(i.agent) === tr.dataset.agent);
    if (row) openAlert(Object.assign({}, row.sample, { _grp: row }));
  });
}

/* =========================================================== investigations */
function renderInvestigations() {
  const pb = S.playbooks || [];
  $("#pbCount").textContent = pb.length + " playbooks";
  $("#pbList").innerHTML = pb.map((p) => `
    <div class="sess ${p.key === S.pbKey ? "on" : ""}" data-pb="${esc(p.key)}">
      <b>${esc(p.title)}</b><span>${esc(p.urgency)} · ${p.steps} étapes · ${esc((p.mitre || []).join(", ") || "sans MITRE")}</span>
    </div>`).join("") || '<div class="empty">Catalogue indisponible.</div>';
  $$("#pbList [data-pb]").forEach((n) => n.onclick = () => { S.pbKey = n.dataset.pb; renderInvestigations(); });
  if (!S.pbKey && pb.length) S.pbKey = pb[0].key;
  if (S.pbKey && !S.loaded["pb:" + S.pbKey]) loadPlaybook(S.pbKey); else paintPlaybook();
}

function loadPlaybook(key) {
  api("/api/playbook/" + encodeURIComponent(key)).then((d) => {
    S.loaded["pb:" + key] = d.playbook;
    if (S.pbKey === key) paintPlaybook();
  }).catch((e) => { if (String(e.message) !== "401") $("#pbHead").innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
}

function paintPlaybook() {
  const p = S.loaded["pb:" + S.pbKey];
  if (!p) return;
  const urg = (p.urgency || "").toLowerCase();
  const k = urg.includes("crit") ? "crit" : urg.includes("haut") ? "high" : urg.includes("moyen") ? "med" : "low";
  $("#pbTitle").textContent = p.title || S.pbKey;
  $("#pbSev").innerHTML = `<span class="chip ${k}">${esc(p.urgency || "—")}</span>`;

  const steps = Array.isArray(p.steps) ? p.steps : [];
  const cmds = Array.isArray(p.commands) ? p.commands : [];

  const stepsHtml = steps.map((st, i) => `<dt>étape ${i + 1}</dt><dd>${esc(typeof st === "string" ? st : (st.title || ""))}</dd>`).join("");
  const cmdsHtml = cmds.map((c) => `
    <div style="margin-bottom:6px">
      <div class="note" style="margin-bottom:2px">${esc(c.label || c.os || "commande")}</div>
      <div class="cmd">${esc(c.cmd || "")}<button class="btn sm" data-copy="${esc(c.cmd || "")}">copier</button></div>
    </div>`).join("");

  $("#pbHead").innerHTML = `
    ${p.why ? `<p class="note" style="margin:0 0 10px">${esc(p.why)}</p>` : ""}
    <dl class="kv">${stepsHtml}
      <dt>MITRE</dt><dd>${esc((p.mitre || []).join(", ") || "—")}</dd>
    </dl>
    ${cmdsHtml ? `<h4 style="font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#5c6a61;margin:12px 0 6px">commandes</h4>${cmdsHtml}` : ""}`;
  $$("#pbHead [data-copy]").forEach((b) => b.onclick = () => { navigator.clipboard.writeText(b.dataset.copy); toast("commande copiée"); });

  const nodes = steps.length ? steps.map((st, i) => ({ title: typeof st === "string" ? st : (st.title || "étape"), n: i + 1 }))
    : Array.from({ length: 4 }, (_, i) => ({ title: "étape " + (i + 1), n: i + 1 }));
  const chainSev = ["low", "low", "med", "med", "high", "high", "crit"];
  $("#pbChain").innerHTML = `<div class="chain-flow">` + nodes.map((s, i) => {
    const sevK = chainSev[Math.min(chainSev.length - 1, Math.floor((i / Math.max(1, nodes.length - 1)) * 6))];
    const court = String(s.title).split(/[.:(]/)[0].slice(0, 26);
    return `<div class="node ${sevK}" title="${esc(s.title)}"><span class="ic">${ICONS.flash}</span>
      <span class="t"><b>${esc(court)}</b><span>étape ${pad(s.n)}</span></span></div>` +
      (i < nodes.length - 1 ? '<span class="link"></span>' : "");
  }).join("") + `</div>`;
}

/* ================================================================ ressources */
function renderAssets() {
  const lab = S.lab || {};
  const agents = lab.agents || [];
  const on = agents.filter((a) => a.status === "ONLINE").length;
  $("#agentTiles").innerHTML = [
    ["low", "agents en ligne", on + "/" + agents.length],
    ["med", "tâches traitées", num(lab.tasks_total ?? 0)],
    ["med", "en cours", num(lab.tasks_running ?? 0)],
    [lab.available === false ? "crit" : "low", "orchestrateur", lab.available === false ? "hors ligne" : "joignable"],
  ].map(([k, l, v]) => `<div class="tile ${k}"><div class="v" style="font-size:${String(v).length > 8 ? 14 : 20}px">${esc(v)}</div><div class="l">${l}</div></div>`).join("");

  $("#agentCards").innerHTML = agents.length ? agents.map((a) => `
    <div class="card ${a.status === "ONLINE" ? "" : "off"}">
      <div class="h"><span class="dot ${a.status === "ONLINE" ? "on" : "off"}"></span><b>${esc(a.name || a.agent_id)}</b>
        <span class="p">:${esc((a.endpoint || "").split(":").pop())}</span></div>
      <div class="note">${esc(a.agent_id)} · ${esc(a.status)}</div>
      <div class="caps">${(a.capabilities || []).slice(0, 5).map((c) => `<span>${esc(c)}</span>`).join("")}</div>
      <div class="foot">vu ${esc((a.last_seen || "").slice(11, 19) || "—")}</div>
    </div>`).join("") : `<div class="empty">${esc(lab.error || "Orchestrateur injoignable.")}</div>`;

  const hosts = (S.overview.agents || []);
  $("#hostTable").innerHTML = `<thead><tr><th>Poste</th><th>Version</th><th>IP</th><th>Statut</th></tr></thead><tbody>` +
    (hosts.length ? hosts.map((h) => `<tr><td class="name">${esc(h.name || h.id || "—")}</td>
      <td class="mono">${esc(h.version || "—")}</td><td class="mono">${esc(h.ip || "—")}</td>
      <td>${h.status === "active" ? '<span class="badge-ok">actif</span>' : `<span class="badge-warn">${esc(h.status || "inconnu")}</span>`}</td></tr>`).join("")
      : '<tr><td colspan="4" class="empty">Aucun poste remonté.</td></tr>') + "</tbody>";

  const tasks = (lab.tasks || []).slice().sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || ""))).slice(0, 8);
  $("#taskTable").innerHTML = `<thead><tr><th>Tâche</th><th>Capacité</th><th>Agent</th><th>Durée</th><th>Statut</th></tr></thead><tbody>` +
    (tasks.length ? tasks.map((t) => `<tr><td class="id">${esc(t.task_id)}</td><td class="mono">${esc(t.capability || "—")}</td>
      <td class="mono">${esc(t.agent_id || "—")}</td><td class="id">${t.duration_ms ? Math.round(t.duration_ms) + " ms" : "—"}</td>
      <td>${t.status === "COMPLETED" ? '<span class="badge-ok">terminé</span>' : `<span class="badge-warn">${esc(t.status || "—")}</span>`}</td></tr>`).join("")
      : '<tr><td colspan="5" class="empty">Aucune tâche.</td></tr>') + "</tbody>";
}

/* ================================================================== rapports */
function renderReports() {
  const o = S.overview;
  const sum = o.summary || {};
  $("#repTitle").textContent = "Bilan opérationnel";
  $("#repModel").textContent = sum.model || sum.engine || "moteur interne";
  $("#repBody").innerHTML = sum.text ? md(sum.text) : '<div class="empty">Aucun bilan généré. Utilisez /api/summary?refresh=1.</div>';
  $("#repSub").textContent = sum.generated_at ? `généré ${ago((Date.now() - new Date(sum.generated_at).getTime()) / 1000)}` : "bilan";

  const byPlay = {};
  S.alerts.forEach((a) => { const k = a.playbook || "sans playbook"; byPlay[k] = (byPlay[k] || 0) + 1; });
  const items = Object.entries(byPlay).sort((a, b) => b[1] - a[1]).map(([label, n]) => ({ label, n }));
  $("#repPlay").innerHTML = items.length ? bars(items, "var(--teal)") : '<div class="empty">Aucune alerte classée.</div>';

  const finds = o.findings || [];
  $("#repFind").textContent = finds.length + " constats";
  $("#repFindList").innerHTML = finds.map((f) => `
    <div class="find ${esc(f.level || "info")}"><span class="bar"></span>
      <div style="min-width:0">
        <h4>${esc(f.title)}</h4><p>${esc(f.detail)}</p>
        ${(f.actions || []).length ? `<div class="ev">→ ${f.actions.map(esc).join(" · ")}</div>` : ""}
        ${f.evidence ? `<div class="ev">${esc(f.evidence)}</div>` : ""}
      </div></div>`).join("") || '<div class="empty">Aucun constat.</div>';
}

/* ================================================================ parametres */
function renderSettings() {
  const o = S.overview;
  const lab = S.lab || {};
  $("#setServices").innerHTML = `<dl class="kv">
    <dt>dashboard</dt><dd>${esc(location.origin)} · HTTP + SQLite, zéro dépendance</dd>
    <dt>collecte</dt><dd>${esc(o.collected_at ? o.collected_at.slice(0, 19).replace("T", " ") : "aucun snapshot")} (${ago(o.age_seconds)})</dd>
    <dt>orchestrateur</dt><dd>${lab.available === false ? '<span class="badge-bad">injoignable</span>' : '<span class="badge-ok">joignable</span>'} · ${esc(lab.error || "")}</dd>
    <dt>bilan</dt><dd>${esc(o.summary?.model || "moteur interne")}</dd>
    <dt>jeton de lecture</dt><dd>${S.token ? '<span class="badge-ok">fourni</span>' : '<span class="badge-warn">absent</span>'} · en-tête <code>X-SOC-Token</code></dd>
  </dl>`;
  $("#setEnv").innerHTML = `<p class="note">Les valeurs ne sont jamais affichées : seules leur présence est listée, côté serveur.</p>
    <div class="kv"><dt>requêtes</dt><dd>ouvertes uniquement vers l'indexeur local, l'orchestrateur local et l'API du modèle si configurée</dd>
    <dt>stockage</dt><dd>SQLite local (alertes, snapshots, bilans)</dd></div>`;
}

/* ===================================================================== chat */
function renderChat() {
  $("#sessions").innerHTML = S.sessions.map((s, i) => `
    <div class="sess ${i === S.curSess ? "on" : ""}" data-s="${i}">
      <b>${esc(s.title || "Discussion")}</b><span>${s.msgs.length} messages</span></div>`).join("");
  $$("#sessions [data-s]").forEach((n) => n.onclick = () => { S.curSess = +n.dataset.s; renderChat(); });
  const cur = S.sessions[S.curSess];
  if (!cur) {
    $("#msgs").innerHTML = `<div class="prompts">
      <div class="note" style="margin-bottom:8px">Questions rapides sur le snapshot courant :</div>
      ${["Combien d'alertes critiques ?", "État des agents", "La collecte est-elle fraîche ?",
         "Quels constats sont ouverts ?", "Volume d'alertes en banque"]
        .map((q) => `<button class="btn" data-ask="${esc(q)}">${esc(q)}</button>`).join("")}</div>`;
    $$("#msgs [data-ask]").forEach((b) => b.onclick = () => { $("#ask").value = b.dataset.ask; ask(); });
    return;
  }
  $("#msgs").innerHTML = (cur ? cur.msgs : []).map((m) => `
    <div class="msg ${m.role === "me" ? "me" : "ai"}">
      <div class="who">${m.role === "me" ? "vous" : (m.engine || "assistant")}</div>
      ${m.role === "me" ? esc(m.text) : md(m.text)}</div>`).join("")
    || `<div class="prompts"><div class="note">Posez une question sur l'état courant : alertes, agents, collecte, constats.</div></div>`;
  const box = $("#msgs"); box.scrollTop = box.scrollHeight;
}

function newSession(title) {
  S.sessions.unshift({ title: title || "Discussion " + (S.sessions.length + 1), msgs: [] });
  S.curSess = 0;
  renderChat();
}

function ask() {
  const q = $("#ask").value.trim();
  if (!q) return;
  if (!S.sessions.length) newSession(q.slice(0, 42));
  const cur = S.sessions[S.curSess];
  cur.msgs.push({ role: "me", text: q });
  $("#ask").value = "";
  renderChat();
  const hist = cur.msgs.slice(-6).map((m) => ({ role: m.role === "me" ? "user" : "assistant", content: m.text }));
  const ph = el("div", { class: "msg ai" }, `<div class="who">assistant</div><p class="note">analyse en cours…</p>`);
  $("#msgs").appendChild(ph); $("#msgs").scrollTop = $("#msgs").scrollHeight;
  api("/api/assistant", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question: q, history: hist.slice(0, -1) }),
  }).then((d) => {
    ph.remove();
    cur.msgs.push({ role: "ai", text: d.answer || "(réponse vide)", engine: d.engine === "llm" ? "modèle " + (d.model || "") : "moteur interne" });
    renderChat();
  }).catch((e) => {
    ph.remove();
    cur.msgs.push({ role: "ai", text: "**Erreur** : " + e.message, engine: "assistant" });
    renderChat();
  });
}

/* ================================================================== tiroir */
function bindAlertRows() {
  $$("[data-alert]").forEach((tr) => tr.onclick = () => {
    const key = tr.dataset.alert;
    const a = S.alerts.find((x) => (x.fingerprint || x.rule_id) === key) ||
      (S.overview.recent_alerts || []).find((x) => (x.fingerprint || x.rule_id) === key);
    if (a) openAlert(a);
  });
}

function openAlert(a) {
  $("#drawerTitle").textContent = `Règle ${a.rule_id || "—"} · ${a.agent || "—"}`;
  $("#drawerSev").innerHTML = sevCell(a.level);
  $("#drawerTabs").innerHTML = ["Détail", "Réponse"].map((t, i) =>
    `<button class="tab ${i === 0 ? "on" : ""}" data-t="${i}">${t}</button>`).join("");
  const pb = (S.playbooks || []).find((p) => p.key === a.playbook);
  const vue = () => `
    <dl class="kv">
      <dt>description</dt><dd>${esc(a.description || "—")}</dd>
      <dt>sévérité</dt><dd>niveau ${esc(a.level)} · ${sevCell(a.level)}</dd>
      <dt>agent</dt><dd>${esc(a.agent || "—")}</dd>
      <dt>horodatage</dt><dd>${esc(a.ts || "—")}</dd>
      <dt>groupes</dt><dd>${esc((a.groups || []).join(", ") || "—")}</dd>
      <dt>MITRE</dt><dd>${esc((a.mitre_ids || []).join(", ") || "—")}</dd>
      <dt>playbook</dt><dd>${esc(a.playbook || "—")} ${pb ? `· ${esc(pb.title)}` : ""}</dd>
      <dt>source IP</dt><dd>${esc(a.srcip || "—")}</dd>
      <dt>empreinte</dt><dd class="mono">${esc(a.fingerprint || "—")}</dd>
      <dt>état</dt><dd>${esc(a.state || "nouveau")}</dd>
    </dl>`;
  const reponse = `
    <p class="note">Étapes du playbook ${esc(a.playbook || "générique")} — à exécuter dans l'ordre.</p>
    ${pb ? `<dl class="kv"><dt>urgence</dt><dd>${esc(pb.urgency)}</dd>
      <dt>étapes</dt><dd>${pb.steps}</dd><dt>MITRE</dt><dd>${esc((pb.mitre || []).join(", ") || "—")}</dd></dl>
      <button class="btn" data-goto-pb="${esc(pb.key)}" style="margin-top:10px">Ouvrir le playbook</button>` :
      '<div class="empty">Aucun playbook associé à cette alerte.</div>'}`;
  $("#drawerBody").innerHTML = vue();
  $$("#drawerTabs .tab").forEach((t) => t.onclick = () => {
    $$("#drawerTabs .tab").forEach((x) => x.classList.remove("on")); t.classList.add("on");
    $("#drawerBody").innerHTML = t.dataset.t === "0" ? vue() : reponse;
    const g = $("#drawerBody [data-goto-pb]");
    if (g) g.onclick = () => { closeDrawer(); location.hash = "#investigations"; S.pbKey = g.dataset.gotoPb; renderInvestigations(); };
  });
  $("#drawer").classList.add("open");
}
function closeDrawer() { $("#drawer").classList.remove("open"); }

/* ============================================================ boot & events */
function refreshAll() {
  return Promise.all([
    api("/api/overview").then((d) => { S.overview = d; }),
    api("/api/lab/agents").then((d) => { S.lab = d; }).catch((e) => { S.lab = { available: false, error: String(e.message), agents: [], tasks: [] }; }),
    api("/api/alerts?limit=800").then((d) => { S.alerts = d.alerts || []; }).catch(() => { S.alerts = []; }),
    api("/api/playbooks").then((d) => { S.playbooks = d.playbooks || []; }).catch(() => { S.playbooks = []; }),
  ]).then(() => { renderCounters(); render(S.view); });
}

function boot() {
  const m = (location.hash || "").match(/token=([^&]+)/);
  if (m) { saveToken(decodeURIComponent(m[1])); history.replaceState(null, "", location.pathname + location.hash.replace(m[0], "")); }
  if (!S.token) { try { S.token = localStorage.getItem("soc_token") || ""; } catch (e) {} }
  $("#tokenOk").onclick = () => {
    const t = $("#tokenInput").value.trim();
    saveToken(t);
    api("/api/health").then(() => { $("#tokenModal").classList.remove("open"); $("#tokenErr").textContent = ""; refreshAll(); })
      .catch(() => { $("#tokenErr").textContent = "jeton refusé par le serveur"; });
  };
  $("#tokenInput").onkeydown = (e) => { if (e.key === "Enter") $("#tokenOk").click(); };
  $("#btnRefresh").onclick = () => refreshAll().then(() => toast("données rechargées"));
  $("#btnBell").onclick = () => { location.hash = "#reports"; };
  $("#btnPrint").onclick = () => window.print();
  $("#btnNewChat").onclick = () => newSession();
  $("#btnAsk").onclick = ask;
  $("#ask").onkeydown = (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); ask(); } };
  $("#drawerClose").onclick = closeDrawer;
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  $("#q").oninput = (e) => { S.q = e.target.value; renderAlerts(); };
  $("#fSev").onchange = (e) => { S.fSev = e.target.value; renderAlerts(); };
  $("#fAgent").onchange = (e) => { S.fAgent = e.target.value; renderAlerts(); };
  $("#btnExport").onclick = () => {
    const head = ["regle", "description", "severite", "agent", "mitre", "horodatage"];
    const rows = S.alerts.map((a) => [a.rule_id, a.description, a.level, a.agent, (a.mitre_ids || []).join(" "), a.ts]);
    const csv = [head, ...rows].map((r) => r.map((c) => `"${String(c ?? "").replace(/"/g, '""')}"`).join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const a = el("a", { href: url, download: "alertes.csv" }); document.body.appendChild(a); a.click(); a.remove();
  };
  $("#btnAgentsRefresh").onclick = () => api("/api/lab/agents").then((d) => { S.lab = d; renderCounters(); renderAssets(); toast("orchestrateur interrogé"); })
    .catch((e) => toast("orchestrateur injoignable : " + e.message));
  $("#btnFocus").onclick = () => { S.fSev = "crit"; location.hash = "#alerts"; $("#fSev").value = "crit"; renderAlerts(); };

  /* inspection d'echantillon */
  $("#btnRev").onclick = () => {
    const f = $("#revFile").files[0];
    const path = $("#revPath").value.trim();
    if (!f && !path) return toast("choisissez un fichier ou un chemin");
    const go = (payload) => {
      $("#revOut").innerHTML = '<div class="empty">analyse…</div>';
      api("/api/reverse", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
        .then((d) => { S.rev = d; paintReverse(d); })
        .catch((e) => { $("#revOut").innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
    };
    if (f) {
      if (f.size > 2 * 1024 * 1024) return toast("fichier trop gros (2 Mo max)");
      const rd = new FileReader();
      rd.onload = () => go({ name: f.name, content_b64: String(rd.result).split(",")[1] || "" });
      rd.readAsDataURL(f);
    } else go({ path });
  };

  /* audit d'exposition */
  $("#btnRed").onclick = () => {
    $("#redOut").innerHTML = '<div class="empty">audit…</div>';
    api("/api/redteam").then((d) => { S.red = d; paintRed(d); })
      .catch((e) => { $("#redOut").innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
  };

  /* navigation */
  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-view]");
    if (t && !t.closest(".item, .pill")) { e.preventDefault(); location.hash = "#" + t.dataset.view; }
  });
  window.addEventListener("hashchange", route);

  const tick = () => { const d = new Date(); $("#clock").textContent = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
  tick(); setInterval(tick, 1000);

  if (!S.token) { openToken(); route(); return; }
  refreshAll().catch((e) => { if (String(e.message) !== "401") toast("chargement : " + e.message); });
  route();
  setInterval(() => { if (document.visibilityState === "visible") refreshAll().catch(() => {}); }, 60000);
}

function paintReverse(d) {
  const ind = d.indicators || [];
  $("#revEngine").textContent = d.truncated ? "tronqué à 2 Mo" : (d.size ? num(d.size) + " octets" : "");
  $("#revOut").innerHTML = `
    <dl class="kv">
      <dt>fichier</dt><dd>${esc(d.name || "—")}</dd>
      <dt>taille</dt><dd>${num(d.size)} octets</dd>
      <dt>sha256</dt><dd class="mono">${esc(d.sha256 || "—")}</dd>
      <dt>entropie</dt><dd>${esc(d.entropy)} bits/octet ${d.entropy > 7.2 ? '<span class="badge-warn">possiblement emballé ou chiffré</span>' : ""}</dd>
      <dt>type</dt><dd>${esc(d.kind || "—")}</dd>
      <dt>indicateurs</dt><dd>${ind.length ? ind.map((i) => `<span class="chip ${i.severity === "haute" ? "crit" : i.severity === "moyenne" ? "high" : "ghost"}">${esc(i.name)}</span>`).join(" ") : '<span class="badge-ok">aucun</span>'}</dd>
    </dl>
    ${ind.length ? `<div style="margin-top:10px"><table><thead><tr><th>indicateur</th><th>preuve</th></tr></thead><tbody>` +
      ind.map((i) => `<tr><td class="name">${esc(i.name)}</td><td class="mono">${esc(i.evidence)}</td></tr>`).join("") + `</tbody></table></div>` : ""}
    ${(d.strings || []).length ? `<h4 style="font-size:11px;color:#9ff0bd;margin:12px 0 5px">chaînes notables</h4>
      <div class="cmd" style="max-height:180px;overflow:auto">${esc(d.strings.join("\n"))}</div>` : ""}`;
}

function paintRed(d) {
  const checks = d.checks || [];
  const ok = checks.filter((c) => c.status === "ok").length;
  $("#redScore").innerHTML = `<span class="chip ${ok === checks.length ? "low" : "high"}">${ok}/${checks.length} conformes</span>`;
  $("#redOut").innerHTML = `<table><thead><tr><th>contrôle</th><th>résultat</th><th>détail</th></tr></thead><tbody>` +
    checks.map((c) => `<tr><td class="name">${esc(c.name)}</td>
      <td>${c.status === "ok" ? '<span class="badge-ok">conforme</span>' : c.status === "warn" ? '<span class="badge-warn">à surveiller</span>' : '<span class="badge-bad">non conforme</span>'}</td>
      <td class="mono">${esc(c.detail)}</td></tr>`).join("") + "</tbody></table>" +
    `<p class="note" style="margin-top:9px">${esc(d.note || "")}</p>`;
}

document.addEventListener("DOMContentLoaded", boot);
