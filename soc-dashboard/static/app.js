/* SOC Console — logique de la page. Aucune dependance : fetch + DOM. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

const TOKEN_KEY = 'soc_read_token';
const getToken = () => localStorage.getItem(TOKEN_KEY) || '';
const state = { ov: null, lab: null, view: 'dashboard', level: '0', q: '', picked: null };

/* ---------------------------------------------------------------- utilitaires */
const esc = t => String(t ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const sev = lvl => (lvl >= 12 ? 'crit' : lvl >= 8 ? 'high' : lvl >= 4 ? 'mid' : 'low');
const sevLabel = k => ({ crit: 'critique', high: 'élevé', mid: 'moyen', low: 'faible' }[k] || k);
const fmtAge = s => s == null ? 'jamais' : s < 90 ? 'il y a ' + s + ' s' : s < 5400 ? 'il y a ' + Math.round(s / 60) + ' min' : 'il y a ' + Math.round(s / 3600) + ' h';
const hhmm = ts => String(ts || '').replace('T', ' ').slice(11, 16) || '—';
const dayhm = ts => String(ts || '').replace('T', ' ').slice(0, 16);
const num = n => (n == null ? '—' : Number(n).toLocaleString('fr-FR'));

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('on');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove('on'), 2200);
}

function apiFetch(url, opts = {}) {
  opts.headers = Object.assign({}, opts.headers || {}, getToken() ? { 'X-SOC-Token': getToken() } : {});
  return fetch(url, opts);
}

/* -------------------------------------------------------------- jeton lecture */
if (location.hash.startsWith('#token=')) {
  localStorage.setItem(TOKEN_KEY, decodeURIComponent(location.hash.slice(7)));
  history.replaceState(null, '', location.pathname);
}
function askToken(msg) {
  $('#tokenErr').textContent = msg || '';
  $('#tokenInput').value = '';
  $('#tokenModal').classList.add('open');
  setTimeout(() => $('#tokenInput').focus(), 60);
}
$('#tokenSave').onclick = () => {
  const v = $('#tokenInput').value.trim();
  if (!v) { $('#tokenErr').textContent = 'Jeton vide.'; return; }
  localStorage.setItem(TOKEN_KEY, v);
  $('#tokenModal').classList.remove('open');
  load();
};
$('#tokenClear').onclick = () => { localStorage.removeItem(TOKEN_KEY); askToken('Jeton effacé.'); };
$('#tokenInput').addEventListener('keydown', e => { if (e.key === 'Enter') $('#tokenSave').click(); });
$('#btnToken').onclick = () => askToken(getToken() ? 'Jeton actuel remplacé ?' : '');

/* ------------------------------------------------------------------- markdown */
function mdRender(md) {
  const lines = String(md || '').split('\n');
  let out = '', mode = null;
  const close = () => { if (mode) { out += '</' + mode + '>'; mode = null; } };
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) { close(); continue; }
    const inline = line.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/`([^`]+)`/g, '<code>$1</code>');
    if (line.startsWith('#')) { close(); out += '<h3>' + esc(line.replace(/^#+\s*/, '')) + '</h3>'; continue; }
    const ol = line.match(/^(\d+)\.\s+(.*)$/), ul = line.match(/^[-*]\s+(.*)$/);
    if (ol) { if (mode !== 'ol') { close(); out += '<ol>'; mode = 'ol'; } out += '<li>' + ol[2] + '</li>'; continue; }
    if (ul) { if (mode !== 'ul') { close(); out += '<ul>'; mode = 'ul'; } out += '<li>' + ul[1] + '</li>'; continue; }
    close();
    out += '<p>' + inline + '</p>';
  }
  close();
  return out;
}

/* ----------------------------------------------------------------- navigation */
function go(view) {
  state.view = view;
  $$('.view').forEach(v => v.classList.toggle('on', v.id === 'view-' + view));
  $$('.navitem').forEach(n => n.classList.toggle('on', n.dataset.view === view));
  $$('.ricon[data-view]').forEach(n => n.classList.toggle('on', n.dataset.view === view));
  if (view === 'agents' && !state.lab) loadLab();
  history.replaceState(null, '', '#' + view);
}
$$('[data-view]').forEach(el => el.addEventListener('click', e => {
  const v = el.dataset.view;
  if (!v) return;
  e.preventDefault();
  go(v);
}));

/* ---------------------------------------------------------------------- KPI */
function renderKpis(o) {
  const k = o.kpi || {};
  const score = k.score || 0;
  const cls = score >= 80 ? 'ok' : score >= 55 ? 'warn' : 'crit';
  const cards = [
    { lab: 'Score de posture', val: score + '/100', sub: 'couverture + bruit critique', cls },
    { lab: 'Alertes 24 h', val: num(k.alerts_24h), sub: (k.alerts_critique + k.alerts_eleve) + ' critiques ou élevées', cls: k.alerts_critique ? 'crit' : '' },
    { lab: 'Critiques', val: num(k.alerts_critique), sub: 'niveau ≥ 12', cls: 'crit' },
    { lab: 'Postes actifs', val: (k.agents_active ?? 0) + '/' + (k.agents_total ?? 0), sub: k.vulns_total ? k.vulns_total + ' vulnérabilités' : 'agents Wazuh enregistrés', cls: '' },
  ];
  $('#kpis').innerHTML = cards.map(c => `
    <div class="kpi ${c.cls}">
      <div class="lab">${esc(c.lab)}</div>
      <div class="val">${esc(c.val)}</div>
      <div class="sub">${esc(c.sub)}</div>
    </div>`).join('');
}

/* ------------------------------------------------------------ volume d'alertes */
function buckets(o) {
  const t = o.timeline || [];
  if (t.length) {
    return t.map(x => ({ label: hhmm(x.ts), crit: 0, high: 0, mid: 0, total: x.count || 0 }));
  }
  // Repli : la serie n'est pas fournie, on la reconstruit depuis les alertes
  // recentes (24 tranches d'une heure).
  const now = new Date();
  const out = [];
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3600e3);
    out.push({ label: String(d.getHours()).padStart(2, '0') + 'h', crit: 0, high: 0, mid: 0, total: 0 });
  }
  (o.recent_alerts || []).forEach(a => {
    const d = new Date(String(a.ts).replace(/(\d{2})(\d{2})$/, '$1:$2'));
    if (isNaN(d)) return;
    const diff = Math.floor((now - d) / 3600e3);
    if (diff < 0 || diff > 23) return;
    const b = out[23 - diff];
    const k = sev(a.level);
    if (b[k] != null) b[k] += 1; else b.mid += 1;
    b.total += 1;
  });
  return out;
}

function renderVolume(o) {
  const data = buckets(o);
  const max = Math.max(1, ...data.map(d => d.total));
  const W = 640, H = 168, pad = 2, bw = W / data.length;
  const total = data.reduce((s, d) => s + d.total, 0);
  $('#volTotal').textContent = num(total) + ' alertes';
  $('#volTag').textContent = (o.timeline || []).length ? (o.timeline.length + ' tranches') : '24 h';

  const bars = data.map((d, i) => {
    const x = i * bw + pad;
    const w = Math.max(1.5, bw - pad * 2);
    const scale = (H - 8) / max;
    let y = H;
    const parts = [['mid', '#64748b'], ['high', '#f59e0b'], ['crit', '#ef4444']];
    let svg = '';
    for (const [key, color] of parts) {
      const v = d[key] || 0;
      if (!v) continue;
      const h = Math.max(1, v * scale);
      y -= h;
      svg += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${w.toFixed(1)}" height="${h.toFixed(1)}" fill="${color}" rx="1"/>`;
    }
    if (!d.total) svg += `<rect x="${x.toFixed(1)}" y="${H - 1}" width="${w.toFixed(1)}" height="1" fill="#1b2721"/>`;
    return svg + `<title>${esc(d.label)} — ${d.total} alerte(s)</title>`;
  }).join('');

  const ticks = data.map((d, i) => (i % 4 === 0)
    ? `<text x="${(i * bw + bw / 2).toFixed(1)}" y="${H + 12}" fill="#6b7d73" font-size="9" font-family="ui-monospace,monospace" text-anchor="middle">${esc(d.label)}</text>`
    : '').join('');

  $('#volChart').setAttribute('viewBox', `0 0 ${W} ${H + 16}`);
  $('#volChart').innerHTML = `<g>${bars}</g>${ticks}`;
}

/* -------------------------------------------------------------------- donut */
function renderDonut(o) {
  const bank = o.alert_bank || {};
  const lv = bank.by_level || {};
  const rows = [
    { k: 'critique', n: (lv['5'] || 0) + (lv['6'] || 0) + (lv['7'] || 0), c: '#ef4444' },
    { k: 'élevé', n: (lv['4'] || 0), c: '#f59e0b' },
    { k: 'moyen', n: (lv['3'] || 0) + (lv['2'] || 0), c: '#64748b' },
  ];
  const total = rows.reduce((s, r) => s + r.n, 0) || 1;
  const R = 46, C = 2 * Math.PI * R;
  let off = 0, arcs = '';
  rows.forEach(r => {
    const len = (r.n / total) * C;
    arcs += `<circle cx="60" cy="60" r="${R}" fill="none" stroke="${r.c}" stroke-width="11"
      stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}"
      transform="rotate(-90 60 60)" stroke-linecap="butt"/>`;
    off += len;
  });
  $('#donut').innerHTML = arcs +
    `<text class="mid" x="60" y="60" text-anchor="middle">${num(bank.total || 0)}</text>` +
    `<text class="midl" x="60" y="74" text-anchor="middle">alertes</text>`;

  $('#sevList').innerHTML = rows.map(r => `
    <div class="brow"><span><i class="dot" style="background:${r.c}"></i> ${esc(r.k)}</span>
      <span class="n">${num(r.n)}</span>
      <div class="btrack"><div class="bfill" style="width:${Math.round(r.n / total * 100)}%;background:${r.c}"></div></div>
    </div>`).join('');
}

/* ------------------------------------------------------------------ alertes */
function alertRows(list, cols) {
  if (!list.length) return `<tr><td colspan="${cols}" class="empty">Aucune alerte à ce niveau.</td></tr>`;
  return list.map(a => {
    const k = sev(a.level);
    const mitre = (a.mitre_ids || []).join(' ');
    if (cols === 5) {
      return `<tr data-i="${a.fingerprint || ''}">
        <td class="mono">${hhmm(a.ts)}</td>
        <td><span class="chip ${k}">${a.level}</span></td>
        <td><div class="desc"><span class="mono">${esc(a.rule_id || '')}</span> ${esc(a.description || '')}</div></td>
        <td class="mono">${esc(a.agent || '—')}</td>
        <td class="mono">${esc(mitre || '—')}</td></tr>`;
    }
    return `<tr data-i="${a.fingerprint || ''}">
      <td class="mono">${hhmm(a.ts)}</td>
      <td><span class="chip ${k}">${a.level}</span></td>
      <td class="mono">${esc(a.rule_id || '')}</td>
      <td><div class="desc">${esc(a.description || '')}</div></td>
      <td class="mono">${esc(a.agent || '—')}</td>
      <td class="mono">${esc(a.srcip || '—')}</td>
      <td class="mono">${esc(mitre || '—')}</td></tr>`;
  }).join('');
}

function bindRows(sel) {
  $$(sel + ' tr[data-i]').forEach(tr => tr.onclick = () => {
    const a = (state.ov?.recent_alerts || []).find(x => x.fingerprint === tr.dataset.i);
    if (a) openAlert(a);
  });
}

function renderRecent(o) {
  $('#recentBody').innerHTML = alertRows((o.recent_alerts || []).slice(0, 10), 5);
  bindRows('#recentBody');
  $('#nAlerts').textContent = num((o.alert_bank || {}).total || (o.recent_alerts || []).length);
}

function renderAlerts(o) {
  let list = o.recent_alerts || [];
  if (state.level !== '0') list = list.filter(a => sev(a.level) === state.level);
  if (state.q) {
    const q = state.q.toLowerCase();
    list = list.filter(a => [a.description, a.agent, a.rule_id, a.srcip, (a.mitre_ids || []).join(' ')]
      .join(' ').toLowerCase().includes(q));
  }
  $('#alertsBody').innerHTML = alertRows(list, 7);
  bindRows('#alertsBody');
  $('#alertsSub').textContent = list.length + ' alerte(s) affichée(s) — banque locale';
}

/* ------------------------------------------------------------------ constats */
function findingCard(f) {
  const lvl = String(f.level || 'info').toLowerCase();
  const cls = lvl.startsWith('crit') ? 'critique' : lvl.startsWith('elev') || lvl.startsWith('élev') ? 'eleve' : lvl.startsWith('moy') ? 'moyen' : 'info';
  const chip = cls === 'critique' ? 'crit' : cls === 'eleve' ? 'high' : cls === 'moyen' ? 'mid' : 'low';
  const actions = (f.actions || []).map(a => `<p style="color:#8aa294">› ${esc(a)}</p>`).join('');
  return `<div class="find ${cls}">
    <div class="b"></div>
    <div style="flex:1">
      <div style="display:flex;gap:8px;align-items:center">
        <span class="chip ${chip}">${esc(f.level || 'info')}</span>
        <h3>${esc(f.title || '')}</h3>
      </div>
      <p>${esc(f.detail || '')}</p>
      ${f.evidence ? `<p class="mono" style="margin-top:4px">preuve : ${esc(f.evidence)}</p>` : ''}
      ${actions}
    </div>
  </div>`;
}

function renderFindings(o) {
  const f = o.findings || [];
  const html = f.length ? f.map(findingCard).join('') : '<div class="empty">Aucun constat.</div>';
  $('#findings').innerHTML = html;
  $('#findingsFull').innerHTML = html;
}

/* ---------------------------------------------------------------- playbooks */
function renderPlaybooks(o) {
  const pb = o.playbooks || [];
  $('#pbCount').textContent = pb.length + ' playbook(s)';
  $('#pbBody').innerHTML = pb.length ? pb.map(p => `
    <tr data-pb="${esc(p.key)}">
      <td><strong>${esc(p.title)}</strong><div class="mono" style="margin-top:2px">${esc(p.key)}</div></td>
      <td><span class="chip ${p.urgency === 'haute' ? 'crit' : p.urgency === 'moyenne' ? 'mid' : 'low'}">${esc(p.urgency)}</span></td>
      <td class="mono">${p.steps}</td>
      <td class="mono">${esc((p.mitre || []).join(' · ') || '—')}</td>
    </tr>`).join('') : '<tr><td colspan="4" class="empty">Aucun playbook.</td></tr>';
  $$('#pbBody tr[data-pb]').forEach(tr => tr.onclick = () => openPlaybook(tr.dataset.pb));
}

/* ------------------------------------------------------------------- bilan */
function renderSummary(o) {
  const s = o.summary || {};
  $('#sumEngine').textContent = s.engine ? (s.engine === 'llm' ? 'LLM · ' + (s.model || '') : 'moteur de règles') : '—';
  $('#summary').innerHTML = s.text
    ? mdRender(s.text) + `<p class="note" style="margin-top:10px">Généré ${esc(dayhm(s.generated_at))} UTC</p>`
    : '<div class="empty">Bilan pas encore généré.</div>';
}

/* ------------------------------------------------------------------ rapports */
function renderReports(o) {
  const rows = [
    ['Collecte', dayhm(o.collected_at) + ' UTC'],
    ['Fraîcheur', fmtAge(o.age_seconds) + (o.stale ? ' — périmé' : '')],
    ['Manager', (o.manager && (o.manager.version || o.manager.status)) || '—'],
    ['Collecteur', (o.collector && o.collector.host) || '—'],
    ['Banque', num((o.alert_bank || {}).total) + ' alertes'],
    ['Erreurs', (o.errors || []).length ? o.errors.join(' · ') : 'aucune'],
  ];
  $('#collectKv').innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');

  const bp = (o.alert_bank || {}).by_playbook || {};
  const entries = Object.entries(bp).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(e => e[1]));
  $('#pbBars').innerHTML = entries.length ? entries.map(([k, n]) => `
    <div class="brow"><span>${esc(k)}</span><span class="n">${num(n)}</span>
      <div class="btrack"><div class="bfill" style="width:${Math.round(n / max * 100)}%;background:var(--green)"></div></div>
    </div>`).join('') : '<div class="empty">Aucune donnée.</div>';
}

/* -------------------------------------------------------------------- agents */
async function loadLab() {
  try {
    const r = await apiFetch('/api/lab/agents');
    if (r.status === 401) { askToken('Jeton absent ou invalide.'); return; }
    state.lab = await r.json();
    renderAgents();
  } catch (err) {
    state.lab = { available: false, error: err.message };
    renderAgents();
  }
}

function renderAgents() {
  const lab = state.lab || { available: false, error: 'chargement…' };
  const agents = lab.agents || [];
  const on = agents.filter(a => a.status === 'ONLINE').length;

  $('#nAgents').textContent = agents.length ? on + '/' + agents.length : '0';
  $('#agentsSub').textContent = lab.available
    ? 'Réseau d\'agents — orchestrateur local, ' + on + ' en ligne'
    : 'Orchestrateur injoignable — ' + (lab.error || 'inconnu');

  $('#agentKpis').innerHTML = [
    { lab: 'Agents en ligne', val: on + '/' + agents.length, sub: 'orchestrateur 127.0.0.1:8000', cls: on === agents.length && agents.length ? 'ok' : 'warn' },
    { lab: 'Tâches traitées', val: num(lab.tasks_total ?? 0), sub: 'depuis le démarrage', cls: '' },
    { lab: 'En cours', val: num(lab.tasks_running ?? 0), sub: 'délégations actives', cls: '' },
    { lab: 'Dernière tâche', val: (lab.tasks || [])[0]?.task_id || '—', sub: (lab.tasks || [])[0]?.status || 'aucune', cls: '' },
  ].map(c => `<div class="kpi ${c.cls}"><div class="lab">${esc(c.lab)}</div><div class="val">${esc(c.val)}</div><div class="sub">${esc(c.sub)}</div></div>`).join('');

  $('#agentCards').innerHTML = agents.length ? agents.map(a => {
    const isOn = a.status === 'ONLINE';
    const port = String(a.endpoint || '').replace(/\/$/, '').split(':').pop();
    const caps = (a.capabilities || []).slice(0, 6);
    return `<div class="acard ${isOn ? '' : 'off'}">
      <div class="top-line"><span class="dot ${isOn ? 'on' : 'off'}"></span>
        <span class="name">${esc(a.agent_id)}</span>
        <span class="port">:${esc(port)}</span></div>
      <div class="note">${esc(a.name || '')}</div>
      <div class="caps">${caps.map(c => `<span>${esc(typeof c === 'string' ? c : c.name || '')}</span>`).join('')}</div>
      <div class="foot">${isOn ? 'dernier contact ' + esc(dayhm(a.last_seen) || '—') : 'hors ligne'}</div>
    </div>`;
  }).join('') : `<div class="empty">${esc(lab.error || 'Aucun agent enregistré.')}</div>`;

  const tasks = (lab.tasks || []).slice().sort((a, b) => {
    // La plus recente en tete : l'orchestrateur renvoie l'ordre de creation.
    const n = t => parseInt(String(t.task_id || '').replace(/\D/g, ''), 10) || 0;
    return n(b) - n(a);
  });
  $('#taskBody').innerHTML = tasks.length ? tasks.slice(0, 8).map(t => `
    <tr><td class="mono">${esc(t.task_id)}</td>
      <td class="mono">${esc(t.capability || '—')}</td>
      <td class="mono">${esc(t.agent_id || '—')}</td>
      <td><span class="chip ${/COMPLETED/.test(t.status) ? 'ok' : /FAIL|ERROR|NO_AGENT/.test(t.status) ? 'crit' : 'ghost'}">${esc(t.status || '')}</span></td>
      <td class="mono">${t.duration_ms ? Math.round(t.duration_ms) + ' ms' : '—'}</td></tr>`).join('')
    : '<tr><td colspan="5" class="empty">Aucune tâche enregistrée.</td></tr>';
}

/* -------------------------------------------------------------------- tiroir */
function openDrawer(chipText, title, body) {
  $('#dChip').className = 'chip ' + (chipText.cls || 'ghost');
  $('#dChip').textContent = chipText.text;
  $('#dTitle').textContent = title;
  $('#dBody').innerHTML = body;
  $('#drawer').classList.add('open');
}
$('#dClose').onclick = () => $('#drawer').classList.remove('open');
document.addEventListener('keydown', e => { if (e.key === 'Escape') $('#drawer').classList.remove('open'); });

function openAlert(a) {
  const k = sev(a.level);
  const kv = [
    ['Règle', a.rule_id], ['Niveau', a.level + ' — ' + sevLabel(k)], ['Agent', a.agent],
    ['Horodatage', dayhm(a.ts) + ' UTC'], ['Source', a.srcip || '—'], ['Groupes', (a.groups || []).join(', ') || '—'],
    ['MITRE', (a.mitre_ids || []).join(', ') || '—'], ['Empreinte', a.fingerprint || '—'],
  ];
  openDrawer({ text: sevLabel(k), cls: k }, a.description || 'Alerte',
    `<dl class="kv">${kv.map(([x, y]) => `<dt>${esc(x)}</dt><dd>${esc(y)}</dd>`).join('')}</dl>
     <div style="margin-top:14px;display:flex;gap:8px">
       <button class="btn primary" id="dPb">Piste de réponse</button>
       <button class="btn" id="dCopy">Copier l'empreinte</button>
     </div>`);
  $('#dPb').onclick = () => openPlaybook(a.playbook || 'generic_high');
  $('#dCopy').onclick = async () => {
    try { await navigator.clipboard.writeText(a.fingerprint || ''); toast('Empreinte copiée'); }
    catch { toast('Copie refusée par le navigateur'); }
  };
}

async function openPlaybook(key) {
  openDrawer({ text: 'playbook', cls: 'ghost' }, 'Piste de réponse', '<div class="empty">chargement…</div>');
  try {
    const r = await apiFetch('/api/playbook/' + encodeURIComponent(key));
    const { playbook: p } = await r.json();
    $('#dTitle').textContent = p.title;
    $('#dChip').textContent = 'urgence ' + p.urgency;
    $('#dChip').className = 'chip ' + (p.urgency === 'haute' ? 'crit' : p.urgency === 'moyenne' ? 'mid' : 'low');
    const cmds = (p.commands || []).map(c => `
      <div class="note" style="margin-top:6px">${esc(c.label)} <span style="opacity:.6">[${esc(c.os)}]</span></div>
      <div class="mono" style="position:relative;background:#06090a;border:1px solid var(--line);border-radius:6px;padding:8px 40px 8px 10px;margin:4px 0 10px;color:#b7f7cf;white-space:pre-wrap;word-break:break-word">${esc(c.cmd)}<button class="btn" data-copy="${esc(c.cmd)}" style="position:absolute;top:4px;right:4px;padding:2px 7px;font-size:10px">Copier</button></div>`).join('');
    $('#dBody').innerHTML = `
      <p style="margin-top:0;color:var(--dim)">${esc(p.why || '')}</p>
      ${(p.mitre || []).length ? `<p class="note mono">MITRE : ${p.mitre.map(esc).join(' · ')}</p>` : ''}
      <h3 style="font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim2);margin:16px 0 6px">Étapes</h3>
      <ol style="padding-left:18px;color:var(--dim)">${(p.steps || []).map(s => `<li style="margin:4px 0">${esc(s)}</li>`).join('')}</ol>
      <h3 style="font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim2);margin:16px 0 6px">Commandes</h3>
      ${cmds}
      <p class="note">Rien n'est exécuté automatiquement : ces commandes sont à lancer par l'analyste.</p>`;
    $$('#dBody [data-copy]').forEach(b => b.onclick = async () => {
      try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Copié'; }
      catch { b.textContent = 'Ctrl+C'; }
      setTimeout(() => { b.textContent = 'Copier'; }, 1500);
    });
    history.replaceState(null, '', '#pb=' + encodeURIComponent(key));
  } catch (err) {
    $('#dBody').innerHTML = '<div class="empty">Piste indisponible : ' + esc(err.message) + '</div>';
  }
}

/* ------------------------------------------------------------------- rendu */
function render(o) {
  state.ov = o;
  const stale = o.stale;
  $('#railDot').style.background = stale ? 'var(--amber)' : 'var(--green)';
  $('#liveLabel').textContent = stale ? 'RETARD' : 'LIVE';
  $('#collected').textContent = 'dernière collecte ' + fmtAge(o.age_seconds);
  $('#dashSub').textContent = 'Situation consolidée du SOC · ' + fmtAge(o.age_seconds);
  $('#sideStatus').innerHTML = (o.errors || []).length
    ? `<span style="color:#fca5a5">collecte : ${esc(o.errors[0])}</span>`
    : `collecte saine · <span class="mono">${esc(dayhm(o.collected_at))}</span>`;

  renderKpis(o);
  renderVolume(o);
  renderDonut(o);
  renderRecent(o);
  renderFindings(o);
  renderAlerts(o);
  renderPlaybooks(o);
  renderSummary(o);
  renderReports(o);
}

async function load() {
  try {
    const r = await apiFetch('/api/overview');
    if (r.status === 401) { askToken('Jeton absent ou invalide.'); return; }
    const o = await r.json();
    if (!o.ready) {
      $('#sideStatus').textContent = o.message || 'aucune donnée';
      $('#recentBody').innerHTML = `<tr><td colspan="5" class="empty">${esc(o.message || 'Aucun snapshot.')}</td></tr>`;
      return;
    }
    render(o);
    if (state.view === 'agents') loadLab();
  } catch (err) {
    $('#sideStatus').innerHTML = `<span style="color:#fca5a5">tableau de bord injoignable : ${esc(err.message)}</span>`;
  }
}

/* ------------------------------------------------------------------ actions */
$('#btnRefresh').onclick = () => { load(); if (state.view === 'agents') loadLab(); toast('Actualisé'); };
$('#btnAgents').onclick = () => { loadLab().then(() => toast('Agents actualisés')); };
$('#btnSummary').onclick = async () => {
  const b = $('#btnSummary');
  b.textContent = 'Génération…';
  try { await apiFetch('/api/summary/refresh', { method: 'POST' }); await load(); toast('Bilan régénéré'); }
  finally { b.textContent = 'Régénérer le bilan'; }
};
$('#btnExport').onclick = () => {
  const list = state.ov?.recent_alerts || [];
  const head = 'ts,niveau,regle,description,agent,source,mitre\n';
  const body = list.map(a => [a.ts, a.level, a.rule_id, '"' + String(a.description || '').replace(/"/g, '""') + '"',
    a.agent, a.srcip || '', (a.mitre_ids || []).join('|')].join(',')).join('\n');
  const blob = new Blob([head + body], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'alertes-soc.csv';
  a.click();
  URL.revokeObjectURL(a.href);
  toast('CSV exporté');
};
$$('#filters .fchip').forEach(b => b.onclick = () => {
  $$('#filters .fchip').forEach(x => x.classList.remove('on'));
  b.classList.add('on');
  state.level = b.dataset.level;
  if (state.ov) renderAlerts(state.ov);
});
$('#q').addEventListener('input', e => {
  state.q = e.target.value.trim();
  if (state.ov) renderAlerts(state.ov);
});
$('#clock').onclick = () => {};

/* -------------------------------------------------------------------- boot */
function tick() {
  const d = new Date();
  $('#clock').textContent = String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
}
tick();
setInterval(tick, 15000);

const initial = (location.hash || '').replace('#', '');
if (['dashboard', 'alerts', 'agents', 'investigations', 'reports'].includes(initial)) go(initial);
load();
loadLab();
if (location.hash.startsWith('#pb=')) openPlaybook(decodeURIComponent(location.hash.slice(4)));
setInterval(() => { if (!document.hidden) load(); }, 60000);
