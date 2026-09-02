/* ============================================================
   CloudGuard AI — Real-Time Monitoring Engine
   ============================================================ */

'use strict';

// ── Constants ──────────────────────────────────────────────
const NAV_TITLES = {
  overview:  'Security overview',
  detection: 'Threat detection',
  traffic:   'Network traffic',
  threatmap: 'Global threat map',
  alerts:    'Security alerts',
  auditlog:  'Audit log',
  reports:   'Reports & analytics'
};

const MODEL_LABELS = {
  rf:  'Random Forest v2.4',
  svm: 'SVM v1.9',
  xgb: 'XGBoost v3.1',
  iso: 'Isolation Forest v1.2'
};

const MODEL_ACCURACY = { rf: 98.7, svm: 96.1, xgb: 99.1, iso: 94.3 };

const GEO_SOURCES = [
  { city: 'Moscow',      country: 'Russia',       lat: 55.75, lng: 37.62,  flag: '🇷🇺' },
  { city: 'Beijing',     country: 'China',         lat: 39.90, lng: 116.40, flag: '🇨🇳' },
  { city: 'Seoul',       country: 'South Korea',   lat: 37.56, lng: 126.97, flag: '🇰🇷' },
  { city: 'Tehran',      country: 'Iran',          lat: 35.69, lng: 51.39,  flag: '🇮🇷' },
  { city: 'Bucharest',   country: 'Romania',       lat: 44.43, lng: 26.10,  flag: '🇷🇴' },
  { city: 'Lagos',       country: 'Nigeria',       lat: 6.45,  lng: 3.39,   flag: '🇳🇬' },
  { city: 'São Paulo',   country: 'Brazil',        lat: -23.54, lng: -46.63, flag: '🇧🇷' },
  { city: 'Amsterdam',   country: 'Netherlands',   lat: 52.37, lng: 4.90,   flag: '🇳🇱' },
  { city: 'Minsk',       country: 'Belarus',       lat: 53.90, lng: 27.56,  flag: '🇧🇾' },
  { city: 'Pyongyang',   country: 'North Korea',   lat: 39.02, lng: 125.75, flag: '🇰🇵' },
  { city: 'Caracas',     country: 'Venezuela',     lat: 10.48, lng: -66.87, flag: '🇻🇪' },
  { city: 'Jakarta',     country: 'Indonesia',     lat: -6.21, lng: 106.84, flag: '🇮🇩' }
];

const TARGET = { lat: 39.04, lng: -77.49, label: 'AWS us-east-1' };

const EVENT_TEMPLATES = [
  { type: 'safe',       proto: 'HTTPS', msg: 'Normal HTTPS traffic classified benign',       score: () => rnd(0.01, 0.09) },
  { type: 'safe',       proto: 'DNS',   msg: 'DNS resolution · benign domain',                score: () => rnd(0.02, 0.07) },
  { type: 'safe',       proto: 'SSH',   msg: 'Authenticated SSH session · known host',        score: () => rnd(0.03, 0.11) },
  { type: 'safe',       proto: 'HTTP',  msg: 'CloudTrail API event processed',                score: () => rnd(0.01, 0.05) },
  { type: 'safe',       proto: 'TLS',   msg: 'Certificate rotation · valid chain',            score: () => rnd(0.01, 0.06) },
  { type: 'suspicious', proto: 'TCP',   msg: 'Outbound volume spike · data exfil suspected', score: () => rnd(0.75, 0.89) },
  { type: 'suspicious', proto: 'UDP',   msg: 'Port scan anomaly · 3000+ ports probed',       score: () => rnd(0.71, 0.85) },
  { type: 'suspicious', proto: 'ICMP',  msg: 'ICMP flood · possible DDoS probe',             score: () => rnd(0.68, 0.82) },
  { type: 'threat',     proto: 'HTTP',  msg: 'Ransomware C2 beacon detected',                score: () => rnd(0.91, 0.99) },
  { type: 'threat',     proto: 'SMTP',  msg: 'Phishing payload in mail body',                score: () => rnd(0.88, 0.98) },
  { type: 'threat',     proto: 'DNS',   msg: 'DNS tunneling · covert channel',               score: () => rnd(0.85, 0.97) },
  { type: 'threat',     proto: 'RDP',   msg: 'Brute-force login attempt · RDP',              score: () => rnd(0.86, 0.99) },
  { type: 'threat',     proto: 'SSH',   msg: 'Credential stuffing · 82 failed auths',        score: () => rnd(0.90, 0.99) },
  { type: 'threat',     proto: 'TLS',   msg: 'Self-signed cert · possible MitM',             score: () => rnd(0.83, 0.95) }
];

const PROTOCOLS = ['HTTPS', 'DNS', 'SSH', 'HTTP', 'TLS', 'TCP', 'UDP', 'SMTP', 'RDP'];

// ── Helpers ────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const rnd  = (a, b) => +(Math.random() * (b - a) + a).toFixed(3);
const rndI = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const pick = arr => arr[rndI(0, arr.length - 1)];
const fmtN = n => Number(n).toLocaleString('en-US');
const fmtT = d => new Intl.DateTimeFormat('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(d);
const fmtRel = d => {
  const s = Math.floor((Date.now() - d) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
};
const randIP = () => `10.${rndI(0,255)}.${rndI(0,255)}.${rndI(1,254)}`;

// ── State ──────────────────────────────────────────────────
const state = {
  incidents: [
    { id: 1, severity: 'critical', title: 'Ransomware C2 beacon detected',       source: '10.24.18.42 → finance-api',    ts: new Date(Date.now() - 2*60000),   status: 'open' },
    { id: 2, severity: 'high',     title: 'Unusual outbound data transfer',       source: '10.24.33.18 → external IP',    ts: new Date(Date.now() - 18*60000),  status: 'open' },
    { id: 3, severity: 'medium',   title: 'Suspicious authentication pattern',    source: 'admin@cloudguard.io',          ts: new Date(Date.now() - 42*60000),  status: 'open' },
    { id: 4, severity: 'high',     title: 'Phishing payload blocked',             source: 'mail-gateway → inbox',         ts: new Date(Date.now() - 3600000),   status: 'resolved' },
    { id: 5, severity: 'medium',   title: 'Port scan anomaly detected',           source: '172.16.0.88 → core-vpc',      ts: new Date(Date.now() - 7200000),   status: 'resolved' }
  ],
  nextId: 6,
  events: 2481920,
  threats: 27,
  activeModel: 'rf',
  streamPaused: false,
  settings: { pushNotif: false, sound: false, autoResolve: 60, maxFeed: 20, threshold: 75 },
  notifications: [],
  auditLog: [],
  attackVectors: [],
  countryHits: {},
  throughputHistory: { inbound: Array(30).fill(0), outbound: Array(30).fill(0) },
  activityHistory: Array(24).fill(0).map(() => rndI(5, 85)),
  eventsPerMinBucket: [],
  suspiciousCount: 0,
  totalFeedCount: 0,
  theme: 'dark'
};

// ── Audit Logger ───────────────────────────────────────────
function audit(category, msg) {
  state.auditLog.unshift({ ts: new Date(), category, msg });
  if (state.auditLog.length > 200) state.auditLog.pop();
  if ($('auditlog') && $('auditlog').classList.contains('active')) renderAuditLog('all');
}

// ── Toast ──────────────────────────────────────────────────
function showToast(text, type = 'info') {
  const t = $('toast');
  t.textContent = text;
  t.className = `toast show toast-${type}`;
  clearTimeout(t._to);
  t._to = setTimeout(() => t.classList.remove('show'), 3000);
}

// ── Clock ──────────────────────────────────────────────────
function setClock() {
  $('clock').textContent = new Intl.DateTimeFormat('en-US', {
    weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit'
  }).format(new Date());
}

// ── Navigation ─────────────────────────────────────────────
function switchView(view) {
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === view));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  $('pageTitle').textContent = NAV_TITLES[view] || view;
  window.scrollTo({ top: 0, behavior: 'smooth' });
  if (view === 'threatmap' && !mapState.initialized) initMap();
  if (view === 'traffic') updateTrafficView();
  if (view === 'auditlog') renderAuditLog('all');
}

// ── Incidents & Alerts ─────────────────────────────────────
function renderIncidents() {
  $('incidentList').innerHTML = state.incidents
    .filter(i => i.status === 'open')
    .slice(0, 4)
    .map(item => `<div class="incident">
      <i class="severity ${item.severity}"></i>
      <div><strong>${item.title}</strong><small>${item.source}</small></div>
      <time>${fmtRel(item.ts)}</time>
    </div>`).join('');
  $('alertBadge').textContent = state.incidents.filter(i => i.status === 'open').length;
}

function renderAlerts(filter = 'all') {
  const rows = state.incidents.filter(i =>
    filter === 'all' ? true :
    filter === 'resolved' ? i.status === 'resolved' :
    i.severity === filter
  );
  $('alertRows').innerHTML = rows.length
    ? rows.map(i => `<div class="alert-row">
        <span class="badge ${i.severity}">${i.severity.toUpperCase()}</span>
        <strong>${i.title}</strong>
        <span class="source">${i.source}</span>
        <time>${fmtRel(i.ts)}</time>
        <span class="status-pill ${i.status}">${i.status === 'open' ? '● OPEN' : '✓ RESOLVED'}</span>
        ${i.status === 'open'
          ? `<button class="resolve" data-id="${i.id}">Resolve</button>`
          : '<span></span>'}
      </div>`).join('')
    : '<div class="empty-result"><span>✓</span><div><h3>No matching alerts</h3><p>Your filter has no incidents at this time.</p></div></div>';
}

function addIncident(severity, title, source) {
  const inc = { id: state.nextId++, severity, title, source, ts: new Date(), status: 'open' };
  state.incidents.unshift(inc);
  state.threats++;
  $('threatCount').textContent = state.threats;
  $('threatDelta').textContent = state.threats - 27;
  renderIncidents();
  renderAlerts(document.querySelector('.filter.active')?.dataset.filter || 'all');
  pushNotification(`🚨 ${severity.toUpperCase()}: ${title}`, severity);
  audit('alert', `New ${severity} alert: "${title}" from ${source}`);
}

// ── Notification Center ────────────────────────────────────
function pushNotification(text, sev = 'info') {
  const n = { id: Date.now(), text, sev, ts: new Date() };
  state.notifications.unshift(n);
  if (state.notifications.length > 30) state.notifications.pop();
  renderNotifications();
  $('notifDot').style.display = 'block';
  if (state.settings.pushNotif && 'Notification' in window && Notification.permission === 'granted') {
    new Notification('CloudGuard AI', { body: text });
  }
}

function renderNotifications() {
  const list = $('notifList');
  if (!state.notifications.length) {
    list.innerHTML = '<p class="notif-empty">No notifications</p>';
    return;
  }
  list.innerHTML = state.notifications.slice(0, 15).map(n =>
    `<div class="notif-item notif-${n.sev}">
      <span class="notif-text">${n.text}</span>
      <time>${fmtRel(n.ts)}</time>
    </div>`
  ).join('');
}

// ── Live Event Feed ────────────────────────────────────────
function appendFeed() {
  if (state.streamPaused) return;
  const tpl = pick(EVENT_TEMPLATES);
  const ip   = randIP();
  const score = tpl.score();
  const ts   = fmtT(new Date());
  const feed = $('eventFeed');
  const line = document.createElement('div');
  line.className = tpl.type;
  line.textContent = `${ts}  [${tpl.proto}]  ${ip}  ${tpl.msg}  ·  score ${score.toFixed(2)}`;
  feed.appendChild(line);

  state.eventsPerMinBucket.push(Date.now());
  state.totalFeedCount++;
  if (tpl.type !== 'safe') state.suspiciousCount++;

  const max = state.settings.maxFeed;
  while (feed.children.length > max) feed.removeChild(feed.firstChild);
  feed.scrollTop = feed.scrollHeight;

  // Update stats
  const oneMin = Date.now() - 60000;
  state.eventsPerMinBucket = state.eventsPerMinBucket.filter(t => t > oneMin);
  $('eventsPerMin').textContent = state.eventsPerMinBucket.length;
  const rate = state.totalFeedCount > 0 ? Math.round(state.suspiciousCount / state.totalFeedCount * 100) : 0;
  $('suspiciousRate').textContent = rate + '%';

  // Randomly escalate threat to incident
  if (tpl.type === 'threat' && Math.random() < 0.18) {
    const sev = score > 0.93 ? 'critical' : 'high';
    addIncident(sev, tpl.msg, `${ip} → core-vpc`);
    // trigger pipeline alert state
    pipelineFlash();
  }
}

function pipelineFlash() {
  const icon = $('pipelineAlert');
  if (!icon) return;
  icon.textContent = '●';
  icon.style.color = 'var(--orange)';
  setTimeout(() => { icon.textContent = '○'; icon.style.color = ''; }, 2500);
}

// ── Scan ──────────────────────────────────────────────────
function runScan(label = 'Live traffic', parsedRows = null) {
  const model  = state.activeModel;
  const acc    = MODEL_ACCURACY[model];
  const conf   = (acc - 1 + Math.random() * 2).toFixed(1);
  const threat = pick(['Credential access', 'Lateral movement', 'Data exfiltration', 'C2 beacon', 'Privilege escalation']);
  const score  = rnd(0.82, 0.99);

  state.events += rndI(250, 900);
  $('eventCount').textContent = fmtN(state.events);

  let parsedHtml = '';
  if (parsedRows) {
    parsedHtml = `<div class="parsed-rows"><p class="eyebrow">PARSED FEATURES · ${parsedRows} rows</p></div>`;
  }

  $('scanResult').innerHTML = `<div class="scan-result">
    <div class="verdict">
      <span class="risk">!</span>
      <div>
        <p class="eyebrow">CLASSIFICATION COMPLETE · ${MODEL_LABELS[model]}</p>
        <h3>${threat} detected in ${label}</h3>
        <p>Behavioural pattern consistent with ${threat.toLowerCase()}. Score: ${score} · Confidence: ${conf}%</p>
        ${parsedHtml}
      </div>
    </div>
    <div class="confidence"><b>${conf}%</b><span>model confidence</span><small class="muted" style="display:block;margin-top:5px">Threshold: ${state.settings.threshold}%</small></div>
  </div>`;

  appendFeed();
  showToast('Scan complete — detection result updated', 'success');
  audit('analyst', `Manual scan run on "${label}" using ${MODEL_LABELS[model]}`);
  addIncident('high', `${threat} detected in ${label}`, `${randIP()} → cloud-infra`);
}

// ── File Upload & CSV Parsing ──────────────────────────────
function handleFileUpload(file) {
  if (!file) return;
  $('fileStatus').textContent = `${file.name} · ${Math.ceil(file.size / 1024)} KB`;
  audit('analyst', `Log file uploaded: ${file.name} (${Math.ceil(file.size/1024)} KB)`);

  const ext = file.name.split('.').pop().toLowerCase();
  if (ext === 'csv' || ext === 'txt') {
    Papa.parse(file, {
      header: true,
      skipEmptyLines: true,
      complete: result => {
        const rows = result.data.length;
        const cols = result.meta.fields || [];
        const summary = $('parsedSummary');
        summary.hidden = false;
        summary.innerHTML = `<p class="eyebrow">PARSED</p>
          <strong>${fmtN(rows)} rows</strong>
          <small>${cols.slice(0, 5).join(', ')}${cols.length > 5 ? '…' : ''}</small>`;
        showToast(`Parsed ${fmtN(rows)} rows from ${file.name}`, 'success');
        runScan(file.name, rows);
      },
      error: () => runScan(file.name)
    });
  } else {
    runScan(file.name);
  }
}

// ── Chart.js — Activity Chart (Overview) ──────────────────
let activityChartInstance = null;
function initActivityChart() {
  const ctx = $('activityChart');
  if (!ctx) return;
  const labels = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2,'0')}:00`);
  activityChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Threats',
        data: state.activityHistory,
        backgroundColor: state.activityHistory.map(v => v > 75
          ? 'rgba(255,173,82,0.7)'
          : 'rgba(90,228,210,0.55)'),
        borderColor: state.activityHistory.map(v => v > 75
          ? 'rgba(255,173,82,1)'
          : 'rgba(90,228,210,0.9)'),
        borderWidth: 1,
        borderRadius: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { callbacks: {
        label: c => ` ${c.raw} events`
      }}},
      scales: {
        x: { grid: { color: 'rgba(158,217,205,0.06)' }, ticks: { color: '#718c87', font: { family: 'DM Mono', size: 9 }, maxTicksLimit: 7 }},
        y: { grid: { color: 'rgba(158,217,205,0.06)' }, ticks: { color: '#718c87', font: { family: 'DM Mono', size: 9 }}, beginAtZero: true }
      }
    }
  });
}

function updateActivityChart(range) {
  if (!activityChartInstance) return;
  const data = range === '7 days'
    ? Array.from({ length: 7 }, () => rndI(20, 150))
    : state.activityHistory;
  const labels = range === '7 days'
    ? ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
    : Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2,'0')}:00`);
  activityChartInstance.data.labels = labels;
  activityChartInstance.data.datasets[0].data = data;
  activityChartInstance.data.datasets[0].backgroundColor = data.map(v =>
    v > 75 ? 'rgba(255,173,82,0.7)' : 'rgba(90,228,210,0.55)');
  activityChartInstance.data.datasets[0].borderColor = data.map(v =>
    v > 75 ? 'rgba(255,173,82,1)' : 'rgba(90,228,210,0.9)');
  activityChartInstance.update('none');
  $('chartTotal').textContent = range === '7 days' ? data.reduce((a,b)=>a+b,0) : state.threats;
}

// ── Chart.js — Throughput Chart (Traffic) ─────────────────
let throughputChartInstance = null;
function initThroughputChart() {
  const ctx = $('throughputChart');
  if (!ctx || throughputChartInstance) return;
  const labels = Array.from({ length: 30 }, (_, i) => `-${29-i}s`);
  throughputChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label: 'Inbound',  data: [...state.throughputHistory.inbound],  borderColor: 'rgba(90,228,210,0.85)',  backgroundColor: 'rgba(90,228,210,0.08)', fill: true, tension: 0.4, pointRadius: 0 },
        { label: 'Outbound', data: [...state.throughputHistory.outbound], borderColor: 'rgba(255,173,82,0.85)',  backgroundColor: 'rgba(255,173,82,0.08)', fill: true, tension: 0.4, pointRadius: 0 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { labels: { color: '#8ba49f', font: { family: 'Manrope', size: 11 }, boxWidth: 10 }}},
      scales: {
        x: { grid: { color: 'rgba(158,217,205,0.06)' }, ticks: { color: '#718c87', font: { family: 'DM Mono', size: 9 }, maxTicksLimit: 6 }},
        y: { grid: { color: 'rgba(158,217,205,0.06)' }, ticks: { color: '#718c87', font: { family: 'DM Mono', size: 9 }, callback: v => v + ' MB' }, beginAtZero: true }
      }
    }
  });
}

// ── Chart.js — Weekly Chart (Reports) ────────────────────
let weeklyChartInstance = null;
function initWeeklyChart() {
  const ctx = $('weeklyChart');
  if (!ctx || weeklyChartInstance) return;
  const days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  const data = [24, 38, 45, 27, 62, 48, state.threats];
  weeklyChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels: days,
      datasets: [{
        label: 'Threats detected',
        data,
        borderColor: 'rgba(168,148,255,0.9)',
        backgroundColor: 'rgba(168,148,255,0.08)',
        fill: true,
        tension: 0.4,
        pointBackgroundColor: 'rgba(168,148,255,1)',
        pointRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }},
      scales: {
        x: { grid: { color: 'rgba(158,217,205,0.06)' }, ticks: { color: '#718c87', font: { family: 'DM Mono' }}},
        y: { grid: { color: 'rgba(158,217,205,0.06)' }, ticks: { color: '#718c87', font: { family: 'DM Mono' }}, beginAtZero: true }
      }
    }
  });
}

// ── Network Traffic View ───────────────────────────────────
const PROTO_WEIGHTS = { HTTPS: 0.42, DNS: 0.18, SSH: 0.10, HTTP: 0.08, TLS: 0.09, TCP: 0.06, UDP: 0.04, SMTP: 0.02, RDP: 0.01 };
let trafficInterval = null;

function updateTrafficView() {
  initThroughputChart();
  const inb = rnd(12, 95);
  const out = rnd(5, 60);
  const pps = rndI(1200, 8500);
  const anomaly = rnd(0.01, 0.35);

  state.throughputHistory.inbound.push(inb);
  state.throughputHistory.inbound.shift();
  state.throughputHistory.outbound.push(out);
  state.throughputHistory.outbound.shift();

  $('inboundRate').textContent  = inb.toFixed(1) + ' MB/s';
  $('outboundRate').textContent = out.toFixed(1) + ' MB/s';
  $('ppsRate').textContent      = fmtN(pps);
  $('anomalyScore').textContent = anomaly.toFixed(2);
  $('anomalyScore').className   = anomaly > 0.6 ? 'warning' : anomaly > 0.3 ? '' : 'positive';

  if (throughputChartInstance) {
    throughputChartInstance.data.datasets[0].data = [...state.throughputHistory.inbound];
    throughputChartInstance.data.datasets[1].data = [...state.throughputHistory.outbound];
    throughputChartInstance.update('none');
  }

  // Protocol breakdown
  $('protoList').innerHTML = Object.entries(PROTO_WEIGHTS)
    .sort((a, b) => b[1] - a[1])
    .map(([p, w]) => {
      const pct = Math.round(w * 100);
      const color = p === 'RDP' || p === 'SMTP' ? 'var(--orange)' : 'var(--cyan)';
      return `<div class="proto-row">
        <span class="proto-name">${p}</span>
        <div class="proto-bar-wrap"><div class="proto-bar" style="width:${pct}%;background:${color}"></div></div>
        <span class="proto-pct">${pct}%</span>
      </div>`;
    }).join('');

  // Top talkers
  const talkers = Array.from({ length: 5 }, () => ({
    ip: randIP(), bytes: rndI(50, 980), proto: pick(PROTOCOLS), risk: Math.random() > 0.75 ? 'high' : 'low'
  })).sort((a, b) => b.bytes - a.bytes);
  $('topTalkers').innerHTML = talkers.map(t => `<div class="talker-row">
    <span class="talker-ip">${t.ip}</span>
    <span class="proto-badge">${t.proto}</span>
    <div class="talker-bar-wrap"><div class="talker-bar" style="width:${t.bytes/10}%;background:${t.risk==='high'?'var(--orange)':'var(--cyan)'}"></div></div>
    <span class="talker-bytes">${t.bytes} MB</span>
    <span class="talker-risk ${t.risk}">${t.risk === 'high' ? '⚠ HIGH' : '✓ OK'}</span>
  </div>`).join('');
}

// ── Leaflet Threat Map ─────────────────────────────────────
const mapState = { initialized: false, map: null, markers: [], arcLayer: null };

function initMap() {
  if (mapState.initialized) return;
  mapState.initialized = true;

  const container = $('threatMapContainer');
  container.style.height = '420px';

  mapState.map = L.map('threatMapContainer', {
    center: [20, 10],
    zoom: 2,
    zoomControl: true,
    attributionControl: false
  });

  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '© OpenStreetMap contributors © CARTO',
    subdomains: 'abcd',
    maxZoom: 19
  }).addTo(mapState.map);

  // Target marker
  const targetIcon = L.divIcon({ className: '', html: '<div class="map-marker map-target">🛡</div>', iconSize: [30, 30], iconAnchor: [15, 15] });
  L.marker([TARGET.lat, TARGET.lng], { icon: targetIcon }).addTo(mapState.map).bindPopup(`<b>${TARGET.label}</b><br>Your protected infrastructure`);

  // Initial attack markers
  GEO_SOURCES.forEach(src => addAttackMarker(src));

  // Periodic new attacks
  setInterval(() => {
    const src = pick(GEO_SOURCES);
    addAttackMarker(src);
    updateCountryHits(src);
    updateAttackVectors(src);
  }, 4000);

  renderCountryList();
}

function addAttackMarker(src) {
  const sev   = Math.random() > 0.6 ? 'critical' : Math.random() > 0.5 ? 'high' : 'suspicious';
  const color = sev === 'critical' ? '#ff7070' : sev === 'high' ? '#ffad52' : '#5ae4d2';
  const icon  = L.divIcon({ className: '', html: `<div class="map-marker" style="background:${color};box-shadow:0 0 12px ${color}"></div>`, iconSize: [12, 12], iconAnchor: [6, 6] });
  const marker = L.marker([src.lat + rnd(-1,1), src.lng + rnd(-1,1)], { icon })
    .addTo(mapState.map)
    .bindPopup(`<b>${src.city}, ${src.country}</b><br>Severity: ${sev}<br>Protocol: ${pick(PROTOCOLS)}`);

  // Draw arc to target
  const arcPoints = createArc([src.lat, src.lng], [TARGET.lat, TARGET.lng]);
  const polyline = L.polyline(arcPoints, { color, weight: 1, opacity: 0.5, dashArray: '4,6' }).addTo(mapState.map);

  // Fade and remove after 8s
  setTimeout(() => {
    mapState.map.removeLayer(marker);
    mapState.map.removeLayer(polyline);
  }, 8000);

  updateCountryHits(src);
}

function createArc(from, to, steps = 30) {
  const points = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const lat = from[0] + (to[0] - from[0]) * t;
    const lng = from[1] + (to[1] - from[1]) * t;
    const arc = Math.sin(Math.PI * t) * 20;
    points.push([lat + arc, lng]);
  }
  return points;
}

function updateCountryHits(src) {
  state.countryHits[src.country] = (state.countryHits[src.country] || 0) + 1;
  renderCountryList();
}

function renderCountryList() {
  const sorted = Object.entries(state.countryHits)
    .sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = sorted[0]?.[1] || 1;
  $('countryList').innerHTML = sorted.map(([country, count]) => {
    const src = GEO_SOURCES.find(s => s.country === country);
    const pct = Math.round(count / max * 100);
    return `<div class="country-row">
      <span>${src?.flag || '🌍'} ${country}</span>
      <div class="country-bar-wrap"><div class="country-bar" style="width:${pct}%"></div></div>
      <span class="country-count">${count}</span>
    </div>`;
  }).join('');
}

function updateAttackVectors(src) {
  state.attackVectors.unshift({ src, ts: new Date(), proto: pick(PROTOCOLS), score: rnd(0.6, 0.99) });
  if (state.attackVectors.length > 8) state.attackVectors.pop();
  $('attackVectors').innerHTML = state.attackVectors.map(v => `<div class="vector-row">
    <div class="vector-from">${v.src.flag} ${v.src.city}</div>
    <div class="vector-arrow">→ ${TARGET.label}</div>
    <div class="vector-meta">${v.proto} · ${fmtRel(v.ts)} · <span class="warning">${v.score.toFixed(2)}</span></div>
  </div>`).join('');
}

// ── Audit Log ─────────────────────────────────────────────
function renderAuditLog(filter) {
  document.querySelectorAll('.audit-filter').forEach(b => b.classList.toggle('active', b.dataset.afilter === filter));
  const logs = filter === 'all' ? state.auditLog : state.auditLog.filter(l => l.category === filter);
  $('auditTable').innerHTML = logs.length
    ? logs.map(l => `<div class="audit-row">
        <span class="audit-cat audit-${l.category}">${l.category.toUpperCase()}</span>
        <span class="audit-msg">${l.msg}</span>
        <time class="audit-ts">${fmtT(l.ts)}</time>
      </div>`).join('')
    : '<p class="muted" style="padding:20px">No log entries for this filter.</p>';
}

// ── Settings ──────────────────────────────────────────────
function openSettings() {
  $('settingsOverlay').hidden = false;
  $('pushNotifToggle').checked = state.settings.pushNotif;
  $('soundToggle').checked     = state.settings.sound;
  $('autoResolve').value       = state.settings.autoResolve;
  $('maxFeed').value           = state.settings.maxFeed;
  $('confidenceThreshold').value = state.settings.threshold;
  $('thresholdLabel').textContent = state.settings.threshold + '%';
}
function saveSettings() {
  state.settings.pushNotif   = $('pushNotifToggle').checked;
  state.settings.sound       = $('soundToggle').checked;
  state.settings.autoResolve = Number($('autoResolve').value);
  state.settings.maxFeed     = Number($('maxFeed').value);
  state.settings.threshold   = Number($('confidenceThreshold').value);

  // Safely request push notification permission — the Notification API
  // can throw SecurityError on file:// protocol or in restricted contexts.
  if (state.settings.pushNotif) {
    try {
      if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission().catch(() => {
          // Permission denied silently — that's fine
        });
      } else if (!('Notification' in window)) {
        // Browser doesn't support notifications — disable the toggle silently
        state.settings.pushNotif = false;
        $('pushNotifToggle').checked = false;
      }
    } catch (e) {
      // SecurityError on file:// or other restricted origin — disable gracefully
      state.settings.pushNotif = false;
      $('pushNotifToggle').checked = false;
      console.warn('Push notifications not available in this context:', e.message);
    }
  }

  $('settingsOverlay').hidden = true;
  showToast('Settings saved ✓', 'success');
  audit('analyst', 'Settings updated');
}

// ── Theme Toggle ──────────────────────────────────────────
function toggleTheme() {
  state.theme = state.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', state.theme);
  $('themeToggle').textContent = state.theme === 'dark' ? '☾' : '☀';
  audit('analyst', `Theme switched to ${state.theme} mode`);
}

// ── Auto-refresh ──────────────────────────────────────────
let refreshInterval = null;
function setRefreshInterval(ms) {
  if (refreshInterval) clearInterval(refreshInterval);
  if (ms === 0) return;
  refreshInterval = setInterval(() => {
    state.activityHistory.push(rndI(5, 90));
    state.activityHistory.shift();
    updateActivityChart($('chartRange').value);
    updateTrafficMetrics();
    renderIncidents();
  }, ms);
}

function updateTrafficMetrics() {
  const active = document.querySelector('.view.active')?.id;
  if (active === 'traffic') updateTrafficView();
}

// ── Report Download ────────────────────────────────────────
function downloadReport() {
  const report = {
    generatedAt: new Date().toISOString(),
    project: 'CloudGuard AI Threat Detection',
    model: MODEL_LABELS[state.activeModel],
    settings: state.settings,
    metrics: { eventsAnalyzed: state.events, threatsDetected: state.threats, detectionAccuracy: MODEL_ACCURACY[state.activeModel] + '%', responseTime: '1.8 min' },
    incidents: state.incidents.map(i => ({ ...i, ts: i.ts.toISOString() })),
    threatsByCountry: state.countryHits,
    auditSummary: { totalActions: state.auditLog.length, analystActions: state.auditLog.filter(l=>l.category==='analyst').length }
  };
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  link.download = `cloudguard-report-${Date.now()}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
  showToast('Security report downloaded', 'success');
  audit('analyst', 'Full security report exported');
}

// ── Drag & Drop ────────────────────────────────────────────
function initDropzone() {
  const zone = $('dropzone');
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) { $('fileInput').files = e.dataTransfer.files; handleFileUpload(file); }
  });
}

// ── Seeding the feed ──────────────────────────────────────
function seedFeed() {
  const feed = $('eventFeed');
  EVENT_TEMPLATES.slice(0, 6).forEach(tpl => {
    const line = document.createElement('div');
    line.className = tpl.type;
    line.textContent = `${fmtT(new Date())}  [${tpl.proto}]  ${randIP()}  ${tpl.msg}  ·  score ${tpl.score().toFixed(2)}`;
    feed.appendChild(line);
  });
}

// ── Initial audit entries ──────────────────────────────────
function seedAuditLog() {
  const seed = [
    { category: 'system', msg: 'CloudGuard AI started — Random Forest v2.4 loaded' },
    { category: 'system', msg: 'Live event stream connected · 14,320 events/min' },
    { category: 'system', msg: 'Geo-IP database loaded · 32M records' },
    { category: 'alert',  msg: 'Critical alert: Ransomware C2 beacon detected on 10.24.18.42' },
    { category: 'alert',  msg: 'High alert: Unusual outbound data transfer from 10.24.33.18' },
    { category: 'analyst', msg: 'Analyst Sayyad Ibrahim resolved incident #4 (Phishing payload)' },
    { category: 'analyst', msg: 'Analyst Sayyad Ibrahim resolved incident #5 (Port scan anomaly)' }
  ];
  seed.forEach((e, i) => {
    state.auditLog.push({ ts: new Date(Date.now() - (seed.length - i) * 300000), ...e });
  });
}

// ── Event Wiring ──────────────────────────────────────────
function wireEvents() {
  // Navigation
  document.querySelectorAll('.nav-item').forEach(btn =>
    btn.addEventListener('click', () => {
      switchView(btn.dataset.view);
      if (btn.dataset.view === 'reports') { initWeeklyChart(); }
    })
  );
  document.querySelectorAll('[data-go]').forEach(btn =>
    btn.addEventListener('click', () => switchView(btn.dataset.go))
  );

  // Scan button
  $('scanButton').addEventListener('click', () => {
    runScan('live cloud traffic');
    if (!$('detection').classList.contains('active')) switchView('detection');
  });

  // File upload
  $('chooseFile').addEventListener('click', () => $('fileInput').click());
  $('fileInput').addEventListener('change', e => handleFileUpload(e.target.files[0]));

  // Model selector
  $('modelSelect').addEventListener('change', e => {
    state.activeModel = e.target.value;
    $('activeModelLabel').textContent = MODEL_LABELS[state.activeModel];
    const acc = MODEL_ACCURACY[state.activeModel];
    $('accuracyVal').textContent = acc + '%';
    audit('analyst', `ML model switched to ${MODEL_LABELS[state.activeModel]}`);
    showToast(`Model switched to ${MODEL_LABELS[state.activeModel]}`, 'info');
  });

  // Chart range
  $('chartRange').addEventListener('change', e => updateActivityChart(e.target.value));

  // Alert filters
  document.querySelectorAll('.filter').forEach(btn =>
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderAlerts(btn.dataset.filter);
    })
  );

  // Resolve incident
  $('alertRows').addEventListener('click', e => {
    const id = Number(e.target.dataset.id);
    if (!id) return;
    const inc = state.incidents.find(i => i.id === id);
    if (!inc) return;
    inc.status = 'resolved';
    renderAlerts(document.querySelector('.filter.active').dataset.filter);
    renderIncidents();
    showToast('Incident marked as resolved', 'success');
    audit('analyst', `Incident #${id} resolved: "${inc.title}"`);
  });

  // Download report
  $('downloadReport').addEventListener('click', downloadReport);

  // Notifications
  $('notifBtn').addEventListener('click', () => {
    const dd = $('notifDropdown');
    const open = !dd.hidden;
    dd.hidden = open;
    $('notifBtn').setAttribute('aria-expanded', !open);
    if (!open) { $('notifDot').style.display = 'none'; renderNotifications(); }
  });
  $('clearNotifs').addEventListener('click', () => {
    state.notifications = [];
    renderNotifications();
  });
  document.addEventListener('click', e => {
    if (!$('notifWrap').contains(e.target)) $('notifDropdown').hidden = true;
  });

  // Theme
  $('themeToggle').addEventListener('click', toggleTheme);

  // Settings
  $('settingsBtn').addEventListener('click', openSettings);
  $('closeSettings').addEventListener('click', () => $('settingsOverlay').hidden = true);
  $('saveSettings').addEventListener('click', saveSettings);
  $('settingsOverlay').addEventListener('click', e => { if (e.target === $('settingsOverlay')) $('settingsOverlay').hidden = true; });
  $('confidenceThreshold').addEventListener('input', e => $('thresholdLabel').textContent = e.target.value + '%');

  // Pause stream
  $('pauseStream').addEventListener('click', () => {
    state.streamPaused = !state.streamPaused;
    $('pauseStream').textContent = state.streamPaused ? '▶ Resume' : '⏸ Pause';
    $('streamStatus').innerHTML = state.streamPaused
      ? '<i style="background:var(--orange)"></i> PAUSED'
      : '<i></i> ACTIVE';
    audit('analyst', state.streamPaused ? 'Event stream paused' : 'Event stream resumed');
  });

  // Audit filters
  document.querySelectorAll('.audit-filter').forEach(btn =>
    btn.addEventListener('click', () => renderAuditLog(btn.dataset.afilter))
  );

  // Export audit
  $('exportAudit').addEventListener('click', () => {
    const csv = ['Timestamp,Category,Message',
      ...state.auditLog.map(l => `"${l.ts.toISOString()}","${l.category}","${l.msg}"`)
    ].join('\n');
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    link.download = `cloudguard-audit-${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(link.href);
    showToast('Audit log exported as CSV', 'success');
  });

  // Refresh rate
  $('refreshRate').addEventListener('change', e => {
    setRefreshInterval(Number(e.target.value));
    audit('analyst', `Auto-refresh interval set to ${e.target.value === '0' ? 'off' : e.target.value + 'ms'}`);
  });
}

// ── Bootstrap ─────────────────────────────────────────────
function bootstrap() {
  setClock();
  setInterval(setClock, 1000);
  seedFeed();
  seedAuditLog();
  renderIncidents();
  renderAlerts();
  initActivityChart();
  initDropzone();
  wireEvents();

  // Live feed ticker
  setInterval(appendFeed, 3800);

  // Default auto-refresh
  setRefreshInterval(15000);

  // Seed initial notifications
  setTimeout(() => pushNotification('🚨 CRITICAL: Ransomware C2 beacon on 10.24.18.42', 'critical'), 1500);
  setTimeout(() => pushNotification('⚠ HIGH: Unusual outbound transfer detected', 'high'), 3000);
  setTimeout(() => pushNotification('ℹ System: Model Random Forest v2.4 loaded & healthy', 'info'), 4500);

  // Seed country hits
  GEO_SOURCES.slice(0, 5).forEach(s => {
    state.countryHits[s.country] = rndI(1, 12);
  });

  audit('system', 'CloudGuard AI dashboard initialised successfully');
}

bootstrap();
