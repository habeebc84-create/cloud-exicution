const state = {
  incidents: [
    { id: 1, severity: 'critical', title: 'Ransomware signature detected', source: '10.24.18.42 → finance-api', time: '2 min ago', status: 'open' },
    { id: 2, severity: 'high', title: 'Unusual outbound traffic', source: '10.24.33.18 → external IP', time: '18 min ago', status: 'open' },
    { id: 3, severity: 'medium', title: 'Suspicious authentication pattern', source: 'admin@cloudguard.io', time: '42 min ago', status: 'open' },
    { id: 4, severity: 'high', title: 'Phishing payload blocked', source: 'mail-gateway → inbox', time: '1 hr ago', status: 'resolved' },
    { id: 5, severity: 'medium', title: 'Port scan anomaly', source: '172.16.0.88 → core-vpc', time: '2 hr ago', status: 'resolved' }
  ],
  events: 2481920,
  threats: 27
};

const navTitles = { overview: 'Security overview', detection: 'Threat detection', alerts: 'Security alerts', reports: 'Reports & analytics' };
const feedMessages = [
  ['safe', 'INFO   10.24.11.08  Normal HTTPS traffic · score 0.02'],
  ['safe', 'INFO   10.24.18.31  CloudTrail event processed · score 0.04'],
  ['suspicious', 'WARN   10.24.33.18  Outbound volume anomaly · score 0.87'],
  ['safe', 'INFO   10.24.07.92  DNS request classified benign · score 0.08'],
  ['suspicious', 'ALERT  10.24.18.42  Ransomware signature match · score 0.96']
];

function formatNumber(n) { return n.toLocaleString('en-US'); }
function setClock() { document.getElementById('clock').textContent = new Intl.DateTimeFormat('en-US', { weekday:'short', hour:'2-digit', minute:'2-digit', second:'2-digit' }).format(new Date()); }
function showToast(text) { const toast = document.getElementById('toast'); toast.textContent = text; toast.classList.add('show'); setTimeout(() => toast.classList.remove('show'), 2800); }

function renderBars(range = '24 hours') {
  const base = range === '7 days' ? [24,38,45,27,62,48,70,55,30,46,80,66] : [10,18,14,27,20,33,48,31,22,60,43,28,70,35,51,84,43,35,60,52,32,77,42,67];
  document.getElementById('barChart').innerHTML = base.map((v, i) => `<div class="bar ${v > 75 ? 'hot' : ''}" style="height:${v}%" title="${v} events"></div>`).join('');
  document.getElementById('chartTotal').textContent = range === '7 days' ? '184' : state.threats;
}
function renderIncidents() {
  document.getElementById('incidentList').innerHTML = state.incidents.slice(0, 3).map(item => `<div class="incident"><i class="severity ${item.severity}"></i><div><strong>${item.title}</strong><small>${item.source}</small></div><time>${item.time}</time></div>`).join('');
  document.getElementById('alertBadge').textContent = state.incidents.filter(i => i.status === 'open').length;
}
function renderAlerts(filter = 'all') {
  const rows = state.incidents.filter(i => filter === 'all' || (filter === 'resolved' ? i.status === 'resolved' : i.severity === filter));
  document.getElementById('alertRows').innerHTML = rows.length ? rows.map(i => `<div class="alert-row"><span class="badge ${i.severity}">${i.severity.toUpperCase()}</span><strong>${i.title}</strong><span class="source">${i.source}</span><time>${i.time}</time><span class="status-pill ${i.status}">${i.status === 'open' ? '● OPEN' : '✓ RESOLVED'}</span>${i.status === 'open' ? `<button class="resolve" data-id="${i.id}">Resolve</button>` : '<span></span>'}</div>`).join('') : '<div class="empty-result"><span>✓</span><div><h3>No matching alerts</h3><p>Your filter has no incidents at this time.</p></div></div>';
}
function seedFeed() { document.getElementById('eventFeed').innerHTML = feedMessages.slice(0,4).map(([type,msg]) => `<div class="${type}">${msg}</div>`).join(''); }
function appendFeed() { const [type,msg] = feedMessages[Math.floor(Math.random() * feedMessages.length)]; const feed = document.getElementById('eventFeed'); feed.insertAdjacentHTML('beforeend', `<div class="${type}">${new Date().toLocaleTimeString()}  ${msg}</div>`); while(feed.children.length > 7) feed.removeChild(feed.firstChild); feed.scrollTop = feed.scrollHeight; }
function runScan(label = 'Live traffic') {
  const confidence = (92 + Math.random() * 7.5).toFixed(1);
  state.events += Math.floor(250 + Math.random() * 900);
  document.getElementById('eventCount').textContent = formatNumber(state.events);
  document.getElementById('scanResult').innerHTML = `<div class="scan-result"><div class="verdict"><span class="risk">!</span><div><p class="eyebrow">CLASSIFICATION COMPLETE</p><h3>Suspicious activity found in ${label}</h3><p>Behavioral pattern resembles credential access and abnormal outbound transfer.</p></div></div><div class="confidence"><b>${confidence}%</b><span>model confidence</span></div></div>`;
  appendFeed(); showToast('Scan complete — detection result updated');
}
function switchView(view) { document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === view)); document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view)); document.getElementById('pageTitle').textContent = navTitles[view]; window.scrollTo({top:0, behavior:'smooth'}); }

document.querySelectorAll('.nav-item').forEach(button => button.addEventListener('click', () => switchView(button.dataset.view)));
document.querySelectorAll('[data-go]').forEach(button => button.addEventListener('click', () => switchView(button.dataset.go)));
document.getElementById('chartRange').addEventListener('change', e => renderBars(e.target.value));
document.getElementById('scanButton').addEventListener('click', () => { runScan('live cloud traffic'); if (!document.getElementById('detection').classList.contains('active')) switchView('detection'); });
document.getElementById('chooseFile').addEventListener('click', () => document.getElementById('fileInput').click());
document.getElementById('fileInput').addEventListener('change', e => { const file = e.target.files[0]; if (!file) return; document.getElementById('fileStatus').textContent = `${file.name} · ${Math.ceil(file.size / 1024)} KB`; runScan(file.name); });
document.querySelectorAll('.filter').forEach(button => button.addEventListener('click', () => { document.querySelectorAll('.filter').forEach(b => b.classList.remove('active')); button.classList.add('active'); renderAlerts(button.dataset.filter); }));
document.getElementById('alertRows').addEventListener('click', e => { const id = Number(e.target.dataset.id); if (!id) return; const incident = state.incidents.find(i => i.id === id); incident.status = 'resolved'; renderAlerts(document.querySelector('.filter.active').dataset.filter); renderIncidents(); showToast('Incident marked as resolved'); });
document.getElementById('downloadReport').addEventListener('click', () => { const report = { generatedAt: new Date().toISOString(), project: 'CloudGuard AI Threat Detection', model: document.getElementById('modelSelect').value, metrics: { eventsAnalyzed: state.events, threatsDetected: state.threats, detectionAccuracy: '98.7%', responseTime: '1.8 min' }, incidents: state.incidents }; const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], {type:'application/json'})); link.download = 'cloudguard-security-report.json'; link.click(); URL.revokeObjectURL(link.href); showToast('Security report downloaded'); });

setClock(); setInterval(setClock, 1000); setInterval(appendFeed, 4300); renderBars(); renderIncidents(); renderAlerts(); seedFeed();
