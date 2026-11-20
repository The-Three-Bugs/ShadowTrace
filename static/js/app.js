/* ===================== SHADOWTRACE FRONTEND ===================== */

const state = {
  currentRunId: null,
  page: 1,
  perPage: 50,
  logSearch: '',
  logSeverity: 'All',
  threatSearch: '',
  threatSeverity: 'All',
  charts: {}
};

/* ===================== UTILITIES ===================== */
const $ = (id) => document.getElementById(id);

function toast(type, title, msg) {
  const stack = $('toastStack');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  const icon = type === 'success' ? 'check-circle-2' : type === 'error' ? 'alert-octagon' : 'info';
  el.innerHTML = `
    <i data-lucide="${icon}" class="toast-icon"></i>
    <div class="toast-body">
      <div class="toast-title">${title}</div>
      <div class="toast-msg">${msg}</div>
    </div>`;
  stack.appendChild(el);
  lucide.createIcons();
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 350); }, 4200);
}

function setLoader(active) {
  $('loaderOverlay').classList.toggle('active', active);
}

function setPipeline(step, note) {
  document.querySelectorAll('.pipe-step').forEach((el) => {
    const s = parseInt(el.dataset.step, 10);
    el.classList.toggle('done', s < step);
    el.classList.toggle('active', s === step);
  });
  if (note) $('pipelineNote').textContent = note;
}

function resetPipeline() {
  document.querySelectorAll('.pipe-step').forEach((el) => el.classList.remove('active', 'done'));
  $('pipelineNote').textContent = 'Awaiting input…';
}

function countUp(el, target) {
  const start = parseInt(el.textContent.replace(/\D/g, ''), 10) || 0;
  const duration = 700;
  const startTime = performance.now();
  function tick(now) {
    const t = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(start + (target - start) * eased).toLocaleString();
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

/* ===================== NAVIGATION ===================== */
const viewMeta = {
  dashboard: { title: 'Security Overview', crumb: 'Dashboard' },
  analyzer: { title: 'Log Analyzer', crumb: 'Log Analyzer' },
  investigations: { title: 'Investigation Management', crumb: 'Investigations' },
  threats: { title: 'Threat Detection', crumb: 'Threat Detection' },
  settings: { title: 'Settings', crumb: 'Settings' }
};

function switchView(view) {
  document.querySelectorAll('.nav-item').forEach((el) =>
    el.classList.toggle('active', el.dataset.view === view));
  document.querySelectorAll('.view').forEach((el) =>
    el.classList.toggle('active', el.id === `view-${view}`));

  const meta = viewMeta[view] || viewMeta.dashboard;
  $('pageTitle').textContent = meta.title;
  $('crumbCurrent').textContent = meta.crumb;

  if (view === 'dashboard') loadStats();
  if (view === 'analyzer') { loadLogs(); loadUploadHistory(); }
  if (view === 'investigations') loadInvestigations();
  if (view === 'threats') loadThreats();
  if (view === 'reports' && typeof window.populateReportRuns === 'function') window.populateReportRuns();
}

document.querySelectorAll('.nav-item').forEach((el) => {
  el.addEventListener('click', () => switchView(el.dataset.view));
  el.addEventListener('mousemove', (e) => {
    const r = el.getBoundingClientRect();
    el.style.setProperty('--mx', `${e.clientX - r.left}px`);
    el.style.setProperty('--my', `${e.clientY - r.top}px`);
  });
});

/* ===================== API ===================== */
const api = {
  // Auth API (Member 1 - SECURITY-1)
  async me() {
    const r = await fetch('/api/auth/me');
    return r.json();
  },
  async login(username, password) {
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await r.json();
    return { status: r.status, data };
  },
  async logout() {
    const r = await fetch('/api/auth/logout', { method: 'POST' });
    return r.json();
  },
  async changePassword(currentPassword, newPassword) {
    const r = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword
      })
    });
    const data = await r.json();
    return { status: r.status, data };
  },
  async stats(runId) {
    const rId = runId || state.currentRunId;
    const url = rId ? `/api/stats?run_id=${rId}` : '/api/stats';
    const r = await fetch(url);
    return r.json();
  },
  async logs(runId) {
    const p = new URLSearchParams({
      search: state.logSearch,
      severity: state.logSeverity,
      page: state.page,
      per_page: state.perPage
    });
    const rId = runId || state.currentRunId;
    if (rId) p.set('run_id', rId);
    const r = await fetch(`/api/logs?${p}`);
    return r.json();
  },
  async detections(runId) {
    const p = new URLSearchParams({
      search: state.threatSearch,
      severity: state.threatSeverity
    });
    const rId = runId || state.currentRunId;
    if (rId) p.set('run_id', rId);
    const r = await fetch(`/api/detections?${p}`);
    return r.json();
  },
  async runs() {
    const r = await fetch('/api/runs');
    return r.json();
  },
  async activateRun(runId) {
    const r = await fetch(`/api/runs/${runId}/activate`, { method: 'POST' });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Failed to activate file.');
    return data;
  },
  async upload(file) {
    const fd = new FormData();
    fd.append('file', file);
    const r = await fetch('/api/upload', { method: 'POST', body: fd });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Upload failed.');
    return data;
  },
  async loadSample() {
    const r = await fetch('/api/load-sample', { method: 'POST' });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Failed to load sample.');
    return data;
  },
  async getInvestigations(search = '', status = 'All') {
    const p = new URLSearchParams({ search, status });
    const r = await fetch(`/api/investigations?${p}`);
    return r.json();
  },
  async createInvestigation(payload) {
    const r = await fetch('/api/investigations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error?.message || 'Failed to create investigation.');
    return data;
  },
  async getInvestigation(id) {
    const r = await fetch(`/api/investigations/${id}`);
    const data = await r.json();
    if (!r.ok) throw new Error(data.error?.message || 'Failed to fetch investigation.');
    return data;
  },
  async updateInvestigation(id, payload) {
    const r = await fetch(`/api/investigations/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error?.message || 'Failed to update investigation.');
    return data;
  },
  async uploadEvidence(invId, file) {
    const fd = new FormData();
    fd.append('file', file);
    const r = await fetch(`/api/investigations/${invId}/evidence`, { method: 'POST', body: fd });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error?.message || 'Failed to upload evidence.');
    return data;
  }
};

/* ===================== INVESTIGATIONS & EVIDENCE ===================== */
let currentInvestigationId = null;

async function loadInvestigations() {
  const search = $('invSearchInput') ? $('invSearchInput').value : '';
  const status = $('invStatusFilter') ? $('invStatusFilter').value : 'All';
  try {
    const res = await api.getInvestigations(search, status);
    if (res.ok) {
      const invs = res.data.investigations;
      const tbody = $('investigationsTableBody');
      if (!tbody) return;
      
      if ($('invCountLabel')) {
        $('invCountLabel').textContent = `${invs.length} total investigations`;
      }
      if ($('navInvBadge')) {
        $('navInvBadge').textContent = invs.length;
      }
      
      if (invs.length === 0) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="7">No investigations found. Create one to begin.</td></tr>`;
        return;
      }
      
      tbody.innerHTML = invs.map(inv => `
        <tr class="clickable-row" data-id="${inv.id}" style="cursor: pointer;">
          <td><strong style="color: #22d3ee;">${escapeHtml(inv.investigation_uid)}</strong></td>
          <td>${escapeHtml(inv.title)}</td>
          <td><span class="status-pill status-${inv.status.toLowerCase().replace(/\s+/g, '-')}">${escapeHtml(inv.status)}</span></td>
          <td style="font-size: 12px; color: #8a99ad;">${escapeHtml(inv.created_at)}</td>
          <td><span style="background: rgba(34,211,238,0.1); color: #22d3ee; padding: 2px 8px; border-radius: 4px; font-weight: 500;">${inv.evidence_count} files</span></td>
          <td><span style="background: rgba(239,68,68,0.1); color: #f87171; padding: 2px 8px; border-radius: 4px; font-weight: 500;">${inv.findings_count} findings</span></td>
          <td>
            <button class="btn ghost sm view-inv-btn" data-id="${inv.id}" style="padding: 4px 10px; font-size: 12px;">
              <i data-lucide="eye" style="width:14px;height:14px;"></i> Inspect
            </button>
          </td>
        </tr>
      `).join('');
      lucide.createIcons();
      
      tbody.querySelectorAll('.clickable-row, .view-inv-btn').forEach(el => {
        el.addEventListener('click', (e) => {
          e.stopPropagation();
          const id = el.dataset.id || el.closest('tr').dataset.id;
          loadInvestigationDetails(id);
        });
      });
    }
  } catch (err) {
    console.error(err);
    toast('error', 'Error', 'Failed to load investigations.');
  }
}

async function loadInvestigationDetails(id) {
  currentInvestigationId = id;
  setLoader(true);
  try {
    const res = await api.getInvestigation(id);
    setLoader(false);
    if (res.ok) {
      const inv = res.data.item;
      $('detInvTitle').textContent = inv.title;
      $('detInvUid').textContent = `UID: ${inv.investigation_uid}`;
      $('detInvDesc').textContent = inv.description || 'No description provided.';
      $('detInvCreated').textContent = inv.created_at;
      $('detInvUpdated').textContent = inv.updated_at;
      $('detInvStatusSelect').value = inv.status;
      
      // Evidence list
      const evTbody = $('evidenceTableBody');
      if (inv.evidence_files.length === 0) {
        evTbody.innerHTML = `<tr class="empty-row"><td colspan="6">No evidence uploaded to this investigation yet.</td></tr>`;
      } else {
        evTbody.innerHTML = inv.evidence_files.map(ev => `
          <tr>
            <td>#${ev.id}</td>
            <td><strong>${escapeHtml(ev.original_filename)}</strong></td>
            <td>${(ev.file_size / 1024).toFixed(1)} KB</td>
            <td><code style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #22d3ee;" title="${ev.sha256_hash}">${ev.sha256_hash.substring(0, 16)}...</code></td>
            <td style="font-size: 12px; color: #8a99ad;">${ev.upload_timestamp}</td>
            <td><span class="status-pill status-${ev.integrity_status && ev.integrity_status.includes('Verified') ? 'success' : 'danger'}">${escapeHtml(ev.integrity_status || 'Unknown')}</span></td>
          </tr>
        `).join('');
      }
      
      $('invListCard').style.display = 'none';
      $('invDetailsCard').style.display = 'block';
      lucide.createIcons();
    }
  } catch (err) {
    setLoader(false);
    console.error(err);
    toast('error', 'Error', 'Failed to load investigation details.');
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function bindInvestigations() {
  const searchInput = $('invSearchInput');
  const statusFilter = $('invStatusFilter');
  if (searchInput) {
    searchInput.addEventListener('input', () => loadInvestigations());
  }
  if (statusFilter) {
    statusFilter.addEventListener('change', () => loadInvestigations());
  }
  
  const openModalBtn = $('openCreateInvModalBtn');
  const modal = $('createInvModal');
  const cancelModalBtn = $('cancelCreateInvBtn');
  const submitModalBtn = $('submitCreateInvBtn');
  
  if (openModalBtn && modal) {
    openModalBtn.addEventListener('click', () => {
      $('newInvTitle').value = '';
      $('newInvDesc').value = '';
      $('newInvStatus').value = 'Open';
      modal.classList.add('active');
    });
  }
  if (cancelModalBtn && modal) {
    cancelModalBtn.addEventListener('click', () => modal.classList.remove('active'));
  }
  if (submitModalBtn) {
    submitModalBtn.addEventListener('click', async () => {
      const title = $('newInvTitle').value.trim();
      const description = $('newInvDesc').value.trim();
      const status = $('newInvStatus').value;
      if (!title) {
        toast('error', 'Validation Error', 'Investigation title is required.');
        return;
      }
      try {
        setLoader(true);
        const res = await api.createInvestigation({ title, description, status });
        setLoader(false);
        if (res.ok) {
          modal.classList.remove('active');
          toast('success', 'Success', 'Investigation created successfully.');
          loadInvestigations();
        }
      } catch (err) {
        setLoader(false);
        toast('error', 'Error', err.message || 'Failed to create investigation.');
      }
    });
  }
  
  const backBtn = $('backToInvListBtn');
  if (backBtn) {
    backBtn.addEventListener('click', () => {
      $('invDetailsCard').style.display = 'none';
      $('invListCard').style.display = 'block';
      currentInvestigationId = null;
      loadInvestigations();
    });
  }
  
  const updateStatusBtn = $('updateInvStatusBtn');
  if (updateStatusBtn) {
    updateStatusBtn.addEventListener('click', async () => {
      if (!currentInvestigationId) return;
      const status = $('detInvStatusSelect').value;
      try {
        setLoader(true);
        const res = await api.updateInvestigation(currentInvestigationId, { status });
        setLoader(false);
        if (res.ok) {
          toast('success', 'Updated', 'Investigation status updated successfully.');
          loadInvestigationDetails(currentInvestigationId);
        }
      } catch (err) {
        setLoader(false);
        toast('error', 'Error', err.message || 'Failed to update status.');
      }
    });
  }
  
  const triggerUploadBtn = $('triggerEvidenceUploadBtn');
  const fileInput = $('evidenceFileInput');
  if (triggerUploadBtn && fileInput) {
    triggerUploadBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file || !currentInvestigationId) return;
      if (!file.name.toLowerCase().endswith('.csv')) {
        toast('error', 'Invalid File', 'Only CSV files are supported.');
        return;
      }
      try {
        setLoader(true);
        await api.uploadEvidence(currentInvestigationId, file);
        setLoader(false);
        fileInput.value = '';
        toast('success', 'Evidence Uploaded', 'CSV evidence uploaded and SHA-256 integrity hash calculated.');
        loadInvestigationDetails(currentInvestigationId);
      } catch (err) {
        setLoader(false);
        fileInput.value = '';
        toast('error', 'Upload Failed', err.message || 'Failed to upload evidence.');
      }
    });
  }
}


/* ===================== DASHBOARD ===================== */
const chartDefaults = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      labels: {
        color: '#c3cbe4',
        font: { family: 'Inter', size: 12, weight: '500' },
        boxWidth: 10, boxHeight: 10, usePointStyle: true, pointStyle: 'circle', padding: 16
      }
    },
    tooltip: {
      backgroundColor: 'rgba(10,15,30,0.95)',
      titleColor: '#f1f5ff',
      bodyColor: '#c3cbe4',
      borderColor: 'rgba(34,211,238,0.3)',
      borderWidth: 1,
      padding: 12,
      cornerRadius: 10,
      titleFont: { family: 'Inter', size: 12, weight: '600' },
      bodyFont: { family: 'JetBrains Mono', size: 11 }
    }
  }
};

function gradient(ctx, c1, c2) {
  const g = ctx.createLinearGradient(0, 0, 0, 240);
  g.addColorStop(0, c1);
  g.addColorStop(1, c2);
  return g;
}

function renderNormalChart(data) {
  const ctx = $('chartNormalVsSuspicious').getContext('2d');
  if (state.charts.normal) state.charts.normal.destroy();
  state.charts.normal = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Normal', 'Suspicious'],
      datasets: [{
        data: [data.Normal, data.Suspicious],
        backgroundColor: [
          gradient(ctx, 'rgba(34,211,238,0.95)', 'rgba(139,92,246,0.75)'),
          gradient(ctx, 'rgba(244,63,94,0.95)', 'rgba(245,158,11,0.85)')
        ],
        borderColor: 'rgba(10,15,30,1)',
        borderWidth: 3,
        hoverOffset: 8,
        hoverBorderColor: '#22d3ee'
      }]
    },
    options: {
      ...chartDefaults,
      cutout: '68%',
      plugins: {
        ...chartDefaults.plugins,
        legend: { ...chartDefaults.plugins.legend, position: 'bottom' }
      }
    }
  });
}

function renderSeverityChart(data) {
  const ctx = $('chartSeverity').getContext('2d');
  if (state.charts.severity) state.charts.severity.destroy();
  const labels = ['Critical', 'High', 'Medium', 'Low'];
  const colors = [
    gradient(ctx, 'rgba(244,63,94,0.9)', 'rgba(244,63,94,0.15)'),
    gradient(ctx, 'rgba(245,158,11,0.9)', 'rgba(245,158,11,0.15)'),
    gradient(ctx, 'rgba(59,130,246,0.9)', 'rgba(59,130,246,0.15)'),
    gradient(ctx, 'rgba(16,185,129,0.9)', 'rgba(16,185,129,0.15)')
  ];
  state.charts.severity = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Events',
        data: labels.map((l) => data[l] || 0),
        backgroundColor: colors,
        borderColor: ['#f43f5e', '#f59e0b', '#3b82f6', '#10b981'],
        borderWidth: 1.5,
        borderRadius: 8,
        borderSkipped: false,
        barThickness: 36
      }]
    },
    options: {
      ...chartDefaults,
      plugins: { ...chartDefaults.plugins, legend: { display: false } },
      scales: {
        x: {
          grid: { display: false },
          ticks: { color: '#7f8aab', font: { family: 'Inter', size: 11, weight: '500' } }
        },
        y: {
          grid: { color: 'rgba(120,145,200,0.08)', drawBorder: false },
          ticks: { color: '#7f8aab', font: { family: 'JetBrains Mono', size: 11 }, precision: 0 }
        }
      }
    }
  });
}

function renderTimelineChart(data) {
  const ctx = $('chartTimeline').getContext('2d');
  if (state.charts.timeline) state.charts.timeline.destroy();
  const entries = Object.entries(data || {});
  const labels = entries.map(([k]) => k.replace('T', ' ').slice(5));
  const values = entries.map(([, v]) => v);
  if (!labels.length) {
    state.charts.timeline = new Chart(ctx, {
      type: 'line',
      data: { labels: ['—'], datasets: [{ data: [0], borderColor: 'rgba(34,211,238,0.3)', borderWidth: 2 }] },
      options: { ...chartDefaults, plugins: { ...chartDefaults.plugins, legend: { display: false } } }
    });
    return;
  }
  const g = ctx.createLinearGradient(0, 0, 0, 260);
  g.addColorStop(0, 'rgba(34,211,238,0.45)');
  g.addColorStop(1, 'rgba(34,211,238,0)');

  state.charts.timeline = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Events',
        data: values,
        borderColor: '#22d3ee',
        backgroundColor: g,
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointBackgroundColor: '#0a0f1e',
        pointBorderColor: '#22d3ee',
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 7,
        pointHoverBackgroundColor: '#22d3ee',
        pointHoverBorderColor: '#fff',
        pointHoverBorderWidth: 2
      }]
    },
    options: {
      ...chartDefaults,
      plugins: { ...chartDefaults.plugins, legend: { display: false } },
      interaction: { intersect: false, mode: 'index' },
      scales: {
        x: {
          grid: { color: 'rgba(120,145,200,0.06)', drawBorder: false },
          ticks: { color: '#7f8aab', font: { family: 'JetBrains Mono', size: 10 }, maxRotation: 0, autoSkipPadding: 24 }
        },
        y: {
          grid: { color: 'rgba(120,145,200,0.08)', drawBorder: false },
          ticks: { color: '#7f8aab', font: { family: 'JetBrains Mono', size: 11 }, precision: 0 },
          beginAtZero: true
        }
      }
    }
  });
}

function sevBadge(sev) {
  const safe = ['Critical', 'High', 'Medium', 'Low', 'Informational'].includes(sev) ? sev : 'Low';
  return `<span class="sev ${safe}">${safe}</span>`;
}

async function loadStats() {
  try {
    const s = await api.stats();
    countUp($('kpiTotal'), s.total_events || 0);
    countUp($('kpiSuspicious'), s.suspicious_events || 0);
    countUp($('kpiCritical'), s.critical_alerts || 0);
    $('kpiStatus').textContent = s.last_status || 'Idle';
    $('kpiFilename').textContent = s.filename || 'No dataset loaded';
    $('lastRunLabel').textContent = s.filename ? `Last run · ${s.filename}` : 'No analysis yet';
    $('engineStatus').textContent = s.total_events > 0 ? 'Engine Ready' : 'Engine Idle';

    renderNormalChart(s.normal_vs_suspicious || { Normal: 0, Suspicious: 0 });
    renderSeverityChart(s.severity_breakdown || {});
    renderTimelineChart(s.events_over_time || {});

    const tbody = $('recentBody');
    const rows = s.recent_activity || [];
    if (!rows.length) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="5">No events analyzed yet.</td></tr>`;
    } else {
      tbody.innerHTML = rows.map((r) => `
        <tr>
          <td class="mono">${r.timestamp || '—'}</td>
          <td class="mono">${r.source_ip || '—'}</td>
          <td>${r.event_type || '—'}</td>
          <td>${sevBadge(r.severity)}</td>
          <td style="color:var(--txt-2);font-size:12px;">${r.detection_reason || '—'}</td>
        </tr>`).join('');
    }
    lucide.createIcons();
  } catch (e) {
    console.error(e);
  }
}

/* ===================== LOG ANALYZER ===================== */
async function loadLogs() {
  try {
    const data = await api.logs();
    const tbody = $('logsBody');
    const rows = data.logs || [];
    $('logCountLabel').textContent = `${data.total || 0} records`;

    if (!rows.length) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="7">No events yet. Upload a CSV or load the sample dataset.</td></tr>`;
    } else {
      tbody.innerHTML = rows.map((r) => `
        <tr>
          <td class="mono">${r.timestamp || '—'}</td>
          <td class="mono">${r.source_ip || '—'}</td>
          <td>${r.username || '—'}</td>
          <td>${r.event_type || '—'}</td>
          <td>${r.status || '—'}</td>
          <td>${sevBadge(r.severity)}</td>
          <td style="color:var(--txt-2);font-size:12px;max-width:280px;">${r.detection_reason || '—'}</td>
        </tr>`).join('');
    }

    const totalPages = Math.max(1, Math.ceil((data.total || 0) / state.perPage));
    $('pageInfo').textContent = `Page ${state.page} of ${totalPages}`;
    $('prevPage').disabled = state.page <= 1;
    $('nextPage').disabled = state.page >= totalPages;
  } catch (e) {
    console.error(e);
  }
}

function bindAnalyzerFilters() {
  let t1, t2;
  $('logSearch').addEventListener('input', (e) => {
    clearTimeout(t1);
    t1 = setTimeout(() => { state.logSearch = e.target.value.trim(); state.page = 1; loadLogs(); }, 280);
  });
  $('logSeverity').addEventListener('change', (e) => {
    state.logSeverity = e.target.value; state.page = 1; loadLogs();
  });
  $('prevPage').addEventListener('click', () => { if (state.page > 1) { state.page--; loadLogs(); } });
  $('nextPage').addEventListener('click', () => { state.page++; loadLogs(); });
}

/* ===================== UPLOAD & SAMPLE ===================== */
async function runUpload(file) {
  setLoader(true);
  resetPipeline();
  setPipeline(1, 'Receiving file…');
  try {
    const res = await api.upload(file);
    setPipeline(2, 'Validating records…');
    await new Promise((r) => setTimeout(r, 250));
    setPipeline(3, 'Applying detection rules…');
    await new Promise((r) => setTimeout(r, 250));
    setPipeline(4, 'Saving results…');
    await new Promise((r) => setTimeout(r, 200));

    showRunStats(res.stats);
    toast('success', 'Analysis Complete', `Processed ${res.stats.valid} valid records · ${res.stats.suspicious} suspicious events flagged.`);
    state.currentRunId = null; // show newly uploaded run
    await loadUploadHistory();
    await loadStats();
    await loadLogs();
    await loadThreats();
    if (typeof window.populateReportRuns === 'function') window.populateReportRuns();
    setPipeline(5, 'Done.');
    switchView('analyzer');
  } catch (e) {
    toast('error', 'Upload Failed', e.message || 'Unable to process file.');
    setPipeline(0, 'Failed.');
  } finally {
    setLoader(false);
  }
}

async function runSample() {
  setLoader(true);
  resetPipeline();
  setPipeline(1, 'Loading sample dataset…');
  try {
    const res = await api.loadSample();
    setPipeline(2, 'Validating records…');
    await new Promise((r) => setTimeout(r, 200));
    setPipeline(3, 'Applying detection rules…');
    await new Promise((r) => setTimeout(r, 200));
    setPipeline(4, 'Saving results…');
    await new Promise((r) => setTimeout(r, 200));
    showRunStats(res.stats);
    toast('success', 'Sample Loaded', `${res.stats.suspicious} suspicious events detected from ${res.stats.valid} records.`);
    state.currentRunId = null;
    await loadUploadHistory();
    await loadStats();
    await loadLogs();
    await loadThreats();
    if (typeof window.populateReportRuns === 'function') window.populateReportRuns();
    setPipeline(5, 'Done.');
    switchView('analyzer');
  } catch (e) {
    toast('error', 'Sample Load Failed', e.message || 'Unable to load sample.');
  } finally {
    setLoader(false);
  }
}

function showRunStats(s) {
  $('runStats').style.display = 'grid';
  $('rsTotal').textContent = s.total || 0;
  $('rsValid').textContent = s.valid || 0;
  $('rsInvalid').textContent = s.invalid || 0;
  $('rsSuspicious').textContent = s.suspicious || 0;
}

function bindUploader() {
  const dz = $('dropzone');
  const input = $('fileInput');
  const uploadTriggerBtn = $('uploadCsvTriggerBtn');

  if (uploadTriggerBtn) {
    uploadTriggerBtn.addEventListener('click', (e) => {
      e.preventDefault();
      input.click();
    });
  }

  dz.addEventListener('click', () => input.click());
  input.addEventListener('change', (e) => {
    if (e.target.files[0]) runUpload(e.target.files[0]);
    input.value = '';
  });

  ['dragenter', 'dragover'].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('dragover'); }));
  ['dragleave', 'drop'].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('dragover'); }));
  dz.addEventListener('drop', (e) => {
    const f = e.dataTransfer.files[0];
    if (f) runUpload(f);
  });

  $('loadSampleBtn').addEventListener('click', runSample);
  $('downloadTemplate').addEventListener('click', () => {
    window.location.href = '/api/download-template';
  });

  bindHistoryGrid();
}

/* ===================== UPLOAD HISTORY GRID ===================== */
let selectedHistoryRunId = null;
let historyRunsCache = [];

async function loadUploadHistory() {
  const tbody = $('uploadHistoryBody');
  const loadBtn = $('loadPreviousFileBtn');
  const barBtn = $('loadPreviousFileBarBtn');
  const selectedBar = $('historySelectedBar');
  if (!tbody) return;

  try {
    const res = await api.runs();
    const runs = (res && res.data) ? res.data : [];
    historyRunsCache = runs;

    if (!runs.length) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="5">No files uploaded yet. Upload a CSV to view history.</td></tr>`;
      if (loadBtn) loadBtn.disabled = true;
      if (barBtn) barBtn.disabled = true;
      if (selectedBar) selectedBar.style.display = 'none';
      selectedHistoryRunId = null;
      return;
    }

    tbody.innerHTML = runs.map((r) => {
      const isSelected = selectedHistoryRunId === r.id;
      const isCurrentActive = state.currentRunId ? state.currentRunId === r.id : false;
      const statusClass = (r.status || 'Completed').toLowerCase();
      return `
        <tr class="history-row ${isSelected ? 'selected' : ''}" data-run-id="${r.id}">
          <td style="text-align: center;">
            <input type="radio" name="historyFileSelect" class="history-radio" value="${r.id}" ${isSelected ? 'checked' : ''} />
          </td>
          <td>
            <div class="history-fname">
              <i data-lucide="file-spreadsheet"></i>
              <span title="${escapeHtml(r.filename)}">${escapeHtml(r.filename)}</span>
              ${isCurrentActive ? '<span class="status-pill status-success" style="font-size: 10px; padding: 2px 6px; margin-left: 6px;">Active</span>' : ''}
            </div>
          </td>
          <td style="font-size: 12px; color: var(--txt-2); font-family: 'JetBrains Mono', monospace;">
            ${escapeHtml(r.timestamp || '—')}
          </td>
          <td>
            <span style="font-size: 12px; font-weight: 600; color: #22d3ee;">${r.total_records || 0}</span>
            ${r.suspicious_count > 0 ? `<span style="font-size: 11px; color: #fb7185; margin-left: 4px;">(${r.suspicious_count} flagged)</span>` : ''}
          </td>
          <td>
            <span class="status-pill status-success" style="font-size: 10.5px;">${escapeHtml(r.status || 'Completed')}</span>
          </td>
        </tr>
      `;
    }).join('');

    if (window.lucide) lucide.createIcons();
    updateHistorySelectionUI();
  } catch (err) {
    console.warn('Failed to load upload history:', err);
    tbody.innerHTML = `<tr class="empty-row"><td colspan="5">Failed to load upload history.</td></tr>`;
  }
}

function selectHistoryRun(runId) {
  selectedHistoryRunId = parseInt(runId, 10);
  document.querySelectorAll('#uploadHistoryTable tr.history-row').forEach((tr) => {
    const id = parseInt(tr.dataset.runId, 10);
    const radio = tr.querySelector('input[type="radio"]');
    if (id === selectedHistoryRunId) {
      tr.classList.add('selected');
      if (radio) radio.checked = true;
    } else {
      tr.classList.remove('selected');
      if (radio) radio.checked = false;
    }
  });
  updateHistorySelectionUI();
}

function updateHistorySelectionUI() {
  const loadBtn = $('loadPreviousFileBtn');
  const barBtn = $('loadPreviousFileBarBtn');
  const selectedBar = $('historySelectedBar');
  const nameEl = $('historySelectedName');
  const metaEl = $('historySelectedMeta');

  if (!selectedHistoryRunId) {
    if (loadBtn) loadBtn.disabled = true;
    if (barBtn) barBtn.disabled = true;
    if (selectedBar) selectedBar.style.display = 'none';
    return;
  }

  const run = historyRunsCache.find((r) => r.id === selectedHistoryRunId);
  if (loadBtn) loadBtn.disabled = false;
  if (barBtn) barBtn.disabled = false;
  if (selectedBar) {
    selectedBar.style.display = 'flex';
    if (nameEl) nameEl.textContent = run ? run.filename : `Run #${selectedHistoryRunId}`;
    if (metaEl) metaEl.textContent = run ? `(${run.timestamp} · ${run.total_records} records)` : '';
  }
}

async function loadSelectedPreviousFile() {
  if (!selectedHistoryRunId) {
    toast('info', 'No File Selected', 'Please click a CSV file in the history grid first.');
    return;
  }

  const run = historyRunsCache.find((r) => r.id === selectedHistoryRunId);
  const fname = run ? run.filename : `Run #${selectedHistoryRunId}`;

  setLoader(true);
  try {
    const res = await api.activateRun(selectedHistoryRunId);
    state.currentRunId = selectedHistoryRunId;
    state.page = 1;

    if (res.stats) {
      showRunStats(res.stats);
    }

    await loadStats(state.currentRunId);
    await loadLogs(state.currentRunId);
    await loadThreats();
    await loadUploadHistory();

    toast('success', 'File Loaded', `Successfully loaded previous file: "${fname}" with ${res.stats?.valid || res.run?.valid_records || 0} valid records.`);
  } catch (err) {
    toast('error', 'Load Failed', err.message || 'Failed to load selected previous file.');
  } finally {
    setLoader(false);
  }
}

function bindHistoryGrid() {
  const tbody = $('uploadHistoryBody');
  const loadBtn = $('loadPreviousFileBtn');
  const barBtn = $('loadPreviousFileBarBtn');

  if (tbody) {
    tbody.addEventListener('click', (e) => {
      const row = e.target.closest('tr.history-row');
      if (row && row.dataset.runId) {
        selectHistoryRun(row.dataset.runId);
      }
    });
  }

  if (loadBtn) {
    loadBtn.addEventListener('click', (e) => {
      e.preventDefault();
      loadSelectedPreviousFile();
    });
  }

  if (barBtn) {
    barBtn.addEventListener('click', (e) => {
      e.preventDefault();
      loadSelectedPreviousFile();
    });
  }
}

/* ===================== THREATS ===================== */
async function loadThreats() {
  try {
    const p = new URLSearchParams({
      search: state.threatSearch,
      severity: state.threatSeverity
    });
    const res = await fetch(`/api/investigations/1/findings?${p}`);
    const data = await res.json();
    const tbody = $('threatsBody');
    const rows = data.data || [];
    $('threatCountLabel').textContent = `${rows.length} findings`;
    $('navThreatBadge').textContent = rows.length;
    $('navThreatBadge').dataset.zero = rows.length === 0;

    if (!rows.length) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="9">No threats detected yet.</td></tr>`;
    } else {
      const getAttackType = (ruleId) => {
        const id = (ruleId || '').toUpperCase();
        if (id === 'RULE-01') return { label: 'Brute Force', color: '#fb7185', bg: 'rgba(244,63,94,0.12)', border: 'rgba(244,63,94,0.35)' };
        if (id === 'RULE-02') return { label: 'Account Takeover', color: '#fbbf24', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.35)' };
        if (id === 'RULE-03') return { label: 'Anomalous Access / DDoS', color: '#60a5fa', bg: 'rgba(59,130,246,0.12)', border: 'rgba(59,130,246,0.35)' };
        return { label: 'Suspicious Activity', color: '#a78bfa', bg: 'rgba(139,92,246,0.12)', border: 'rgba(139,92,246,0.35)' };
      };
      tbody.innerHTML = rows.map((r) => {
        const atk = getAttackType(r.rule_id);
        return `
        <tr class="clickable-row" onclick="openFindingModal(${r.id})" title="Click to inspect finding details">
          <td class="mono">#${r.id}</td>
          <td class="mono">${r.detected_at || '—'}</td>
          <td class="mono">${r.source_ip || '—'}</td>
          <td class="mono" style="color:var(--cyan);font-weight:600;">${r.rule_id || '—'}</td>
          <td><span style="display:inline-block;padding:3px 9px;border-radius:6px;font-size:11px;font-weight:600;color:${atk.color};background:${atk.bg};border:1px solid ${atk.border};white-space:nowrap;">${atk.label}</span></td>
          <td style="color:var(--txt-0);font-weight:500;">${r.rule_name || r.rule_id}</td>
          <td>${sevBadge(r.severity)}</td>
          <td style="color:var(--txt-2);font-size:12px;line-height:1.4;" class="threat-evidence-cell">${escapeHtml(r.description || '—')}</td>
          <td><span class="sev Informational" style="color:#a78bfa;">${r.status || 'New'}</span></td>
        </tr>`;
      }).join('');
    }
  } catch (e) {
    console.error(e);
  }
}

let currentFindingId = null;

async function openFindingModal(id) {
  currentFindingId = id;
  try {
    const res = await fetch(`/api/findings/${id}`);
    const data = await res.json();
    if (!data.ok) throw new Error(data.error);
    const f = data.data;

    $('modalFindingTitle').textContent = `Finding #${f.id} — ${f.rule_id}`;
    $('modalRuleName').textContent = `${f.rule_id}: ${f.rule_name}`;
    $('modalSeverityBadge').innerHTML = sevBadge(f.severity);
    $('modalStatusSelect').value = f.status;
    $('modalDescription').textContent = f.description;
    $('modalEventCount').textContent = (f.supporting_events || []).length;

    const evBody = $('modalEventsBody');
    const evs = f.supporting_events || [];
    if (!evs.length) {
      evBody.innerHTML = `<tr class="empty-row"><td colspan="6">No supporting events.</td></tr>`;
    } else {
      evBody.innerHTML = evs.map((e) => `
        <tr>
          <td class="mono">#${e.id}</td>
          <td class="mono">${e.timestamp}</td>
          <td class="mono">${e.source_ip}</td>
          <td>${e.username}</td>
          <td>${e.event_type}</td>
          <td>${e.status}</td>
        </tr>`).join('');
    }

    renderNotes(f.notes || []);
    $('findingModalOverlay').classList.add('active');
    lucide.createIcons();
  } catch (e) {
    toast('error', 'Error', e.message);
  }
}

function renderNotes(notes) {
  const list = $('modalNotesList');
  if (!notes.length) {
    list.innerHTML = `<div style="font-size:12px;color:var(--txt-2);">No investigation notes yet.</div>`;
    return;
  }
  list.innerHTML = notes.map((n) => `
    <div class="note-item">
      <div class="note-date">${n.created_at || 'Just now'}</div>
      <div>${n.note_text}</div>
    </div>`).join('');
}

document.addEventListener('DOMContentLoaded', () => {
  if ($('modalCloseBtn')) {
    $('modalCloseBtn').addEventListener('click', () => {
      $('findingModalOverlay').classList.remove('active');
    });
  }
  if ($('findingModalOverlay')) {
    $('findingModalOverlay').addEventListener('click', (e) => {
      if (e.target === $('findingModalOverlay')) $('findingModalOverlay').classList.remove('active');
    });
  }
  if ($('modalStatusSelect')) {
    $('modalStatusSelect').addEventListener('change', async (e) => {
      if (!currentFindingId) return;
      try {
        const res = await fetch(`/api/findings/${currentFindingId}/status`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: e.target.value })
        });
        const data = await res.json();
        if (!data.ok) throw new Error(data.error);
        toast('success', 'Status Updated', `Finding #${currentFindingId} status updated to ${e.target.value}`);
        loadThreats();
      } catch (err) {
        toast('error', 'Update Failed', err.message);
      }
    });
  }
  if ($('modalAddNoteBtn')) {
    $('modalAddNoteBtn').addEventListener('click', async () => {
      if (!currentFindingId) return;
      const text = $('modalNoteInput').value.trim();
      if (!text) return;
      try {
        const res = await fetch(`/api/findings/${currentFindingId}/notes`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ note_text: text })
        });
        const data = await res.json();
        if (!data.ok) throw new Error(data.error);
        $('modalNoteInput').value = '';
        toast('success', 'Note Added', 'Investigation note saved successfully.');
        openFindingModal(currentFindingId);
        loadThreats();
      } catch (err) {
        toast('error', 'Failed to Add Note', err.message);
      }
    });
  }
});

function bindThreatFilters() {
  let t;
  $('threatSearch').addEventListener('input', (e) => {
    clearTimeout(t);
    t = setTimeout(() => { state.threatSearch = e.target.value.trim(); loadThreats(); }, 280);
  });
  $('threatSeverity').addEventListener('change', (e) => {
    state.threatSeverity = e.target.value; loadThreats();
  });
}

/* ===================== QUICK ACTIONS ===================== */
function bindQuickActions() {
  $('qaUpload').addEventListener('click', () => { switchView('analyzer'); setTimeout(() => $('fileInput').click(), 300); });
  $('qaSample').addEventListener('click', runSample);
  $('qaThreats').addEventListener('click', () => switchView('threats'));
  $('refreshBtn').addEventListener('click', () => {
    loadStats(); loadLogs(); loadThreats();
    toast('info', 'Refreshed', 'Dashboard data reloaded.');
  });
}

/* ===================== 3D TILT ===================== */
function bindTilt() {
  document.querySelectorAll('.tilt').forEach((el) => {
    el.addEventListener('mousemove', (e) => {
      const r = el.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width - 0.5;
      const y = (e.clientY - r.top) / r.height - 0.5;
      el.style.transform = `perspective(900px) rotateY(${x * 8}deg) rotateX(${-y * 8}deg) translateY(-4px) scale(1.01)`;
    });
    el.addEventListener('mouseleave', () => {
      el.style.transform = '';
    });
  });
}

/* ===================== THREE BUGS TRANSITIONS ===================== */
function triggerScreenFlash() {
  const flash = $('screenCyberWarp');
  if (!flash) return;
  flash.classList.add('flash');
  setTimeout(() => flash.classList.remove('flash'), 450);
}

function animateLandingToLoginTransition(onComplete) {
  const stage = $('bugTeleportStage');
  const flyerBit = $('bugFlyerBit');
  const flyerGlitch = $('bugFlyerGlitch');
  const flyerScout = $('bugFlyerScout');
  const landingContent = document.querySelector('.landing-content');
  const loginContainer = document.querySelector('.neu-login-container');

  if (landingContent) landingContent.classList.add('trans-out');
  triggerScreenFlash();

  if (!stage || !flyerBit || !flyerGlitch || !flyerScout) {
    if (onComplete) onComplete();
    return;
  }

  // Measure start and destination positions
  const startCards = document.querySelectorAll('.landing-char-card');
  const targetPods = [$('charPodBit'), $('charPodGlitch'), $('charPodScout')];

  const w = window.innerWidth;
  const h = window.innerHeight;

  // Defaults if elements not yet rendered
  let bitStart = { x: w * 0.35, y: h * 0.55 };
  let glitchStart = { x: w * 0.5, y: h * 0.55 };
  let scoutStart = { x: w * 0.65, y: h * 0.55 };

  if (startCards.length >= 3) {
    const r0 = startCards[0].getBoundingClientRect();
    const r1 = startCards[1].getBoundingClientRect();
    const r2 = startCards[2].getBoundingClientRect();
    bitStart = { x: r0.left + r0.width / 2 - 36, y: r0.top + r0.height / 2 - 40 };
    glitchStart = { x: r1.left + r1.width / 2 - 36, y: r1.top + r1.height / 2 - 40 };
    scoutStart = { x: r2.left + r2.width / 2 - 36, y: r2.top + r2.height / 2 - 40 };
  }

  // Set initial flyer positions
  stage.classList.add('active');
  flyerBit.style.transform = `translate(${bitStart.x}px, ${bitStart.y}px) scale(0.6)`;
  flyerGlitch.style.transform = `translate(${glitchStart.x}px, ${glitchStart.y}px) scale(0.6)`;
  flyerScout.style.transform = `translate(${scoutStart.x}px, ${scoutStart.y}px) scale(0.6)`;
  flyerBit.style.opacity = '1';
  flyerGlitch.style.opacity = '1';
  flyerScout.style.opacity = '1';

  // Fly animation with hyperdrive swoop
  requestAnimationFrame(() => {
    setTimeout(() => {
      let bitEnd = { x: w * 0.38 - 36, y: h * 0.28 };
      let glitchEnd = { x: w * 0.5 - 36, y: h * 0.25 };
      let scoutEnd = { x: w * 0.62 - 36, y: h * 0.28 };

      if (targetPods[0] && targetPods[1] && targetPods[2]) {
        const tb0 = targetPods[0].getBoundingClientRect();
        const tb1 = targetPods[1].getBoundingClientRect();
        const tb2 = targetPods[2].getBoundingClientRect();
        if (tb0.width > 0) bitEnd = { x: tb0.left + tb0.width / 2 - 36, y: tb0.top + tb0.height / 2 - 40 };
        if (tb1.width > 0) glitchEnd = { x: tb1.left + tb1.width / 2 - 36, y: tb1.top + tb1.height / 2 - 40 };
        if (tb2.width > 0) scoutEnd = { x: tb2.left + tb2.width / 2 - 36, y: tb2.top + tb2.height / 2 - 40 };
      }

      flyerBit.style.transform = `translate(${bitEnd.x}px, ${bitEnd.y}px) scale(1.1) rotate(-8deg)`;
      flyerGlitch.style.transform = `translate(${glitchEnd.x}px, ${glitchEnd.y}px) scale(1.2) rotate(0deg)`;
      flyerScout.style.transform = `translate(${scoutEnd.x}px, ${scoutEnd.y}px) scale(1.1) rotate(8deg)`;
    }, 50);
  });

  setTimeout(() => {
    if (onComplete) onComplete();
    if (loginContainer) loginContainer.classList.add('trans-in');
    triggerScreenFlash();
    setTimeout(() => {
      flyerBit.style.opacity = '0';
      flyerGlitch.style.opacity = '0';
      flyerScout.style.opacity = '0';
      setTimeout(() => {
        stage.classList.remove('active');
        if (landingContent) landingContent.classList.remove('trans-out');
      }, 400);
    }, 300);
  }, 600);
}

function animateLoginToDashboardTransition(onComplete) {
  const overlay = $('neuLoginOverlay');
  const appShell = document.querySelector('.app-shell');
  const landingVideo = $('landingVideo');
  if (landingVideo) {
    try { landingVideo.pause(); } catch (_) {}
  }

  // Trigger cyber warp screen flash effect
  triggerScreenFlash();

  if (overlay) overlay.classList.add('login-unlocking');

  // Celebrate with flip animations, quote bubbles, and particle effects
  if (window.ThreeBugs) {
    if (typeof window.ThreeBugs.scatter === 'function') {
      window.ThreeBugs.scatter();
    }
    if (window.ThreeBugs.bugs && window.ThreeBugs.bugs.length >= 3) {
      window.ThreeBugs.bugs.forEach((b, idx) => {
        setTimeout(() => {
          if (typeof b.celebrate === 'function') b.celebrate();
        }, idx * 180);
      });
      window.ThreeBugs.bugs[0].say("Access Verified! Welcome Operator 🛡️");
      setTimeout(() => window.ThreeBugs.bugs[1].say("Initializing Threat Telemetry! ⚡"), 600);
      setTimeout(() => window.ThreeBugs.bugs[2].say("Security Console Nominal! 🔍"), 1200);
    }
  }

  setTimeout(() => {
    if (overlay) {
      overlay.classList.add('hidden');
      overlay.classList.remove('login-unlocking');
    }
    if (appShell) {
      appShell.classList.add('dashboard-unlocked');
      setTimeout(() => appShell.classList.remove('dashboard-unlocked'), 850);
    }
    if (onComplete) onComplete();
  }, 680);
}

/* ===================== LANDING INTRO ===================== */
function initLandingIntro() {
  const overlay = $('landingIntroOverlay');
  const video = $('landingVideo');
  const enterBtn = $('landingEnterBtn');
  const skipBtn = $('landingSkipBtn');
  const replayBtn = $('replayIntroBtn');

  function dismissIntro() {
    if (!overlay.classList.contains('fade-out')) {
      animateLandingToLoginTransition(() => {
        overlay.classList.add('fade-out');
        if (video) video.pause();
      });
    }
  }

  function showIntro() {
    overlay.classList.remove('fade-out');
    if (video) {
      video.currentTime = 0;
      video.play().catch(() => {});
    }
  }

  if (enterBtn) enterBtn.addEventListener('click', dismissIntro);
  if (skipBtn) skipBtn.addEventListener('click', dismissIntro);
  if (video) {
    video.addEventListener('ended', dismissIntro);
    video.play().catch(() => {});
  }
  if (replayBtn) {
    replayBtn.addEventListener('click', () => {
      showIntro();
      toast('info', 'Intro Replayed', 'Playing The Three Bugs animation.');
    });
  }

  const switchUserBtn = $('landingSwitchUserBtn');
  if (switchUserBtn) {
    switchUserBtn.addEventListener('click', async () => {
      try { await api.logout(); } catch (_) {}
      currentUser = null;
      updateAuthUI(null);
      const loginOverlay = $('neuLoginOverlay');
      if (loginOverlay) {
        loginOverlay.classList.remove('hidden', 'login-unlocking');
      }
      dismissIntro();
    });
  }
}

/* ===================== CYBER CANVAS PARTICLE NETWORK ===================== */
function initCyberCanvas() {
  const canvas = $('cyberCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let width = canvas.width = window.innerWidth;
  let height = canvas.height = window.innerHeight;

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  }, { passive: true });

  const particles = [];
  // Optimized particle count for high frame-rates
  const count = Math.min(width > 1000 ? 32 : 18, 40);

  for (let i = 0; i < count; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.7,
      vy: (Math.random() - 0.5) * 0.7,
      radius: Math.random() * 1.5 + 1
    });
  }

  let mouseX = -1000;
  let mouseY = -1000;
  let isMoving = false;
  window.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
    isMoving = true;
  }, { passive: true });

  let lastFrame = 0;
  function animate(now) {
    requestAnimationFrame(animate);
    // Throttle canvas draw to ~35fps to avoid starving CPU/GPU
    if (now - lastFrame < 26) return;
    lastFrame = now;

    if (document.hidden) return;

    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = 'rgba(34, 211, 238, 0.75)';

    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0 || p.x > width) p.vx *= -1;
      if (p.y < 0 || p.y > height) p.vy *= -1;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fill();

      for (let j = i + 1; j < particles.length; j++) {
        const p2 = particles[j];
        const dx = p.x - p2.x;
        const dy = p.y - p2.y;
        const distSq = dx * dx + dy * dy;
        // Compare squared distance to avoid expensive Math.sqrt() on every frame
        if (distSq < 10000) { // 100px
          const dist = Math.sqrt(distSq);
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = `rgba(34, 211, 238, ${0.16 * (1 - dist / 100)})`;
          ctx.stroke();
        }
      }

      if (isMoving) {
        const mdx = p.x - mouseX;
        const mdy = p.y - mouseY;
        const mdistSq = mdx * mdx + mdy * mdy;
        if (mdistSq < 16900) { // 130px
          const mdist = Math.sqrt(mdistSq);
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(mouseX, mouseY);
          ctx.strokeStyle = `rgba(139, 92, 246, ${0.35 * (1 - mdist / 130)})`;
          ctx.stroke();
        }
      }
    }
  }
  requestAnimationFrame(animate);
}

/* ===================== CYBER CURSOR (60FPS GPU ACCELERATED) ===================== */
function initCyberCursor() {
  const cursor = $('cyberCursor');
  if (!cursor) return;

  let targetX = -100;
  let targetY = -100;
  let rafPending = false;
  let isHover = false;
  let isDown = false;

  function renderCursor() {
    // Center the whole paw directly on the mouse pointer (offset by half of 20px)
    const offsetX = targetX - 10;
    const offsetY = targetY - 10;
    const scale = isDown ? 0.8 : (isHover ? 1.2 : 1.0);
    const rotate = isDown ? -10 : (isHover ? -6 : 0);
    cursor.style.transform = `translate3d(${offsetX}px, ${offsetY}px, 0) scale(${scale}) rotate(${rotate}deg)`;
    rafPending = false;
  }

  function requestRender() {
    if (!rafPending) {
      rafPending = true;
      requestAnimationFrame(renderCursor);
    }
  }

  window.addEventListener('mousemove', (e) => {
    targetX = e.clientX;
    targetY = e.clientY;
    document.body.classList.add('cursor-active');
    requestRender();
  }, { passive: true });

  window.addEventListener('mousedown', () => {
    isDown = true;
    document.body.classList.add('cursor-down');
    requestRender();
  });

  window.addEventListener('mouseup', () => {
    isDown = false;
    document.body.classList.remove('cursor-down');
    requestRender();
  });

  document.addEventListener('mouseleave', () => {
    document.body.classList.remove('cursor-active');
  });

  const interactiveSelector = 'button, a, input, select, label, textarea, .qa, .dropzone, .nav-item, .kpi, .icon-btn, .clickable, .clickable-row, tr, .bug-entity, [role="button"], [onclick], .history-row';
  document.addEventListener('mouseover', (e) => {
    if (e.target.closest && e.target.closest(interactiveSelector)) {
      isHover = true;
      document.body.classList.add('cursor-hover');
      requestRender();
    }
  }, { passive: true });
  document.addEventListener('mouseout', (e) => {
    if (!e.relatedTarget || !e.relatedTarget.closest || !e.relatedTarget.closest(interactiveSelector)) {
      isHover = false;
      document.body.classList.remove('cursor-hover');
      requestRender();
    }
  }, { passive: true });
}

/* ===================== AUTH & NEUMORPHIC LOGIN CONTROLLER ===================== */
let currentUser = null;
let lockoutInterval = null;

function setCharacterMood(char, mood, text) {
  const pod = $(`charPod${char}`);
  const bubble = $(`charBubble${char}`);
  if (!pod || !bubble) return;

  if (text) bubble.textContent = text;
  pod.classList.add('speaking');
  clearTimeout(pod._speakTimeout);
  pod._speakTimeout = setTimeout(() => {
    pod.classList.remove('speaking');
  }, 3500);
}

function initNeumorphicAuth() {
  const overlay = $('neuLoginOverlay');
  const form = $('neuLoginForm');
  const usernameInput = $('neuUsername');
  const passwordInput = $('neuPassword');
  const togglePwdBtn = $('togglePasswordBtn');
  const togglePwdIcon = $('togglePasswordIcon');
  const alertBox = $('loginAlertBox');
  const alertText = $('loginAlertText');
  const lockoutBar = $('loginLockoutBar');
  const lockoutTimer = $('lockoutTimer');
  const topbarPill = $('authUserPill');
  const topbarUsername = $('topbarUsername');
  const topbarUserRole = $('topbarUserRole');
  const topbarLogoutBtn = $('topbarLogoutBtn');
  const settingsLogoutBtn = $('settingsLogoutBtn');
  const changePasswordForm = $('changePasswordForm');

  // Interactive Character Reactions on Input Focus & Typing
  if (usernameInput) {
    usernameInput.addEventListener('focus', () => {
      setCharacterMood('Bit', 'focus', 'Analyzing telemetry credentials... 👓');
    });
    usernameInput.addEventListener('input', () => {
      const val = usernameInput.value.trim().toLowerCase();
      if (val === 'admin') {
        setCharacterMood('Bit', 'alert', 'Administrator access profile detected! ⚡');
      } else if (val === 'analyst') {
        setCharacterMood('Bit', 'info', 'SOC Analyst operator profile ready.');
      } else if (val === 'viewer') {
        setCharacterMood('Bit', 'info', 'Read-Only Audit viewer profile.');
      }
    });
  }

  if (passwordInput) {
    passwordInput.addEventListener('focus', () => {
      setCharacterMood('Glitch', 'peek', 'Secret keyphrase! I will look away 🙈');
      const avatar = document.querySelector('#charPodGlitch .neu-char-avatar');
      if (avatar) avatar.style.transform = 'scale(0.92) rotate(-8deg)';
    });
    passwordInput.addEventListener('blur', () => {
      const avatar = document.querySelector('#charPodGlitch .neu-char-avatar');
      if (avatar) avatar.style.transform = '';
    });
    passwordInput.addEventListener('input', () => {
      if (passwordInput.value.length > 8) {
        setCharacterMood('Glitch', 'happy', 'High entropy keyphrase! Looking solid 🛡️');
      }
    });
  }

  // Password visibility toggle
  if (togglePwdBtn && passwordInput) {
    togglePwdBtn.addEventListener('click', () => {
      const isPwd = passwordInput.getAttribute('type') === 'password';
      passwordInput.setAttribute('type', isPwd ? 'text' : 'password');
      if (togglePwdIcon) {
        togglePwdIcon.setAttribute('data-lucide', isPwd ? 'eye-off' : 'eye');
        lucide.createIcons();
      }
    });
  }

  // Pre-configured credential chip click
  document.querySelectorAll('.neu-cred-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      if (usernameInput) usernameInput.value = chip.dataset.user;
      if (passwordInput) passwordInput.value = chip.dataset.pass;
      setCharacterMood('Scout', 'ready', `Autofilled ${chip.dataset.user} profile. Click Authenticate!`);
      if (alertBox) alertBox.style.display = 'none';
    });
  });

  // Login Form Submission
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = usernameInput ? usernameInput.value.trim() : '';
      const password = passwordInput ? passwordInput.value : '';

      if (!username || !password) {
        showLoginError('Please enter both username and password.');
        return;
      }

      if (alertBox) alertBox.style.display = 'none';
      setCharacterMood('Glitch', 'working', 'Hashing keyphrase and verifying credentials...');

      try {
        const { status, data } = await api.login(username, password);

        if (status === 200 && data.ok && data.data?.mfa_required) {
          openLoginMfaModal(data.data.methods || { totp: true, email: false });
          return;
        }
        if (status === 200 && data.ok) {
          currentUser = data.data.user;
          updateAuthUI(currentUser);
          setCharacterMood('Scout', 'success', 'Identity confirmed! SOC console unlocked 🛡️');
          toast('success', 'Authentication Successful', `Welcome back, ${currentUser.username} (${currentUser.role}).`);

          // Animate transition from login into the dashboard with The Three Bugs celebration
          setTimeout(() => {
            animateLoginToDashboardTransition();
          }, 350);
        } else if (status === 429) {
          // Throttled / Lockout
          const retryIn = data.error?.retry_after || 60;
          startLockoutCountdown(retryIn);
          setCharacterMood('Scout', 'lockout', 'BRUTE FORCE DETECTED: Throttle active! 🚨');
        } else {
          // Generic failure message (SECURITY-1 requirement: never leak username existence)
          showLoginError(data.error?.message || 'Invalid username or password.');
          setCharacterMood('Glitch', 'error', 'Access denied. Generic error logged 🛑');
          if (passwordInput) {
            passwordInput.value = '';
            passwordInput.focus();
          }
        }
      } catch (err) {
        showLoginError('Connection failed. Server may be unreachable.');
      }
    });
  }

  function showLoginError(msg) {
    if (alertBox && alertText) {
      alertText.textContent = msg;
      alertBox.style.display = 'flex';
      lucide.createIcons();
    }
  }

  function startLockoutCountdown(seconds) {
    if (lockoutInterval) clearInterval(lockoutInterval);
    let rem = seconds;
    if (lockoutBar && lockoutTimer) {
      lockoutTimer.textContent = rem;
      lockoutBar.style.display = 'flex';
    }
    const btn = $('neuLoginSubmitBtn');
    if (btn) btn.disabled = true;

    lockoutInterval = setInterval(() => {
      rem--;
      if (lockoutTimer) lockoutTimer.textContent = rem;
      if (rem <= 0) {
        clearInterval(lockoutInterval);
        if (lockoutBar) lockoutBar.style.display = 'none';
        if (btn) btn.disabled = false;
        if (alertBox) alertBox.style.display = 'none';
      }
    }, 1000);
  }

  // Logout Handlers
  async function performLogout() {
    try {
      await api.logout();
    } catch (_) {}
    currentUser = null;
    toast('info', 'Logged Out', 'Session ended safely.');

    const stage = $('bugTeleportStage');
    const flyerBit = $('bugFlyerBit');
    const flyerGlitch = $('bugFlyerGlitch');
    const flyerScout = $('bugFlyerScout');
    const appShell = document.querySelector('.app-shell');

    triggerScreenFlash();
    if (appShell) appShell.classList.remove('dashboard-unlocked');

    if (overlay) {
      overlay.classList.remove('hidden', 'login-unlocking');
    }

    if (stage && flyerBit && flyerGlitch && flyerScout) {
      const w = window.innerWidth;
      const h = window.innerHeight;
      stage.classList.add('active');
      flyerBit.style.transform = `translate(${-80}px, ${h * 0.2}px) scale(0.7)`;
      flyerGlitch.style.transform = `translate(${w * 0.5 - 36}px, ${-80}px) scale(0.7)`;
      flyerScout.style.transform = `translate(${w + 80}px, ${h * 0.2}px) scale(0.7)`;
      flyerBit.style.opacity = '1';
      flyerGlitch.style.opacity = '1';
      flyerScout.style.opacity = '1';

      requestAnimationFrame(() => {
        setTimeout(() => {
          flyerBit.style.transform = `translate(${w * 0.38 - 36}px, ${h * 0.28}px) scale(1.05) rotate(-6deg)`;
          flyerGlitch.style.transform = `translate(${w * 0.5 - 36}px, ${h * 0.25}px) scale(1.15) rotate(0deg)`;
          flyerScout.style.transform = `translate(${w * 0.62 - 36}px, ${h * 0.28}px) scale(1.05) rotate(6deg)`;
        }, 30);
        setTimeout(() => {
          flyerBit.style.opacity = '0';
          flyerGlitch.style.opacity = '0';
          flyerScout.style.opacity = '0';
          stage.classList.remove('active');
        }, 650);
      });
    }

    if (usernameInput) usernameInput.value = '';
    if (passwordInput) passwordInput.value = '';
    updateAuthUI(null);
  }

  if (topbarLogoutBtn) topbarLogoutBtn.addEventListener('click', performLogout);
  if (settingsLogoutBtn) settingsLogoutBtn.addEventListener('click', performLogout);

  // Change Password Handler (Settings View)
  if (changePasswordForm) {
    changePasswordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const curr = $('currentPasswordInput') ? $('currentPasswordInput').value : '';
      const newP = $('newPasswordInput') ? $('newPasswordInput').value : '';
      const confP = $('confirmPasswordInput') ? $('confirmPasswordInput').value : '';

      if (newP !== confP) {
        toast('error', 'Validation Error', 'New passwords do not match.');
        return;
      }
      if (newP.length < 8) {
        toast('error', 'Weak Password', 'Password must be at least 8 characters long.');
        return;
      }

      try {
        const { status, data } = await api.changePassword(curr, newP);
        if (status === 200 && data.ok && data.data?.mfa_required) {
          openLoginMfaModal(data.data.methods || { totp: true, email: false });
          return;
        }
        if (status === 200 && data.ok) {
          toast('success', 'Password Updated', 'Session invalidated for security. Please log in again.');
          changePasswordForm.reset();
          // SECURITY-1 requires re-authentication after password change
          setTimeout(() => {
            performLogout();
          }, 1200);
        } else {
          toast('error', 'Update Failed', data.error?.message || 'Failed to change password.');
        }
      } catch (err) {
        toast('error', 'Error', 'Failed to communicate with authentication server.');
      }
    });
  }

  // Check initial session
  checkSession();
}

async function checkSession() {
  const overlay = $('neuLoginOverlay');
  // Enforce fresh authentication on every page load/refresh for SOC security
  try { await api.logout(); } catch (_) {}
  currentUser = null;
  if (overlay) overlay.classList.remove('hidden');
  updateAuthUI(null);
}

function updateAuthUI(user) {
  const topbarUser = $('topbarUsername');
  const topbarRole = $('topbarUserRole');
  const settingsUser = $('settingsUsername');
  const settingsRole = $('settingsUserRoleBadge');
  const landingActiveRow = $('landingActiveUserRow');
  const landingActiveUser = $('landingActiveUsername');

  if (user) {
    if (topbarUser) topbarUser.textContent = user.username;
    if (topbarRole) topbarRole.textContent = user.role;
    if (settingsUser) settingsUser.textContent = user.username;
    if (settingsRole) settingsRole.textContent = user.role;
    if (landingActiveRow) landingActiveRow.style.display = 'block';
    if (landingActiveUser) landingActiveUser.textContent = `${user.username} (${user.role})`;
  } else {
    if (topbarUser) topbarUser.textContent = 'Guest';
    if (topbarRole) topbarRole.textContent = 'Unauthenticated';
    if (settingsUser) settingsUser.textContent = 'Not Logged In';
    if (settingsRole) settingsRole.textContent = 'None';
    if (landingActiveRow) landingActiveRow.style.display = 'none';
  }
  applyRbacUi(user);
}

let currentActiveUser = null;

function applyRbacUi(user) {
  currentActiveUser = user || null;
  const role = user ? user.role : 'Viewer';
  const isAdmin = role === 'Admin' || role === 'Administrator';
  const adminControls = $('rbacAdminControls');
  const adminNotice = $('rbacAdminLockedNotice');

  if (isAdmin) {
    if (adminControls) adminControls.style.display = 'block';
    if (adminNotice) adminNotice.style.display = 'none';
    loadRbacUsers();
  } else {
    if (adminControls) adminControls.style.display = 'none';
    if (adminNotice) adminNotice.style.display = 'block';
  }

  // Enforce Viewer read-only restrictions on mutating controls
  const isViewer = role === 'Viewer';
  const mutatingIds = ['uploadCsvTriggerBtn', 'loadSampleBtn', 'newInvBtn', 'createInvBtn'];
  mutatingIds.forEach((id) => {
    const el = $(id);
    if (el) {
      el.disabled = isViewer;
      el.style.opacity = isViewer ? '0.45' : '';
      el.style.pointerEvents = isViewer ? 'none' : '';
      if (isViewer) el.title = 'Viewer role is read-only';
    }
  });
}

async function loadRbacUsers() {
  const tbody = $('rbacUsersBody');
  if (!tbody) return;
  try {
    const res = await fetch('/api/users');
    if (!res.ok) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="4">Unable to load users (Admin access required).</td></tr>';
      return;
    }
    const json = await res.json();
    const users = json.data || [];
    if (!users.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No users found.</td></tr>';
      return;
    }
    tbody.innerHTML = users.map((u) => {
      const isSelf = currentActiveUser && currentActiveUser.id === u.id;
      return `
        <tr>
          <td class="mono">#${u.id}</td>
          <td style="font-weight:600;color:var(--txt-0);">
            ${escapeHtml(u.username)} ${isSelf ? '<span style="font-size:10px;color:var(--cyan);margin-left:4px;">(You)</span>' : ''}
            ${u.email ? `<div style="font-size:11px;color:var(--txt-2);font-weight:400;">${escapeHtml(u.email)}</div>` : '<div style="font-size:11px;color:var(--txt-3);font-weight:400;">No email</div>'}
          </td>
          <td>
            <select class="select" style="padding:4px 8px;font-size:12px;" ${isSelf ? 'disabled title="Cannot change your own active role"' : ''} onchange="updateSocUserRole(${u.id}, this.value)">
              <option value="Admin" ${u.role === 'Admin' || u.role === 'Administrator' ? 'selected' : ''}>Admin</option>
              <option value="Analyst" ${u.role === 'Analyst' ? 'selected' : ''}>Analyst</option>
              <option value="Viewer" ${u.role === 'Viewer' ? 'selected' : ''}>Viewer</option>
            </select>
          </td>
          <td style="text-align:right;white-space:nowrap;">
            <button class="btn ghost" style="padding:4px 10px;font-size:11.5px;color:var(--cyan);border-color:rgba(34,211,238,0.3);margin-right:6px;" onclick="openEditSocUserModal(${u.id}, '${escapeHtml(u.username)}', '${escapeHtml(u.email || '')}', '${escapeHtml(u.role)}', ${isSelf})">
              <i data-lucide="pencil" style="width:13px;height:13px;"></i> Edit
            </button>
            <button class="btn ghost" style="padding:4px 10px;font-size:11.5px;color:#fb7185;border-color:rgba(244,63,94,0.3);" ${isSelf ? 'disabled title="Cannot delete your own account"' : ''} onclick="deleteSocUser(${u.id}, '${escapeHtml(u.username)}')">
              <i data-lucide="trash-2" style="width:13px;height:13px;"></i> Delete
            </button>
          </td>
        </tr>`;
    }).join('');
    if (window.lucide) lucide.createIcons();
  } catch (e) {
    console.error('Failed to load RBAC users:', e);
  }
}

function openEditSocUserModal(userId, username, email, role, isSelf) {
  const existing = document.getElementById('editSocUserOverlay');
  if (existing) existing.remove();
  const normalizedRole = role === 'Administrator' ? 'Admin' : role;
  const overlay = document.createElement('div');
  overlay.id = 'editSocUserOverlay';
  overlay.style.cssText = 'position:fixed;inset:0;z-index:999999;background:rgba(4,7,15,0.82);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;padding:20px;';
  overlay.innerHTML = `
    <div style="width:100%;max-width:420px;background:linear-gradient(160deg,rgba(18,24,42,0.98),rgba(9,13,24,0.98));border:1px solid rgba(34,211,238,0.4);border-radius:16px;padding:24px;box-shadow:0 20px 50px rgba(0,0,0,0.8);">
      <h3 style="margin:0 0 14px;color:#fff;font-size:17px;">Edit SOC User #${userId}</h3>
      <div style="margin-bottom:12px;">
        <label class="modal-label">Username</label>
        <input type="text" id="editSocUsername" value="${escapeHtml(username)}" minlength="3" style="width:100%;background:rgba(15,23,42,0.8);border:1px solid var(--border);border-radius:8px;padding:8px 12px;color:#fff;" />
      </div>
      <div style="margin-bottom:12px;">
        <label class="modal-label">Email (for OTP)</label>
        <input type="email" id="editSocEmail" value="${escapeHtml(email)}" placeholder="user@org.com" style="width:100%;background:rgba(15,23,42,0.8);border:1px solid var(--border);border-radius:8px;padding:8px 12px;color:#fff;" />
      </div>
      <div style="margin-bottom:18px;">
        <label class="modal-label">Role</label>
        <select id="editSocRole" class="select" style="width:100%;" ${isSelf ? 'disabled title="Cannot change your own active role"' : ''}>
          <option value="Admin" ${normalizedRole === 'Admin' ? 'selected' : ''}>Admin</option>
          <option value="Analyst" ${normalizedRole === 'Analyst' ? 'selected' : ''}>Analyst</option>
          <option value="Viewer" ${normalizedRole === 'Viewer' ? 'selected' : ''}>Viewer</option>
        </select>
      </div>
      <div style="display:flex;gap:10px;justify-content:flex-end;">
        <button type="button" class="btn ghost" id="editSocCancelBtn">Cancel</button>
        <button type="button" class="btn primary" id="editSocSaveBtn">Save Changes</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  overlay.querySelector('#editSocCancelBtn').addEventListener('click', () => overlay.remove());
  overlay.querySelector('#editSocSaveBtn').addEventListener('click', async () => {
    const newUsername = overlay.querySelector('#editSocUsername').value.trim();
    const newEmail = overlay.querySelector('#editSocEmail').value.trim();
    const newRole = overlay.querySelector('#editSocRole').value;
    const res = await fetch(`/api/users/${userId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: newUsername, email: newEmail, role: newRole })
    });
    const json = await res.json();
    if (res.ok && json.ok) {
      toast('success', 'User Updated', `Saved changes for ${json.data.username}.`);
      if (isSelf && currentUser) {
        currentUser.username = json.data.username;
        updateAuthUI(currentUser);
      }
      overlay.remove();
      loadRbacUsers();
    } else {
      toast('error', 'Update Failed', json.error?.message || 'Could not update user.');
    }
  });
}

async function updateSocUserRole(userId, newRole) {
  try {
    const res = await fetch(`/api/users/${userId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: newRole })
    });
    const json = await res.json();
    if (res.ok && json.ok) {
      toast('success', 'Role Updated', `${json.data.username} is now ${newRole}.`);
      loadRbacUsers();
    } else {
      toast('error', 'Update Failed', json.error?.message || 'Could not update role.');
      loadRbacUsers();
    }
  } catch (e) {
    toast('error', 'Error', 'Failed to communicate with server.');
  }
}

function showCyberConfirm(title, message, confirmLabel = 'Confirm', onConfirm) {
  const existing = document.getElementById('cyberConfirmOverlay');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'cyberConfirmOverlay';
  overlay.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(4,7,15,0.78);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;padding:20px;animation:fadeIn 0.2s ease;';
  overlay.innerHTML = `
    <div style="width:100%;max-width:420px;background:linear-gradient(160deg,rgba(18,24,42,0.98),rgba(9,13,24,0.98));border:1px solid rgba(244,63,94,0.45);border-radius:16px;padding:22px 24px;box-shadow:0 20px 50px rgba(0,0,0,0.75),0 0 28px rgba(244,63,94,0.2);">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
        <div style="width:38px;height:38px;border-radius:10px;background:rgba(244,63,94,0.14);border:1px solid rgba(244,63,94,0.4);display:grid;place-items:center;color:#fb7185;">
          <i data-lucide="alert-triangle" style="width:18px;height:18px;"></i>
        </div>
        <h3 style="margin:0;font-size:16px;font-weight:700;color:#fff;">${escapeHtml(title)}</h3>
      </div>
      <p style="margin:0 0 20px;font-size:13.5px;line-height:1.5;color:var(--txt-1);">${message}</p>
      <div style="display:flex;gap:10px;justify-content:flex-end;">
        <button type="button" class="btn ghost" id="cyberConfirmCancel">Cancel</button>
        <button type="button" class="btn primary" id="cyberConfirmOk" style="background:linear-gradient(135deg,#f43f5e,#e11d48);color:#fff;box-shadow:0 6px 20px rgba(244,63,94,0.4);">${escapeHtml(confirmLabel)}</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  if (window.lucide) lucide.createIcons();

  const close = () => overlay.remove();
  overlay.querySelector('#cyberConfirmCancel').addEventListener('click', close);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
  overlay.querySelector('#cyberConfirmOk').addEventListener('click', () => {
    close();
    if (typeof onConfirm === 'function') onConfirm();
  });
}

async function deleteSocUser(userId, username) {
  showCyberConfirm(
    'Revoke SOC Access',
    `Are you sure you want to revoke access and delete SOC user <strong style="color:#22d3ee;">${escapeHtml(username)}</strong>? This action cannot be undone.`,
    'Revoke & Delete',
    async () => {
      try {
        const res = await fetch(`/api/users/${userId}`, { method: 'DELETE' });
        const json = await res.json();
        if (res.ok && json.ok) {
          toast('success', 'User Deleted', `Removed user ${username}.`);
          loadRbacUsers();
        } else {
          toast('error', 'Delete Failed', json.error?.message || 'Could not delete user.');
        }
      } catch (e) {
        toast('error', 'Error', 'Failed to communicate with server.');
      }
    }
  );
}

/* ===================== INIT ===================== */
document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();
  initLandingIntro();
  initCyberCanvas();
  initCyberCursor();
  initNeumorphicAuth();
  checkSession();

  // Settings sub-tabs switching
  document.querySelectorAll('.settings-tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.settingsTab;
      document.querySelectorAll('.settings-tab-btn').forEach((b) => {
        b.classList.remove('active', 'primary');
        b.classList.add('ghost');
      });
      btn.classList.add('active', 'primary');
      btn.classList.remove('ghost');

      document.querySelectorAll('.settings-tab-panel').forEach((panel) => {
        panel.style.display = panel.id === `settings-tab-${target}` ? 'block' : 'none';
      });
    });
  });

  const changeUsernameForm = $('changeUsernameForm');
  if (changeUsernameForm) {
    changeUsernameForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const newUsername = $('newUsernameInput').value.trim();
      if (newUsername.length < 3) {
        toast('error', 'Validation Error', 'Username must be at least 3 characters.');
        return;
      }
      try {
        const res = await fetch('/api/auth/change-username', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: newUsername })
        });
        const json = await res.json();
        if (res.ok && json.ok) {
          if (currentUser) currentUser.username = json.data.username;
          updateAuthUI(currentUser || { username: json.data.username, role: json.data.role });
          changeUsernameForm.reset();
          toast('success', 'Username Updated', `Active username changed to ${json.data.username}.`);
        } else {
          toast('error', 'Update Failed', json.error?.message || 'Could not update username.');
        }
      } catch (err) {
        toast('error', 'Error', 'Failed to communicate with server.');
      }
    });
  }

  const createUserForm = $('createUserForm');
  if (createUserForm) {
    createUserForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = $('newSocUsername').value.trim();
      const email = $('newSocEmail') ? $('newSocEmail').value.trim() : '';
      const password = $('newSocPassword').value;
      const role = $('newSocRole').value;
      try {
        const res = await fetch('/api/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, email, password, role })
        });
        const json = await res.json();
        if (res.ok && json.ok) {
          toast('success', 'User Created', `Created ${username} (${role}).`);
          createUserForm.reset();
          loadRbacUsers();
        } else {
          toast('error', 'Creation Failed', json.error?.message || 'Could not create user.');
        }
      } catch (err) {
        toast('error', 'Error', 'Failed to communicate with server.');
      }
    });
  }
  bindAnalyzerFilters();
  bindThreatFilters();
  bindUploader();
  bindQuickActions();
  bindTilt();
  bindInvestigations();
  loadStats();
  loadLogs();
  loadUploadHistory();
  loadThreats();
  loadInvestigations();
  // Toggle MFA (Enable / Disable)
  const toggleMfaBtn = $('toggleMfaBtn');
  if (toggleMfaBtn) {
    let mfaState = false;
    toggleMfaBtn.addEventListener('click', async () => {
      mfaState = !mfaState;
      const res = await fetch('/api/auth/mfa/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: mfaState })
      });
      const json = await res.json();
      if (res.ok && json.ok) {
        $('toggleMfaLabel').textContent = json.data.mfa_enabled ? 'Disable MFA' : 'Enable MFA';
        toggleMfaBtn.classList.toggle('primary', json.data.mfa_enabled);
        toast('success', 'MFA Updated', json.data.mfa_enabled ? 'MFA is now enabled for login.' : 'MFA disabled; normal login restored.');
      } else {
        mfaState = !mfaState;
        toast('error', 'MFA Error', json.error?.message || 'Could not toggle MFA.');
      }
    });
  }

  // Login MFA Verification Modal (supports choosing Google Auth or Email OTP)
  window.openLoginMfaModal = function(methods) {
    const existing = document.getElementById('loginMfaOverlay');
    if (existing) existing.remove();
    const hasTotp = !!methods.totp;
    const hasEmail = !!methods.email;
    let selectedMethod = hasTotp ? 'totp' : 'email';

    const mfaOverlay = document.createElement('div');
    mfaOverlay.id = 'loginMfaOverlay';
    mfaOverlay.style.cssText = 'position:fixed;inset:0;z-index:999999;background:rgba(4,7,15,0.85);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;padding:20px;';
    mfaOverlay.innerHTML = `
      <div style="width:100%;max-width:410px;background:linear-gradient(160deg,rgba(18,24,42,0.98),rgba(9,13,24,0.98));border:1px solid rgba(34,211,238,0.45);border-radius:16px;padding:24px;box-shadow:0 20px 50px rgba(0,0,0,0.8);">
        <h3 style="margin:0 0 6px;color:#fff;font-size:17px;">Two-Factor Authentication</h3>
        <p style="margin:0 0 14px;font-size:12.5px;color:var(--txt-2);">Choose your preferred verification method:</p>
        <div style="display:flex;gap:8px;margin-bottom:14px;">
          ${hasTotp ? '<button type="button" class="btn primary mfa-method-btn" data-method="totp" style="flex:1;font-size:12px;">Google Auth</button>' : ''}
          ${hasEmail ? '<button type="button" class="btn ' + (hasTotp ? 'ghost' : 'primary') + ' mfa-method-btn" data-method="email" style="flex:1;font-size:12px;">Email OTP</button>' : ''}
        </div>
        <div id="mfaEmailSendRow" style="display:${selectedMethod === 'email' ? 'flex' : 'none'};justify-content:space-between;align-items:center;margin-bottom:12px;">
          <span style="font-size:12px;color:var(--txt-2);">Send 6-digit code to your email</span>
          <button type="button" class="btn secondary" id="mfaSendEmailBtn" style="font-size:11.5px;padding:5px 10px;">Send OTP</button>
        </div>
        <input type="text" id="loginMfaCodeInput" autocomplete="off" class="neu-input" placeholder="Enter 6-digit code" maxlength="6" style="width:100%;background:rgba(15,23,42,0.8);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:10px;color:#fff;" />
        <div id="loginMfaError" style="display:none;font-size:12px;color:#fb7185;background:rgba(244,63,94,0.12);border:1px solid rgba(244,63,94,0.35);border-radius:8px;padding:8px 12px;margin-bottom:14px;"></div>
        <div style="display:flex;gap:10px;justify-content:flex-end;">
          <button type="button" class="btn ghost" id="loginMfaCancelBtn">Cancel</button>
          <button type="button" class="btn primary" id="loginMfaVerifyBtn">Verify &amp; Login</button>
        </div>
      </div>
    `;
    document.body.appendChild(mfaOverlay);

    mfaOverlay.querySelectorAll('.mfa-method-btn').forEach((b) => {
      b.addEventListener('click', () => {
        selectedMethod = b.dataset.method;
        mfaOverlay.querySelectorAll('.mfa-method-btn').forEach(x => { x.classList.remove('primary'); x.classList.add('ghost'); });
        b.classList.add('primary'); b.classList.remove('ghost');
        mfaOverlay.querySelector('#mfaEmailSendRow').style.display = selectedMethod === 'email' ? 'flex' : 'none';
      });
    });

    const sendBtn = mfaOverlay.querySelector('#mfaSendEmailBtn');
    if (sendBtn) {
      sendBtn.addEventListener('click', async () => {
        const res = await fetch('/api/auth/login/send-otp', { method: 'POST' });
        const json = await res.json();
        if (res.ok && json.ok) toast('success', 'OTP Sent', json.data.message);
        else toast('error', 'OTP Error', json.error?.message || 'Failed to send OTP.');
      });
    }

    mfaOverlay.querySelector('#loginMfaCancelBtn').addEventListener('click', () => mfaOverlay.remove());
    mfaOverlay.querySelector('#loginMfaVerifyBtn').addEventListener('click', async () => {
      const code = mfaOverlay.querySelector('#loginMfaCodeInput').value.trim();
      const res = await fetch('/api/auth/login/mfa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, method: selectedMethod })
      });
      const json = await res.json();
      if (res.ok && json.ok) {
        mfaOverlay.remove();
        currentUser = json.data.user;
        updateAuthUI(currentUser);
        toast('success', 'Authentication Successful', `Welcome back, ${currentUser.username} (${currentUser.role}).`);
        animateLoginToDashboardTransition(() => {
          const loginOv = $('neuLoginOverlay');
          if (loginOv) loginOv.classList.add('hidden');
        });
      } else {
        const errEl = mfaOverlay.querySelector('#loginMfaError');
        if (errEl) {
          errEl.style.display = 'block';
          errEl.textContent = json.error?.message || 'Wrong or expired 6-digit code. Please try again.';
        }
        toast('error', 'Invalid Code', json.error?.message || 'Wrong or expired verification code.');
      }
    });
  };

  // Google Authenticator MFA Setup
  const setupMfaBtn = $('setupMfaBtn');
  const verifyMfaBtn = $('verifyMfaBtn');
  if (setupMfaBtn) {
    setupMfaBtn.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/auth/mfa/setup', { method: 'POST' });
        const json = await res.json();
        if (res.ok && json.ok) {
          $('mfaSecretText').textContent = json.data.secret;
          $('mfaSetupBox').style.display = 'block';
          toast('info', 'MFA Secret Generated', 'Add this secret key in Google Authenticator and verify.');
        } else {
          toast('error', 'MFA Error', json.error?.message || 'Could not start MFA setup.');
        }
      } catch (e) {
        toast('error', 'Error', 'Failed to communicate with server.');
      }
    });
  }
  if (verifyMfaBtn) {
    verifyMfaBtn.addEventListener('click', async () => {
      const code = $('mfaVerifyCodeInput').value.trim();
      try {
        const res = await fetch('/api/auth/mfa/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code })
        });
        const json = await res.json();
        if (res.ok && json.ok) {
          $('mfaSetupBox').style.display = 'none';
          toast('success', 'Google Auth Enabled', 'MFA is now active on your account.');
        } else {
          toast('error', 'Verification Failed', json.error?.message || 'Invalid 6-digit code.');
        }
      } catch (e) {
        toast('error', 'Error', 'Failed to verify MFA code.');
      }
    });
  }

  // Forgot Password Modal (Login & Settings)
  function openForgotPasswordModal() {
    const existing = document.getElementById('forgotPwdOverlay');
    if (existing) existing.remove();
    let activeMethod = 'email';
    let verifiedCode = '';

    const overlay = document.createElement('div');
    overlay.id = 'forgotPwdOverlay';
    overlay.style.cssText = 'position:fixed;inset:0;z-index:999999;background:rgba(4,7,15,0.82);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;padding:20px;';
    overlay.innerHTML = `
      <div style="width:100%;max-width:450px;background:linear-gradient(160deg,rgba(18,24,42,0.98),rgba(9,13,24,0.98));border:1px solid rgba(34,211,238,0.4);border-radius:16px;padding:24px;box-shadow:0 20px 50px rgba(0,0,0,0.8);">
        <h3 style="margin:0 0 6px;color:#fff;font-size:17px;">Reset Password (Google Auth)</h3>
        <p style="margin:0 0 14px;font-size:12.5px;color:var(--txt-2);">Search your SOC username, verify with your 6-digit Google Authenticator code, then reset.</p>

        <!-- Step 1: Search Username -->
        <div style="margin-bottom:12px;">
          <label class="modal-label">1. Enter Username</label>
          <div style="display:flex;gap:8px;">
            <input type="text" id="fpUsername" autocomplete="off" class="neu-input" placeholder="Enter username" style="flex:1;background:rgba(15,23,42,0.8);border:1px solid var(--border);border-radius:8px;padding:8px 12px;color:#fff;" />
            <button type="button" class="btn secondary" id="fpSearchBtn">Search</button>
          </div>
        </div>

        <div id="fpStatusMsg" style="font-size:12px;padding:8px 12px;border-radius:8px;margin-bottom:12px;display:none;"></div>

        <!-- Step 2: Google Auth Verification -->
        <div id="fpRecoveryBox" style="display:none;">
          <label class="modal-label">2. Google Authenticator Code</label>
          <div style="display:flex;gap:8px;margin-bottom:14px;">
            <input type="text" id="fpCode" autocomplete="off" class="neu-input" placeholder="Enter 6-digit Google Auth code" maxlength="6" style="flex:1;background:rgba(15,23,42,0.8);border:1px solid var(--border);border-radius:8px;padding:8px 12px;color:#fff;" />
            <button type="button" class="btn primary" id="fpVerifyCodeBtn">Verify</button>
          </div>
        </div>

        <!-- Step 3: New Password & Confirm Password (unlocked after code verification) -->
        <div id="fpNewPwdBox" style="display:none;margin-bottom:18px;">
          <label class="modal-label">3. New Password (min 8 chars)</label>
          <input type="password" id="fpNewPwd" class="neu-input" placeholder="New secure password" minlength="8" style="width:100%;background:rgba(15,23,42,0.8);border:1px solid var(--border);border-radius:8px;padding:8px 12px;color:#fff;margin-bottom:10px;" />
          <label class="modal-label">Confirm Password</label>
          <input type="password" id="fpConfirmPwd" class="neu-input" placeholder="Repeat new password" minlength="8" style="width:100%;background:rgba(15,23,42,0.8);border:1px solid var(--border);border-radius:8px;padding:8px 12px;color:#fff;" />
        </div>

        <!-- Step 4: Post-Reset -->
        <div id="fpDoneBox" style="display:none;text-align:center;padding:10px 0;">
          <div style="color:#34d399;font-weight:700;font-size:15px;margin-bottom:8px;">✓ Password Reset Complete</div>
          <p style="font-size:12.5px;color:var(--txt-2);margin:0 0 16px;">Your password has been updated. Return to the Login page to sign in.</p>
          <div style="display:flex;gap:10px;justify-content:center;">
            <button type="button" class="btn primary" id="fpGoLoginBtn">Go to Login Page</button>
          </div>
        </div>

        <div id="fpFooterBtns" style="display:flex;gap:10px;justify-content:flex-end;">
          <button type="button" class="btn ghost" id="fpCancelBtn">Cancel</button>
          <button type="button" class="btn primary" id="fpResetBtn" style="display:none;">Save Password</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    const statusEl = overlay.querySelector('#fpStatusMsg');
    const setStatus = (msg, ok) => {
      statusEl.style.display = 'block';
      statusEl.style.color = ok ? '#34d399' : '#fb7185';
      statusEl.style.background = ok ? 'rgba(16,185,129,0.1)' : 'rgba(244,63,94,0.1)';
      statusEl.style.border = ok ? '1px solid rgba(16,185,129,0.3)' : '1px solid rgba(244,63,94,0.3)';
      statusEl.textContent = msg;
    };

    overlay.querySelector('#fpCancelBtn').addEventListener('click', () => overlay.remove());

    overlay.querySelector('#fpSearchBtn').addEventListener('click', async () => {
      const username = overlay.querySelector('#fpUsername').value.trim();
      const res = await fetch('/api/auth/forgot-password/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });
      const json = await res.json();
      if (!res.ok || !json.ok) {
        overlay.querySelector('#fpRecoveryBox').style.display = 'none';
        setStatus(json.error?.message || 'Username not found.', false);
        return;
      }
      const d = json.data;
      if (!d.has_totp) {
        overlay.querySelector('#fpRecoveryBox').style.display = 'none';
        setStatus('Google Authenticator is not connected to this account.', false);
        return;
      }
      activeMethod = 'totp';
      overlay.querySelector('#fpRecoveryBox').style.display = 'block';
      setStatus(`Account "${d.username}" found! Enter your 6-digit Google Authenticator code.`, true);
    });

    const verifyBtn = overlay.querySelector('#fpVerifyCodeBtn');
    verifyBtn.addEventListener('click', async () => {
      const username = overlay.querySelector('#fpUsername').value.trim();
      const code = overlay.querySelector('#fpCode').value.trim();
      verifyBtn.disabled = true;
      verifyBtn.textContent = 'Verifying...';
      try {
        const res = await fetch('/api/auth/forgot-password/verify-code', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, code, method: 'totp' })
        });
        const json = await res.json();
        if (res.ok && json.ok) {
          verifiedCode = code;
          verifyBtn.textContent = 'Verified ✓';
          verifyBtn.style.background = 'linear-gradient(135deg,#10b981,#059669)';
          setStatus('Verified ✓ — Enter and confirm your new password below.', true);
          overlay.querySelector('#fpNewPwdBox').style.display = 'block';
          overlay.querySelector('#fpResetBtn').style.display = 'inline-flex';
        } else {
          verifyBtn.disabled = false;
          verifyBtn.textContent = 'Verify';
          setStatus(json.error?.message || 'Wrong or expired verification code.', false);
        }
      } catch (e) {
        verifyBtn.disabled = false;
        verifyBtn.textContent = 'Verify';
        setStatus('Network error while verifying code.', false);
      }
    });

    overlay.querySelector('#fpResetBtn').addEventListener('click', async () => {
      const username = overlay.querySelector('#fpUsername').value.trim();
      const new_password = overlay.querySelector('#fpNewPwd').value;
      const confirm_password = overlay.querySelector('#fpConfirmPwd').value;
      if (new_password.length < 8) {
        setStatus('Password must be at least 8 characters.', false);
        return;
      }
      if (new_password !== confirm_password) {
        setStatus('Passwords do not match.', false);
        return;
      }
      const res = await fetch('/api/auth/forgot-password/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, code: verifiedCode, new_password })
      });
      const json = await res.json();
      if (res.ok && json.ok) {
        overlay.querySelector('#fpRecoveryBox').style.display = 'none';
        overlay.querySelector('#fpNewPwdBox').style.display = 'none';
        overlay.querySelector('#fpFooterBtns').style.display = 'none';
        overlay.querySelector('#fpDoneBox').style.display = 'block';
        setStatus('Password saved successfully!', true);

        overlay.querySelector('#fpGoLoginBtn').addEventListener('click', () => {
          overlay.remove();
          const loginOv = $('neuLoginOverlay');
          if (loginOv) loginOv.classList.remove('hidden', 'login-unlocking');
        });
      } else {
        setStatus(json.error?.message || 'Could not reset password.', false);
      }
    });
  }

  const loginForgotPwdBtn = $('loginForgotPwdBtn');
  const settingsForgotPwdBtn = $('settingsForgotPwdBtn');
  if (loginForgotPwdBtn) loginForgotPwdBtn.addEventListener('click', openForgotPasswordModal);
  if (settingsForgotPwdBtn) settingsForgotPwdBtn.addEventListener('click', openForgotPasswordModal);
});