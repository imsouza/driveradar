const LABELS = {
  nvidia: 'NVIDIA GeForce',
  amd: 'AMD Radeon',
  intel: 'Intel Arc',
  windows: 'Windows 11'
};
const SHORT_LABELS = { nvidia: 'NVIDIA', amd: 'AMD', intel: 'Intel', windows: 'Windows' };
const I18N = window.DriveRadarDesktopI18n;

const $ = (sel) => document.querySelector(sel);

let currentData = null;
let currentSettings = null;
let currentAppInfo = null;
let activeHistoryVendor = 'all';
let historySearch = '';
let activeAlertVendor = 'all';
let toastTimer = null;

function activeLang() {
  return I18N.resolveLang(currentSettings?.language || 'system', currentAppInfo?.systemLocale || navigator.language);
}

function tr(key, vars = null) {
  return I18N.t(activeLang(), key, vars);
}

function node(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined && text !== null) el.textContent = String(text);
  return el;
}

function formatDate(value, includeTime = false) {
  if (!value) return tr('date.unknown');
  const d = /^\d{4}-\d{2}-\d{2}$/.test(String(value))
    ? new Date(`${value}T12:00:00Z`)
    : new Date(Number(value) < 10_000_000_000 ? Number(value) * 1000 : value);
  if (Number.isNaN(d.getTime())) return tr('date.unknown');
  return new Intl.DateTimeFormat(I18N.localeFor(activeLang()), includeTime
    ? { dateStyle: 'medium', timeStyle: 'short' }
    : { dateStyle: 'medium', timeZone: 'UTC' }).format(d);
}

function scoreTone(score) {
  if (score >= 72) return '';
  if (score >= 50) return 'medium';
  return 'low';
}

function localizeConfidence(label, score) {
  const low = String(label || '').toLowerCase();
  if (low === 'confirmada' || low === 'confirmed' || score >= 88) return tr('conf.confirmed');
  if (low === 'alta' || low === 'high' || score >= 72) return tr('conf.high');
  if (low === 'moderada' || low === 'moderate' || low === 'medium' || score >= 50) return tr('conf.medium');
  return tr('conf.low');
}

function localizeChannel(channel) {
  const raw = String(channel || '').trim();
  if (!raw) return '';
  const low = raw.toLowerCase();
  if (low.includes('preview opcional')) return tr('channel.previewD');
  if (low.includes('segurança (b)') || low.includes('seguranca (b)')) return tr('channel.securityB');
  if (low.includes('emergencial') || low.includes('out-of-band')) return tr('channel.outOfBand');
  return raw;
}

function resolveRisk(obj) {
  if (!obj || typeof obj !== 'object') {
    return { level: 'moderate', score: 38, critical_reasons: [], action: 'wait' };
  }
  const ra = obj.risk_assessment && typeof obj.risk_assessment === 'object' ? obj.risk_assessment : null;
  const rawAction = obj.recommendation?.action || obj.recommendation_action || 'wait';
  const rawLevel = String(ra?.level || obj.risk_level || '').toLowerCase();
  let score = ra?.score !== undefined && ra?.score !== null
    ? Number(ra.score)
    : obj.risk_score !== undefined && obj.risk_score !== null
      ? Number(obj.risk_score)
      : (rawLevel === 'critical' || rawAction === 'do_not_install' ? 90 : rawLevel === 'high' ? 65 : rawAction === 'install' ? 15 : 38);
  const criticalReasons = Array.isArray(ra?.critical_reasons) ? ra.critical_reasons : (Array.isArray(obj.critical_reasons) ? obj.critical_reasons : []);
  const isCritical = rawLevel === 'critical' || rawAction === 'do_not_install' || score >= 80;
  const level = isCritical ? 'critical' : ['high', 'moderate', 'low'].includes(rawLevel) ? rawLevel : (score >= 55 ? 'high' : score >= 25 ? 'moderate' : 'low');
  const action = isCritical ? 'do_not_install' : rawAction;
  return {
    level,
    score: Number.isFinite(score) ? Math.max(0, Math.min(100, Math.round(score))) : (isCritical ? 90 : 38),
    critical_reasons: criticalReasons,
    action
  };
}

function localizeAssessment(assessment, lang) {
  if (!assessment || typeof assessment !== 'object') return assessment;
  const tblock = lang && lang !== 'pt-BR' ? assessment.translations?.[lang] : null;
  if (!tblock || typeof tblock !== 'object') return assessment;
  return {
    ...assessment,
    headline: tblock.headline || assessment.headline,
    summary: tblock.summary || assessment.summary,
    recommendation: assessment.recommendation
      ? {
          ...assessment.recommendation,
          target_audience: tblock.target_audience || assessment.recommendation.target_audience,
          reason: tblock.reason || assessment.recommendation.reason
        }
      : undefined,
    risk_assessment: assessment.risk_assessment
      ? {
          ...assessment.risk_assessment,
          critical_reasons: Array.isArray(tblock.critical_reasons) && tblock.critical_reasons.length
            ? tblock.critical_reasons
            : assessment.risk_assessment.critical_reasons
        }
      : undefined
  };
}

function localizeSummary(summary, lang) {
  if (!summary || typeof summary !== 'object') return summary;
  const tblock = lang && lang !== 'pt-BR' ? summary.translations?.[lang] : null;
  if (!tblock || typeof tblock !== 'object') return summary;
  return {
    ...summary,
    headline: tblock.headline || summary.headline,
    summary: tblock.summary || summary.summary,
    recommendation_reason: tblock.recommendation_reason || summary.recommendation_reason,
    critical_reasons: Array.isArray(tblock.critical_reasons) && tblock.critical_reasons.length ? tblock.critical_reasons : summary.critical_reasons,
    highlights: Array.isArray(tblock.highlights) && tblock.highlights.length ? tblock.highlights : summary.highlights,
    fixed_issues: Array.isArray(tblock.fixed_issues) && tblock.fixed_issues.length ? tblock.fixed_issues : summary.fixed_issues,
    known_issues: Array.isArray(tblock.known_issues) && tblock.known_issues.length ? tblock.known_issues : summary.known_issues,
    watch_items: Array.isArray(tblock.watch_items) && tblock.watch_items.length ? tblock.watch_items : summary.watch_items
  };
}

function applyStaticLabels() {
  document.documentElement.lang = activeLang();
  const navMap = { drivers: 'nav.drivers', history: 'nav.history', alerts: 'nav.alerts', settings: 'nav.settings' };
  document.querySelectorAll('.nav-item').forEach((btn) => {
    if (navMap[btn.dataset.tab]) btn.textContent = tr(navMap[btn.dataset.tab]);
  });
  $('#btn-refresh').textContent = tr('btn.refresh');
  $('#banner-download').textContent = tr('banner.download');
  $('#banner-install').textContent = tr('banner.install');
  $('#tab-drivers h1').textContent = tr('drivers.title');
  $('#drivers-subtitle').textContent = tr('drivers.subtitle');
  $('#tab-history h1').textContent = tr('history.title');
  $('#tab-history .panel-header p').textContent = tr('history.subtitle');
  $('#history-search').placeholder = tr('history.search');
  $('#tab-alerts h1').textContent = tr('alerts.title');
  $('#tab-alerts .panel-header p').textContent = tr('alerts.subtitle');
  $('#tab-settings h1').textContent = tr('settings.title');
  $('#tab-settings .panel-header p').textContent = tr('settings.subtitle');
  $('#save-toast').textContent = tr('settings.saved');
}

function switchTab(tab) {
  document.querySelectorAll('.nav-item').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === tab);
  });
  document.querySelectorAll('.tab-panel').forEach((panel) => {
    const active = panel.id === `tab-${tab}`;
    panel.hidden = !active;
    panel.classList.toggle('active', active);
  });
}

function renderSyncMeta(data) {
  const dot = $('#sync-dot');
  const status = $('#sync-status');
  const timeEl = $('#sync-time');
  if (!data) {
    status.textContent = tr('sync.connecting');
    timeEl.textContent = tr('sync.waiting');
    return;
  }
  dot.classList.toggle('offline', Boolean(data._offline));
  status.textContent = data._offline
    ? tr('sync.offline')
    : data.status === 'partial'
      ? tr('sync.partial')
      : tr('sync.synced');
  timeEl.textContent = tr('sync.updatedAt', { date: formatDate(data.last_updated, true) });
}

function renderDrivers(data) {
  const grid = $('#driver-grid');
  grid.replaceChildren();
  const drivers = data?.drivers || {};
  const assessments = data?.advisor?.assessments || {};
  const enabledVendors = currentSettings?.vendors || { nvidia: true, amd: true, intel: true, windows: true };
  const visibleVendors = Object.keys(LABELS).filter((v) => enabledVendors[v]);
  const listToRender = visibleVendors.length ? visibleVendors : Object.keys(LABELS);

  const actionLabels = {
    install: tr('action.install'),
    wait: tr('action.wait'),
    do_not_install: tr('action.do_not_install')
  };

  const lang = activeLang();
  listToRender.forEach((vendor) => {
    const item = drivers[vendor] || {};
    const ver = item.verification || {};
    const score = Number(ver.score || 0);
    const tone = scoreTone(score);
    const assess = localizeAssessment(assessments[vendor], lang);
    const riskInfo = resolveRisk(assess);
    const isCritical = assess?.status === 'ready' && (riskInfo.level === 'critical' || riskInfo.action === 'do_not_install');
    const card = node('article', `card${isCritical ? ' risk-critical' : ''}`);

    const head = node('div', 'card-head');
    head.append(node('h2', '', LABELS[vendor]));
    head.append(node('span', `score-label ${tone}`, `${score}% · ${localizeConfidence(ver.label, score)}`));
    card.append(head);

    const verRow = node('div', 'ver-row');
    verRow.append(node('strong', '', item.version || tr('drivers.unavailable')));
    const metaParts = [formatDate(item.release_date)];
    if (item.channel) metaParts.push(localizeChannel(item.channel));
    if (item.os_build) metaParts.push(`Build ${item.os_build}`);
    if (item.file_size) metaParts.push(item.file_size);
    verRow.append(node('small', '', metaParts.join(' · ')));
    card.append(verRow);

    const meter = node('div', 'meter');
    const fill = node('span', tone);
    fill.style.width = `${Math.max(2, score)}%`;
    meter.append(fill);
    card.append(meter);

    const conflicts = ver.conflicts || [];
    if (conflicts.length) {
      const cBox = node('div', 'conflict-box');
      cBox.append(node('strong', '', tr('drivers.newerReported', { version: conflicts[0].version })));
      cBox.append(node('span', '', `${conflicts[0].publisher}: ${conflicts[0].title || ''}`));
      card.append(cBox);
    }

    const rec = assess?.recommendation;
    const action = isCritical ? 'do_not_install' : (rec?.action || 'wait');
    const vBoxClass = isCritical ? 'verdict-box critical do_not_install' : `verdict-box ${action}${riskInfo.level === 'high' ? ' high' : ''}`;
    const vBox = node('div', vBoxClass);
    const vTop = node('div', 'verdict-top');
    vTop.append(node('small', '', tr('drivers.rec')));
    const vBadges = node('div', 'verdict-badges');
    if (isCritical) vBadges.append(node('span', 'critical-badge', tr('action.criticalBadge')));
    if (assess?.risk_assessment?.level) {
      vBadges.append(node('span', `risk-pill risk-${riskInfo.level}`, tr('risk.scoreLabel', { level: tr(`risk.${riskInfo.level}`), score: riskInfo.score })));
    }
    vTop.append(vBadges);
    vBox.append(vTop);
    vBox.append(node('strong', '', actionLabels[action] || tr('action.wait')));
    vBox.append(node('p', '', rec?.reason || assess?.headline || tr('drivers.waitingReview')));
    if (isCritical && riskInfo.critical_reasons.length) {
      const crUl = node('ul', 'critical-reasons-list');
      riskInfo.critical_reasons.forEach((reason) => crUl.append(node('li', '', reason)));
      vBox.append(crUl);
    }
    card.append(vBox);

    if (assess?.summary || (ver.agreements || []).length) {
      const details = node('details');
      details.append(node('summary', '', tr('drivers.summaryToggle', { count: (ver.agreements || []).length })));
      if (assess?.summary) details.append(node('p', '', assess.summary));
      const chips = node('div', 'chips');
      (ver.agreements || []).forEach((ag) => {
        const label = ag.publisher || ag.source_name || 'Source';
        const btn = node('button', `chip-btn ${ag.tier === 'primary' ? 'primary' : ''}`, label);
        btn.type = 'button';
        btn.title = ag.title || label;
        btn.addEventListener('click', () => window.driveRadar.openExternal(ag.url));
        chips.append(btn);
      });
      details.append(chips);
      card.append(details);
    }

    const foot = node('div', 'card-foot');
    const links = node('div', 'link-row');
    if (item.official_url) {
      const dl = node('button', 'link-btn', vendor === 'windows' ? tr('drivers.officialPage') : tr('drivers.download'));
      dl.type = 'button';
      dl.addEventListener('click', () => window.driveRadar.openExternal(item.official_url));
      links.append(dl);
    }
    if (item.release_notes_url) {
      const rn = node('button', 'link-btn muted', tr('drivers.notes'));
      rn.type = 'button';
      rn.addEventListener('click', () => window.driveRadar.openExternal(item.release_notes_url));
      links.append(rn);
    }
    foot.append(links);
    if (item.version) {
      const btn = node('button', 'btn-outline', tr('drivers.details'));
      btn.type = 'button';
      btn.addEventListener('click', () => {
        const hist = (currentData?.history?.[vendor] || []).find((h) => h.version === item.version) || {
          version: item.version,
          date: item.release_date,
          channel: item.channel,
          os_build: item.os_build,
          file_size: item.file_size,
          source_name: item.source_name,
          official_url: item.official_url,
          release_notes_url: item.release_notes_url,
          primary_verified: ver.primary_confirmed,
          verification: ver
        };
        openHistoryDialog(vendor, hist, 0);
      });
      foot.append(btn);
    }
    card.append(foot);
    grid.append(card);
  });
}

function renderHistory(data) {
  const history = data?.history || {};
  const filters = $('#history-filters');
  filters.replaceChildren();
  [['all', tr('history.all')], ...Object.keys(LABELS).map((v) => [v, SHORT_LABELS[v]])].forEach(([key, label]) => {
    const count = key === 'all'
      ? Object.values(history).reduce((s, arr) => s + (arr?.length || 0), 0)
      : (history[key] || []).length;
    const btn = node('button', `filter-pill ${activeHistoryVendor === key ? 'active' : ''}`, `${label} (${count})`);
    btn.type = 'button';
    btn.addEventListener('click', () => {
      activeHistoryVendor = key;
      renderHistory(currentData);
    });
    filters.append(btn);
  });

  const grid = $('#history-grid');
  grid.replaceChildren();
  const lang = activeLang();
  const q = historySearch.trim().toLowerCase();
  const vendors = activeHistoryVendor === 'all' ? Object.keys(LABELS) : [activeHistoryVendor];
  vendors.forEach((vendor) => {
    const card = node('article', 'history-card');
    const items = (history[vendor] || []).filter((item) => {
      if (!q) return true;
      const rs = localizeSummary(item.release_summary, lang) || {};
      const hay = [item.version, item.channel, localizeChannel(item.channel), item.os_build, item.date, rs.headline, rs.summary, ...(rs.highlights || []), ...(rs.fixed_issues || []), ...(rs.known_issues || [])].filter(Boolean).join(' ').toLowerCase();
      return hay.includes(q);
    });
    const head = node('div', 'history-card-head');
    head.append(node('h2', '', LABELS[vendor]));
    head.append(node('small', '', tr(items.length === 1 ? 'history.records' : 'history.recordsPlural', { count: items.length })));
    card.append(head);

    const ol = node('ol');
    if (!items.length) ol.append(node('li', '', q ? tr('history.emptyFilter') : tr('history.empty')));
    const curVer = data?.drivers?.[vendor]?.version;
    items.forEach((item, idx) => {
      const li = node('li');
      const btn = node('button', 'history-row');
      btn.type = 'button';
      const left = node('div');
      left.append(node('strong', '', item.version));
      const metaParts = [formatDate(item.date)];
      if (item.channel) metaParts.push(localizeChannel(item.channel));
      if (item.verification?.score !== undefined) metaParts.push(`${item.verification.score}%`);
      left.append(node('small', '', metaParts.join(' · ')));
      const localSummary = localizeSummary(item.release_summary, lang);
      if (localSummary?.headline) left.append(node('div', 'snippet', localSummary.headline));
      const rightCol = node('div', 'history-row-meta');
      const isCur = item.version === curVer;
      rightCol.append(node('span', isCur ? 'tag-current' : 'tag-detail', isCur ? tr('history.current') : tr('history.details')));
      if (localSummary) {
        const rsRisk = resolveRisk(localSummary);
        if (rsRisk.level === 'critical' || rsRisk.action === 'do_not_install') {
          rightCol.append(node('span', 'tag-critical', tr('action.criticalBadge')));
        }
      }
      btn.append(left, rightCol);
      btn.addEventListener('click', () => openHistoryDialog(vendor, item, idx));
      li.append(btn);
      ol.append(li);
    });
    card.append(ol);
    grid.append(card);
  });
}

function populateDialog(vendor, item, isLoading) {
  const body = $('#dialog-body');
  const lang = activeLang();
  $('#dialog-eyebrow').textContent = `${LABELS[vendor]} · ${tr('dialog.eyebrow')}`;
  $('#dialog-title').textContent = `${LABELS[vendor]} ${item.version || ''}`.trim();
  body.replaceChildren();

  if (isLoading) {
    body.append(node('p', '', tr('dialog.loading')));
  }

  const actionLabels = {
    install: tr('action.install'),
    wait: tr('action.wait'),
    do_not_install: tr('action.do_not_install')
  };

  const rs = localizeSummary(item.release_summary, lang);
  if (rs) {
    const riskInfo = resolveRisk(rs);
    const isCritical = riskInfo.level === 'critical' || riskInfo.action === 'do_not_install';
    const act = isCritical ? 'do_not_install' : (rs.recommendation_action || 'wait');
    const vBox = node('div', isCritical ? 'verdict-box critical do_not_install' : `verdict-box ${act}${riskInfo.level === 'high' ? ' high' : ''}`);
    const vTop = node('div', 'verdict-top');
    vTop.append(node('small', '', tr('drivers.rec')));
    const badges = node('div', 'verdict-badges');
    if (isCritical) badges.append(node('span', 'critical-badge', tr('action.criticalBadge')));
    if (rs.risk_level) {
      badges.append(node('span', `risk-pill risk-${riskInfo.level}`, tr('risk.scoreLabel', { level: tr(`risk.${riskInfo.level}`), score: riskInfo.score })));
    }
    vTop.append(badges);
    vBox.append(vTop);
    vBox.append(node('strong', '', actionLabels[act] || tr('action.wait')));
    vBox.append(node('p', '', rs.recommendation_reason || ''));
    if (isCritical && riskInfo.critical_reasons.length) {
      const crUl = node('ul', 'critical-reasons-list');
      riskInfo.critical_reasons.forEach((reason) => crUl.append(node('li', '', reason)));
      vBox.append(crUl);
    }
    body.append(vBox);
    if (rs.headline) body.append(node('strong', '', rs.headline));
    if (rs.summary) body.append(node('p', '', rs.summary));

    [
      [tr('dialog.highlights'), rs.highlights || []],
      [tr('dialog.fixed'), rs.fixed_issues || []],
      [tr('dialog.known'), rs.known_issues || []],
      [tr('dialog.watch'), rs.watch_items || []]
    ].forEach(([title, list]) => {
      if (!list.length) return;
      const sec = node('div', 'dialog-section');
      sec.append(node('h3', '', title));
      const ul = node('ul');
      list.forEach((line) => ul.append(node('li', '', line)));
      sec.append(ul);
      body.append(sec);
    });
  }

  const meta = node('div', 'dialog-section');
  meta.append(node('h3', '', tr('dialog.meta')));
  const dl = node('dl', 'dl-grid');
  [
    [tr('dialog.version'), item.version || '—'],
    [tr('dialog.release'), formatDate(item.date)],
    [tr('dialog.channel'), localizeChannel(item.channel) || '—'],
    [tr('dialog.build'), item.os_build || '—'],
    [tr('dialog.size'), item.file_size || '—'],
    [tr('dialog.verifiedAt'), formatDate(item.verified_at, true)]
  ].forEach(([k, v]) => {
    dl.append(node('dt', '', k), node('dd', '', v));
  });
  meta.append(dl);
  body.append(meta);

  const foot = node('div', 'link-row');
  foot.style.marginTop = '1rem';
  if (item.release_notes_url) {
    const rn = node('button', 'link-btn', tr('dialog.officialNotes'));
    rn.type = 'button';
    rn.addEventListener('click', () => window.driveRadar.openExternal(item.release_notes_url));
    foot.append(rn);
  }
  if (item.official_url) {
    const dlBtn = node('button', 'link-btn muted', tr('dialog.officialPage'));
    dlBtn.type = 'button';
    dlBtn.addEventListener('click', () => window.driveRadar.openExternal(item.official_url));
    foot.append(dlBtn);
  }
  if (foot.children.length) body.append(foot);
}

async function openHistoryDialog(vendor, item) {
  const dialog = $('#history-dialog');
  const lang = activeLang();
  const needsEnrich = !item.release_summary?.enriched_at
    || (lang !== 'pt-BR' && !item.release_summary?.translations?.[lang]);
  populateDialog(vendor, item, needsEnrich);
  if (!dialog.open) dialog.showModal();
  if (!needsEnrich || !item.version) return;
  try {
    const enriched = await window.driveRadar.getHistoryEntry(vendor, item.version, lang);
    if (currentData?.history?.[vendor]) {
      const idx = currentData.history[vendor].findIndex((h) => h.version === enriched.version);
      if (idx !== -1) currentData.history[vendor][idx] = enriched;
    }
    if (dialog.open) {
      populateDialog(vendor, enriched, false);
      renderHistory(currentData);
    }
  } catch (_) {
    if (dialog.open) populateDialog(vendor, item, false);
  }
}

function renderAlerts(data) {
  const alerts = data?.security_alerts || [];
  const filters = $('#alert-filters');
  filters.replaceChildren();
  [['all', tr('history.all')], ...Object.keys(SHORT_LABELS).map((v) => [v, SHORT_LABELS[v]])].forEach(([key, label]) => {
    const count = key === 'all' ? alerts.length : alerts.filter((a) => (a.vendors || []).includes(key)).length;
    const btn = node('button', `filter-pill ${activeAlertVendor === key ? 'active' : ''}`, `${label} (${count})`);
    btn.type = 'button';
    btn.addEventListener('click', () => {
      activeAlertVendor = key;
      renderAlerts(currentData);
    });
    filters.append(btn);
  });

  const list = $('#alert-list');
  list.replaceChildren();
  const filtered = activeAlertVendor === 'all' ? alerts : alerts.filter((a) => (a.vendors || []).includes(activeAlertVendor));
  if (!filtered.length) {
    list.append(node('p', '', tr('alerts.empty')));
    return;
  }
  const sevLabel = {
    critical: tr('sev.critical'),
    high: tr('sev.high'),
    medium: tr('sev.medium'),
    info: tr('sev.info')
  };
  filtered.forEach((a) => {
    const card = node('article', `alert-card ${a.severity || 'info'}`);
    const vendors = (a.vendors || []).map((v) => SHORT_LABELS[v] || v).join(', ') || 'General';
    card.append(node('div', 'meta', `${sevLabel[a.severity] || 'Info'} · ${vendors} · ${a.source} · ${formatDate(a.published_at)}`));
    const btn = node('button', 'title-btn', a.title || 'Alert');
    btn.type = 'button';
    btn.addEventListener('click', () => window.driveRadar.openExternal(a.link));
    card.append(btn);
    if (a.summary) card.append(node('p', '', a.summary));
    list.append(card);
  });
}

function showSaveToast() {
  const toast = $('#save-toast');
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, 2000);
}

async function updateSetting(partial) {
  const prevLang = activeLang();
  currentSettings = await window.driveRadar.saveSettings(partial);
  document.documentElement.dataset.theme = currentSettings.theme || 'system';
  if (activeLang() !== prevLang) {
    applyStaticLabels();
    renderAll(currentData);
    renderSettings();
  } else {
    renderDrivers(currentData);
  }
  showSaveToast();
}

function makeToggleRow(title, desc, checked, onChange) {
  const row = node('div', 'setting-row');
  const label = node('label');
  label.append(node('strong', '', title), node('small', '', desc));
  const input = node('input');
  input.type = 'checkbox';
  input.checked = Boolean(checked);
  input.addEventListener('change', () => onChange(input.checked));
  row.append(label, input);
  return row;
}

function makeSelectRow(title, desc, value, options, onChange) {
  const row = node('div', 'setting-row');
  const label = node('label');
  label.append(node('strong', '', title), node('small', '', desc));
  const select = node('select');
  options.forEach(([val, text]) => {
    const opt = node('option', '', text);
    opt.value = String(val);
    if (String(val) === String(value)) opt.selected = true;
    select.append(opt);
  });
  select.addEventListener('change', () => onChange(select.value));
  row.append(label, select);
  return row;
}

function renderSettings() {
  if (!currentSettings) return;
  const root = $('#settings-container');
  root.replaceChildren();

  const gMon = node('section', 'settings-group');
  gMon.append(node('h2', '', tr('settings.monitoring')));
  const vendorRow = node('div', 'setting-row');
  const vLabel = node('label');
  vLabel.append(node('strong', '', tr('settings.vendors')), node('small', '', tr('settings.vendorsDesc')));
  const vChecks = node('div', 'vendor-checks');
  Object.keys(LABELS).forEach((v) => {
    const wrap = node('label', 'vendor-check');
    const cb = node('input');
    cb.type = 'checkbox';
    cb.checked = Boolean(currentSettings.vendors?.[v]);
    cb.addEventListener('change', () => updateSetting({ vendors: { ...currentSettings.vendors, [v]: cb.checked } }));
    wrap.append(cb, document.createTextNode(SHORT_LABELS[v]));
    vChecks.append(wrap);
  });
  vendorRow.append(vLabel, vChecks);
  gMon.append(vendorRow);

  gMon.append(makeSelectRow(
    tr('settings.interval'),
    tr('settings.intervalDesc'),
    currentSettings.pollIntervalMinutes,
    [[15, tr('settings.min15')], [30, tr('settings.min30')], [60, tr('settings.h1')], [180, tr('settings.h3')], [360, tr('settings.h6')]],
    (val) => updateSetting({ pollIntervalMinutes: Number(val) })
  ));
  gMon.append(makeToggleRow(tr('settings.skipBeta'), tr('settings.skipBetaDesc'), currentSettings.ignoreBetaPreview, (v) => updateSetting({ ignoreBetaPreview: v })));
  gMon.append(makeToggleRow(tr('settings.notifyConflicts'), tr('settings.notifyConflictsDesc'), currentSettings.notifyConflicts, (v) => updateSetting({ notifyConflicts: v })));
  root.append(gMon);

  const gNotif = node('section', 'settings-group');
  gNotif.append(node('h2', '', tr('settings.notifications')));
  gNotif.append(makeToggleRow(tr('settings.notifEnable'), tr('settings.notifEnableDesc'), currentSettings.notificationsEnabled, (v) => updateSetting({ notificationsEnabled: v })));
  gNotif.append(makeToggleRow(tr('settings.notifSound'), tr('settings.notifSoundDesc'), currentSettings.notificationSound, (v) => updateSetting({ notificationSound: v })));
  gNotif.append(makeSelectRow(
    tr('settings.secLevel'),
    tr('settings.secLevelDesc'),
    currentSettings.securitySeverity,
    [['off', tr('settings.secOff')], ['critical', tr('settings.secCrit')], ['high', tr('settings.secHigh')], ['all', tr('settings.secAll')]],
    (v) => updateSetting({ securitySeverity: v })
  ));
  gNotif.append(makeToggleRow(tr('settings.quiet'), tr('settings.quietDesc'), currentSettings.quietHoursEnabled, (v) => updateSetting({ quietHoursEnabled: v })));

  const qRow = node('div', 'setting-row');
  const qLabel = node('label');
  qLabel.append(node('strong', '', tr('settings.quietRange')), node('small', '', tr('settings.quietRangeDesc')));
  const range = node('div', 'time-range');
  const tStart = node('input'); tStart.type = 'time'; tStart.value = currentSettings.quietHoursStart;
  const tEnd = node('input'); tEnd.type = 'time'; tEnd.value = currentSettings.quietHoursEnd;
  tStart.addEventListener('change', () => updateSetting({ quietHoursStart: tStart.value }));
  tEnd.addEventListener('change', () => updateSetting({ quietHoursEnd: tEnd.value }));
  range.append(tStart, document.createTextNode(tr('settings.until')), tEnd);
  qRow.append(qLabel, range);
  gNotif.append(qRow);

  const testRow = node('div', 'setting-row');
  const testLbl = node('label');
  testLbl.append(node('strong', '', tr('settings.testTitle')), node('small', '', tr('settings.testDesc')));
  const testBtn = node('button', 'btn-outline', tr('settings.testBtn'));
  testBtn.type = 'button';
  testBtn.addEventListener('click', () => window.driveRadar.testNotification());
  testRow.append(testLbl, testBtn);
  gNotif.append(testRow);
  root.append(gNotif);

  const gTray = node('section', 'settings-group');
  gTray.append(node('h2', '', tr('settings.trayGroup')));
  gTray.append(makeToggleRow(tr('settings.startup'), tr('settings.startupDesc'), currentSettings.launchAtStartup, (v) => updateSetting({ launchAtStartup: v })));
  gTray.append(makeToggleRow(tr('settings.startMin'), tr('settings.startMinDesc'), currentSettings.startMinimized, (v) => updateSetting({ startMinimized: v })));
  gTray.append(makeToggleRow(tr('settings.closeTray'), tr('settings.closeTrayDesc'), currentSettings.closeToTray, (v) => updateSetting({ closeToTray: v })));
  gTray.append(makeToggleRow(tr('settings.minTray'), tr('settings.minTrayDesc'), currentSettings.minimizeToTray, (v) => updateSetting({ minimizeToTray: v })));
  root.append(gTray);

  const gApp = node('section', 'settings-group');
  gApp.append(node('h2', '', tr('settings.appGroup')));
  gApp.append(makeSelectRow(
    tr('settings.language'),
    tr('settings.languageDesc'),
    currentSettings.language || 'system',
    [
      ['system', tr('settings.langSystem')],
      ['pt-BR', 'Português (BR)'],
      ['en', 'English'],
      ['es', 'Español'],
      ['fr', 'Français']
    ],
    (v) => updateSetting({ language: v })
  ));
  gApp.append(makeSelectRow(
    tr('settings.theme'),
    tr('settings.themeDesc'),
    currentSettings.theme,
    [
      ['system', tr('settings.themeSystem')],
      ['dark', tr('settings.themeDark')],
      ['light', tr('settings.themeLight')],
      ['midnight', tr('settings.themeMidnight')],
      ['nord', tr('settings.themeNord')],
      ['forest', tr('settings.themeForest')],
      ['sand', tr('settings.themeSand')]
    ],
    (v) => updateSetting({ theme: v })
  ));
  gApp.append(makeToggleRow(tr('settings.autoCheck'), tr('settings.autoCheckDesc'), currentSettings.autoCheckUpdates, (v) => updateSetting({ autoCheckUpdates: v })));
  gApp.append(makeToggleRow(tr('settings.autoDl'), tr('settings.autoDlDesc'), currentSettings.autoDownloadUpdates, (v) => updateSetting({ autoDownloadUpdates: v })));

  const updBox = node('div', 'updater-box');
  const updInfo = node('div');
  updInfo.append(node('strong', '', `DriveRadar v${currentAppInfo?.version || '1.0.0'}`));
  const updMsg = node('small', '', currentAppInfo?.updater?.message || '');
  updMsg.id = 'settings-updater-msg';
  updInfo.append(updMsg);
  const updActions = node('div', 'banner-actions');
  const checkBtn = node('button', 'btn-outline', tr('settings.checkBtn'));
  checkBtn.type = 'button';
  checkBtn.addEventListener('click', () => window.driveRadar.checkAppUpdates());
  const installBtn = node('button', 'btn-accent', tr('banner.install'));
  installBtn.type = 'button';
  installBtn.id = 'settings-updater-install';
  installBtn.hidden = currentAppInfo?.updater?.state !== 'downloaded';
  installBtn.addEventListener('click', () => window.driveRadar.installAppUpdate());
  updActions.append(installBtn, checkBtn);
  updBox.append(updInfo, updActions);
  gApp.append(updBox);

  const adv = node('details');
  adv.style.marginTop = '.75rem';
  adv.append(node('summary', '', tr('settings.advApi')));
  const urlRow = node('div', 'setting-row');
  const uLbl = node('label');
  uLbl.append(node('strong', '', tr('settings.apiBase')), node('small', '', tr('settings.apiBaseDesc')));
  const urlInput = node('input');
  urlInput.type = 'url';
  urlInput.style.width = '280px';
  urlInput.value = currentSettings.apiBaseUrl;
  urlInput.addEventListener('change', () => updateSetting({ apiBaseUrl: urlInput.value }));
  urlRow.append(uLbl, urlInput);
  adv.append(urlRow);
  gApp.append(adv);
  root.append(gApp);
}

function renderUpdaterBanner(status) {
  const banner = $('#update-banner');
  const text = $('#update-banner-text');
  const dlBtn = $('#banner-download');
  const instBtn = $('#banner-install');
  const msgEl = $('#settings-updater-msg');
  const settingsInstBtn = $('#settings-updater-install');
  if (msgEl && status?.message) msgEl.textContent = status.message;
  if (settingsInstBtn) settingsInstBtn.hidden = status?.state !== 'downloaded';

  if (!status || !['available', 'downloading', 'downloaded'].includes(status.state)) {
    banner.hidden = true;
    return;
  }
  banner.hidden = false;
  text.textContent = status.message || '';
  dlBtn.hidden = status.state !== 'available';
  instBtn.hidden = status.state !== 'downloaded';
}

function renderAll(data) {
  currentData = data;
  renderSyncMeta(data);
  if (!data) return;
  renderDrivers(data);
  renderHistory(data);
  renderAlerts(data);
}

document.addEventListener('DOMContentLoaded', async () => {
  document.querySelectorAll('.nav-item').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });
  $('#btn-refresh').addEventListener('click', async () => {
    const btn = $('#btn-refresh');
    btn.disabled = true;
    try {
      const data = await window.driveRadar.refreshNow();
      renderAll(data);
    } finally {
      btn.disabled = false;
    }
  });
  $('#history-search').addEventListener('input', (e) => {
    historySearch = e.target.value || '';
    if (currentData) renderHistory(currentData);
  });
  $('#dialog-close').addEventListener('click', () => $('#history-dialog').close());
  $('#history-dialog').addEventListener('click', (e) => {
    if (e.target === $('#history-dialog')) $('#history-dialog').close();
  });
  $('#banner-download').addEventListener('click', () => window.driveRadar.downloadAppUpdate());
  $('#banner-install').addEventListener('click', () => window.driveRadar.installAppUpdate());

  window.driveRadar.onDataUpdated((data) => renderAll(data));
  window.driveRadar.onUpdaterStatus((status) => renderUpdaterBanner(status));
  window.driveRadar.onNavigate((tab) => switchTab(tab));

  currentSettings = await window.driveRadar.getSettings();
  document.documentElement.dataset.theme = currentSettings.theme || 'system';
  currentAppInfo = await window.driveRadar.getAppInfo();
  $('#app-version').textContent = `v${currentAppInfo?.version || '1.0.0'}`;
  applyStaticLabels();
  renderSettings();
  renderUpdaterBanner(currentAppInfo?.updater);

  try {
    const data = await window.driveRadar.getData();
    renderAll(data);
  } catch (_) {
    $('#sync-status').textContent = tr('sync.error');
  }
});
