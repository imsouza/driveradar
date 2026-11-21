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

  listToRender.forEach((vendor) => {
    const item = drivers[vendor] || {};
    const ver = item.verification || {};
    const score = Number(ver.score || 0);
    const tone = scoreTone(score);
    const card = node('article', 'card');

    const head = node('div', 'card-head');
    head.append(node('h2', '', LABELS[vendor]));
    head.append(node('span', `score-label ${tone}`, `${score}% · ${ver.label || tr('conf.low')}`));
    card.append(head);

    const verRow = node('div', 'ver-row');
    verRow.append(node('strong', '', item.version || tr('drivers.unavailable')));
    const metaParts = [formatDate(item.release_date)];
    if (item.channel) metaParts.push(item.channel);
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

    const assess = assessments[vendor];
    const rec = assess?.recommendation;
    const action = rec?.action || 'wait';
    const vBox = node('div', `verdict-box ${action}`);
    vBox.append(node('small', '', tr('drivers.rec')));
    vBox.append(node('strong', '', actionLabels[action] || tr('action.wait')));
    vBox.append(node('p', '', rec?.reason || assess?.headline || tr('drivers.waitingReview')));
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
  const q = historySearch.trim().toLowerCase();
  const vendors = activeHistoryVendor === 'all' ? Object.keys(LABELS) : [activeHistoryVendor];
  vendors.forEach((vendor) => {
    const card = node('article', 'history-card');
    const items = (history[vendor] || []).filter((item) => {
      if (!q) return true;
      const rs = item.release_summary || {};
      const hay = [item.version, item.channel, item.os_build, item.date, rs.headline, rs.summary, ...(rs.highlights || []), ...(rs.fixed_issues || []), ...(rs.known_issues || [])].filter(Boolean).join(' ').toLowerCase();
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
      if (item.channel) metaParts.push(item.channel);
      if (item.verification?.score !== undefined) metaParts.push(`${item.verification.score}%`);
      left.append(node('small', '', metaParts.join(' · ')));
      if (item.release_summary?.headline) left.append(node('div', 'snippet', item.release_summary.headline));
      const isCur = item.version === curVer;
      const right = node('span', isCur ? 'tag-current' : 'tag-detail', isCur ? tr('history.current') : tr('history.details'));
      btn.append(left, right);
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

  const rs = item.release_summary;
  if (rs) {
    const vBox = node('div', `verdict-box ${rs.recommendation_action || 'wait'}`);
    vBox.append(node('small', '', tr('drivers.rec')));
    vBox.append(node('strong', '', actionLabels[rs.recommendation_action] || tr('action.wait')));
    vBox.append(node('p', '', rs.recommendation_reason || ''));
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
    [tr('dialog.channel'), item.channel || '—'],
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
  const needsEnrich = !item.release_summary?.enriched_at;
  populateDialog(vendor, item, needsEnrich);
  if (!dialog.open) dialog.showModal();
  if (!needsEnrich || !item.version) return;
  try {
    const enriched = await window.driveRadar.getHistoryEntry(vendor, item.version);
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
    [['system', tr('settings.themeSystem')], ['dark', tr('settings.themeDark')], ['light', tr('settings.themeLight')]],
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
  const checkBtn = node('button', 'btn-outline', tr('settings.checkBtn'));
  checkBtn.type = 'button';
  checkBtn.addEventListener('click', () => window.driveRadar.checkAppUpdates());
  updBox.append(updInfo, checkBtn);
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
  if (msgEl && status?.message) msgEl.textContent = status.message;

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
