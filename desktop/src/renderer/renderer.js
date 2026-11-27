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
let voteState = { token: '', issuedAt: 0, tallies: {}, myVotes: {}, pending: new Set() };
const DRIVER_DOWN_TAGS = [
  ['black_screen', 'vote.tag.black_screen'],
  ['crash_bsod', 'vote.tag.crash_bsod'],
  ['fps_drop', 'vote.tag.fps_drop'],
  ['install_fail', 'vote.tag.install_fail'],
  ['audio_display', 'vote.tag.audio_display']
];

async function refreshVoteSession() {
  try {
    const res = await window.driveRadar.getVoteSession();
    if (!res) return;
    voteState.token = res.vote_token || '';
    voteState.issuedAt = Date.now();
    voteState.tallies = { ...voteState.tallies, ...(res.tallies || {}) };
    voteState.myVotes = { ...voteState.myVotes, ...(res.my_votes || {}) };
    if (currentData) {
      renderDrivers(currentData);
      renderAlerts(currentData);
    }
  } catch (_) {}
}

async function submitDesktopVote(targetType, targetId, vote, reasonTag) {
  const key = `${targetType}:${targetId}`;
  if (voteState.pending.has(key)) return;
  voteState.pending.add(key);
  try {
    if (!voteState.token) await refreshVoteSession();
    const elapsed = Date.now() - voteState.issuedAt;
    if (elapsed < 1150) {
      await new Promise((resolve) => setTimeout(resolve, 1150 - elapsed));
    }
    let out = await window.driveRadar.castVote({
      vote_token: voteState.token,
      target_type: targetType,
      target_id: targetId,
      vote,
      reason_tag: reasonTag || null
    });
    if (out?.error === 403) {
      await refreshVoteSession();
      await new Promise((resolve) => setTimeout(resolve, 1150));
      out = await window.driveRadar.castVote({
        vote_token: voteState.token,
        target_type: targetType,
        target_id: targetId,
        vote,
        reason_tag: reasonTag || null
      });
    }
    if (out?.tally) voteState.tallies[key] = out.tally;
    if (out?.my_vote) voteState.myVotes[key] = out.my_vote;
    if (currentData) {
      renderDrivers(currentData);
      renderAlerts(currentData);
    }
  } finally {
    voteState.pending.delete(key);
  }
}

function buildDriverVoteBar(vendor, version, initialCommunity) {
  const targetId = `${vendor}:${version}`;
  const key = `driver:${targetId}`;
  const tally = voteState.tallies[key] || initialCommunity || { up: 0, down: 0, total: 0, quorum_met: false, signal: 'insufficient' };
  const myVote = voteState.myVotes[key] || null;
  const box = node('div', 'community-bar');
  const row = node('div', 'community-row');
  const info = node('div', 'community-info');
  const total = Number(tally.total || 0);
  const summaryText = total === 0
    ? tr('vote.noVotesYet')
    : !tally.quorum_met
      ? tr('vote.formingSample', { count: total })
      : tr('vote.driverStats', { pct: tally.approval_pct ?? 0, count: total });
  info.append(node('small', 'community-eyebrow', tr('vote.driverTitle')), node('span', 'community-summary', summaryText));
  if (tally.signal === 'warning') {
    const issueLbl = tally.top_issue ? tr(`vote.tag.${tally.top_issue}`) : '';
    info.append(node('span', 'community-warn-pill', tr('vote.communityWarning', { issue: issueLbl })));
  }
  const actions = node('div', 'vote-actions');
  const upBtn = node('button', `vote-btn up${myVote?.vote === 'up' ? ' active' : ''}`, `👍 ${tr('vote.stableBtn')} (${tally.up || 0})`);
  upBtn.type = 'button';
  const downBtn = node('button', `vote-btn down${myVote?.vote === 'down' ? ' active' : ''}`, `👎 ${tr('vote.issueBtn')} (${tally.down || 0})`);
  downBtn.type = 'button';
  actions.append(upBtn, downBtn);
  row.append(info, actions);
  box.append(row);

  const picker = node('div', 'vote-tags-picker');
  picker.hidden = true;
  picker.append(node('small', '', tr('vote.pickSymptom')));
  const pills = node('div', 'vote-tag-pills');
  DRIVER_DOWN_TAGS.forEach(([tagCode, lblKey]) => {
    const tBtn = node('button', `vote-tag-btn${myVote?.tag === tagCode ? ' active' : ''}`, tr(lblKey));
    tBtn.type = 'button';
    tBtn.addEventListener('click', () => submitDesktopVote('driver', targetId, 'down', tagCode));
    pills.append(tBtn);
  });
  picker.append(pills);
  box.append(picker);

  upBtn.addEventListener('click', () => submitDesktopVote('driver', targetId, 'up', 'stable'));
  downBtn.addEventListener('click', () => { picker.hidden = !picker.hidden; });
  return box;
}

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

function releaseAgeDays(value) {
  if (!value) return null;
  const d = /^\d{4}-\d{2}-\d{2}$/.test(String(value))
    ? new Date(`${value}T12:00:00Z`)
    : new Date(Number(value) < 10_000_000_000 ? Number(value) * 1000 : value);
  if (Number.isNaN(d.getTime())) return null;
  return Math.floor((Date.now() - d.getTime()) / 86_400_000);
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
      : (rawLevel === 'critical' || rawAction === 'do_not_install' ? 90 : rawLevel === 'high' ? 65 : (rawAction === 'install' || rawAction === 'observe') ? 15 : 38);
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
  const out = {
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
  ['highlights', 'positive_signals', 'risk_signals', 'watch_items'].forEach((group) => {
    if (Array.isArray(out[group]) && Array.isArray(tblock[group])) {
      out[group] = out[group].map((item, idx) => (tblock[group][idx] ? { ...item, text: tblock[group][idx] } : item));
    }
  });
  return out;
}

function localizeBreakdownStep(step) {
  const code = step?.code;
  if (!code) return step?.label || '';
  if (code === 'independent_publishers') {
    const count = Number(step.count || 1);
    return tr(count === 1 ? 'breakdown.independent_publishers' : 'breakdown.independent_publishersPlural', { count });
  }
  if (code === 'version_conflicts') {
    const count = Number(step.count || 1);
    return tr(count === 1 ? 'breakdown.version_conflicts' : 'breakdown.version_conflictsPlural', { count });
  }
  return tr(`breakdown.${code}`);
}

function localizeAction(action) {
  const map = {
    install: tr('action.install'),
    observe: tr('action.observe'),
    wait: tr('action.wait'),
    do_not_install: tr('action.do_not_install')
  };
  return map[action] || tr('action.wait');
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
  const navMap = { drivers: 'nav.drivers', history: 'nav.history', alerts: 'nav.alerts', settings: 'nav.settings', about: 'nav.about' };
  document.querySelectorAll('.nav-item').forEach((btn) => {
    if (navMap[btn.dataset.tab]) btn.textContent = tr(navMap[btn.dataset.tab]);
  });
  $('#btn-refresh').textContent = tr('btn.refresh');
  $('#banner-download').textContent = tr('banner.download');
  $('#banner-install').textContent = tr('banner.install');
  $('#tab-drivers h1').textContent = tr('drivers.title');
  $('#drivers-subtitle').textContent = tr('drivers.subtitle');
  $('#drivers-tip-title').textContent = tr('drivers.waitTipTitle');
  $('#drivers-tip-body').textContent = tr('drivers.waitTipBody');
  $('#tab-history h1').textContent = tr('history.title');
  $('#tab-history .panel-header p').textContent = tr('history.subtitle');
  $('#history-search').placeholder = tr('history.search');
  $('#tab-alerts h1').textContent = tr('alerts.title');
  $('#tab-alerts .panel-header p').textContent = tr('alerts.subtitle');
  $('#tab-settings h1').textContent = tr('settings.title');
  $('#tab-settings .panel-header p').textContent = tr('settings.subtitle');
  $('#tab-about h1').textContent = tr('about.title');
  $('#tab-about .panel-header p').textContent = tr('about.subtitle');
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

  const lang = activeLang();
  listToRender.forEach((vendor) => {
    const item = drivers[vendor] || {};
    const ver = item.verification || {};
    const score = Number(ver.score || 0);
    const tone = scoreTone(score);
    const assess = localizeAssessment(assessments[vendor], lang);
    const riskInfo = resolveRisk(assess);
    const maturity = assess?.maturity || item.maturity || {};
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

    const meter = node('progress', `meter-progress ${tone}`.trim());
    meter.max = 100;
    meter.value = Math.max(2, score);
    card.append(meter);

    if (item.verdict_change && item.verdict_change.from_action && item.verdict_change.to_action) {
      const vc = item.verdict_change;
      const key = vc.escalated ? 'drivers.verdictEscalated' : 'drivers.verdictChanged';
      card.append(node(
        'div',
        `verdict-change-banner${vc.escalated ? ' escalated' : ''}`,
        tr(key, { from: localizeAction(vc.from_action), to: localizeAction(vc.to_action) })
      ));
    }

    if (maturity.in_quarantine && !maturity.security_bypass && !isCritical && riskInfo.level !== 'high') {
      const callout = node('div', 'fresh-callout');
      const pct = Number(maturity.progress_pct || 25);
      const remHours = Math.max(1, Math.round(Number(maturity.remaining_hours || 48)));
      callout.append(
        node('strong', '', tr('drivers.soakTitle', { day: maturity.soak_day || 1, total: maturity.window_days || 4, pct })),
        node('span', '', tr('drivers.freshRelease', { hours: remHours }))
      );
      const bar = node('progress', 'meter-progress soak');
      bar.max = 100;
      bar.value = pct;
      callout.append(bar);
      card.append(callout);
    }

    const conflicts = ver.conflicts || [];
    if (conflicts.length) {
      const cBox = node('div', 'conflict-box');
      cBox.append(node('strong', '', tr('drivers.newerReported', { version: conflicts[0].version })));
      cBox.append(node('span', '', `${conflicts[0].publisher}: ${conflicts[0].title || ''}`));
      card.append(cBox);
    }

    const rec = assess?.recommendation;
    const action = isCritical ? 'do_not_install' : (rec?.action || (maturity.in_quarantine ? 'observe' : 'wait'));
    const vBoxClass = isCritical ? 'verdict-box critical do_not_install' : `verdict-box ${action}${riskInfo.level === 'high' ? ' high' : ''}`;
    const vBox = node('div', vBoxClass);
    const vTop = node('div', 'verdict-top');
    vTop.append(node('small', '', tr('drivers.rec')));
    const vBadges = node('div', 'verdict-badges');
    if (isCritical) {
      vBadges.append(node('span', 'critical-badge', tr('action.criticalBadge')));
    } else if (action === 'observe' && maturity.soak_day) {
      vBadges.append(node('span', 'pill-blue', tr('action.observeDay', { day: maturity.soak_day, total: maturity.window_days || 4 })));
    }
    if (assess?.risk_assessment?.level) {
      vBadges.append(node('span', `risk-pill risk-${riskInfo.level}`, tr('risk.scoreLabel', { level: tr(`risk.${riskInfo.level}`), score: riskInfo.score })));
    }
    vTop.append(vBadges);
    vBox.append(vTop);
    vBox.append(node('strong', '', localizeAction(action)));
    vBox.append(node('p', '', rec?.reason || assess?.headline || tr('drivers.waitingReview')));
    if (isCritical && riskInfo.critical_reasons.length) {
      const crUl = node('ul', 'critical-reasons-list');
      riskInfo.critical_reasons.forEach((reason) => crUl.append(node('li', '', reason)));
      vBox.append(crUl);
    }
    if (rec?.target_audience) {
      vBox.append(node('p', 'target-note', tr('drivers.target', { val: rec.target_audience })));
    }
    card.append(vBox);

    if (assess?.summary || (ver.agreements || []).length) {
      const details = node('details');
      details.append(node('summary', '', tr('drivers.summaryToggle', { count: (ver.agreements || []).length })));
      if (assess?.summary) details.append(node('p', '', assess.summary));

      const signalGroups = [
        [tr('drivers.highlights'), assess?.highlights || [], 'highlights'],
        [tr('drivers.positives'), assess?.positive_signals || [], 'positives'],
        [tr('drivers.risks'), assess?.risk_signals || [], 'risks'],
        [tr('drivers.watch'), assess?.watch_items || [], 'watch']
      ].filter(([, arr]) => arr.some((entry) => entry?.text));
      if (signalGroups.length) {
        const sGrid = node('div', 'signal-mini-grid');
        signalGroups.forEach(([title, arr, cls]) => {
          const box = node('div', `signal-mini-box ${cls}`);
          box.append(node('small', '', title));
          const ul = node('ul');
          arr.forEach((entry) => {
            if (entry?.text) ul.append(node('li', '', entry.text));
          });
          box.append(ul);
          sGrid.append(box);
        });
        details.append(sGrid);
      }

      if ((ver.breakdown || []).length) {
        const bList = node('ul', 'breakdown-list');
        ver.breakdown.forEach((step) => {
          const li = node('li');
          li.append(node('span', '', localizeBreakdownStep(step)));
          const sign = step.delta > 0 ? `+${step.delta}` : String(step.delta);
          li.append(node('span', `breakdown-delta ${step.kind || 'neutral'}`, `${sign} pts`));
          bList.append(li);
        });
        details.append(bList);
      }

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

    if (item.version) {
      card.append(buildDriverVoteBar(vendor, item.version, item.community));
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
          sha256: item.sha256,
          source_name: item.source_name,
          official_url: item.official_url,
          release_notes_url: item.release_notes_url,
          primary_verified: ver.primary_confirmed,
          verification: ver,
          verdict_history: item.verdict_history
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
    vBox.append(node('strong', '', localizeAction(act)));
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

  const verSnap = item.verification || (item.version === currentData?.drivers?.[vendor]?.version ? currentData?.drivers?.[vendor]?.verification : null);
  if (verSnap && (verSnap.breakdown || []).length) {
    const crossSec = node('div', 'dialog-section');
    crossSec.append(node('h3', '', tr('dialog.crossover')));
    const bList = node('ul', 'breakdown-list');
    verSnap.breakdown.forEach((step) => {
      const li = node('li');
      li.append(node('span', '', localizeBreakdownStep(step)));
      const sign = step.delta > 0 ? `+${step.delta}` : String(step.delta);
      li.append(node('span', `breakdown-delta ${step.kind || 'neutral'}`, `${sign} pts`));
      bList.append(li);
    });
    crossSec.append(bList);
    body.append(crossSec);
  }

  const vHist = item.verdict_history || (item.version === currentData?.drivers?.[vendor]?.version ? currentData?.drivers?.[vendor]?.verdict_history : null) || [];
  if (vHist.length > 1) {
    const vhSec = node('div', 'dialog-section');
    vhSec.append(node('h3', '', tr('dialog.verdictHistory')));
    const vhList = node('ul', 'breakdown-list');
    vHist.forEach((step) => {
      const li = node('li');
      const rLabel = step.risk_level ? tr(`risk.${step.risk_level}`) : '';
      li.append(
        node('span', '', `${localizeAction(step.action)}${rLabel ? ` (${rLabel})` : ''}`),
        node('span', '', formatDate(step.at, true))
      );
      vhList.append(li);
    });
    vhSec.append(vhList);
    body.append(vhSec);
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
  if (item.sha256) {
    dl.append(node('dt', '', 'SHA-256'));
    const shaDd = node('dd');
    shaDd.append(document.createTextNode(`${item.sha256.slice(0, 18)}…`));
    const copyBtn = node('button', 'copy-hash-btn', tr('dialog.copy'));
    copyBtn.type = 'button';
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(item.sha256);
        copyBtn.textContent = tr('dialog.copied');
        setTimeout(() => { copyBtn.textContent = tr('dialog.copy'); }, 1500);
      } catch (_) {}
    });
    shaDd.append(copyBtn);
    dl.append(shaDd);
  }
  meta.append(dl);
  body.append(meta);

  const foot = node('div', 'link-row mt-1');
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
    const aKey = a.id ? `alert:${a.id}` : '';
    const tally = (aKey && voteState.tallies[aKey]) || a.community || { up: 0, down: 0, signal: 'insufficient' };
    const myVote = aKey ? voteState.myVotes[aKey] : null;
    const isFp = tally.signal === 'likely_false_positive';
    const card = node('article', `alert-card ${a.severity || 'info'}${isFp ? ' likely-fp' : ''}`);
    const vendors = (a.vendors || []).map((v) => SHORT_LABELS[v] || v).join(', ') || 'General';
    card.append(node('div', 'meta', `${sevLabel[a.severity] || 'Info'} · ${vendors} · ${a.source} · ${formatDate(a.published_at)}`));
    const btn = node('button', 'title-btn', a.title || 'Alert');
    btn.type = 'button';
    btn.addEventListener('click', () => window.driveRadar.openExternal(a.link));
    card.append(btn);
    if (a.summary) card.append(node('p', '', a.summary));
    if (a.id) {
      const vBar = node('div', 'alert-vote-bar');
      if (isFp) vBar.append(node('span', 'risk-pill risk-moderate', tr('vote.flaggedFalsePos')));
      const upBtn = node('button', `vote-btn compact up${myVote?.vote === 'up' ? ' active' : ''}`, `✓ ${tr('vote.alertUseful')} (${tally.up || 0})`);
      upBtn.type = 'button';
      const downBtn = node('button', `vote-btn compact down${myVote?.vote === 'down' ? ' active' : ''}`, `✕ ${tr('vote.alertFalsePos')} (${tally.down || 0})`);
      downBtn.type = 'button';
      upBtn.addEventListener('click', () => submitDesktopVote('alert', a.id, 'up', 'useful_alert'));
      downBtn.addEventListener('click', () => submitDesktopVote('alert', a.id, 'down', 'false_positive'));
      vBar.append(upBtn, downBtn);
      card.append(vBar);
    }
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
    renderAbout();
  } else {
    renderDrivers(currentData);
    renderAbout();
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
  gMon.append(makeToggleRow(tr('settings.notifyEscalation'), tr('settings.notifyEscalationDesc'), currentSettings.notifyEscalation !== false, (v) => updateSetting({ notifyEscalation: v })));
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

  const adv = node('details', 'mt-sm');
  adv.append(node('summary', '', tr('settings.advApi')));
  const urlRow = node('div', 'setting-row');
  const uLbl = node('label');
  const feedback = node('small', 'api-feedback', '');
  uLbl.append(node('strong', '', tr('settings.apiBase')), node('small', '', tr('settings.apiBaseDesc')), feedback);
  const urlControls = node('div', 'api-url-controls');
  const urlInput = node('input', 'api-url-input');
  urlInput.type = 'url';
  urlInput.value = currentSettings.apiBaseUrl;
  const resetBtn = node('button', 'btn-outline', tr('settings.apiReset'));
  resetBtn.type = 'button';
  const defaultApiUrl = currentAppInfo?.defaultApiUrl || 'https://optlabs.com.br/driveradar';

  async function applyValidatedApiUrl(candidate) {
    feedback.className = 'api-feedback';
    feedback.textContent = tr('settings.apiValidating');
    const res = await window.driveRadar.validateApiEndpoint(candidate);
    if (!res?.ok) {
      feedback.className = 'api-feedback error';
      feedback.textContent = res?.error || tr('settings.apiInvalid');
      urlInput.value = currentSettings.apiBaseUrl;
      return;
    }
    urlInput.value = res.url;
    feedback.className = 'api-feedback ok';
    feedback.textContent = tr('settings.apiValid');
    await updateSetting({ apiBaseUrl: res.url });
  }

  urlInput.addEventListener('change', () => applyValidatedApiUrl(urlInput.value));
  resetBtn.addEventListener('click', () => applyValidatedApiUrl(defaultApiUrl));
  urlControls.append(urlInput, resetBtn);
  urlRow.append(uLbl, urlControls);
  adv.append(urlRow);
  gApp.append(adv);
  root.append(gApp);
}

function renderAbout() {
  const root = $('#about-container');
  if (!root) return;
  root.replaceChildren();

  const methodSec = node('section', 'settings-group');
  methodSec.append(node('p', 'about-eyebrow', tr('about.methodEyebrow')));
  methodSec.append(node('h2', '', tr('about.confidenceTitle')));
  methodSec.append(node('p', 'about-lead', tr('about.confidenceCopy')));
  const mList = node('ul', 'method-list');
  [
    ['primary', tr('about.rulePrimary')],
    ['independent', tr('about.ruleCorrob')],
    ['conflict', tr('about.ruleConflict')],
    ['stale', tr('about.ruleStale')]
  ].forEach(([tone, text]) => {
    const li = node('li');
    li.append(node('span', `method-dot ${tone}`), node('span', '', text));
    mList.append(li);
  });
  methodSec.append(mList);
  methodSec.append(node('p', 'about-tip', tr('about.waitTip')));
  root.append(methodSec);

  const riskSec = node('section', 'settings-group');
  riskSec.append(node('h2', '', tr('about.riskTitle')));
  riskSec.append(node('p', 'about-lead', tr('about.riskCopy')));
  const rList = node('ul', 'method-list');
  [
    ['critical', tr('about.riskCritical')],
    ['stale', tr('about.riskHigh')],
    ['independent', tr('about.riskModerate')],
    ['independent', tr('about.riskObserve')],
    ['primary', tr('about.riskLow')]
  ].forEach(([tone, text]) => {
    const li = node('li');
    li.append(node('span', `method-dot ${tone}`), node('span', '', text));
    rList.append(li);
  });
  riskSec.append(rList);
  root.append(riskSec);

  const appSec = node('section', 'settings-group');
  appSec.append(node('h2', '', tr('about.appGroup')));
  appSec.append(node('p', 'about-lead', tr('about.appDesc')));
  const baseUrl = currentSettings?.apiBaseUrl || 'https://optlabs.com.br/driveradar';
  const dl = node('dl', 'dl-grid');
  [
    [tr('about.version'), `v${currentAppInfo?.version || '1.3.0'}`],
    [tr('about.platform'), currentAppInfo?.platform === 'win32' ? 'Windows (Electron)' : (currentAppInfo?.platform || 'Windows')],
    [tr('about.server'), baseUrl]
  ].forEach(([k, v]) => dl.append(node('dt', '', k), node('dd', '', v)));
  appSec.append(dl);

  const links = node('div', 'about-links');
  [
    [tr('about.openWeb'), `${baseUrl}/`],
    [tr('about.privacy'), `${baseUrl}/privacidade`],
    [tr('about.terms'), `${baseUrl}/termos`]
  ].forEach(([label, href]) => {
    const btn = node('button', 'btn-outline', label);
    btn.type = 'button';
    btn.addEventListener('click', () => window.driveRadar.openExternal(href));
    links.append(btn);
  });
  appSec.append(links);
  root.append(appSec);
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
  $('#app-version').textContent = `v${currentAppInfo?.version || '1.3.0'}`;
  applyStaticLabels();
  renderSettings();
  renderAbout();
  renderUpdaterBanner(currentAppInfo?.updater);

  try {
    const data = await window.driveRadar.getData();
    renderAll(data);
    refreshVoteSession();
  } catch (_) {
    $('#sync-status').textContent = tr('sync.error');
  }
});
