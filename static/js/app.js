const LABELS = {
  nvidia: 'NVIDIA GeForce',
  amd: 'AMD Radeon',
  intel: 'Intel Arc',
  windows: 'Windows 11'
};

const SHORT_LABELS = {
  nvidia: 'NVIDIA',
  amd: 'AMD',
  intel: 'Intel',
  windows: 'Windows'
};

const $ = (selector) => document.querySelector(selector);
const SEEN_ALERTS_KEY = 'driveradar-seen-alerts-v1';
const SEEN_VERSIONS_KEY = 'driveradar-seen-versions-v1';
const SEEN_VERDICTS_KEY = 'driveradar-seen-verdicts-v1';
const ALERT_PREFS_KEY = 'driveradar-alert-preferences-v1';
const ALERT_CATEGORIES = ['nvidia', 'amd', 'intel', 'windows', 'vulnerabilities'];

const I18N = window.DriveRadarI18n || {
  t: (k, _v, f) => f || k,
  locale: () => 'pt-BR',
  getLang: () => 'pt-BR',
  setLang: (l) => l,
  applyStatic: () => {}
};
const tr = (key, vars = null, fallback = '') => I18N.t(key, vars, fallback);

const VALID_THEMES = ['system', 'dark', 'light', 'midnight', 'nord', 'forest', 'sand'];

let latestData = null;
let notificationRegistration = null;
let activeAlertVendor = 'all';
let activeHistoryVendor = 'all';
let historySearchQuery = '';
let activeSourceFilter = 'all';
let sourceSearchQuery = '';
let openDialogContext = null;

function localizeBreakdownLabel(step) {
  const code = step?.code;
  if (!code) return step?.label || '';
  if (code === 'independent_publishers') {
    const count = Number(step.count || 1);
    return tr(count === 1 ? 'breakdown.independent_publishers' : 'breakdown.independent_publishersPlural', { count }, step.label);
  }
  if (code === 'version_conflicts') {
    const count = Number(step.count || 1);
    return tr(count === 1 ? 'breakdown.version_conflicts' : 'breakdown.version_conflictsPlural', { count }, step.label);
  }
  return tr(`breakdown.${code}`, null, step.label);
}

function localizeChannel(channel) {
  const raw = String(channel || '').trim();
  if (!raw) return '';
  const low = raw.toLowerCase();
  if (low.includes('preview opcional')) return tr('channel.previewD', null, raw);
  if (low.includes('segurança (b)') || low.includes('seguranca (b)')) return tr('channel.securityB', null, raw);
  if (low.includes('emergencial') || low.includes('out-of-band')) return tr('channel.outOfBand', null, raw);
  return raw;
}

function localizeRecConfidence(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (raw === 'alta' || raw === 'high' || raw === 'élevée') return tr('conf.high', null, value);
  if (raw === 'media' || raw === 'média' || raw === 'moderate' || raw === 'medium' || raw === 'moderada' || raw === 'modérée') return tr('conf.medium', null, value);
  if (raw === 'baixa' || raw === 'low' || raw === 'baja' || raw === 'faible') return tr('conf.low', null, value);
  return value || '';
}

function resolveRisk(obj) {
  if (!obj || typeof obj !== 'object') {
    return { level: 'moderate', score: 38, categories: [], critical_reasons: [], action: 'wait' };
  }
  const ra = obj.risk_assessment && typeof obj.risk_assessment === 'object' ? obj.risk_assessment : null;
  const rawAction = obj.recommendation?.action || obj.recommendation_action || 'wait';
  const rawLevel = String(ra?.level || obj.risk_level || '').toLowerCase();
  let score = ra?.score !== undefined && ra?.score !== null
    ? Number(ra.score)
    : obj.risk_score !== undefined && obj.risk_score !== null
      ? Number(obj.risk_score)
      : (rawLevel === 'critical' || rawAction === 'do_not_install' ? 90 : rawLevel === 'high' ? 65 : (rawAction === 'install' || rawAction === 'observe') ? 15 : 38);
  const categories = Array.isArray(ra?.categories) ? ra.categories : (Array.isArray(obj.risk_categories) ? obj.risk_categories : []);
  const criticalReasons = Array.isArray(ra?.critical_reasons) ? ra.critical_reasons : (Array.isArray(obj.critical_reasons) ? obj.critical_reasons : []);
  const isCritical = rawLevel === 'critical' || rawAction === 'do_not_install' || score >= 80;
  const level = isCritical ? 'critical' : ['high', 'moderate', 'low'].includes(rawLevel) ? rawLevel : (score >= 55 ? 'high' : score >= 25 ? 'moderate' : 'low');
  const action = isCritical ? 'do_not_install' : rawAction;
  return {
    level,
    score: Number.isFinite(score) ? Math.max(0, Math.min(100, Math.round(score))) : (isCritical ? 90 : 38),
    categories,
    critical_reasons: criticalReasons,
    action
  };
}

function localizeAssessment(assessment, lang) {
  if (!assessment || typeof assessment !== 'object') return assessment;
  const tblock = lang && lang !== 'pt-BR' ? assessment.translations?.[lang] : null;
  const out = {
    ...assessment,
    recommendation: assessment.recommendation ? { ...assessment.recommendation } : undefined,
    risk_assessment: assessment.risk_assessment ? { ...assessment.risk_assessment } : undefined
  };
  if (tblock && typeof tblock === 'object') {
    if (tblock.headline) out.headline = tblock.headline;
    if (tblock.summary) out.summary = tblock.summary;
    if (out.recommendation) {
      if (tblock.target_audience) out.recommendation.target_audience = tblock.target_audience;
      if (tblock.reason) out.recommendation.reason = tblock.reason;
    }
    if (out.risk_assessment && Array.isArray(tblock.critical_reasons) && tblock.critical_reasons.length) {
      out.risk_assessment.critical_reasons = tblock.critical_reasons;
    }
    ['highlights', 'positive_signals', 'risk_signals', 'watch_items'].forEach((group) => {
      if (Array.isArray(out[group]) && Array.isArray(tblock[group])) {
        out[group] = out[group].map((item, idx) => (tblock[group][idx] ? { ...item, text: tblock[group][idx] } : item));
      }
    });
  }
  return out;
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

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}

function safeUrl(value) {
  try {
    const url = new URL(value, window.location.origin);
    if (url.username || url.password) return '#';
    return ['http:', 'https:'].includes(url.protocol) ? url.href : '#';
  } catch (_) {
    return '#';
  }
}

function externalLink(label, url, className = '', title = '') {
  const link = node('a', className, label);
  link.href = safeUrl(url);
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  if (title) link.title = title;
  return link;
}

function parseDateValue(value) {
  if (!value) return null;
  const date = /^\d{4}-\d{2}-\d{2}$/.test(String(value))
    ? new Date(`${value}T12:00:00Z`)
    : new Date(Number(value) < 10_000_000_000 ? Number(value) * 1000 : value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatDate(value, includeTime = false) {
  const date = parseDateValue(value);
  if (!date) return tr('date.unknown', null, 'Data não informada');
  return new Intl.DateTimeFormat(I18N.locale(), includeTime
    ? { dateStyle: 'medium', timeStyle: 'short' }
    : { dateStyle: 'medium', timeZone: 'UTC' }).format(date);
}

function relativeDaysLabel(value) {
  const date = parseDateValue(value);
  if (!date) return '';
  const diffDays = Math.round((Date.now() - date.getTime()) / 86_400_000);
  if (diffDays <= 0) return tr('date.today', null, 'hoje');
  if (diffDays === 1) return tr('date.yesterday', null, 'há 1 dia');
  return tr('date.daysAgo', { days: diffDays }, `há ${diffDays} dias`);
}

function releaseAgeDays(value) {
  const date = parseDateValue(value);
  if (!date) return null;
  return Math.floor((Date.now() - date.getTime()) / 86_400_000);
}

function daysBetween(dateStrA, dateStrB) {
  const a = parseDateValue(dateStrA);
  const b = parseDateValue(dateStrB);
  if (!a || !b) return null;
  return Math.round(Math.abs(a.getTime() - b.getTime()) / 86_400_000);
}

function confidenceTone(score) {
  if (score >= 88) return 'confirmed';
  if (score >= 72) return 'high';
  if (score >= 50) return 'medium';
  return 'low';
}

function confidenceLabel(score, backendLabel) {
  if (score >= 88) return tr('conf.confirmed', null, backendLabel || 'confirmada');
  if (score >= 72) return tr('conf.high', null, backendLabel || 'alta');
  if (score >= 50) return tr('conf.medium', null, backendLabel || 'moderada');
  return tr('conf.low', null, backendLabel || 'baixa');
}

function renderCrossover(data) {
  const verification = data.verification || {};
  const score = Number(verification.score || 0);
  const publishers = Number(verification.independent_publishers || 0);
  const conflicts = verification.conflicts || [];
  const sources = [...new Map((verification.agreements || []).map((item) => [item.publisher || item.source_name, item])).values()];
  const block = node('section', `crossover-block ${confidenceTone(score)}`);
  block.append(node('small', '', tr('crossover.title', null, 'RESULTADO DO CROSSOVER')));
  block.append(node('strong', '', tr(
    publishers === 1 ? 'crossover.score' : 'crossover.scorePlural',
    { score, count: publishers },
    `${score}% · ${publishers}`
  )));
  let summary = verification.primary_confirmed
    ? tr('crossover.primaryYes', null, 'Versão e data confirmadas em fonte primária.')
    : tr('crossover.primaryNo', null, 'Ainda sem confirmação em fonte primária.');
  summary += ' ';
  summary += conflicts.length
    ? tr(conflicts.length === 1 ? 'crossover.conflictYes' : 'crossover.conflictYesPlural', { count: conflicts.length }, '')
    : tr('crossover.conflictNo', null, 'Nenhum conflito encontrado.');
  if (verification.date_delta_days > 1) {
    summary += ' ' + tr('crossover.dateDelta', { days: verification.date_delta_days }, '');
  }
  block.append(node('p', '', summary));

  const breakdown = verification.breakdown || [];
  if (breakdown.length) {
    const details = node('details', 'score-breakdown');
    details.append(node('summary', '', tr('crossover.breakdownToggle', null, 'Ver composição do score')));
    const list = node('ul', 'breakdown-list');
    breakdown.forEach((step) => {
      const li = node('li');
      li.append(node('span', '', localizeBreakdownLabel(step)));
      const sign = step.delta > 0 ? `+${step.delta}` : String(step.delta);
      li.append(node('span', `breakdown-delta ${step.kind || 'neutral'}`, `${sign} pts`));
      list.append(li);
    });
    details.append(list);
    block.append(details);
  }

  if (conflicts.length) {
    const callout = node('div', 'conflict-callout');
    callout.append(node('strong', '', tr('crossover.conflictHeading', null, 'Divergência / versão mais recente reportada')));
    const ul = node('ul');
    conflicts.forEach((c) => {
      const li = node('li');
      const pub = c.publisher || c.source_name || 'External';
      const prefix = c.conflict_type === 'newer_reported'
        ? tr('crossover.newerReported', { pub, ver: c.version }, `${pub}: ${c.version} `)
        : tr('crossover.diffReported', { pub, ver: c.version }, `${pub}: ${c.version} `);
      li.append(document.createTextNode(prefix));
      li.append(externalLink(c.title || c.url || tr('card.source', null, 'Fonte'), c.url));
      ul.append(li);
    });
    callout.append(ul);
    block.append(callout);
  }

  const sourceList = node('div', 'crossover-sources');
  sourceList.append(node('small', '', tr('crossover.sources', { count: sources.length }, 'FONTES CRUZADAS')));
  const chips = node('div', 'chips');
  sources.forEach((item) => {
    const label = item.publisher || item.source_name;
    chips.append(externalLink(label, item.url, `chip ${item.tier || ''}`, item.title || label));
  });
  if (!chips.children.length) chips.append(node('span', 'chip muted', tr('crossover.noSources', null, 'Nenhuma fonte concordante')));
  sourceList.append(chips);
  block.append(sourceList);
  return block;
}

function renderStructuredFallbackSignals(structured) {
  const highlights = (structured?.highlights || []).map((t) => ({ text: t, citations: [] }));
  const positives = (structured?.fixed_issues || []).map((t) => ({ text: t, citations: [] }));
  const risks = (structured?.known_issues || []).map((t) => ({ text: t, citations: [] }));
  if (!highlights.length && !positives.length && !risks.length) return null;

  const details = node('details', 'analysis-details');
  details.open = false;
  details.append(node('summary', '', tr('review.officialToggle', null, 'Destaques, correções e problemas das notas oficiais')));
  const signals = node('div', 'signal-grid');
  [
    [tr('review.highlights', null, 'DESTAQUES'), highlights, 'highlights-box'],
    [tr('review.positives', null, 'CORREÇÕES'), positives, 'positives-box'],
    [tr('review.risks', null, 'PROBLEMAS'), risks, 'risks-box']
  ].forEach(([label, values, cls]) => {
    if (!values.length) return;
    const group = node('div', cls);
    group.append(node('small', '', label));
    const list = node('ul');
    values.slice(0, 4).forEach((v) => list.append(node('li', '', v.text)));
    group.append(list);
    signals.append(group);
  });
  details.append(signals);
  return details;
}

function localizeActionLabel(action) {
  const map = {
    install: tr('action.install', null, 'Instalar'),
    observe: tr('action.observe', null, 'Em Observação'),
    wait: tr('action.wait', null, 'Aguardar'),
    do_not_install: tr('action.do_not_install', null, 'Crítico — Não instalar')
  };
  return map[action] || tr('action.wait', null, 'Aguardar');
}

function renderTechnicalReview(rawAssessment, advisorStatus = 'pending', structuredNotes = null, driverMaturity = null) {
  const assessment = localizeAssessment(rawAssessment, I18N.getLang());
  const ready = assessment?.status === 'ready';
  const processing = advisorStatus === 'pending';
  const risks = assessment?.risk_signals || [];
  const positives = assessment?.positive_signals || [];
  const maturity = assessment?.maturity || driverMaturity || {};
  const recommendation = assessment?.recommendation || (ready && risks.length ? {
    action: 'wait',
    reason: tr('review.waitDefault'),
    citations: risks.flatMap((item) => item.citations || []).slice(0, 3)
  } : ready && positives.length ? {
    action: maturity.in_quarantine ? 'observe' : 'install',
    reason: '',
    citations: positives.flatMap((item) => item.citations || []).slice(0, 3)
  } : {
    action: maturity.in_quarantine ? 'observe' : 'wait',
    reason: processing ? tr('review.waitDefault') : tr('review.waitUnavailable')
  });

  const riskInfo = resolveRisk({ ...assessment, recommendation });
  const action = ready ? riskInfo.action : recommendation.action || 'wait';
  const isCritical = ready && (riskInfo.level === 'critical' || action === 'do_not_install');
  const block = node('section', `technical-note ${ready ? 'ready' : 'pending'}`);
  const verdictClass = isCritical ? 'verdict critical do_not_install' : `verdict ${action}${riskInfo.level === 'high' ? ' high' : ''}`;
  const verdict = node('div', verdictClass);
  const verdictTop = node('div', 'verdict-top');
  verdictTop.append(node('small', '', tr('review.verdict', null, 'RECOMENDAÇÃO')));
  const badges = node('div', 'verdict-badges');
  if (isCritical) {
    badges.append(node('span', 'critical-badge', tr('action.criticalBadge', null, 'CRÍTICO')));
  } else if (action === 'observe' && maturity.soak_day) {
    badges.append(node('span', 'pill blue', tr('action.observeDay', { day: maturity.soak_day, total: maturity.window_days || 4 })));
  }
  if (ready && assessment?.risk_assessment?.level) {
    const levelLabel = tr(`risk.${riskInfo.level}`, null, riskInfo.level);
    badges.append(node('span', `risk-pill risk-${riskInfo.level}`, tr('risk.scoreLabel', { level: levelLabel, score: riskInfo.score })));
  }
  if (recommendation.confidence) {
    badges.append(node('span', 'pill muted', tr('review.confidence', { val: localizeRecConfidence(recommendation.confidence) })));
  }
  verdictTop.append(badges);
  verdict.append(verdictTop);
  verdict.append(node('strong', '', localizeActionLabel(action)));
  verdict.append(node('p', '', recommendation.reason));
  if (isCritical && riskInfo.critical_reasons.length) {
    const crList = node('ul', 'critical-reasons-list');
    riskInfo.critical_reasons.forEach((reason) => crList.append(node('li', '', reason)));
    verdict.append(crList);
  }
  if (recommendation.target_audience) {
    verdict.append(node('p', 'target-audience', tr('review.target', { val: recommendation.target_audience })));
  }
  const verdictSources = node('div', 'signal-references');
  (recommendation.citations || []).forEach((citation) => {
    verdictSources.append(externalLink(citation.publisher || 'Fonte', citation.url, '', citation.title || ''));
  });
  if (verdictSources.children.length) verdict.append(verdictSources);
  block.append(verdict);

  const heading = node('div', 'technical-note-heading');
  const title = node('div');
  title.append(node('small', '', tr('review.sourcesSay', null, 'O QUE AS FONTES DIZEM')));
  title.append(node('strong', '', ready ? assessment.headline : processing ? tr('review.processing') : tr('review.unavailable')));
  heading.append(title);
  block.append(heading);
  block.append(node('p', '', ready
    ? assessment.summary
    : processing
      ? tr('review.processingCopy')
      : tr('review.unavailableCopy')));

  if (!ready) {
    const fallback = renderStructuredFallbackSignals(structuredNotes);
    if (fallback) block.append(fallback);
    return block;
  }

  const details = node('details', 'analysis-details');
  details.open = false;
  details.append(node('summary', '', tr('review.detailsToggle', null, 'Ver destaques, prós, riscos e citações')));
  const signals = node('div', 'signal-grid');
  const groups = [
    [tr('review.highlights', null, 'DESTAQUES'), assessment.highlights || [], 'highlights-box'],
    [tr('review.positives', null, 'PONTOS FAVORÁVEIS'), assessment.positive_signals || [], 'positives-box'],
    [tr('review.risks', null, 'LIMITAÇÕES E RISCOS'), assessment.risk_signals || [], 'risks-box'],
    [tr('review.watch', null, 'ACOMPANHAR'), assessment.watch_items || [], 'watch-box']
  ];
  groups.forEach(([label, values, cls]) => {
    const group = node('div', cls);
    group.append(node('small', '', label));
    const list = node('ul');
    values.forEach((value) => {
      if (!value?.text) return;
      const item = node('li', 'grounded-signal');
      item.append(node('span', '', value.text));
      const references = node('span', 'signal-references');
      (value.citations || []).forEach((citation) => {
        references.append(externalLink(citation.publisher || 'Fonte', citation.url, '', citation.title || ''));
      });
      if (references.children.length) item.append(references);
      list.append(item);
    });
    if (!list.children.length) list.append(node('li', 'muted', tr('review.noExtra')));
    group.append(list);
    signals.append(group);
  });
  details.append(signals);

  const citations = node('div', 'advisor-sources');
  citations.append(node('small', '', tr('review.sources', null, 'FONTES DA ANÁLISE')));
  const chips = node('div', 'chips');
  (assessment.citations || []).forEach((citation) => {
    chips.append(externalLink(citation.publisher, citation.url, `chip ${citation.tier || ''}`, citation.title || ''));
  });
  if (!chips.children.length) chips.append(node('span', 'chip muted', tr('review.noCitation')));
  citations.append(chips);
  details.append(citations);
  block.append(details);
  return block;
}

function findHistoryItem(vendor, version) {
  const list = latestData?.history?.[vendor] || [];
  return list.find((item) => item.version === version) || null;
}

function renderDriver(vendor, data, assessment, advisorStatus) {
  const verification = data.verification || {};
  const score = Number(verification.score || 0);
  const tone = confidenceTone(score);
  const riskInfo = resolveRisk(localizeAssessment(assessment, I18N.getLang()));
  const card = node('article', `driver-card ${vendor}${assessment?.status === 'ready' && riskInfo.level === 'critical' ? ' risk-critical' : ''}`);

  const heading = node('div', 'card-heading');
  const identity = node('div', 'driver-identity');
  identity.append(node('span', 'vendor-mark', vendor.slice(0, 2).toUpperCase()));
  const identityText = node('div');
  const sourceLabels = {
    stale: tr('card.stale'),
    verified: tr('card.verified'),
    unconfirmed: tr('card.unconfirmed'),
    unavailable: tr('card.sourceDown')
  };
  identityText.append(node('h3', '', LABELS[vendor]), node('small', '', sourceLabels[data.source_status] || ''));
  identity.append(identityText);
  heading.append(identity);
  heading.append(node('span', `confidence ${tone}`, `${score}% ${confidenceLabel(score, verification.label)}`));
  card.append(heading);

  const version = node('div', 'version-block');
  version.append(node('small', '', tr('card.confirmedVersion')), node('strong', '', data.version || tr('card.unavailable')));
  const meta = node('div', 'version-meta');
  const rel = relativeDaysLabel(data.release_date);
  const parts = [`${formatDate(data.release_date)}${rel ? ` (${rel})` : ''}`];
  if (data.channel) parts.push(localizeChannel(data.channel));
  if (data.os_build) parts.push(`Build ${data.os_build}`);
  if (data.file_size) parts.push(data.file_size);
  meta.append(node('span', '', parts.join(' · ')));
  version.append(meta);
  card.append(version);

  const meter = node('div', 'confidence-meter');
  const fill = node('span', tone);
  fill.style.width = `${Math.max(2, score)}%`;
  meter.append(fill);
  card.append(meter);

  const maturity = assessment?.maturity || data.maturity || {};
  const isCritCard = assessment?.status === 'ready' && (riskInfo.level === 'critical' || riskInfo.action === 'do_not_install');
  if (data.verdict_change && data.verdict_change.from_action && data.verdict_change.to_action) {
    const vc = data.verdict_change;
    const bannerKey = vc.escalated ? 'card.verdictEscalated' : 'card.verdictChanged';
    const banner = node(
      'div',
      `verdict-change-banner${vc.escalated ? ' escalated' : ''}`,
      tr(bannerKey, {
        from: localizeActionLabel(vc.from_action),
        to: localizeActionLabel(vc.to_action)
      })
    );
    card.append(banner);
  }
  if (maturity.in_quarantine && !maturity.security_bypass && !isCritCard && riskInfo.level !== 'high') {
    const callout = node('div', 'fresh-callout');
    const pct = Number(maturity.progress_pct || 25);
    const remHours = Math.max(1, Math.round(Number(maturity.remaining_hours || 48)));
    callout.append(
      node('strong', '', tr('card.soakTitle', { day: maturity.soak_day || 1, total: maturity.window_days || 4, pct })),
      node('span', '', tr('card.freshRelease', { hours: remHours }))
    );
    const bar = node('div', 'soak-meter');
    const barFill = node('span');
    barFill.style.width = `${pct}%`;
    bar.append(barFill);
    callout.append(bar);
    card.append(callout);
  }

  card.append(renderCrossover(data));
  card.append(renderTechnicalReview(assessment, advisorStatus, data.structured_notes, data.maturity));

  const facts = node('dl', 'facts');
  const factRows = [
    [tr('card.primarySource'), verification.primary_confirmed ? tr('card.confirmedBy', { name: data.source_name || 'Vendor' }) : tr('card.notConfirmed')],
    [tr('card.publishers'), verification.independent_publishers || 0],
    [tr('card.conflicts'), (verification.conflicts || []).length],
    [tr('card.dataState'), sourceLabels[data.source_status] || '']
  ];
  factRows.forEach(([term, value]) => {
    facts.append(node('dt', '', term), node('dd', '', value));
  });
  card.append(facts);

  if (window.DriveRadarVotes && data.version) {
    const voteBar = window.DriveRadarVotes.renderDriverVoteBar(vendor, data.version, data.community);
    if (voteBar) card.append(voteBar);
  }

  const actions = node('div', 'card-actions');
  const links = node('div', 'card-action-links');
  links.append(externalLink(vendor === 'windows' ? tr('card.officialUpdate') : tr('card.officialDownload'), data.official_url, 'primary-link'));
  if (data.release_notes_url) {
    links.append(externalLink(tr('card.officialNotes'), data.release_notes_url, 'secondary-link'));
  }
  if (data.source_url && data.source_url !== data.official_url && data.source_url !== data.release_notes_url) {
    links.append(externalLink(tr('card.source'), data.source_url, 'secondary-link'));
  }
  actions.append(links);
  if (data.version) {
    const detailBtn = node('button', 'detail-button', tr('card.fullDetails'));
    detailBtn.type = 'button';
    detailBtn.addEventListener('click', () => {
      const histItem = findHistoryItem(vendor, data.version) || {
        version: data.version,
        date: data.release_date,
        channel: data.channel,
        os_build: data.os_build,
        file_size: data.file_size,
        sha256: data.sha256,
        source_name: data.source_name,
        source_url: data.source_url,
        official_url: data.official_url,
        release_notes_url: data.release_notes_url,
        verified_at: latestData?.last_updated,
        primary_verified: verification.primary_confirmed,
        verification
      };
      openHistoryDetails(vendor, histItem, 0);
    });
    actions.append(detailBtn);
  }
  card.append(actions);
  return card;
}

function renderDrivers(drivers, advisor) {
  const grid = $('#driver-grid');
  grid.replaceChildren();
  Object.keys(LABELS).forEach((vendor) => grid.append(renderDriver(vendor, drivers[vendor] || {}, advisor?.assessments?.[vendor], advisor?.status)));
}

function renderAlertFilters(alerts) {
  const container = $('#alert-filters');
  container.replaceChildren();
  const options = [['all', tr('filter.all')], ...Object.keys(SHORT_LABELS).map((v) => [v, SHORT_LABELS[v]])];
  options.forEach(([key, label]) => {
    const count = key === 'all'
      ? alerts.length
      : alerts.filter((a) => (a.vendors || []).includes(key)).length;
    const btn = node('button', `filter-pill ${activeAlertVendor === key ? 'active' : ''}`, `${label} (${count})`);
    btn.type = 'button';
    btn.addEventListener('click', () => {
      activeAlertVendor = key;
      renderAlerts(alerts);
    });
    container.append(btn);
  });
}

function renderAlerts(alerts) {
  renderAlertFilters(alerts || []);
  const container = $('#alert-list');
  container.replaceChildren();
  const filtered = activeAlertVendor === 'all'
    ? (alerts || [])
    : (alerts || []).filter((a) => (a.vendors || []).includes(activeAlertVendor));

  if (!filtered.length) {
    const empty = node('div', 'notice neutral');
    empty.append(
      node('strong', '', activeAlertVendor === 'all' ? tr('alerts.emptyAll') : tr('alerts.emptyVendor', { vendor: SHORT_LABELS[activeAlertVendor] })),
      node('p', '', tr('alerts.emptyDesc'))
    );
    container.append(empty);
    return;
  }

  const severityLabel = {
    critical: tr('sev.critical'),
    high: tr('sev.high'),
    medium: tr('sev.medium'),
    info: tr('sev.info')
  };
  const severityTone = { critical: 'red', high: 'amber', medium: 'amber', info: 'muted' };
  filtered.slice(0, 10).forEach((alert) => {
    const sev = alert.severity || 'info';
    const item = node('article', `alert-item severity-${sev}`);
    item.append(node('span', 'alert-icon', sev === 'critical' ? '!!' : '!'));
    const body = node('div', 'alert-body');
    const tags = node('div', 'alert-tags');
    tags.append(node('span', `pill ${severityTone[sev] || 'muted'}`, severityLabel[sev] || 'Info'));
    (alert.vendors || []).forEach((v) => {
      if (SHORT_LABELS[v]) tags.append(node('span', 'pill muted', SHORT_LABELS[v]));
    });
    body.append(tags);
    body.append(externalLink(alert.title || 'Alert', alert.link));
    if (alert.summary) body.append(node('p', 'alert-summary', alert.summary));
    const rel = relativeDaysLabel(alert.published_at);
    body.append(node('small', '', `${alert.source || 'External'} · ${formatDate(alert.published_at)}${rel ? ` (${rel})` : ''}`));
    if (window.DriveRadarVotes && alert.id) {
      const alertVotes = window.DriveRadarVotes.renderAlertVoteBar(alert);
      if (alertVotes) body.append(alertVotes);
    }
    item.append(body);
    container.append(item);
  });
}

function renderHistorySummarySections(rawSummary, fallbackVerification) {
  const summary = localizeSummary(rawSummary, I18N.getLang());
  const fragment = document.createDocumentFragment();
  if (summary) {
    const recSec = node('div', 'dialog-section');
    const riskInfo = resolveRisk(summary);
    const action = riskInfo.action || 'wait';
    const isCritical = riskInfo.level === 'critical' || action === 'do_not_install';
    const verdict = node('div', isCritical ? 'verdict critical do_not_install' : `verdict ${action}${riskInfo.level === 'high' ? ' high' : ''}`);
    const verdictTop = node('div', 'verdict-top');
    verdictTop.append(node('small', '', tr('dialog.recTitle')));
    const badges = node('div', 'verdict-badges');
    if (isCritical) badges.append(node('span', 'critical-badge', tr('action.criticalBadge', null, 'CRÍTICO')));
    if (summary.risk_level) {
      const levelLabel = tr(`risk.${riskInfo.level}`, null, riskInfo.level);
      badges.append(node('span', `risk-pill risk-${riskInfo.level}`, tr('risk.scoreLabel', { level: levelLabel, score: riskInfo.score })));
    }
    verdictTop.append(badges);
    verdict.append(verdictTop);
    verdict.append(node('strong', '', localizeActionLabel(action)));
    verdict.append(node('p', '', summary.recommendation_reason || ''));
    if (isCritical && riskInfo.critical_reasons.length) {
      const crList = node('ul', 'critical-reasons-list');
      riskInfo.critical_reasons.forEach((reason) => crList.append(node('li', '', reason)));
      verdict.append(crList);
    }
    recSec.append(verdict);
    if (summary.headline) recSec.append(node('h3', '', summary.headline));
    if (summary.summary) recSec.append(node('p', 'dialog-summary-text', summary.summary));

    const boxes = [
      [tr('dialog.highlights'), summary.highlights || [], 'highlights'],
      [tr('dialog.fixed'), summary.fixed_issues || [], 'fixed'],
      [tr('dialog.known'), summary.known_issues || [], 'known'],
      [tr('dialog.watch'), summary.watch_items || [], 'watch']
    ].filter(([, items]) => items.length > 0);

    if (boxes.length) {
      const grid = node('div', 'dialog-notes-grid');
      boxes.forEach(([label, items, cls]) => {
        const box = node('div', `dialog-notes-box ${cls}`);
        box.append(node('small', '', label));
        const ul = node('ul');
        items.forEach((txt) => ul.append(node('li', '', txt)));
        box.append(ul);
        grid.append(box);
      });
      recSec.append(grid);
    }
    fragment.append(recSec);
  }

  if (fallbackVerification) {
    const crossSec = node('div', 'dialog-section');
    crossSec.append(node('h3', '', tr('dialog.crossover')));
    const vScore = Number(fallbackVerification.score || 0);
    const meter = node('div', 'confidence-meter');
    const fill = node('span', confidenceTone(vScore));
    fill.style.width = `${Math.max(2, vScore)}%`;
    meter.append(fill);
    crossSec.append(meter);
    crossSec.append(node('p', 'dialog-summary-text',
      tr('dialog.crossoverStats', {
        score: vScore,
        conf: confidenceLabel(vScore, fallbackVerification.label),
        pubs: fallbackVerification.independent_publishers || 1,
        conflicts: fallbackVerification.conflict_count || 0
      })
    ));
    if ((fallbackVerification.breakdown || []).length) {
      const list = node('ul', 'breakdown-list');
      fallbackVerification.breakdown.forEach((step) => {
        const li = node('li');
        li.append(node('span', '', localizeBreakdownLabel(step)));
        const sign = step.delta > 0 ? `+${step.delta}` : String(step.delta);
        li.append(node('span', `breakdown-delta ${step.kind || 'neutral'}`, `${sign} pts`));
        list.append(li);
      });
      crossSec.append(list);
    }
    if ((fallbackVerification.agreements || []).length) {
      const chips = node('div', 'chips');
      chips.style.marginTop = '.65rem';
      fallbackVerification.agreements.forEach((ag) => {
        const label = ag.publisher || ag.source_name || 'Source';
        chips.append(externalLink(label, ag.url, `chip ${ag.tier || ''}`, ag.title || label));
      });
      crossSec.append(chips);
    }
    fragment.append(crossSec);
  }
  return fragment;
}

function populateHistoryDialog(vendor, item, index, isLoading = false) {
  const body = $('#history-dialog-body');
  const currentVersion = latestData?.drivers?.[vendor]?.version;
  const isCurrent = item.version && item.version === currentVersion;
  $('#history-dialog-eyebrow').textContent = `${LABELS[vendor]} · ${tr('dialog.eyebrow')}`;
  $('#history-dialog-title').textContent = `${LABELS[vendor]} ${item.version || ''}`.trim();
  body.replaceChildren();

  const strip = node('div', 'dialog-strip');
  strip.append(node('span', isCurrent ? 'pill teal' : 'pill muted', isCurrent ? tr('history.current') : `#${index + 1}`));
  if (item.channel) strip.append(node('span', 'pill', localizeChannel(item.channel)));
  if (item.os_build) strip.append(node('span', 'pill muted', `Build ${item.os_build}`));
  if (item.verification?.score !== undefined && item.verification?.score !== null) {
    strip.append(node('span', 'pill teal', `Crossover ${item.verification.score}%`));
  }
  const rsRisk = item.release_summary ? resolveRisk(item.release_summary) : null;
  if (rsRisk && (rsRisk.level === 'critical' || rsRisk.action === 'do_not_install')) {
    strip.append(node('span', 'pill critical', tr('action.criticalBadge', null, 'CRÍTICO')));
  }
  body.append(strip);

  if (isLoading) {
    body.append(node('div', 'dialog-loading', tr('dialog.loading')));
  }

  const verSnapshot = item.verification || (isCurrent ? latestData?.drivers?.[vendor]?.verification : null);
  body.append(renderHistorySummarySections(item.release_summary, verSnapshot));

  const vHistory = item.verdict_history || (isCurrent ? latestData?.drivers?.[vendor]?.verdict_history : null) || [];
  if (vHistory.length > 1) {
    const vhSec = node('div', 'dialog-section');
    vhSec.append(node('h3', '', tr('dialog.verdictHistory')));
    const vhList = node('ul', 'verdict-timeline');
    vHistory.forEach((step) => {
      const li = node('li');
      const actLabel = localizeActionLabel(step.action);
      const rLabel = step.risk_level ? tr(`risk.${step.risk_level}`, null, step.risk_level) : '';
      li.append(
        node('span', '', `${actLabel}${rLabel ? ` (${rLabel})` : ''}`),
        node('span', 'muted', formatDate(step.at, true))
      );
      vhList.append(li);
    });
    vhSec.append(vhList);
    body.append(vhSec);
  }

  const metaSec = node('div', 'dialog-section');
  metaSec.append(node('h3', '', tr('dialog.metadata')));
  const facts = node('dl', 'history-details');
  const rows = [
    [tr('dialog.version'), item.version || '—'],
    [tr('dialog.releaseDate'), formatDate(item.date)],
    [tr('dialog.channel'), localizeChannel(item.channel) || '—'],
    [tr('dialog.firstSeen'), formatDate(item.first_seen_at || item.verified_at, true)],
    [tr('dialog.lastVerified'), formatDate(item.verified_at, true)],
    [tr('dialog.sourceReg'), item.source_name || 'Vendor'],
    [tr('dialog.primaryConf'), item.primary_verified ? tr('conf.confirmed') : tr('card.notConfirmed')]
  ];
  if (item.os_build) rows.splice(3, 0, [tr('dialog.build'), item.os_build]);
  if (item.file_size) rows.splice(3, 0, [tr('dialog.size'), item.file_size]);
  rows.forEach(([term, value]) => facts.append(node('dt', '', term), node('dd', '', value)));

  if (item.sha256) {
    facts.append(node('dt', '', 'SHA-256'));
    const dd = node('dd');
    dd.append(document.createTextNode(`${item.sha256.slice(0, 18)}…`));
    const copyBtn = node('button', 'copy-hash-btn', tr('dialog.copy'));
    copyBtn.type = 'button';
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(item.sha256);
        copyBtn.textContent = tr('dialog.copied');
        setTimeout(() => { copyBtn.textContent = tr('dialog.copy'); }, 1500);
      } catch (_) {}
    });
    dd.append(copyBtn);
    facts.append(dd);
  }
  metaSec.append(facts);
  body.append(metaSec);

  const actions = node('div', 'dialog-actions');
  if (item.release_notes_url) actions.append(externalLink(tr('dialog.openNotes'), item.release_notes_url, 'primary-link'));
  if (item.official_url && item.official_url !== item.release_notes_url) {
    actions.append(externalLink(tr('dialog.openOfficial'), item.official_url, 'secondary-link'));
  }
  if (item.source_url && item.source_url !== item.official_url && item.source_url !== item.release_notes_url) {
    actions.append(externalLink(tr('dialog.openSource'), item.source_url, 'secondary-link'));
  }
  if (actions.children.length) body.append(actions);
}

async function openHistoryDetails(vendor, item, index) {
  const dialog = $('#history-dialog');
  const lang = I18N.getLang();
  openDialogContext = { vendor, item, index };
  const needsEnrich = !item.release_summary?.enriched_at
    || (lang !== 'pt-BR' && !item.release_summary?.translations?.[lang]);
  populateHistoryDialog(vendor, item, index, needsEnrich);
  if (!dialog.open) dialog.showModal();

  if (!needsEnrich || !item.version) return;
  try {
    const resp = await fetch(`/driveradar/api/history/${encodeURIComponent(vendor)}/${encodeURIComponent(item.version)}?lang=${encodeURIComponent(lang)}`);
    if (!resp.ok) {
      populateHistoryDialog(vendor, item, index, false);
      return;
    }
    const enriched = await resp.json();
    if (latestData?.history?.[vendor]) {
      const idx = latestData.history[vendor].findIndex((h) => h.version === enriched.version);
      if (idx !== -1) latestData.history[vendor][idx] = enriched;
    }
    openDialogContext = { vendor, item: enriched, index };
    if (dialog.open) {
      populateHistoryDialog(vendor, enriched, index, false);
      renderHistory(latestData?.history || {});
    }
  } catch (_) {
    if (dialog.open) populateHistoryDialog(vendor, item, index, false);
  }
}

function renderHistoryFilters(history) {
  const container = $('#history-filters');
  container.replaceChildren();
  const options = [['all', tr('filter.all')], ...Object.keys(LABELS).map((v) => [v, SHORT_LABELS[v]])];
  options.forEach(([key, label]) => {
    const count = key === 'all'
      ? Object.values(history || {}).reduce((sum, arr) => sum + (arr?.length || 0), 0)
      : (history?.[key] || []).length;
    const btn = node('button', `filter-pill ${activeHistoryVendor === key ? 'active' : ''}`, `${label} (${count})`);
    btn.type = 'button';
    btn.addEventListener('click', () => {
      activeHistoryVendor = key;
      renderHistory(history);
    });
    container.append(btn);
  });
}

function matchesHistorySearch(item, query) {
  if (!query) return true;
  const rs = localizeSummary(item.release_summary, I18N.getLang()) || {};
  const haystack = [
    item.version,
    item.channel,
    localizeChannel(item.channel),
    item.os_build,
    item.date,
    rs.headline,
    rs.summary,
    ...(rs.highlights || []),
    ...(rs.fixed_issues || []),
    ...(rs.known_issues || [])
  ].filter(Boolean).join(' ').toLowerCase();
  return haystack.includes(query);
}

function renderHistory(history) {
  renderHistoryFilters(history || {});
  const grid = $('#history-grid');
  grid.replaceChildren();
  const lang = I18N.getLang();
  const query = historySearchQuery.trim().toLowerCase();
  const vendors = activeHistoryVendor === 'all' ? Object.keys(LABELS) : [activeHistoryVendor];
  const actionLabels = {
    install: tr('action.install'),
    observe: tr('action.observe'),
    wait: tr('action.wait'),
    do_not_install: tr('action.criticalBadge', null, 'CRÍTICO')
  };
  const actionTone = { install: 'teal', observe: 'blue', wait: 'amber', do_not_install: 'critical' };

  vendors.forEach((vendor) => {
    const box = node('article', 'history-card');
    const allItems = history?.[vendor] || [];
    const items = allItems.filter((item) => matchesHistorySearch(item, query));
    const head = node('div', 'history-card-head');
    head.append(node('h3', '', LABELS[vendor]));
    head.append(node('span', 'pill muted', tr(items.length === 1 ? 'history.records' : 'history.recordsPlural', { count: items.length })));
    box.append(head);

    const list = node('ol');
    if (!items.length) {
      list.append(node('li', 'empty-row', query ? tr('history.emptyFilter') : tr('history.empty')));
    }
    const currentVersion = latestData?.drivers?.[vendor]?.version;
    items.forEach((item, index) => {
      const row = node('li');
      const button = node('button', 'history-row');
      button.type = 'button';
      button.setAttribute('aria-label', `${LABELS[vendor]} ${item.version}`);
      const main = node('div', 'history-row-main');
      const titleRow = node('div', 'history-row-title');
      titleRow.append(node('strong', '', item.version));
      if (item.verification?.score !== undefined && item.verification?.score !== null) {
        titleRow.append(node('span', 'pill teal', `${item.verification.score}%`));
      }
      main.append(titleRow);

      const nextItem = items[index + 1];
      const delta = nextItem ? daysBetween(item.date, nextItem.date) : null;
      const dateParts = [formatDate(item.date)];
      if (delta !== null) dateParts.push(`+${delta}d`);
      if (item.channel) dateParts.push(localizeChannel(item.channel));
      if (item.os_build) dateParts.push(`Build ${item.os_build}`);
      main.append(node('small', '', dateParts.join(' · ')));

      const localSummary = localizeSummary(item.release_summary, lang);
      const headline = localSummary?.headline;
      if (headline) main.append(node('div', 'history-snippet', headline));

      const metaCol = node('div', 'history-row-meta');
      const isCurrent = item.version === currentVersion;
      metaCol.append(node('span', `tag-action ${isCurrent ? 'current' : ''}`, isCurrent ? tr('history.current') : tr('history.detailsLink')));
      if (localSummary?.recommendation_action || localSummary?.risk_level) {
        const riskInfo = resolveRisk(localSummary);
        const act = riskInfo.level === 'critical' ? 'do_not_install' : (localSummary.recommendation_action || 'wait');
        metaCol.append(node('span', `pill ${actionTone[act] || 'muted'}`, actionLabels[act] || act));
      }
      button.append(main, metaCol);
      button.addEventListener('click', () => openHistoryDetails(vendor, item, index));
      row.append(button);
      list.append(row);
    });
    box.append(list);
    grid.append(box);
  });
}

function alertFingerprint(alert) {
  return [alert.title || '', alert.link || '', alert.published_at || ''].join('|');
}

function defaultAlertPreferences() {
  return { enabled: false, categories: Object.fromEntries(ALERT_CATEGORIES.map((category) => [category, true])) };
}

function getAlertPreferences() {
  try {
    const stored = JSON.parse(localStorage.getItem(ALERT_PREFS_KEY));
    const defaults = defaultAlertPreferences();
    return {
      enabled: stored?.enabled === true,
      categories: Object.fromEntries(ALERT_CATEGORIES.map((category) => [category, stored?.categories?.[category] ?? defaults.categories[category]]))
    };
  } catch (_) {
    return defaultAlertPreferences();
  }
}

function setNotificationState() {
  const preferences = getAlertPreferences();
  const selected = ALERT_CATEGORIES.filter((category) => preferences.categories[category]).length;
  const supported = window.isSecureContext && 'Notification' in window && 'serviceWorker' in navigator;
  const active = supported && preferences.enabled && Notification.permission === 'granted';
  let status = active
    ? tr(selected === 1 ? 'status.notifActive' : 'status.notifActivePlural', { count: selected })
    : tr('status.notifOff');
  if (!supported) status = tr('status.notifUnsupported');
  if (supported && Notification.permission === 'denied') status = tr('status.notifBlocked');
  $('#notification-status').textContent = status;
  $('#notification-label').textContent = active
    ? tr('header.alertsCount', { count: selected })
    : tr('header.alertsConfig');
  $('#notification-button').classList.toggle('active', active);
}

async function showBrowserNotification(title, options) {
  if (notificationRegistration) {
    await notificationRegistration.showNotification(title, options);
    return;
  }
  new Notification(title, options);
}

function extractVerdictSnapshot(data) {
  const out = {};
  Object.entries(data?.drivers || {}).forEach(([vendor, drv]) => {
    const ver = drv?.version;
    const assessment = data?.advisor?.assessments?.[vendor];
    if (!ver || assessment?.status !== 'ready') return;
    const risk = resolveRisk(assessment);
    out[vendor] = { version: ver, action: risk.action, level: risk.level };
  });
  return out;
}

function rememberCurrentNotifications(data) {
  if (!data) return;
  const alerts = data?.security_alerts || [];
  const versions = Object.fromEntries(Object.entries(data?.drivers || {}).map(([vendor, item]) => [vendor, item?.version || null]));
  localStorage.setItem(SEEN_ALERTS_KEY, JSON.stringify(alerts.map(alertFingerprint).slice(0, 100)));
  localStorage.setItem(SEEN_VERSIONS_KEY, JSON.stringify(versions));
  localStorage.setItem(SEEN_VERDICTS_KEY, JSON.stringify(extractVerdictSnapshot(data)));
}

async function notifyChanges(data) {
  const preferences = getAlertPreferences();
  if (!preferences.enabled || !('Notification' in window) || Notification.permission !== 'granted') return;
  const alerts = data?.security_alerts || [];
  const fingerprints = alerts.map(alertFingerprint);
  const saved = localStorage.getItem(SEEN_ALERTS_KEY);
  if (!saved) {
    rememberCurrentNotifications(data);
    return;
  }

  let seen = [];
  try { seen = JSON.parse(saved); } catch (_) { seen = []; }
  const fresh = preferences.categories.vulnerabilities
    ? alerts.filter((alert) => !seen.includes(alertFingerprint(alert)))
    : [];
  localStorage.setItem(SEEN_ALERTS_KEY, JSON.stringify(fingerprints.slice(0, 100)));
  for (const alert of fresh.slice(0, 3)) {
    await showBrowserNotification(tr('notif.alertTitle', null, 'DriveRadar Alert'), {
      body: alert.title || '',
      icon: '/driveradar/static/logo.png',
      badge: '/driveradar/static/favicon-16.png',
      tag: `driveradar-${alertFingerprint(alert)}`,
      data: { url: safeUrl(alert.link || '/driveradar/') }
    });
  }

  let previousVersions = {};
  try { previousVersions = JSON.parse(localStorage.getItem(SEEN_VERSIONS_KEY)) || {}; } catch (_) { previousVersions = {}; }
  let previousVerdicts = {};
  try { previousVerdicts = JSON.parse(localStorage.getItem(SEEN_VERDICTS_KEY)) || {}; } catch (_) { previousVerdicts = {}; }

  const currentVersions = Object.fromEntries(Object.entries(data?.drivers || {}).map(([vendor, item]) => [vendor, item?.version || null]));
  const currentVerdicts = extractVerdictSnapshot(data);
  localStorage.setItem(SEEN_VERSIONS_KEY, JSON.stringify(currentVersions));
  localStorage.setItem(SEEN_VERDICTS_KEY, JSON.stringify({ ...previousVerdicts, ...currentVerdicts }));

  const riskRank = { low: 0, moderate: 1, high: 2, critical: 3 };
  for (const vendor of ALERT_CATEGORIES.filter((category) => category !== 'vulnerabilities')) {
    if (!preferences.categories[vendor]) continue;
    const version = currentVersions[vendor];
    const curVerdict = currentVerdicts[vendor];
    const prevVerdict = previousVerdicts[vendor];
    if (version && previousVersions[vendor] && previousVersions[vendor] !== version) {
      const actLabel = localizeActionLabel(curVerdict?.action || 'observe');
      await showBrowserNotification(tr('notif.newReleaseTitle', { vendor: LABELS[vendor], version }), {
        body: tr('notif.newReleaseBody', { action: actLabel }),
        icon: '/driveradar/static/logo.png',
        badge: '/driveradar/static/favicon-16.png',
        tag: `driveradar-version-${vendor}-${version}`,
        data: { url: '/driveradar/' }
      });
    } else if (
      version &&
      curVerdict &&
      prevVerdict &&
      prevVerdict.version === version &&
      (curVerdict.level === 'critical' || curVerdict.level === 'high') &&
      (riskRank[curVerdict.level] || 0) > (riskRank[prevVerdict.level] || 0)
    ) {
      await showBrowserNotification(tr('notif.escalationTitle', { vendor: LABELS[vendor], version }), {
        body: tr('notif.escalationBody', { action: localizeActionLabel(curVerdict.action) }),
        icon: '/driveradar/static/logo.png',
        badge: '/driveradar/static/favicon-16.png',
        tag: `driveradar-escalation-${vendor}-${version}-${curVerdict.level}`,
        data: { url: '/driveradar/' }
      });
    }
  }
}

function syncAlertForm() {
  const preferences = getAlertPreferences();
  $('#alerts-enabled').checked = preferences.enabled;
  document.querySelectorAll('[name="alert-category"]').forEach((input) => { input.checked = preferences.categories[input.value]; });
  syncSelectAll();
  $('#alerts-form-error').hidden = true;
}

function syncSelectAll() {
  const inputs = [...document.querySelectorAll('[name="alert-category"]')];
  const selected = inputs.filter((input) => input.checked).length;
  $('#alert-category-all').checked = selected === inputs.length;
  $('#alert-category-all').indeterminate = selected > 0 && selected < inputs.length;
}

async function saveAlertPreferences(event) {
  event.preventDefault();
  const enabled = $('#alerts-enabled').checked;
  const categories = Object.fromEntries([...document.querySelectorAll('[name="alert-category"]')].map((input) => [input.value, input.checked]));
  const error = $('#alerts-form-error');
  if (enabled && !Object.values(categories).some(Boolean)) {
    error.textContent = tr('alertsDialog.categories');
    error.hidden = false;
    return;
  }
  if (enabled && Notification.permission !== 'granted') {
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') {
      error.textContent = tr('status.notifBlocked');
      error.hidden = false;
      return;
    }
  }
  localStorage.setItem(ALERT_PREFS_KEY, JSON.stringify({ enabled, categories }));
  rememberCurrentNotifications(latestData);
  setNotificationState();
  $('#alerts-dialog').close();
  if (enabled) {
    await showBrowserNotification('DriveRadar', {
      body: tr('alertsDialog.save'),
      icon: '/driveradar/static/logo.png', badge: '/driveradar/static/favicon-16.png',
      tag: 'driveradar-preferences', data: { url: '/driveradar/' }
    });
  }
}

async function initNotifications() {
  const button = $('#notification-button');
  const supported = window.isSecureContext && 'Notification' in window && 'serviceWorker' in navigator;
  if (!supported) button.disabled = true;
  if (supported) {
    try {
      notificationRegistration = await navigator.serviceWorker.register('/driveradar/service-worker.js', { scope: '/driveradar/' });
    } catch (_) {
      button.disabled = true;
    }
  }
  setNotificationState();
  button.addEventListener('click', () => { syncAlertForm(); $('#alerts-dialog').showModal(); });
  $('#alerts-dialog-close').addEventListener('click', () => $('#alerts-dialog').close());
  $('#alerts-dialog').addEventListener('click', (event) => { if (event.target === $('#alerts-dialog')) $('#alerts-dialog').close(); });
  $('#alerts-form').addEventListener('submit', saveAlertPreferences);
  $('#alert-category-all').addEventListener('change', (event) => {
    document.querySelectorAll('[name="alert-category"]').forEach((input) => { input.checked = event.target.checked; });
    syncSelectAll();
  });
  document.querySelectorAll('[name="alert-category"]').forEach((input) => input.addEventListener('change', syncSelectAll));
}

function renderSourceFilters(sources) {
  const container = $('#source-filters');
  container.replaceChildren();
  const counts = {
    all: sources.length,
    reachable: sources.filter((s) => s.status === 'reachable').length,
    matched: sources.filter((s) => (s.matched_versions || []).length > 0).length,
    unavailable: sources.filter((s) => s.status !== 'reachable').length
  };
  [
    ['all', tr('sources.all', { count: counts.all })],
    ['reachable', tr('sources.reachable', { count: counts.reachable })],
    ['matched', tr('sources.matched', { count: counts.matched })],
    ['unavailable', tr('sources.unavailable', { count: counts.unavailable })]
  ].forEach(([key, label]) => {
    const btn = node('button', `filter-pill ${activeSourceFilter === key ? 'active' : ''}`, label);
    btn.type = 'button';
    btn.addEventListener('click', () => {
      activeSourceFilter = key;
      renderSources(latestData?.source_audit || {});
    });
    container.append(btn);
  });
}

function renderSources(audit) {
  const sources = audit.sources || [];
  renderSourceFilters(sources);
  const list = $('#source-list');
  list.replaceChildren();
  $('#source-summary').textContent = tr('sources.summary', {
    reachable: audit.reachable_sources || 0,
    configured: audit.configured_sources || 0,
    publishers: audit.independent_publishers || 0
  });

  const query = sourceSearchQuery.trim().toLowerCase();
  const filtered = sources.filter((s) => {
    if (activeSourceFilter === 'reachable' && s.status !== 'reachable') return false;
    if (activeSourceFilter === 'matched' && !(s.matched_versions || []).length) return false;
    if (activeSourceFilter === 'unavailable' && s.status === 'reachable') return false;
    if (query) {
      const text = `${s.name} ${s.publisher} ${s.tier}`.toLowerCase();
      if (!text.includes(query)) return false;
    }
    return true;
  });

  if (!filtered.length) {
    const empty = node('div', 'source-row');
    empty.append(node('small', '', tr('sources.empty')));
    list.append(empty);
    return;
  }

  filtered.forEach((source) => {
    const row = node('div', 'source-row');
    const info = node('div');
    info.append(externalLink(source.name, source.url));
    const matches = (source.matched_versions || []).length ? ` · Match: ${source.matched_versions.join(', ')}` : '';
    info.append(node('small', '', `${source.publisher} · ${source.tier}${matches}`));
    row.append(info);
    const statusText = source.status === 'reachable'
      ? `${source.latency_ms} ms`
      : `${tr('sources.down')}${source.http_status ? ` (${source.http_status})` : ''}`;
    row.append(node('span', `source-status ${source.status}`, statusText));
    list.append(row);
  });
}

function renderMetrics(data) {
  const collection = data.collection || {};
  const drivers = Object.values(data.drivers || {});
  const verifiedCount = drivers.filter((item) => item?.verification?.primary_confirmed).length;
  const avgScore = drivers.length
    ? Math.round(drivers.reduce((sum, item) => sum + Number(item?.verification?.score || 0), 0) / drivers.length)
    : 0;
  const conflicts = drivers.reduce((sum, item) => sum + (item?.verification?.conflicts?.length || 0), 0);
  const alertsCount = (data.security_alerts || []).length;

  $('#metric-reachable').textContent = `${collection.reachable_sources || 0}/${collection.configured_sources || 0}`;
  $('#metric-reachable-sub').textContent = `${collection.independent_publishers || 0} ${tr('metrics.publishers')}`;
  $('#metric-drivers').textContent = `${verifiedCount}/${drivers.length || 4}`;
  $('#metric-drivers-sub').textContent = verifiedCount === (drivers.length || 4) ? tr('metrics.allVerified') : tr('metrics.partialVerified');
  $('#metric-confidence').textContent = `${avgScore}%`;
  $('#metric-confidence-sub').textContent = tr('metrics.confidenceSub');
  $('#metric-conflicts').textContent = `${conflicts}`;
  $('#metric-conflicts-sub').textContent = tr(alertsCount === 1 ? 'metrics.conflictsSub' : 'metrics.conflictsSubPlural', { count: alertsCount });
}

function renderAll(data) {
  if (!data) return;
  renderMetrics(data);
  renderDrivers(data.drivers || {}, data.advisor || {});
  renderAlerts(data.security_alerts || []);
  renderHistory(data.history || {});
  renderSources(data.source_audit || {});
  const pulse = document.querySelector('.pulse');
  if (pulse) {
    pulse.classList.toggle('partial', data.status === 'partial');
    pulse.classList.remove('error');
  }
  $('#system-label').textContent = data.status === 'partial'
    ? tr('status.partial')
    : data.status === 'warming'
      ? tr('status.warming')
      : tr('status.done');
  $('#updated-at').textContent = tr('status.lastSync', { date: formatDate(data.last_updated, true) });
  $('#analysis-at').textContent = data.advisor?.status === 'ready' && data.advisor?.last_analysis_at
    ? tr('status.analysisAt', { date: formatDate(data.advisor.last_analysis_at, true) })
    : data.advisor?.status === 'pending'
      ? tr('status.analysisPending')
      : tr('status.analysisUnavailable');
}

async function loadData(isManual = false) {
  const refreshBtn = $('#refresh-button');
  if (isManual && refreshBtn) {
    refreshBtn.disabled = true;
    refreshBtn.classList.add('spinning');
  }
  $('#error-box').hidden = true;
  try {
    const response = await fetch(`/driveradar/api/data?t=${Date.now()}`, { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    latestData = data;
    renderAll(data);
    if (window.DriveRadarVotes) {
      window.DriveRadarVotes.refreshSession();
    }
    await notifyChanges(data);
    ['drivers-section', 'alerts-section', 'history-section', 'sources-section'].forEach((id) => { document.getElementById(id).hidden = false; });
    $('#loading').hidden = true;
  } catch (error) {
    $('#loading').hidden = true;
    const pulse = document.querySelector('.pulse');
    if (pulse) pulse.classList.add('error');
    $('#system-label').textContent = tr('status.connFail');
    const box = $('#error-box');
    box.textContent = `${tr('status.connFail')}: ${error.message}`;
    box.hidden = false;
  } finally {
    if (refreshBtn) {
      refreshBtn.disabled = false;
      refreshBtn.classList.remove('spinning');
    }
  }
}

function applyTheme(pref) {
  const effective = pref === 'system'
    ? (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')
    : pref;
  document.documentElement.dataset.theme = VALID_THEMES.includes(effective) ? effective : 'dark';
}

function initTheme() {
  const saved = localStorage.getItem('driveradar-theme');
  const pref = VALID_THEMES.includes(saved) ? saved : 'system';
  applyTheme(pref);
  const select = $('#theme-select');
  if (select) {
    select.value = pref;
    select.addEventListener('change', (event) => {
      const next = VALID_THEMES.includes(event.target.value) ? event.target.value : 'system';
      localStorage.setItem('driveradar-theme', next);
      applyTheme(next);
    });
  }
  const mq = matchMedia('(prefers-color-scheme: light)');
  mq.addEventListener('change', () => {
    const currentPref = localStorage.getItem('driveradar-theme') || 'system';
    if (currentPref === 'system') applyTheme('system');
  });
}

function initLanguage() {
  I18N.applyStatic();
  const select = $('#lang-select');
  if (!select) return;
  select.value = I18N.getLang();
  select.addEventListener('change', (event) => {
    I18N.setLang(event.target.value);
    I18N.applyStatic();
    setNotificationState();
    if (latestData) renderAll(latestData);
    if (openDialogContext && $('#history-dialog')?.open) {
      const freshItem = findHistoryItem(openDialogContext.vendor, openDialogContext.item?.version) || openDialogContext.item;
      openHistoryDetails(openDialogContext.vendor, freshItem, openDialogContext.index);
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initLanguage();
  initTheme();
  initNotifications();
  $('#refresh-button').addEventListener('click', () => loadData(true));
  $('#history-search').addEventListener('input', (event) => {
    historySearchQuery = event.target.value || '';
    if (latestData) renderHistory(latestData.history || {});
  });
  $('#source-search').addEventListener('input', (event) => {
    sourceSearchQuery = event.target.value || '';
    if (latestData) renderSources(latestData.source_audit || {});
  });
  $('#history-dialog-close').addEventListener('click', () => $('#history-dialog').close());
  $('#history-dialog').addEventListener('click', (event) => {
    if (event.target === $('#history-dialog')) $('#history-dialog').close();
  });
  $('#history-dialog').addEventListener('close', () => {
    openDialogContext = null;
  });
  loadData();
  window.setInterval(() => loadData(false), 60_000);
});
