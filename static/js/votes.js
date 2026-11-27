(function () {
  'use strict';

  const DRIVER_DOWN_TAGS = [
    ['black_screen', 'vote.tag.black_screen'],
    ['crash_bsod', 'vote.tag.crash_bsod'],
    ['fps_drop', 'vote.tag.fps_drop'],
    ['install_fail', 'vote.tag.install_fail'],
    ['audio_display', 'vote.tag.audio_display']
  ];

  const state = {
    voteToken: '',
    issuedAtMs: 0,
    tallies: {},
    myVotes: {},
    pendingKeys: new Set()
  };

  function i18n() {
    return window.DriveRadarI18n || { t: (k, _v, f) => f || k };
  }

  function tr(key, vars = null, fallback = '') {
    return i18n().t(key, vars, fallback);
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  async function refreshSession() {
    try {
      const resp = await fetch('/driveradar/api/votes', {
        method: 'GET',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' }
      });
      if (!resp.ok) return null;
      const data = await resp.json();
      state.voteToken = data.vote_token || '';
      state.issuedAtMs = Date.now();
      state.tallies = { ...state.tallies, ...(data.tallies || {}) };
      state.myVotes = { ...state.myVotes, ...(data.my_votes || {}) };
      syncRenderedWidgets();
      return data;
    } catch (_) {
      return null;
    }
  }

  async function ensureMinTokenAge() {
    if (!state.voteToken) {
      await refreshSession();
    }
    const elapsed = Date.now() - state.issuedAtMs;
    if (elapsed < 1150) {
      await new Promise((resolve) => setTimeout(resolve, 1150 - elapsed));
    }
  }

  async function castVote(targetType, targetId, vote, reasonTag) {
    const targetKey = `${targetType}:${targetId}`;
    if (state.pendingKeys.has(targetKey)) return null;
    state.pendingKeys.add(targetKey);
    try {
      await ensureMinTokenAge();
      let resp = await fetch('/driveradar/api/vote', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'X-Requested-With': 'DriveRadar'
        },
        body: JSON.stringify({
          vote_token: state.voteToken,
          target_type: targetType,
          target_id: targetId,
          vote,
          reason_tag: reasonTag || null
        })
      });
      if (resp.status === 403) {
        await refreshSession();
        await ensureMinTokenAge();
        resp = await fetch('/driveradar/api/vote', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
            'X-Requested-With': 'DriveRadar'
          },
          body: JSON.stringify({
            vote_token: state.voteToken,
            target_type: targetType,
            target_id: targetId,
            vote,
            reason_tag: reasonTag || null
          })
        });
      }
      if (!resp.ok) return { error: resp.status };
      const out = await resp.json();
      if (out.tally) state.tallies[targetKey] = out.tally;
      if (out.my_vote) state.myVotes[targetKey] = out.my_vote;
      syncRenderedWidgets(targetKey);
      return out;
    } catch (_) {
      return { error: 'network' };
    } finally {
      state.pendingKeys.delete(targetKey);
    }
  }

  function formatDriverSummary(tally) {
    const total = Number(tally?.total || 0);
    if (total === 0) return tr('vote.noVotesYet', null, 'Sem relatos ainda — valide abaixo');
    if (!tally.quorum_met) {
      return tr('vote.formingSample', { count: total }, `Amostra inicial (${total})`);
    }
    return tr('vote.driverStats', { pct: tally.approval_pct ?? 0, count: total }, `${tally.approval_pct}% (${total})`);
  }

  function populateDriverWidget(container, targetId) {
    const targetKey = `driver:${targetId}`;
    const tally = state.tallies[targetKey] || container._initialTally || { up: 0, down: 0, total: 0, quorum_met: false, signal: 'insufficient' };
    const myVote = state.myVotes[targetKey] || null;
    container.replaceChildren();

    const row = el('div', 'community-row');
    const info = el('div', 'community-info');
    info.append(
      el('small', 'community-eyebrow', tr('vote.driverTitle', null, 'VALIDAÇÃO DA COMUNIDADE')),
      el('span', 'community-summary', formatDriverSummary(tally))
    );
    if (tally.signal === 'warning') {
      const issueLabel = tally.top_issue ? tr(`vote.tag.${tally.top_issue}`, null, tally.top_issue) : '';
      info.append(el('span', 'community-warn-pill', tr('vote.communityWarning', { issue: issueLabel })));
    }
    row.append(info);

    const actions = el('div', 'vote-actions');
    const upBtn = el('button', `vote-btn up${myVote?.vote === 'up' ? ' active' : ''}`, `👍 ${tr('vote.stableBtn', null, 'Estável')} (${tally.up || 0})`);
    upBtn.type = 'button';
    const downBtn = el('button', `vote-btn down${myVote?.vote === 'down' ? ' active' : ''}`, `👎 ${tr('vote.issueBtn', null, 'Problema')} (${tally.down || 0})`);
    downBtn.type = 'button';
    actions.append(upBtn, downBtn);
    row.append(actions);
    container.append(row);

    const tagPicker = el('div', 'vote-tags-picker');
    tagPicker.hidden = !container._pickingDown;
    tagPicker.append(el('small', '', tr('vote.pickSymptom', null, 'Qual sintoma ocorreu?')));
    const tagList = el('div', 'vote-tag-pills');
    DRIVER_DOWN_TAGS.forEach(([tagCode, labelKey]) => {
      const tBtn = el('button', `vote-tag-btn${myVote?.tag === tagCode ? ' active' : ''}`, tr(labelKey, null, tagCode));
      tBtn.type = 'button';
      tBtn.addEventListener('click', async () => {
        container._pickingDown = false;
        await castVote('driver', targetId, 'down', tagCode);
      });
      tagList.append(tBtn);
    });
    tagPicker.append(tagList);
    container.append(tagPicker);

    upBtn.addEventListener('click', async () => {
      container._pickingDown = false;
      await castVote('driver', targetId, 'up', 'stable');
    });
    downBtn.addEventListener('click', () => {
      container._pickingDown = !container._pickingDown;
      tagPicker.hidden = !container._pickingDown;
    });
  }

  function populateAlertWidget(container, alertId) {
    const targetKey = `alert:${alertId}`;
    const tally = state.tallies[targetKey] || container._initialTally || { up: 0, down: 0, total: 0, signal: 'insufficient' };
    const myVote = state.myVotes[targetKey] || null;
    container.replaceChildren();

    const parentArticle = container.closest('.alert-item');
    if (parentArticle) {
      parentArticle.classList.toggle('likely-fp', tally.signal === 'likely_false_positive');
    }

    if (tally.signal === 'likely_false_positive') {
      container.append(el('span', 'pill amber', tr('vote.flaggedFalsePos', null, 'Sinalizado como provável falso positivo')));
    }

    const upBtn = el('button', `vote-btn compact up${myVote?.vote === 'up' ? ' active' : ''}`, `✓ ${tr('vote.alertUseful', null, 'Útil')} (${tally.up || 0})`);
    upBtn.type = 'button';
    const downBtn = el('button', `vote-btn compact down${myVote?.vote === 'down' ? ' active' : ''}`, `✕ ${tr('vote.alertFalsePos', null, 'Falso positivo')} (${tally.down || 0})`);
    downBtn.type = 'button';

    upBtn.addEventListener('click', () => castVote('alert', alertId, 'up', 'useful_alert'));
    downBtn.addEventListener('click', () => castVote('alert', alertId, 'down', 'false_positive'));
    container.append(upBtn, downBtn);
  }

  function renderDriverVoteBar(vendor, version, initialCommunity) {
    if (!vendor || !version) return null;
    const targetId = `${vendor}:${version}`;
    const targetKey = `driver:${targetId}`;
    if (initialCommunity && !state.tallies[targetKey]) {
      state.tallies[targetKey] = initialCommunity;
    }
    const container = el('div', 'community-bar');
    container.dataset.voteWidget = 'driver';
    container.dataset.targetId = targetId;
    container._initialTally = initialCommunity || null;
    container._pickingDown = false;
    populateDriverWidget(container, targetId);
    return container;
  }

  function renderAlertVoteBar(alertItem) {
    const alertId = alertItem?.id;
    if (!alertId) return null;
    const targetKey = `alert:${alertId}`;
    if (alertItem.community && !state.tallies[targetKey]) {
      state.tallies[targetKey] = alertItem.community;
    }
    const container = el('div', 'alert-vote-bar');
    container.dataset.voteWidget = 'alert';
    container.dataset.targetId = alertId;
    container._initialTally = alertItem.community || null;
    populateAlertWidget(container, alertId);
    return container;
  }

  function syncRenderedWidgets(onlyKey = null) {
    document.querySelectorAll('[data-vote-widget="driver"]').forEach((nodeEl) => {
      const tid = nodeEl.dataset.targetId;
      if (!onlyKey || onlyKey === `driver:${tid}`) populateDriverWidget(nodeEl, tid);
    });
    document.querySelectorAll('[data-vote-widget="alert"]').forEach((nodeEl) => {
      const tid = nodeEl.dataset.targetId;
      if (!onlyKey || onlyKey === `alert:${tid}`) populateAlertWidget(nodeEl, tid);
    });
  }

  window.DriveRadarVotes = {
    refreshSession,
    renderDriverVoteBar,
    renderAlertVoteBar,
    syncRenderedWidgets
  };
})();
