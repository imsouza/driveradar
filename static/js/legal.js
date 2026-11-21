(function () {
  'use strict';

  const VALID_THEMES = ['system', 'dark', 'light', 'midnight', 'nord', 'forest', 'sand'];
  const I18N = window.DriveRadarI18n;
  const $ = (sel) => document.querySelector(sel);

  function applyTheme(pref) {
    const effective = pref === 'system'
      ? (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')
      : pref;
    document.documentElement.dataset.theme = VALID_THEMES.includes(effective) ? effective : 'dark';
  }

  function initTheme() {
    let saved = 'system';
    try {
      const candidate = localStorage.getItem('driveradar-theme');
      if (VALID_THEMES.includes(candidate)) saved = candidate;
    } catch (_) {}
    applyTheme(saved);
    const select = $('#theme-select');
    if (select) {
      select.value = saved;
      select.addEventListener('change', (event) => {
        const next = VALID_THEMES.includes(event.target.value) ? event.target.value : 'system';
        try { localStorage.setItem('driveradar-theme', next); } catch (_) {}
        applyTheme(next);
      });
    }
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    mq.addEventListener('change', () => {
      let current = 'system';
      try { current = localStorage.getItem('driveradar-theme') || 'system'; } catch (_) {}
      if (current === 'system') applyTheme('system');
    });
  }

  function initLanguage() {
    if (!I18N) return;
    I18N.applyStatic();
    const select = $('#lang-select');
    if (!select) return;
    select.value = I18N.getLang();
    select.addEventListener('change', (event) => {
      I18N.setLang(event.target.value);
      I18N.applyStatic();
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    initLanguage();
    initTheme();
  });
})();
