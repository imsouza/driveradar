const path = require('path');
const fs = require('fs');
const {
  app,
  BrowserWindow,
  Menu,
  Notification,
  Tray,
  ipcMain,
  nativeImage,
  nativeTheme,
  net,
  safeStorage,
  session,
  shell
} = require('electron');
const { autoUpdater } = require('electron-updater');
const { SUPPORTED: SUPPORTED_LANGS, resolveLang, t } = require('./i18n');
const {
  DEFAULT_API_BASE,
  IMMUTABLE_UPDATER_URL,
  classifyDownloadUrl,
  loadOrCreateVoterProof,
  validateExternalBrowserUrl,
  validateRemoteApiUrl
} = require('./security');

const APP_ID = 'br.com.optlabs.driveradar';
const IS_PORTABLE = Boolean(process.env.PORTABLE_EXECUTABLE_FILE);
const VENDORS = ['nvidia', 'amd', 'intel', 'windows'];
const VENDOR_LABELS = {
  nvidia: 'NVIDIA GeForce',
  amd: 'AMD Radeon',
  intel: 'Intel Arc',
  windows: 'Windows 11'
};

const DEFAULT_SETTINGS = {
  apiBaseUrl: DEFAULT_API_BASE,
  vendors: { nvidia: true, amd: true, intel: true, windows: true },
  pollIntervalMinutes: 60,
  ignoreBetaPreview: false,
  notifyConflicts: true,
  notifyEscalation: true,
  notificationsEnabled: true,
  notificationSound: true,
  securitySeverity: 'high',
  quietHoursEnabled: false,
  quietHoursStart: '22:00',
  quietHoursEnd: '08:00',
  launchAtStartup: false,
  startMinimized: true,
  closeToTray: true,
  minimizeToTray: false,
  language: 'system',
  theme: 'system',
  autoCheckUpdates: true,
  autoDownloadUpdates: true
};

let mainWindow = null;
let tray = null;
let isQuitting = false;
let hasUnreadAlert = false;
let shownTrayHint = false;
let pollTimer = null;
let updateTimer = null;

let settings = { ...DEFAULT_SETTINGS, vendors: { ...DEFAULT_SETTINGS.vendors } };
let seenState = { seeded: false, versions: {}, verdicts: {}, conflicts: {}, alerts: [] };
let cachedData = null;
let voterProof = '';
let updaterStatus = { state: 'idle', version: app.getVersion(), message: '' };
let activeDownloadItem = null;
let lastDownloadedFilePath = '';

function curLang() {
  return resolveLang(settings.language, app.getLocale());
}

function msg(key, vars = null) {
  return t(curLang(), key, vars);
}

function userFile(name) {
  return path.join(app.getPath('userData'), name);
}

function readJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return fallback;
  }
}

function writeJsonAtomic(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

function sanitizeTime(value, fallback) {
  return /^\d{2}:\d{2}$/.test(String(value || '')) ? String(value) : fallback;
}

function sanitizeApiBase(value) {
  const checked = validateRemoteApiUrl(value, { allowInsecureDev: !app.isPackaged });
  return checked.ok ? checked.url : DEFAULT_API_BASE;
}

function mergeSettings(raw) {
  const input = raw && typeof raw === 'object' ? raw : {};
  const vendors = {};
  for (const v of VENDORS) {
    vendors[v] = input.vendors && typeof input.vendors[v] === 'boolean'
      ? input.vendors[v]
      : settings.vendors[v];
  }
  const poll = Number(input.pollIntervalMinutes);
  return {
    apiBaseUrl: sanitizeApiBase(input.apiBaseUrl ?? settings.apiBaseUrl),
    vendors,
    pollIntervalMinutes: Number.isFinite(poll) ? Math.min(1440, Math.max(5, Math.round(poll))) : settings.pollIntervalMinutes,
    ignoreBetaPreview: typeof input.ignoreBetaPreview === 'boolean' ? input.ignoreBetaPreview : settings.ignoreBetaPreview,
    notifyConflicts: typeof input.notifyConflicts === 'boolean' ? input.notifyConflicts : settings.notifyConflicts,
    notifyEscalation: typeof input.notifyEscalation === 'boolean' ? input.notifyEscalation : settings.notifyEscalation,
    notificationsEnabled: typeof input.notificationsEnabled === 'boolean' ? input.notificationsEnabled : settings.notificationsEnabled,
    notificationSound: typeof input.notificationSound === 'boolean' ? input.notificationSound : settings.notificationSound,
    securitySeverity: ['off', 'critical', 'high', 'all'].includes(input.securitySeverity) ? input.securitySeverity : settings.securitySeverity,
    quietHoursEnabled: typeof input.quietHoursEnabled === 'boolean' ? input.quietHoursEnabled : settings.quietHoursEnabled,
    quietHoursStart: sanitizeTime(input.quietHoursStart, settings.quietHoursStart),
    quietHoursEnd: sanitizeTime(input.quietHoursEnd, settings.quietHoursEnd),
    launchAtStartup: typeof input.launchAtStartup === 'boolean' ? input.launchAtStartup : settings.launchAtStartup,
    startMinimized: typeof input.startMinimized === 'boolean' ? input.startMinimized : settings.startMinimized,
    closeToTray: typeof input.closeToTray === 'boolean' ? input.closeToTray : settings.closeToTray,
    minimizeToTray: typeof input.minimizeToTray === 'boolean' ? input.minimizeToTray : settings.minimizeToTray,
    language: ['system', ...SUPPORTED_LANGS].includes(input.language) ? input.language : settings.language,
    theme: ['system', 'dark', 'light', 'midnight', 'nord', 'forest', 'sand'].includes(input.theme) ? input.theme : settings.theme,
    autoCheckUpdates: typeof input.autoCheckUpdates === 'boolean' ? input.autoCheckUpdates : settings.autoCheckUpdates,
    autoDownloadUpdates: typeof input.autoDownloadUpdates === 'boolean' ? input.autoDownloadUpdates : settings.autoDownloadUpdates
  };
}

function applyStartupSetting() {
  if (process.platform !== 'win32' && process.platform !== 'darwin') return;
  try {
    app.setLoginItemSettings({
      openAtLogin: settings.launchAtStartup,
      args: settings.startMinimized ? ['--hidden'] : []
    });
  } catch (_) {}
}

function applyThemeSetting() {
  if (settings.theme === 'light' || settings.theme === 'sand') {
    nativeTheme.themeSource = 'light';
  } else if (settings.theme === 'system') {
    nativeTheme.themeSource = 'system';
  } else {
    nativeTheme.themeSource = 'dark';
  }
}

function isQuietHoursNow() {
  if (!settings.quietHoursEnabled) return false;
  const [sh, sm] = settings.quietHoursStart.split(':').map(Number);
  const [eh, em] = settings.quietHoursEnd.split(':').map(Number);
  const now = new Date();
  const cur = now.getHours() * 60 + now.getMinutes();
  const start = sh * 60 + sm;
  const end = eh * 60 + em;
  if (start === end) return false;
  return start < end ? cur >= start && cur < end : cur >= start || cur < end;
}

function isPreviewOrBeta(channel) {
  const txt = String(channel || '').toLowerCase();
  return txt.includes('beta') || txt.includes('preview') || txt.includes('optional') || txt.includes('opcional');
}

function severityAllowed(severity) {
  if (settings.securitySeverity === 'off') return false;
  if (settings.securitySeverity === 'all') return true;
  if (settings.securitySeverity === 'critical') return severity === 'critical';
  return severity === 'critical' || severity === 'high';
}

function sendToRenderer(channel, payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

function assetPath(name) {
  return path.join(__dirname, '..', 'assets', name);
}

function refreshTray() {
  if (!tray) return;
  const iconFile = hasUnreadAlert ? 'tray-alert.png' : 'tray.png';
  tray.setImage(nativeImage.createFromPath(assetPath(iconFile)));

  const drivers = cachedData?.drivers || {};
  const assessments = cachedData?.advisor?.assessments || {};
  let critCount = 0;
  const versionItems = VENDORS.filter((v) => settings.vendors[v]).map((v) => {
    const d = drivers[v];
    const assess = assessments[v];
    const act = assess?.recommendation?.action;
    const lvl = assess?.risk_assessment?.level;
    const isCrit = assess?.status === 'ready' && (lvl === 'critical' || act === 'do_not_install');
    if (isCrit) critCount += 1;
    const suffix = isCrit
      ? ` [${msg('action.criticalBadge')}]`
      : (assess?.status === 'ready' && act === 'observe')
        ? ` [${msg('tray.tagObserve')}]`
        : '';
    return {
      label: `${VENDOR_LABELS[v]}: ${d?.version || '—'}${suffix}`,
      click: () => showWindow('drivers')
    };
  });

  const tipParts = [`DriveRadar v${app.getVersion()}`];
  if (critCount > 0) tipParts.push(`${critCount} ${msg('action.criticalBadge')}`);
  tray.setToolTip(tipParts.join(' · '));

  const menu = Menu.buildFromTemplate([
    { label: `DriveRadar v${app.getVersion()}`, enabled: false },
    { type: 'separator' },
    ...versionItems,
    { type: 'separator' },
    { label: msg('tray.open'), click: () => showWindow() },
    { label: msg('tray.checkNow'), click: () => fetchLatestData(true) },
    {
      label: settings.notificationsEnabled ? msg('tray.pauseNotif') : msg('tray.resumeNotif'),
      click: () => {
        settings.notificationsEnabled = !settings.notificationsEnabled;
        writeJsonAtomic(userFile('settings.json'), settings);
        refreshTray();
      }
    },
    { label: msg('tray.settings'), click: () => showWindow('settings') },
    { label: msg('tray.checkUpdates'), click: () => checkForAppUpdates(true) },
    { type: 'separator' },
    {
      label: msg('tray.quit'),
      click: () => {
        isQuitting = true;
        app.quit();
      }
    }
  ]);
  tray.setContextMenu(menu);
}

function showWindow(tab = null) {
  hasUnreadAlert = false;
  refreshTray();
  if (!mainWindow || mainWindow.isDestroyed()) {
    createWindow(false);
  }
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
  if (tab) sendToRenderer('app:navigate', tab);
}

function fireNotification(title, body, onClick) {
  if (!Notification.isSupported()) return;
  const n = new Notification({
    title,
    body,
    icon: assetPath('icon.png'),
    silent: !settings.notificationSound
  });
  n.on('click', () => {
    if (onClick) onClick();
    else showWindow();
  });
  n.show();
  hasUnreadAlert = true;
  refreshTray();
}

function alertKey(alert) {
  return [alert.title || '', alert.link || '', alert.published_at || ''].join('|');
}

function extractVerdicts(data) {
  const out = {};
  const drivers = data?.drivers || {};
  const assessments = data?.advisor?.assessments || {};
  for (const v of VENDORS) {
    const ver = drivers[v]?.version;
    const assess = assessments[v];
    if (!ver || assess?.status !== 'ready') continue;
    const act = assess?.recommendation?.action || 'wait';
    const lvl = (act === 'do_not_install' || assess?.risk_assessment?.level === 'critical')
      ? 'critical'
      : (assess?.risk_assessment?.level || 'moderate');
    out[v] = { version: ver, action: act, level: lvl };
  }
  return out;
}

function processNotifications(data) {
  const drivers = data?.drivers || {};
  const alerts = data?.security_alerts || [];
  const liveVerdicts = extractVerdicts(data);

  if (!seenState.seeded) {
    seenState = {
      seeded: true,
      versions: Object.fromEntries(VENDORS.map((v) => [v, drivers[v]?.version || null])),
      verdicts: liveVerdicts,
      conflicts: Object.fromEntries(
        VENDORS.map((v) => [v, (drivers[v]?.verification?.conflicts || []).map((c) => `${c.publisher}:${c.version}`)])
      ),
      alerts: alerts.map(alertKey).slice(0, 100)
    };
    writeJsonAtomic(userFile('state.json'), seenState);
    return;
  }

  const canNotify = settings.notificationsEnabled && !isQuietHoursNow();
  const nextVersions = { ...seenState.versions };
  const nextVerdicts = { ...(seenState.verdicts || {}), ...liveVerdicts };
  const nextConflicts = { ...seenState.conflicts };
  const riskRank = { low: 0, moderate: 1, high: 2, critical: 3 };

  for (const v of VENDORS) {
    const item = drivers[v];
    const ver = item?.version || null;
    const prev = seenState.versions[v];
    const prevVerdict = (seenState.verdicts || {})[v];
    const curVerdict = liveVerdicts[v];
    const lang = curLang();
    const assess = data?.advisor?.assessments?.[v];
    const tblock = lang !== 'pt-BR' ? assess?.translations?.[lang] : null;
    const recReason = tblock?.reason || assess?.recommendation?.reason || '';

    if (ver && ver !== prev) {
      nextVersions[v] = ver;
      const skipPreview = settings.ignoreBetaPreview && isPreviewOrBeta(item.channel);
      if (canNotify && settings.vendors[v] && prev && !skipPreview) {
        const rec = assess?.recommendation?.action;
        const isCritical = rec === 'do_not_install' || assess?.risk_assessment?.level === 'critical';
        const recText = isCritical
          ? msg('notif.recCritical', { reason: recReason })
          : rec === 'install'
            ? msg('notif.recInstall')
            : rec === 'observe'
              ? msg('notif.recObserve')
              : msg('notif.recWait');
        const body = `${item.channel ? `${item.channel} · ` : ''}${recText}${isCritical ? '' : ` ${msg('notif.recFreshTip')}`}`;
        fireNotification(
          msg('notif.newVerTitle', { vendor: VENDOR_LABELS[v], version: ver }),
          body,
          () => showWindow('drivers')
        );
      }
    } else if (
      ver &&
      canNotify &&
      settings.notifyEscalation &&
      settings.vendors[v] &&
      curVerdict &&
      prevVerdict &&
      prevVerdict.version === ver &&
      (curVerdict.level === 'critical' || curVerdict.level === 'high') &&
      (riskRank[curVerdict.level] || 0) > (riskRank[prevVerdict.level] || 0)
    ) {
      const actLabel = msg(`action.${curVerdict.action}`);
      fireNotification(
        msg('notif.escalationTitle', { vendor: VENDOR_LABELS[v], version: ver }),
        msg('notif.escalationBody', { action: actLabel, reason: recReason }),
        () => showWindow('drivers')
      );
    }

    const currentConfs = (item?.verification?.conflicts || []).map((c) => `${c.publisher}:${c.version}`);
    const prevConfs = seenState.conflicts[v] || [];
    const newConfs = currentConfs.filter((k) => !prevConfs.includes(k));
    if (newConfs.length && canNotify && settings.notifyConflicts && settings.vendors[v]) {
      const first = item.verification.conflicts[0];
      fireNotification(
        msg('notif.conflictTitle', { vendor: VENDOR_LABELS[v] }),
        msg('notif.conflictBody', { pub: first.publisher, version: first.version, title: first.title || '' }),
        () => showWindow('drivers')
      );
    }
    nextConflicts[v] = currentConfs;
  }

  const nextAlerts = alerts.map(alertKey).slice(0, 100);
  const newAlerts = alerts.filter((a) => !seenState.alerts.includes(alertKey(a)));
  if (canNotify && newAlerts.length) {
    for (const a of newAlerts.filter((item) => severityAllowed(item.severity)).slice(0, 2)) {
      const relevantVendor = !(a.vendors || []).length || a.vendors.some((v) => settings.vendors[v]);
      if (!relevantVendor) continue;
      fireNotification(
        msg('notif.secTitle', { severity: msg(`sev.${a.severity || 'info'}`), source: a.source || 'DriveRadar' }),
        a.title || msg('notif.secFallback'),
        () => showWindow('alerts')
      );
    }
  }

  seenState = { seeded: true, versions: nextVersions, verdicts: nextVerdicts, conflicts: nextConflicts, alerts: nextAlerts };
  writeJsonAtomic(userFile('state.json'), seenState);
}

async function fetchJson(url) {
  const response = await net.fetch(url, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(15_000)
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function fetchLatestData(isManual = false) {
  try {
    const url = `${settings.apiBaseUrl}/api/data?t=${Date.now()}`;
    const data = await fetchJson(url);
    cachedData = { ...data, _offline: false, _fetchedAt: Date.now() };
    writeJsonAtomic(userFile('last_data.json'), cachedData);
    processNotifications(cachedData);
    refreshTray();
    sendToRenderer('data:updated', cachedData);
    return cachedData;
  } catch (err) {
    const fallback = cachedData || readJson(userFile('last_data.json'), null);
    if (fallback) {
      cachedData = { ...fallback, _offline: true, _error: err.message };
      sendToRenderer('data:updated', cachedData);
      if (isManual) return cachedData;
    }
    throw err;
  }
}

function scheduleUpdateChecks() {
  if (updateTimer) {
    clearInterval(updateTimer);
    updateTimer = null;
  }
  if (settings.autoCheckUpdates) {
    updateTimer = setInterval(() => checkForAppUpdates(false), 6 * 3_600_000);
  }
}

function schedulePoll() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => {
    fetchLatestData(false).catch(() => {});
  }, settings.pollIntervalMinutes * 60_000);
}

function setUpdaterState(next) {
  updaterStatus = { ...updaterStatus, ...next };
  sendToRenderer('updater:status', updaterStatus);
}

function setDownloadState(payload) {
  sendToRenderer('download:status', payload);
}

function setupDownloadManager() {
  session.defaultSession.on('will-download', (_event, item) => {
    activeDownloadItem = item;
    const filename = item.getFilename() || 'driver-package.exe';
    try {
      item.setSaveDialogOptions({
        defaultPath: path.join(app.getPath('downloads'), filename)
      });
    } catch (_) {}

    setDownloadState({
      state: 'progress',
      filename,
      receivedBytes: 0,
      totalBytes: item.getTotalBytes() || 0,
      percent: 0
    });

    item.on('updated', (_e, state) => {
      if (state !== 'progressing') return;
      const received = item.getReceivedBytes() || 0;
      const total = item.getTotalBytes() || 0;
      const pct = total > 0 ? Math.min(100, Math.round((received / total) * 100)) : 0;
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.setProgressBar(total > 0 ? received / total : 2);
      }
      setDownloadState({
        state: 'progress',
        filename: item.getFilename() || filename,
        receivedBytes: received,
        totalBytes: total,
        percent: pct
      });
    });

    item.once('done', (_e, state) => {
      if (activeDownloadItem === item) activeDownloadItem = null;
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.setProgressBar(-1);
      }
      if (state === 'completed') {
        lastDownloadedFilePath = item.getSavePath() || '';
        setDownloadState({
          state: 'completed',
          filename: item.getFilename() || filename,
          savePath: lastDownloadedFilePath,
          percent: 100
        });
      } else if (state === 'cancelled') {
        setDownloadState({ state: 'idle' });
      } else {
        setDownloadState({
          state: 'failed',
          filename: item.getFilename() || filename
        });
      }
    });
  });
}

async function openOrDownloadUrl(rawUrl) {
  const classified = classifyDownloadUrl(rawUrl);
  if (!classified) return { ok: false };
  if (classified.isDirectBinary) {
    if (mainWindow && !mainWindow.isDestroyed()) {
      if (!mainWindow.isVisible()) mainWindow.show();
      mainWindow.focus();
    }
    setDownloadState({
      state: 'starting',
      filename: classified.filename,
      percent: 0
    });
    const opts = classified.headers ? { headers: classified.headers } : undefined;
    session.defaultSession.downloadURL(classified.url, opts);
    return { ok: true, mode: 'download', filename: classified.filename };
  }
  try {
    await shell.openExternal(classified.url, { activate: true });
    return { ok: true, mode: 'browser' };
  } catch (_) {
    return { ok: false };
  }
}

function compareSemver(a, b) {
  const pa = String(a || '').replace(/^v/i, '').split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b || '').replace(/^v/i, '').split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i += 1) {
    if ((pa[i] || 0) > (pb[i] || 0)) return 1;
    if ((pa[i] || 0) < (pb[i] || 0)) return -1;
  }
  return 0;
}

function setupAutoUpdater() {
  if (IS_PORTABLE) return;
  try {
    autoUpdater.setFeedURL({ provider: 'generic', url: IMMUTABLE_UPDATER_URL });
  } catch (_) {}
  autoUpdater.disableDifferentialDownload = true;
  autoUpdater.disableWebInstaller = true;
  autoUpdater.autoDownload = settings.autoDownloadUpdates;
  autoUpdater.autoInstallOnAppQuit = true;

  autoUpdater.on('checking-for-update', () => {
    setUpdaterState({ state: 'checking', message: msg('upd.checking') });
  });
  autoUpdater.on('update-available', (info) => {
    if (settings.autoDownloadUpdates) {
      setUpdaterState({
        state: 'downloading',
        availableVersion: info.version,
        percent: 0,
        message: msg('upd.downloading', { percent: 0 })
      });
    } else {
      setUpdaterState({
        state: 'available',
        availableVersion: info.version,
        message: msg('upd.available', { version: info.version })
      });
      if (settings.notificationsEnabled) {
        fireNotification(msg('upd.notifAvailTitle'), msg('upd.notifAvailBody', { version: info.version }), () => showWindow('settings'));
      }
    }
  });
  autoUpdater.on('update-not-available', () => {
    setUpdaterState({ state: 'up-to-date', message: msg('upd.upToDate', { version: app.getVersion() }) });
  });
  autoUpdater.on('download-progress', (prog) => {
    const pct = Math.round(prog.percent || 0);
    setUpdaterState({
      state: 'downloading',
      percent: pct,
      message: msg('upd.downloading', { percent: pct })
    });
  });
  autoUpdater.on('update-downloaded', (info) => {
    setUpdaterState({
      state: 'downloaded',
      availableVersion: info.version,
      percent: 100,
      message: msg('upd.downloaded', { version: info.version })
    });
    if (settings.notificationsEnabled) {
      fireNotification(msg('upd.notifReadyTitle'), msg('upd.notifReadyBody', { version: info.version }), () => showWindow('settings'));
    }
  });
  autoUpdater.on('error', (err) => {
    setUpdaterState({ state: 'error', message: msg('upd.error', { msg: err?.message || 'network' }) });
  });
}

async function checkForAppUpdates(manual = false) {
  if (!app.isPackaged) {
    setUpdaterState({
      state: 'up-to-date',
      message: manual ? msg('upd.devMode') : ''
    });
    return updaterStatus;
  }
  if (IS_PORTABLE) {
    setUpdaterState({ state: 'checking', message: msg('upd.checking') });
    try {
      const resp = await net.fetch(`${IMMUTABLE_UPDATER_URL}latest.yml?noCache=${Date.now()}`, {
        signal: AbortSignal.timeout(10_000)
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const text = await resp.text();
      const verMatch = text.match(/^\s*version:\s*['"]?([0-9]+\.[0-9]+\.[0-9]+)['"]?/m);
      const remoteVer = verMatch ? verMatch[1] : null;
      if (remoteVer && compareSemver(remoteVer, app.getVersion()) > 0) {
        setUpdaterState({
          state: 'available',
          availableVersion: remoteVer,
          portable: true,
          message: msg('upd.available', { version: remoteVer })
        });
      } else {
        setUpdaterState({ state: 'up-to-date', message: msg('upd.upToDate', { version: app.getVersion() }) });
      }
    } catch (err) {
      setUpdaterState({ state: 'error', message: msg('upd.error', { msg: err?.message || 'network' }) });
    }
    return updaterStatus;
  }
  autoUpdater.autoDownload = settings.autoDownloadUpdates;
  try {
    await autoUpdater.checkForUpdates();
  } catch (_) {}
  return updaterStatus;
}

function createWindow(startHidden) {
  mainWindow = new BrowserWindow({
    width: 1120,
    height: 740,
    minWidth: 880,
    minHeight: 600,
    show: !startHidden,
    autoHideMenuBar: true,
    backgroundColor: '#0c0d0f',
    icon: assetPath('icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  const indexFile = path.join(__dirname, 'renderer', 'index.html');
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event) => {
    event.preventDefault();
  });
  mainWindow.loadFile(indexFile);

  mainWindow.on('focus', () => {
    if (hasUnreadAlert) {
      hasUnreadAlert = false;
      refreshTray();
    }
  });

  mainWindow.on('minimize', (event) => {
    if (settings.minimizeToTray) {
      event.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on('close', (event) => {
    if (!isQuitting && settings.closeToTray) {
      event.preventDefault();
      mainWindow.hide();
      if (!shownTrayHint && Notification.isSupported()) {
        shownTrayHint = true;
        new Notification({
          title: msg('tray.stillActiveTitle'),
          body: msg('tray.stillActiveBody'),
          icon: assetPath('icon.png'),
          silent: true
        }).show();
      }
    }
  });
}

function registerIpc() {
  ipcMain.handle('data:get', async () => {
    if (cachedData) return cachedData;
    return fetchLatestData(false);
  });
  ipcMain.handle('data:refresh', async () => fetchLatestData(true));
  ipcMain.handle('history:entry', async (_event, vendor, version, lang) => {
    if (!VENDORS.includes(vendor) || !version) throw new Error('Invalid params');
    const reqLang = SUPPORTED_LANGS.includes(lang) ? lang : curLang();
    const url = `${settings.apiBaseUrl}/api/history/${encodeURIComponent(vendor)}/${encodeURIComponent(version)}?lang=${encodeURIComponent(reqLang)}`;
    return fetchJson(url);
  });
  ipcMain.handle('settings:get', () => settings);
  ipcMain.handle('settings:save', (_event, partial) => {
    const prevPoll = settings.pollIntervalMinutes;
    const prevUrl = settings.apiBaseUrl;
    const prevAutoCheck = settings.autoCheckUpdates;
    settings = mergeSettings(partial);
    writeJsonAtomic(userFile('settings.json'), settings);
    applyStartupSetting();
    applyThemeSetting();
    autoUpdater.autoDownload = settings.autoDownloadUpdates;
    refreshTray();
    if (settings.pollIntervalMinutes !== prevPoll || settings.apiBaseUrl !== prevUrl) {
      schedulePoll();
      if (settings.apiBaseUrl !== prevUrl) fetchLatestData(true).catch(() => {});
    }
    if (settings.autoCheckUpdates !== prevAutoCheck) {
      scheduleUpdateChecks();
      if (settings.autoCheckUpdates) checkForAppUpdates(false).catch(() => {});
    }
    return settings;
  });
  ipcMain.handle('settings:validateApi', async (_event, rawCandidate) => {
    const checked = validateRemoteApiUrl(rawCandidate, { allowInsecureDev: !app.isPackaged });
    if (!checked.ok) {
      return { ok: false, error: msg('settings.apiInvalid') };
    }
    const cleanUrl = checked.url;
    try {
      const resp = await net.fetch(`${cleanUrl}/health`, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(7_000)
      });
      if (!resp.ok) return { ok: false, error: `${msg('settings.apiInvalid')} (HTTP ${resp.status})` };
      const body = await resp.json();
      if (body?.status === 'ok' && (body?.service === 'driveradar' || body?.service === 'driveradar-api')) {
        return { ok: true, url: cleanUrl };
      }
      return { ok: false, error: msg('settings.apiInvalid') };
    } catch (_) {
      return { ok: false, error: msg('settings.apiInvalid') };
    }
  });
  ipcMain.handle('votes:session', async () => {
    const resp = await net.fetch(`${settings.apiBaseUrl}/api/votes`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'X-DriveRadar-Client-Proof': voterProof
      },
      signal: AbortSignal.timeout(10_000)
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  });
  ipcMain.handle('votes:cast', async (_event, payload) => {
    if (!payload || typeof payload !== 'object') throw new Error('Invalid vote payload');
    const resp = await net.fetch(`${settings.apiBaseUrl}/api/vote`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'X-Requested-With': 'DriveRadar',
        'X-DriveRadar-Client-Proof': voterProof
      },
      body: JSON.stringify({
        vote_token: String(payload.vote_token || ''),
        target_type: String(payload.target_type || ''),
        target_id: String(payload.target_id || ''),
        vote: String(payload.vote || ''),
        reason_tag: payload.reason_tag || null
      }),
      signal: AbortSignal.timeout(10_000)
    });
    if (!resp.ok) return { error: resp.status };
    return resp.json();
  });
  ipcMain.handle('notify:test', () => {
    fireNotification(msg('notif.testTitle'), msg('notif.testBody'), () => showWindow('settings'));
    return true;
  });
  ipcMain.handle('app:info', () => ({
    version: app.getVersion(),
    defaultApiUrl: DEFAULT_API_BASE,
    packaged: app.isPackaged,
    platform: process.platform,
    systemLocale: app.getLocale(),
    resolvedLanguage: curLang(),
    updater: updaterStatus
  }));
  ipcMain.handle('updater:check', () => checkForAppUpdates(true));
  ipcMain.handle('updater:download', async () => {
    if (!app.isPackaged) return updaterStatus;
    if (IS_PORTABLE && updaterStatus.availableVersion) {
      const portableUrl = `${IMMUTABLE_UPDATER_URL}DriveRadar-Portable-${updaterStatus.availableVersion}.exe`;
      setUpdaterState({ state: 'idle', message: '' });
      await openOrDownloadUrl(portableUrl);
      return updaterStatus;
    }
    setUpdaterState({
      state: 'downloading',
      percent: updaterStatus.percent || 0,
      message: msg('upd.downloading', { percent: updaterStatus.percent || 0 })
    });
    try {
      await autoUpdater.downloadUpdate();
    } catch (err) {
      setUpdaterState({ state: 'error', message: msg('upd.error', { msg: err?.message || 'network' }) });
    }
    return updaterStatus;
  });
  ipcMain.handle('updater:install', () => {
    if (!app.isPackaged || IS_PORTABLE) return false;
    isQuitting = true;
    autoUpdater.quitAndInstall(false, true);
    return true;
  });
  ipcMain.handle('driver:download', (_event, rawUrl) => openOrDownloadUrl(rawUrl));
  ipcMain.handle('download:reveal', () => {
    if (lastDownloadedFilePath && fs.existsSync(lastDownloadedFilePath)) {
      shell.showItemInFolder(lastDownloadedFilePath);
      return true;
    }
    return false;
  });
  ipcMain.handle('download:cancel', () => {
    if (activeDownloadItem) {
      try { activeDownloadItem.cancel(); } catch (_) {}
      activeDownloadItem = null;
      return true;
    }
    return false;
  });
  ipcMain.handle('shell:openExternal', async (_event, rawUrl) => {
    const res = await openOrDownloadUrl(rawUrl);
    return Boolean(res?.ok);
  });
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.setAppUserModelId(APP_ID);
  app.on('second-instance', () => showWindow());

  app.whenReady().then(() => {
    session.defaultSession.setPermissionRequestHandler((_wc, _perm, callback) => callback(false));
    session.defaultSession.setPermissionCheckHandler(() => false);
    setupDownloadManager();
    settings = mergeSettings(readJson(userFile('settings.json'), DEFAULT_SETTINGS));
    voterProof = loadOrCreateVoterProof(safeStorage, userFile('voter_proof.json'));
    seenState = { ...seenState, ...readJson(userFile('state.json'), {}) };
    cachedData = readJson(userFile('last_data.json'), null);
    applyThemeSetting();
    applyStartupSetting();

    const startHidden = process.argv.includes('--hidden');
    createWindow(startHidden);

    tray = new Tray(nativeImage.createFromPath(assetPath('tray.png')));
    tray.setToolTip(`DriveRadar v${app.getVersion()}`);
    tray.on('click', () => showWindow());
    tray.on('double-click', () => showWindow());
    refreshTray();

    registerIpc();
    setupAutoUpdater();
    fetchLatestData(false).catch(() => {});
    schedulePoll();

    scheduleUpdateChecks();
    if (settings.autoCheckUpdates) {
      setTimeout(() => checkForAppUpdates(false), 15_000);
    }
  });

  app.on('before-quit', () => {
    isQuitting = true;
    if (pollTimer) clearInterval(pollTimer);
    if (updateTimer) clearInterval(updateTimer);
  });

  app.on('window-all-closed', (event) => {
    if (!isQuitting && settings.closeToTray) {
      event.preventDefault();
    } else if (process.platform !== 'darwin') {
      app.quit();
    }
  });
}
