const { contextBridge, ipcRenderer } = require('electron');

function subscribe(channel, callback) {
  if (typeof callback !== 'function') return () => {};
  const handler = (_event, payload) => callback(payload);
  ipcRenderer.on(channel, handler);
  return () => ipcRenderer.removeListener(channel, handler);
}

contextBridge.exposeInMainWorld('driveRadar', {
  getData: () => ipcRenderer.invoke('data:get'),
  refreshNow: () => ipcRenderer.invoke('data:refresh'),
  getHistoryEntry: (vendor, version, lang) => ipcRenderer.invoke('history:entry', vendor, version, lang),
  getSettings: () => ipcRenderer.invoke('settings:get'),
  saveSettings: (partial) => ipcRenderer.invoke('settings:save', partial),
  validateApiEndpoint: (url) => ipcRenderer.invoke('settings:validateApi', url),
  testNotification: () => ipcRenderer.invoke('notify:test'),
  getAppInfo: () => ipcRenderer.invoke('app:info'),
  checkAppUpdates: () => ipcRenderer.invoke('updater:check'),
  downloadAppUpdate: () => ipcRenderer.invoke('updater:download'),
  installAppUpdate: () => ipcRenderer.invoke('updater:install'),
  openExternal: (url) => ipcRenderer.invoke('shell:openExternal', url),
  onDataUpdated: (cb) => subscribe('data:updated', cb),
  onUpdaterStatus: (cb) => subscribe('updater:status', cb),
  onNavigate: (cb) => subscribe('app:navigate', cb)
});
