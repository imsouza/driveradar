'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const netModule = require('net');

const DEFAULT_API_BASE = 'https://optlabs.com.br/driveradar';
const IMMUTABLE_UPDATER_URL = 'https://optlabs.com.br/driveradar/updates/';
const FORBIDDEN_HOST_SUFFIXES = ['.local', '.internal', '.localhost', '.lan', '.arpa'];

function isPrivateOrReservedIp(ip) {
  const version = netModule.isIP(ip);
  if (version === 4) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }
  if (version === 6) {
    const low = ip.toLowerCase();
    if (low === '::1' || low === '::') return true;
    if (low.startsWith('fc') || low.startsWith('fd') || low.startsWith('fe8') || low.startsWith('fe9') || low.startsWith('fea') || low.startsWith('feb')) {
      return true;
    }
    if (low.startsWith('::ffff:')) {
      return isPrivateOrReservedIp(low.slice(7));
    }
    return false;
  }
  return false;
}

function isPrivateOrReservedHost(hostname) {
  const host = String(hostname || '').trim().toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  if (!host || host === 'localhost') return true;
  if (FORBIDDEN_HOST_SUFFIXES.some((sfx) => host.endsWith(sfx))) return true;
  if (netModule.isIP(host)) return isPrivateOrReservedIp(host);
  return false;
}

function validateRemoteApiUrl(rawUrl, { allowInsecureDev = false } = {}) {
  const trimmed = String(rawUrl || '').trim();
  if (!trimmed) {
    return { ok: true, url: DEFAULT_API_BASE };
  }
  if (trimmed.length > 512 || /[\x00-\x20\x7f]/.test(trimmed)) {
    return { ok: false, reason: 'malformed' };
  }
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch (_) {
    return { ok: false, reason: 'invalid_url' };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, reason: 'credentials_forbidden' };
  }
  const allowedProtocols = allowInsecureDev ? ['https:', 'http:'] : ['https:'];
  if (!allowedProtocols.includes(parsed.protocol)) {
    return { ok: false, reason: 'https_required' };
  }
  if (!allowInsecureDev && isPrivateOrReservedHost(parsed.hostname)) {
    return { ok: false, reason: 'private_host_forbidden' };
  }
  return { ok: true, url: parsed.href.replace(/\/+$/, '') };
}

function validateExternalBrowserUrl(rawUrl) {
  const trimmed = String(rawUrl || '').trim();
  if (!trimmed || trimmed.length > 1024 || /[\x00-\x20\x7f]/.test(trimmed)) {
    return null;
  }
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch (_) {
    return null;
  }
  if (!['https:', 'http:'].includes(parsed.protocol)) return null;
  if (parsed.username || parsed.password) return null;
  if (isPrivateOrReservedHost(parsed.hostname)) return null;
  return parsed.href;
}

function loadOrCreateVoterProof(safeStorage, filePath) {
  try {
    if (fs.existsSync(filePath)) {
      const stored = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (stored?.encrypted && stored?.data && safeStorage?.isEncryptionAvailable?.()) {
        const plain = safeStorage.decryptString(Buffer.from(stored.data, 'base64'));
        if (/^[A-Za-z0-9_-]{32,128}$/.test(plain)) return plain;
      } else if (!stored?.encrypted && typeof stored?.data === 'string' && /^[A-Za-z0-9_-]{32,128}$/.test(stored.data)) {
        return stored.data;
      }
    }
  } catch (_) {}

  const freshProof = crypto.randomBytes(32).toString('base64url');
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const canEncrypt = Boolean(safeStorage?.isEncryptionAvailable?.());
    const payload = canEncrypt
      ? { encrypted: true, data: safeStorage.encryptString(freshProof).toString('base64') }
      : { encrypted: false, data: freshProof };
    const tmp = `${filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(payload), { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmp, filePath);
  } catch (_) {}
  return freshProof;
}

module.exports = {
  DEFAULT_API_BASE,
  IMMUTABLE_UPDATER_URL,
  isPrivateOrReservedHost,
  isPrivateOrReservedIp,
  loadOrCreateVoterProof,
  validateExternalBrowserUrl,
  validateRemoteApiUrl
};
