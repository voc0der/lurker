const crypto = require('node:crypto');
const { db } = require('./db');
const logger = require('./logger');

let _client = null;
let _issuer = null;
let _enabled = false;
let _initError = null;
let _encryptionKey = null; // 32 bytes
let _openid = null;

function _boolEnv(name, defaultValue = false) {
  const v = process.env[name];
  if (v === undefined) return defaultValue;
  return String(v).toLowerCase() === 'true' || v === '1' || String(v).toLowerCase() === 'yes';
}

function _getRequiredEnv(name) {
  const v = process.env[name];
  return v && String(v).trim().length > 0 ? String(v).trim() : null;
}

function _deriveEncryptionKey(jwtKey) {
  const secret = (jwtKey && String(jwtKey)) || process.env.JWT_SECRET_KEY || '';
  // NOTE: if JWT_SECRET_KEY is not set, the app may generate a random key on boot.
  // That is already required to keep cookies valid across restarts.
  if (!secret) {
    // Still derive a key (will be consistent only for this process)
    return crypto.createHash('sha256').update('lurker-default-key').digest();
  }
  return crypto.createHash('sha256').update(secret).digest(); // 32 bytes
}

function _splitCsv(value) {
  return String(value)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function _getClaimByPath(obj, path) {
  if (!obj || !path) return undefined;
  // Support dotted paths and simple [index] notation.
  const parts = String(path).split('.');
  let cur = obj;
  for (const raw of parts) {
    if (cur === null || cur === undefined) return undefined;

    const m = /^([^\[]+)(?:\[(\d+)\])?$/.exec(raw);
    if (!m) return undefined;
    const key = m[1];
    const idx = m[2] !== undefined ? Number(m[2]) : null;

    cur = cur[key];
    if (idx !== null) {
      if (!Array.isArray(cur) || cur.length <= idx) return undefined;
      cur = cur[idx];
    }
  }
  return cur;
}

function _normalizeGroups(value) {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) {
    return value.map((v) => String(v).trim()).filter(Boolean);
  }
  if (typeof value === 'string') {
    // Many IdPs send a CSV string; if not, this still works.
    return _splitCsv(value);
  }
  // Some IdPs use objects like { roles: [...] } or similar; try common shapes.
  if (typeof value === 'object') {
    if (Array.isArray(value.roles)) return value.roles.map((v) => String(v).trim()).filter(Boolean);
    if (Array.isArray(value.groups)) return value.groups.map((v) => String(v).trim()).filter(Boolean);
  }
  return [String(value).trim()].filter(Boolean);
}

function isOIDCEnabled() {
  return _enabled && _client !== null;
}

function getInitError() {
  return _initError;
}

async function initializeOIDC({ jwtKey } = {}) {
  _initError = null;
  _enabled = false;
  _client = null;
  _issuer = null;

  const masterSwitch = _boolEnv('OIDC_ENABLED', false);
  if (!masterSwitch) {
    logger.info('OIDC disabled (OIDC_ENABLED not true).');
    return false;
  }

  const issuerUrl = _getRequiredEnv('OIDC_ISSUER_URL');
  const clientId = _getRequiredEnv('OIDC_CLIENT_ID');
  const clientSecret = _getRequiredEnv('OIDC_CLIENT_SECRET');
  const redirectUri = _getRequiredEnv('OIDC_REDIRECT_URI');

  if (!issuerUrl || !clientId || !clientSecret || !redirectUri) {
    logger.warn('OIDC disabled: missing required env vars. Need OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI.');
    return false;
  }

  try {
    if (!_openid) {
      _openid = await import('openid-client');
    }

    const { Issuer } = _openid;
    _issuer = await Issuer.discover(issuerUrl);

    // openid-client v5/v6 compatible client construction
    _client = new _issuer.Client({
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: [redirectUri],
      response_types: ['code'],
    });

    _encryptionKey = _deriveEncryptionKey(jwtKey);

    _enabled = true;
    logger.info('OIDC initialized successfully.');
    return true;
  } catch (err) {
    _initError = err;
    logger.error('OIDC initialization failed. Falling back to other auth methods.', err);
    _enabled = false;
    _client = null;
    _issuer = null;
    return false;
  }
}

function encryptRefreshToken(refreshToken) {
  if (!refreshToken) return null;
  if (!_encryptionKey) {
    _encryptionKey = _deriveEncryptionKey();
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', _encryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(String(refreshToken), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return `${iv.toString('base64')}.${tag.toString('base64')}.${ciphertext.toString('base64')}`;
}

function decryptRefreshToken(enc) {
  if (!enc) return null;
  if (!_encryptionKey) {
    _encryptionKey = _deriveEncryptionKey();
  }

  const parts = String(enc).split('.');
  if (parts.length !== 3) return null;
  const [ivB64, tagB64, ctB64] = parts;

  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const ct = Buffer.from(ctB64, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', _encryptionKey, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
  return plaintext.toString('utf8');
}

function getAuthorizationUrl({ redirectAfterLogin } = {}) {
  if (!isOIDCEnabled()) {
    throw new Error('OIDC not enabled');
  }

  const scope = _getRequiredEnv('OIDC_SCOPE') || 'openid profile email';
  const redirectUri = _getRequiredEnv('OIDC_REDIRECT_URI');

  const { generators } = _openid;

  const state = generators.state();
  const nonce = generators.nonce();
  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);

  const authorizationUrl = _client.authorizationUrl({
    scope,
    redirect_uri: redirectUri,
    response_type: 'code',
    state,
    nonce,
    code_challenge,
    code_challenge_method: 'S256',
  });

  return {
    authorizationUrl,
    state,
    nonce,
    code_verifier,
    redirectAfterLogin: redirectAfterLogin || '/',
  };
}

async function handleCallback(req, { state, nonce, code_verifier } = {}) {
  if (!isOIDCEnabled()) {
    throw new Error('OIDC not enabled');
  }

  const redirectUri = _getRequiredEnv('OIDC_REDIRECT_URI');

  let params;
  try {
    params = _client.callbackParams(req);
  } catch (_e) {
    // Fallback for environments where callbackParams doesn't like Express req
    params = req.query || {};
  }

  // openid-client v5 and v6 differ slightly; try both.
  let tokenSet;
  try {
    tokenSet = await _client.callback(redirectUri, params, { state, nonce, code_verifier });
  } catch (err1) {
    try {
      tokenSet = await _client.authorizationCallback(redirectUri, params, { state, nonce, code_verifier });
    } catch (err2) {
      logger.error('OIDC callback exchange failed.', err2);
      throw err1;
    }
  }

  let claims;
  try {
    claims = tokenSet.claims();
  } catch (_e) {
    claims = tokenSet.id_token ? _client.decryptIdToken(tokenSet.id_token) : {};
  }

  return { tokenSet, claims };
}

function extractGroupsFromClaims(claims) {
  const groupClaim = process.env.OIDC_GROUP_CLAIM || process.env.OIDC_ADMIN_CLAIM || 'groups';
  const value = _getClaimByPath(claims, groupClaim);
  return _normalizeGroups(value);
}

function isAllowedByGroups(groups) {
  const allowCsv = process.env.OIDC_ALLOWED_GROUPS;
  if (!allowCsv || String(allowCsv).trim() === '') return true;
  const allowed = _splitCsv(allowCsv);
  if (allowed.length === 0) return true;
  return groups.some((g) => allowed.includes(g));
}

function isAdminFromClaims(claims, groups) {
  const claimPath = process.env.OIDC_ADMIN_CLAIM || (process.env.OIDC_GROUP_CLAIM || 'groups');
  const adminValue = process.env.OIDC_ADMIN_VALUE || 'admin';

  const v = _getClaimByPath(claims, claimPath);
  const normalized = _normalizeGroups(v);

  // If admin claim path isn't actually groups, still allow groupClaim to drive admin if desired.
  const combined = new Set([...(groups || []), ...normalized]);
  return combined.has(adminValue);
}

function resolveUsernameFromClaims(claims) {
  // Keep this deterministic and provider-friendly.
  return (
    claims?.preferred_username ||
    claims?.email ||
    claims?.upn ||
    claims?.name ||
    claims?.sub
  );
}

function computeExpiresAtSeconds(tokenSet) {
  if (!tokenSet) return null;
  if (tokenSet.expires_at) return Number(tokenSet.expires_at);
  if (tokenSet.expires_in) {
    return Math.floor(Date.now() / 1000) + Number(tokenSet.expires_in);
  }
  // Some providers include exp in id_token
  return null;
}

async function refreshAccessToken(userId) {
  if (!isOIDCEnabled()) return false;

  const user = db.query('SELECT id, oidc_refresh_token FROM users WHERE id = $id').get({ id: userId });
  if (!user || !user.oidc_refresh_token) return false;

  const refreshToken = decryptRefreshToken(user.oidc_refresh_token);
  if (!refreshToken) {
    logger.warn('OIDC refresh token could not be decrypted.');
    return false;
  }

  let tokenSet;
  try {
    tokenSet = await _client.refresh(refreshToken);
  } catch (err) {
    logger.error('OIDC token refresh failed.', err);
    return false;
  }

  const newRefresh = tokenSet.refresh_token || refreshToken;
  const enc = encryptRefreshToken(newRefresh);
  const expiresAt = computeExpiresAtSeconds(tokenSet);

  db.query(
    'UPDATE users SET oidc_refresh_token = $rt, oidc_token_expires_at = $exp WHERE id = $id'
  ).run({
    rt: enc,
    exp: expiresAt,
    id: userId,
  });

  return true;
}

module.exports = {
  initializeOIDC,
  isOIDCEnabled,
  getInitError,
  getAuthorizationUrl,
  handleCallback,
  encryptRefreshToken,
  decryptRefreshToken,
  refreshAccessToken,
  extractGroupsFromClaims,
  isAllowedByGroups,
  isAdminFromClaims,
  resolveUsernameFromClaims,
  computeExpiresAtSeconds,
};
