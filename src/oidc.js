const crypto = require('node:crypto');
const { db } = require('./db');
const logger = require('./logger');

let _config = null; // OIDC server configuration
let _enabled = false;
let _initError = null;
let _encryptionKey = null; // 32 bytes
let _openid = null;
let _clientId = null;
let _clientSecret = null;
let _redirectUri = null;
let _clientAuth = null; // Client authentication method

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
  return _enabled && _config !== null;
}

function getInitError() {
  return _initError;
}

async function initializeOIDC({ jwtKey } = {}) {
  _initError = null;
  _enabled = false;
  _config = null;

  const masterSwitch = _boolEnv('OIDC_ENABLED', false);
  if (!masterSwitch) {
    logger.info('OIDC disabled (OIDC_ENABLED not true).');
    return false;
  }

  const issuerUrl = _getRequiredEnv('OIDC_ISSUER_URL');
  _clientId = _getRequiredEnv('OIDC_CLIENT_ID');
  _clientSecret = _getRequiredEnv('OIDC_CLIENT_SECRET');
  _redirectUri = _getRequiredEnv('OIDC_REDIRECT_URI');

  if (!issuerUrl || !_clientId || !_clientSecret || !_redirectUri) {
    logger.warn('OIDC disabled: missing required env vars. Need OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI.');
    return false;
  }

  try {
    logger.debug(`[OIDC] Initializing with issuer: ${issuerUrl}`);
    logger.debug(`[OIDC] Client ID: ${_clientId}`);
    logger.debug(`[OIDC] Redirect URI: ${_redirectUri}`);

    if (!_openid) {
      _openid = await import('openid-client');
      logger.debug('openid-client v6 imported');
    }

    // Use the new v6 discovery API
    const discovery = _openid.discovery || _openid.default?.discovery;
    if (!discovery) {
      throw new Error('Could not find discovery function from openid-client');
    }

    _config = await discovery(new URL(issuerUrl), _clientId, _clientSecret);
    logger.debug(`[OIDC] Discovery completed successfully`);

    // Determine client authentication method
    // Default to client_secret_post (configure IDP to support this method)
    const authMethod = process.env.OIDC_CLIENT_AUTH_METHOD || 'client_secret_post';

    switch (authMethod.toLowerCase()) {
      case 'client_secret_post':
        _clientAuth = _openid.ClientSecretPost || _openid.default?.ClientSecretPost;
        break;
      case 'client_secret_jwt':
        _clientAuth = _openid.ClientSecretJwt || _openid.default?.ClientSecretJwt;
        break;
      case 'private_key_jwt':
        _clientAuth = _openid.PrivateKeyJwt || _openid.default?.PrivateKeyJwt;
        break;
      case 'none':
        _clientAuth = _openid.None || _openid.default?.None;
        break;
      case 'client_secret_basic':
      default:
        _clientAuth = _openid.ClientSecretBasic || _openid.default?.ClientSecretBasic;
        break;
    }

    if (!_clientAuth) {
      throw new Error(`Could not find client auth method: ${authMethod}`);
    }

    logger.debug(`Using OIDC client authentication method: ${authMethod}`);

    _encryptionKey = _deriveEncryptionKey(jwtKey);

    _enabled = true;
    logger.info('OIDC initialized successfully.');
    return true;
  } catch (err) {
    _initError = err;
    logger.error('OIDC initialization failed. Falling back to other auth methods.', err);
    _enabled = false;
    _config = null;
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

async function getAuthorizationUrl({ redirectAfterLogin } = {}) {
  if (!isOIDCEnabled()) {
    throw new Error('OIDC not enabled');
  }

  const scope = _getRequiredEnv('OIDC_SCOPE') || 'openid profile email';

  // Use v6 random generators
  const randomState = _openid.randomState || _openid.default?.randomState;
  const randomNonce = _openid.randomNonce || _openid.default?.randomNonce;
  const randomPKCECodeVerifier = _openid.randomPKCECodeVerifier || _openid.default?.randomPKCECodeVerifier;
  const calculatePKCECodeChallenge = _openid.calculatePKCECodeChallenge || _openid.default?.calculatePKCECodeChallenge;

  if (!randomState || !randomNonce || !randomPKCECodeVerifier || !calculatePKCECodeChallenge) {
    throw new Error('Could not find PKCE helper functions from openid-client');
  }

  const state = randomState();
  const nonce = randomNonce();
  const code_verifier = randomPKCECodeVerifier();
  const code_challenge = await calculatePKCECodeChallenge(code_verifier);

  logger.debug('[OIDC] Starting authorization flow');
  logger.debug(`[OIDC] code_verifier type: ${typeof code_verifier}, length: ${String(code_verifier).length}`);
  logger.debug(`[OIDC] code_challenge type: ${typeof code_challenge}, value: ${String(code_challenge)}`);
  logger.debug(`[OIDC] code_verifier (first 20): ${String(code_verifier).substring(0, 20)}...`);

  // Use v6 buildAuthorizationUrl
  const buildAuthorizationUrl = _openid.buildAuthorizationUrl || _openid.default?.buildAuthorizationUrl;
  if (!buildAuthorizationUrl) {
    throw new Error('Could not find buildAuthorizationUrl from openid-client');
  }

  const authorizationUrl = buildAuthorizationUrl(_config, {
    scope,
    redirect_uri: _redirectUri,
    state,
    nonce,
    code_challenge,
    code_challenge_method: 'S256',
  });

  return {
    authorizationUrl: authorizationUrl.href,
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

  // Get the authorization code grant function
  const authorizationCodeGrant = _openid.authorizationCodeGrant || _openid.default?.authorizationCodeGrant;
  if (!authorizationCodeGrant) {
    throw new Error('Could not find authorizationCodeGrant from openid-client');
  }

  // Build the callback URL with query params
  const callbackUrl = new URL(_redirectUri);
  const params = req.query || {};
  for (const [key, value] of Object.entries(params)) {
    callbackUrl.searchParams.set(key, value);
  }

  // Exchange code for tokens using v6 API
  logger.debug('[OIDC] Processing callback');
  logger.debug(`[OIDC] code_verifier type: ${typeof code_verifier}, length: ${code_verifier?.length || 'null'}`);
  logger.debug(`[OIDC] code_verifier (first 20): ${code_verifier ? String(code_verifier).substring(0, 20) + '...' : 'null'}`);
  logger.debug(`[OIDC] Callback URL: ${callbackUrl.href}`);

  const tokenSet = await authorizationCodeGrant(_config, callbackUrl, {
    pkceCodeVerifier: code_verifier,
    expectedState: state,
    expectedNonce: nonce,
  }, _clientAuth);

  // Extract claims from ID token (claims() is a method in openid-client v6)
  let claims = {};
  try {
    claims = tokenSet.claims() || {};
    logger.debug(`[OIDC] ID token claim keys: ${Object.keys(claims).join(', ')}`);
    logger.debug(`[OIDC] Extracted claims from ID token: ${JSON.stringify({ sub: claims.sub, email: claims.email, preferred_username: claims.preferred_username })}`);
  } catch (err) {
    logger.error('[OIDC] Failed to extract claims from ID token:', err);
    logger.error(`[OIDC] tokenSet keys: ${Object.keys(tokenSet).join(', ')}`);
  }

  const sub = claims?.sub;
  if (!sub) {
    logger.error(`[OIDC] Missing sub claim. Available claims: ${Object.keys(claims).join(', ')}`);
    throw new Error('OIDC provider did not return sub claim');
  }

  // Fetch userinfo to get additional claims (like groups) that may not be in ID token
  let userinfo = {};
  if (tokenSet.access_token) {
    try {
      const fetchUserInfo = _openid.fetchUserInfo || _openid.default?.fetchUserInfo;
      if (!fetchUserInfo) {
        logger.warn('[OIDC] fetchUserInfo not available in openid-client');
      } else {
        userinfo = await fetchUserInfo(_config, tokenSet.access_token, tokenSet.claims()?.sub);
        logger.debug(`[OIDC] UserInfo claim keys: ${Object.keys(userinfo).join(', ')}`);

        const groupClaim = process.env.OIDC_GROUP_CLAIM || 'groups';
        logger.debug(`[OIDC] '${groupClaim}' from ID token: ${JSON.stringify(claims[groupClaim])}`);
        logger.debug(`[OIDC] '${groupClaim}' from UserInfo: ${JSON.stringify(userinfo[groupClaim])}`);
      }
    } catch (err) {
      logger.warn('[OIDC] Failed to fetch userinfo (continuing without it):', err.message);
    }
  }

  // Merge userinfo into claims (userinfo takes precedence for overlapping keys)
  const mergedClaims = { ...claims, ...userinfo };
  logger.debug(`[OIDC] Merged claim keys: ${Object.keys(mergedClaims).join(', ')}`);

  return { tokenSet, claims: mergedClaims };
}

function extractGroupsFromClaims(claims) {
  const groupClaim = process.env.OIDC_GROUP_CLAIM || process.env.OIDC_ADMIN_CLAIM || 'groups';
  const value = _getClaimByPath(claims, groupClaim);
  const groups = _normalizeGroups(value);
  logger.debug(`[OIDC] Extracted groups from claim '${groupClaim}': ${JSON.stringify(groups)}`);
  return groups;
}

function isAllowedByGroups(groups) {
  const allowCsv = process.env.OIDC_ALLOWED_GROUPS;
  if (!allowCsv || String(allowCsv).trim() === '') {
    logger.debug('[OIDC] No OIDC_ALLOWED_GROUPS set, allowing all groups');
    return true;
  }
  const allowed = _splitCsv(allowCsv);
  if (allowed.length === 0) return true;

  // Case-insensitive comparison
  const allowedLower = allowed.map(g => g.toLowerCase());
  const groupsLower = groups.map(g => g.toLowerCase());
  const isAllowed = groupsLower.some((g) => allowedLower.includes(g));

  logger.debug(`[OIDC] Group authorization check: user groups=${JSON.stringify(groups)}, allowed=${JSON.stringify(allowed)}, result=${isAllowed}`);
  return isAllowed;
}

function isAdminFromClaims(claims, groups) {
  const claimPath = process.env.OIDC_ADMIN_CLAIM || (process.env.OIDC_GROUP_CLAIM || 'groups');
  const adminValue = (process.env.OIDC_ADMIN_VALUE || 'admin').toLowerCase();

  const v = _getClaimByPath(claims, claimPath);
  const normalized = _normalizeGroups(v);

  // If admin claim path isn't actually groups, still allow groupClaim to drive admin if desired.
  const combined = [...(groups || []), ...normalized].map(g => g.toLowerCase());
  const isAdmin = combined.includes(adminValue);

  logger.debug(`[OIDC] Admin check: groups=${JSON.stringify(groups)}, adminValue=${adminValue}, result=${isAdmin}`);
  return isAdmin;
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

  // Use v6 refreshTokenGrant
  const refreshTokenGrant = _openid.refreshTokenGrant || _openid.default?.refreshTokenGrant;
  if (!refreshTokenGrant) {
    logger.error('Could not find refreshTokenGrant from openid-client');
    return false;
  }

  let tokenSet;
  try {
    tokenSet = await refreshTokenGrant(_config, refreshToken, _clientAuth);
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
