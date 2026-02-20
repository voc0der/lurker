const jwt = require("jsonwebtoken");
const { db } = require("./db");
const { JWT_KEY } = require("./");
const logger = require("./logger");
const oidc = require("./oidc");

function normalizeIp(ip) {
	if (!ip || typeof ip !== "string") return "";
	if (ip.startsWith("::ffff:")) return ip.slice(7);
	return ip;
}

function isLoopbackIp(ip) {
	return ip === "127.0.0.1" || ip === "::1";
}

function getTrustedProxyIps() {
	return (process.env.REVERSE_PROXY_WHITELIST || "")
		.split(",")
		.map((ip) => normalizeIp(ip.trim()))
		.filter(Boolean);
}

function isRemoteHeaderLoginEnabled() {
	const value = String(process.env.REMOTE_HEADER_LOGIN || "").toLowerCase();
	return value === "true" || value === "1";
}

function isTrustedRemoteHeaderSource(req) {
	const remoteAddress = normalizeIp(req.socket?.remoteAddress || "");
	if (!remoteAddress) return false;
	if (isLoopbackIp(remoteAddress)) return true;
	return getTrustedProxyIps().includes(remoteAddress);
}

function parseRemoteGroups(req) {
	if (!isRemoteHeaderLoginEnabled() || !isTrustedRemoteHeaderSource(req)) return [];
	const raw = req.headers["remote-groups"] || req.headers["http_remote_groups"];
	if (!raw) return [];
	return String(raw)
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);
}

function groupsJson(groups) {
	try {
		return JSON.stringify(Array.from(new Set(groups)));
	} catch {
		return "[]";
	}
}

// Helper function to log token issues
function logTokenError(message, error) {
	logger.error(message, error);
}

// Middleware to authenticate using JWT token (from cookies)
async function authenticateToken(req, res, next) {
	const token = req.cookies && req.cookies.auth_token;
	const remoteGroups = parseRemoteGroups(req);
	const isAdminFromHeaders = remoteGroups.includes(process.env.ADMIN_GROUP || "admin") ? 1 : 0;

	if (!token) {
		logger.debug("No token found, redirecting to login.");
		return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
	}

	let decoded;
	try {
		logger.debug("Verifying token...");
		decoded = jwt.verify(token, JWT_KEY);
		logger.debug("Token verified for user:", decoded);
	} catch (error) {
		if (error.name === "TokenExpiredError") {
			logger.debug("Token expired:", error);
			return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}&message=Session expired`);
		}
		logTokenError("Token verification failed:", error);
		return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
	}

	let dbUser;
	try {
		if (decoded?.id) {
			dbUser = db.query("SELECT * FROM users WHERE id = $id").get({ id: decoded.id });
		} else {
			dbUser = db.query("SELECT * FROM users WHERE username = $username").get({ username: decoded.username });
		}

		logger.debug("authenticateToken - loaded user from DB:", {
			id: dbUser?.id,
			username: dbUser?.username,
			infiniteScroll: dbUser?.infiniteScroll,
			useClassicLayout: dbUser?.useClassicLayout,
			themePreference: dbUser?.themePreference,
		});
	} catch (err) {
		logger.error("Database error:", err);
		return res.redirect("/login?message=Database error.");
	}

	if (!dbUser) {
		logger.debug("User not found in database for token:", decoded?.username);
		return res.redirect("/login?message=User not found.");
	}

	// If Remote Header SSO is enabled, keep isAdmin in sync with the header.
	if (isRemoteHeaderLoginEnabled() && remoteGroups.length > 0) {
		const groupsStr = groupsJson(remoteGroups);
		if (dbUser.isAdmin !== isAdminFromHeaders || (dbUser.groups || "[]") !== groupsStr) {
			db.query("UPDATE users SET isAdmin = $isAdmin, groups = $groups WHERE id = $id").run({
				isAdmin: isAdminFromHeaders,
				groups: groupsStr,
				id: dbUser.id,
			});
			// Update in-memory copy for rendering
			dbUser.isAdmin = isAdminFromHeaders;
			dbUser.groups = groupsStr;
			logger.debug(`Updated isAdmin/groups from Remote Header for ${dbUser.username} (${dbUser.id}).`);
		}
	}

	// OIDC refresh: refresh 5 minutes before expiry
	try {
		if (dbUser.oidc_sub && dbUser.oidc_token_expires_at) {
			const now = Math.floor(Date.now() / 1000);
			const expiresIn = Number(dbUser.oidc_token_expires_at) - now;
			if (!Number.isNaN(expiresIn) && expiresIn < 300) {
				await oidc.refreshAccessToken(dbUser.id);
			}
		}
	} catch (err) {
		// Graceful degradation: do not kill the request
		logger.warn("OIDC refresh attempt failed; continuing without refresh.", err);
	}

	req.user = dbUser;
	return next();
}

// Middleware to authenticate admin (checks if user has admin privileges)
async function authenticateAdmin(req, res, next) {
	const token = req.cookies && req.cookies.auth_token;
	const remoteGroups = parseRemoteGroups(req);
	const isAdminFromHeaders = remoteGroups.includes(process.env.ADMIN_GROUP || "admin") ? 1 : 0;

	if (!token) {
		logger.debug("No token found, redirecting to login for admin.");
		return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
	}

	let decoded;
	try {
		logger.debug("Verifying token for admin...");
		decoded = jwt.verify(token, JWT_KEY);
		logger.debug("Admin token verified for user:", decoded);
	} catch (error) {
		if (error.name === "TokenExpiredError") {
			logger.debug("Admin token expired:", error);
			return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}&message=Session expired`);
		}
		logTokenError("Admin token verification failed:", error);
		return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
	}

	let dbUser;
	try {
		if (decoded?.id) {
			dbUser = db.query("SELECT * FROM users WHERE id = $id").get({ id: decoded.id });
		} else {
			dbUser = db.query("SELECT * FROM users WHERE username = $username").get({ username: decoded.username });
		}
	} catch (err) {
		logger.error("Database error:", err);
		return res.redirect("/login?message=Database error.");
	}

	if (!dbUser) {
		logger.debug("Admin user not found in database for token:", decoded?.username);
		return res.redirect("/login?message=Admin user not found.");
	}

	if (isRemoteHeaderLoginEnabled() && remoteGroups.length > 0) {
		const groupsStr = groupsJson(remoteGroups);
		if (dbUser.isAdmin !== isAdminFromHeaders || (dbUser.groups || "[]") !== groupsStr) {
			db.query("UPDATE users SET isAdmin = $isAdmin, groups = $groups WHERE id = $id").run({
				isAdmin: isAdminFromHeaders,
				groups: groupsStr,
				id: dbUser.id,
			});
			dbUser.isAdmin = isAdminFromHeaders;
			dbUser.groups = groupsStr;
		}
	}

	// OIDC refresh check for admins too
	try {
		if (dbUser.oidc_sub && dbUser.oidc_token_expires_at) {
			const now = Math.floor(Date.now() / 1000);
			const expiresIn = Number(dbUser.oidc_token_expires_at) - now;
			if (!Number.isNaN(expiresIn) && expiresIn < 300) {
				await oidc.refreshAccessToken(dbUser.id);
			}
		}
	} catch (err) {
		logger.warn("OIDC refresh attempt failed; continuing without refresh.", err);
	}

	req.user = dbUser;
	if (dbUser.isAdmin) {
		return next();
	}
	logger.debug("User is not an admin:", dbUser.username);
	return res.status(403).send("Only admins can access this route.");
}

module.exports = { authenticateToken, authenticateAdmin };
