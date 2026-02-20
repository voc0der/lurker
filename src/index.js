const express = require("express");
const rateLimit = require("express-rate-limit");
const path = require("node:path");
const crypto = require("node:crypto");
const https = require("https");
const fs = require("fs");
const logger = require("./logger");
const oidc = require("./oidc");

const app = express();
const hasher = new Bun.CryptoHasher("sha256", "secret-key");
const JWT_KEY = process.env.JWT_SECRET_KEY || hasher.update(Math.random().toString()).digest("hex");
const trustedProxyIPs = (process.env.REVERSE_PROXY_WHITELIST || "").split(",").map((ip) => ip.trim());
const httpBinding = process.env.HTTP_BINDING || "0.0.0.0";
const CSRF_COOKIE_NAME = "csrf_token";

function generateCsrfToken() {
	return crypto.randomBytes(32).toString("hex");
}

function safeTokenCompare(a, b) {
	if (typeof a !== "string" || typeof b !== "string") return false;
	const aBuf = Buffer.from(a);
	const bBuf = Buffer.from(b);
	if (aBuf.length !== bBuf.length) return false;
	return crypto.timingSafeEqual(aBuf, bBuf);
}

function isSafeCookieName(name) {
	if (!/^[A-Za-z0-9._-]+$/.test(name)) return false;
	return !["__proto__", "prototype", "constructor"].includes(name);
}

function setKnownCookie(cookies, name, value) {
	switch (name) {
		case "auth_token":
			cookies.auth_token = value;
			break;
		case "oidc_state":
			cookies.oidc_state = value;
			break;
		case "oidc_nonce":
			cookies.oidc_nonce = value;
			break;
		case "oidc_verifier":
			cookies.oidc_verifier = value;
			break;
		case "oidc_redirect":
			cookies.oidc_redirect = value;
			break;
		case CSRF_COOKIE_NAME:
			cookies[CSRF_COOKIE_NAME] = value;
			break;
		default:
			break;
	}
}

function parseCookies(cookieHeader) {
	const cookies = {
		auth_token: undefined,
		oidc_state: undefined,
		oidc_nonce: undefined,
		oidc_verifier: undefined,
		oidc_redirect: undefined,
		[CSRF_COOKIE_NAME]: undefined,
	};
	if (typeof cookieHeader !== "string" || cookieHeader.length === 0) {
		return cookies;
	}

	for (const rawCookie of cookieHeader.split(";")) {
		const [rawName, ...rawValueParts] = rawCookie.split("=");
		const name = rawName ? rawName.trim() : "";
		if (!name) continue;
		if (!isSafeCookieName(name)) continue;
		const rawValue = rawValueParts.join("=").trim();
		try {
			setKnownCookie(cookies, name, decodeURIComponent(rawValue));
		} catch {
			setKnownCookie(cookies, name, rawValue);
		}
	}

	return cookies;
}

module.exports = { JWT_KEY };

async function bootstrap() {
	// Initialize OIDC early so route priority behaves deterministically
	try {
		const initialized = await oidc.initializeOIDC({ jwtKey: JWT_KEY });
		if (initialized) {
			logger.info("OIDC enabled");
		} else {
			logger.info("OIDC not enabled");
		}
	} catch (err) {
		// Graceful degradation: do not prevent server start
		logger.error("OIDC initialization failed; continuing without OIDC.", err);
	}

	app.set("views", path.join(__dirname, "views"));
	app.set("view engine", "pug");

	// CRITICAL: Set trust proxy BEFORE any cookie/session middleware
	// This ensures Express correctly identifies HTTPS requests behind a reverse proxy
	if (process.env.REMOTE_HEADER_LOGIN || oidc.isOIDCEnabled()) {
		// Set trust proxy dynamically based on trustedProxyIPs, fallback to '1'
		if (trustedProxyIPs.some((ip) => ip)) {
			const trustProxyRanges = trustedProxyIPs.join(",");
			app.set("trust proxy", trustProxyRanges);
			logger.info(`Trust proxy enabled with IPs: ${trustProxyRanges}`);
		} else {
			logger.warn("No valid IPs in REVERSE_PROXY_WHITELIST. Falling back to trust proxy: 1.");
			app.set("trust proxy", 1);
		}
	}

	const routes = require("./routes/index");
	app.use(express.json());
	app.use(express.urlencoded({ extended: true }));
	app.use(express.static(path.join(__dirname, "public")));
	app.use(express.static(path.join(__dirname, "assets")));
	app.use((req, _res, next) => {
		req.cookies = parseCookies(req.headers.cookie);
		next();
	});

	app.use((req, res, next) => {
		let csrfToken = req.cookies?.[CSRF_COOKIE_NAME];
		if (typeof csrfToken !== "string" || csrfToken.length < 32) {
			csrfToken = generateCsrfToken();
			res.cookie(CSRF_COOKIE_NAME, csrfToken, {
				httpOnly: true,
				secure: req.secure,
				sameSite: "Strict",
				path: "/",
			});
		}
		res.locals.csrfToken = csrfToken;
		next();
	});

	app.use((req, res, next) => {
		if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
		const cookieToken = req.cookies?.[CSRF_COOKIE_NAME];
		const requestToken = req.get("x-csrf-token") || req.body?._csrf;

		if (!safeTokenCompare(cookieToken, requestToken)) {
			logger.warn("Rejected request due to invalid CSRF token", {
				method: req.method,
				path: req.path,
			});
			return res.status(403).send("Invalid CSRF token");
		}

		return next();
	});

	app.use(
		rateLimit({
			windowMs: 15 * 60 * 1000,
			max: process.env.RATE_LIMIT || 100,
			message: "Too many requests from this IP, please try again later.",
			standardHeaders: true,
			legacyHeaders: false,
			// Skip X-Forwarded-For validation when not behind a reverse proxy
			validate: { xForwardedForHeader: false },
		}),
	);

	app.use("/", routes);

	const sslCertPath = process.env.LURKER_SSL_CERT_PATH;
	const sslKeyPath = process.env.LURKER_SSL_KEY_PATH;

	if (sslCertPath && sslKeyPath) {
		try {
			const sslCert = fs.readFileSync(sslCertPath, "utf8");
			const sslKey = fs.readFileSync(sslKeyPath, "utf8");

			const httpsServer = https.createServer(
				{
					key: sslKey,
					cert: sslCert,
				},
				app,
			);

			const port = process.env.LURKER_PORT || 3000;
			httpsServer.listen(port, httpBinding, () => {
				logger.info(`HTTPS server started on port ${port}`);
			});
		} catch (err) {
			logger.error("Failed to load SSL certificate or key:", err.message);
			process.exit(1);
		}
	} else {
		logger.warn("SSL_CERT_PATH or SSL_KEY_PATH not provided. Falling back to HTTP.");
		const port = process.env.LURKER_PORT || 3000;
		const server = app.listen(port, httpBinding, () => {
			logger.info(`HTTP server started on port ${server.address().port}`);
		});
	}
}

bootstrap().catch((err) => {
	logger.error("Server startup failed", err);
	process.exit(1);
});
