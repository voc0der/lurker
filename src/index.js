const express = require("express");
const rateLimit = require("express-rate-limit");
const path = require("node:path");
const cookieParser = require("cookie-parser");
const https = require("https");
const fs = require("fs");
const logger = require("./logger");
const oidc = require("./oidc");

const app = express();
const hasher = new Bun.CryptoHasher("sha256", "secret-key");
const JWT_KEY = process.env.JWT_SECRET_KEY || hasher.update(Math.random().toString()).digest("hex");
const trustedProxyIPs = (process.env.REVERSE_PROXY_WHITELIST || "").split(",").map((ip) => ip.trim());
const httpBinding = process.env.HTTP_BINDING || "0.0.0.0";

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
	app.use(cookieParser());

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
