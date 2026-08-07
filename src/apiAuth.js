const crypto = require("node:crypto");
const logger = require("./logger");

// Loaded lazily so that importing the whitelist/key helpers does not open the
// sqlite database as a side effect.
function getDb() {
	return require("./db").db;
}

// The API is a separate, key-authenticated surface. It is gated by
// API_WHITELIST, which defaults to loopback only so that a fresh install never
// exposes it beyond the container/host it runs on.
const DEFAULT_API_WHITELIST = "127.0.0.1,::1";
const DISABLED_WHITELIST_VALUES = new Set(["off", "none", "disabled", "false"]);
const ANY_WHITELIST_VALUES = new Set(["*", "all", "any", "0.0.0.0/0", "::/0"]);
const API_KEY_BYTES = 32;
const API_KEY_PREFIX = "lurker_";

function normalizeIp(ip) {
	if (!ip || typeof ip !== "string") return "";
	const trimmed = ip.trim();
	// IPv4-mapped IPv6 (::ffff:10.2.5.50) is how a dual-stack listener reports
	// plain IPv4 peers; compare those as IPv4.
	if (trimmed.toLowerCase().startsWith("::ffff:")) return trimmed.slice(7);
	return trimmed;
}

function ipv4ToInt(ip) {
	const parts = ip.split(".");
	if (parts.length !== 4) return null;

	let value = 0;
	for (const part of parts) {
		if (!/^\d{1,3}$/.test(part)) return null;
		const octet = Number(part);
		if (octet > 255) return null;
		value = value * 256 + octet;
	}
	return value >>> 0;
}

function ipv6ToBigInt(ip) {
	const address = ip.split("%")[0];
	if (!address.includes(":")) return null;

	const halves = address.split("::");
	if (halves.length > 2) return null;

	const split = (part) => (part ? part.split(":") : []);
	let head = split(halves[0]);
	let tail = halves.length === 2 ? split(halves[1]) : [];

	// A trailing dotted quad (64:ff9b::1.2.3.4) fills the last two hextets.
	const groups = tail.length ? tail : head;
	if (groups.length && groups[groups.length - 1].includes(".")) {
		const embedded = ipv4ToInt(groups[groups.length - 1]);
		if (embedded === null) return null;
		const hextets = [
			(embedded >>> 16).toString(16),
			(embedded & 0xffff).toString(16),
		];
		if (tail.length) tail = tail.slice(0, -1).concat(hextets);
		else head = head.slice(0, -1).concat(hextets);
	}

	const missing = 8 - (head.length + tail.length);
	if (halves.length === 2 ? missing < 0 : missing !== 0) return null;
	const expanded =
		halves.length === 2
			? [...head, ...Array(missing).fill("0"), ...tail]
			: head;

	let value = 0n;
	for (const group of expanded) {
		if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
		value = (value << 16n) | BigInt(Number.parseInt(group, 16));
	}
	return value;
}

function matchesCidr(ip, entry) {
	const [network, bitsRaw] = entry.split("/");
	const bits = Number(bitsRaw);
	if (!Number.isInteger(bits) || bits < 0) return false;

	// An address and a range of different families never match.
	if (network.includes(":") || ip.includes(":")) {
		if (bits > 128) return false;
		const ipValue = ipv6ToBigInt(ip);
		const networkValue = ipv6ToBigInt(network);
		if (ipValue === null || networkValue === null) return false;

		const shift = BigInt(128 - bits);
		return ipValue >> shift === networkValue >> shift;
	}

	if (bits > 32) return false;
	const ipValue = ipv4ToInt(ip);
	const networkValue = ipv4ToInt(network);
	if (ipValue === null || networkValue === null) return false;
	if (bits === 0) return true;

	const mask = (0xffffffff << (32 - bits)) >>> 0;
	return (ipValue & mask) >>> 0 === (networkValue & mask) >>> 0;
}

function getApiWhitelistEntries() {
	const configured = process.env.API_WHITELIST;
	const raw =
		typeof configured === "string" && configured.trim()
			? configured
			: DEFAULT_API_WHITELIST;

	return raw
		.split(",")
		.map((entry) => normalizeIp(entry))
		.filter(Boolean);
}

function isApiWhitelisted(ip) {
	const address = normalizeIp(ip);
	if (!address) return false;

	const entries = getApiWhitelistEntries();
	if (
		entries.some((entry) => DISABLED_WHITELIST_VALUES.has(entry.toLowerCase()))
	)
		return false;

	return entries.some((entry) => {
		if (ANY_WHITELIST_VALUES.has(entry.toLowerCase())) return true;
		if (entry.includes("/")) return matchesCidr(address, entry);
		return entry.toLowerCase() === address.toLowerCase();
	});
}

// Deliberately the raw TCP peer, never X-Forwarded-For: a forwarded header is
// attacker-controlled, and the whitelist is the only thing standing between the
// internet and a key-guessing surface.
function getApiSourceIp(req) {
	return normalizeIp(req.socket?.remoteAddress || "");
}

function describeApiWhitelist() {
	const entries = getApiWhitelistEntries();
	const disabled = entries.some((entry) =>
		DISABLED_WHITELIST_VALUES.has(entry.toLowerCase()),
	);
	const unrestricted =
		!disabled &&
		entries.some((entry) => ANY_WHITELIST_VALUES.has(entry.toLowerCase()));

	return {
		configured: Boolean(process.env.API_WHITELIST?.trim()),
		entries,
		disabled,
		unrestricted,
		description: disabled
			? "disabled"
			: unrestricted
				? "any address (unrestricted)"
				: entries.join(", "),
	};
}

function generateApiKey() {
	return `${API_KEY_PREFIX}${crypto.randomBytes(API_KEY_BYTES).toString("base64url")}`;
}

function setUserApiKey(userId) {
	const apiKey = generateApiKey();
	getDb().query("UPDATE users SET apiKey = $apiKey WHERE id = $id").run({
		apiKey,
		id: userId,
	});
	return apiKey;
}

function clearUserApiKey(userId) {
	getDb()
		.query("UPDATE users SET apiKey = NULL WHERE id = $id")
		.run({ id: userId });
}

function extractApiKey(req) {
	const header = req.get("x-api-key");
	if (typeof header === "string" && header.trim()) return header.trim();

	const authorization = req.get("authorization");
	if (typeof authorization === "string") {
		const bearer = authorization.match(/^Bearer\s+(\S+)$/i);
		if (bearer) return bearer[1];
	}

	// Query fallback for feed readers and shell one-liners that cannot set
	// headers. Keys passed this way land in access logs, so headers are better.
	const query = req.query?.api_key ?? req.query?.key;
	if (typeof query === "string" && query.trim()) return query.trim();

	return "";
}

// Keys may arrive in the query string, so anything derived from the url has to
// be scrubbed before it reaches a log line or a feed's self link.
function redactApiKey(url) {
	return String(url ?? "").replace(
		/([?&](?:api_key|key)=)[^&#]*/gi,
		"$1[redacted]",
	);
}

function getUserByApiKey(apiKey) {
	if (!apiKey) return null;
	return (
		getDb()
			.query("SELECT * FROM users WHERE apiKey = $apiKey")
			.get({ apiKey }) || null
	);
}

// Middleware: the API only exists for whitelisted source addresses.
function requireApiAccess(req, res, next) {
	const sourceIp = getApiSourceIp(req);
	if (!isApiWhitelisted(sourceIp)) {
		logger.warn("Rejected API request from non-whitelisted source", {
			sourceIp,
			path: redactApiKey(req.originalUrl),
		});
		return res.status(403).json({
			error: "forbidden",
			message:
				"API access is not enabled for this source address. Add it to API_WHITELIST.",
			source: sourceIp,
		});
	}

	req.apiSourceIp = sourceIp;
	return next();
}

// Middleware: resolve the per-user API key into req.user.
function requireApiKey(req, res, next) {
	const apiKey = extractApiKey(req);
	if (!apiKey) {
		return res.status(401).json({
			error: "unauthorized",
			message:
				"Missing API key. Send it as X-API-Key, Authorization: Bearer, or ?api_key=.",
		});
	}

	let user;
	try {
		user = getUserByApiKey(apiKey);
	} catch (error) {
		logger.error("Failed to look up API key", error);
		return res.status(500).json({
			error: "internal_error",
			message: "Failed to validate API key.",
		});
	}

	if (!user) {
		logger.warn("Rejected API request with unknown key", {
			sourceIp: req.apiSourceIp || getApiSourceIp(req),
			path: redactApiKey(req.originalUrl),
		});
		return res
			.status(401)
			.json({ error: "unauthorized", message: "Invalid API key." });
	}

	req.user = user;
	return next();
}

module.exports = {
	clearUserApiKey,
	describeApiWhitelist,
	extractApiKey,
	generateApiKey,
	getApiSourceIp,
	getApiWhitelistEntries,
	isApiWhitelisted,
	redactApiKey,
	requireApiAccess,
	requireApiKey,
	setUserApiKey,
};
