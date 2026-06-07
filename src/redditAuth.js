const MAX_REDDIT_AUTH_INPUT_LENGTH = 20000;
const VALID_REDDIT_AUTH_TYPES = new Set([
	"auto",
	"bearer",
	"cookie",
	"reddit_session",
]);
const COOKIE_NAME_PATTERN = /^[A-Za-z0-9._-]+$/;
const IGNORED_COOKIE_EXPORT_KEYS = new Set([
	"domain",
	"expires",
	"hostonly",
	"httponly",
	"name",
	"path",
	"priority",
	"samesite",
	"secure",
	"session",
	"size",
	"source_port",
	"source_scheme",
	"value",
]);

function stripWrappingQuotes(value) {
	const trimmed = String(value || "").trim();
	if (trimmed.length < 2) return trimmed;

	const first = trimmed[0];
	const last = trimmed[trimmed.length - 1];
	if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
		return trimmed.slice(1, -1).trim();
	}

	return trimmed;
}

function assertHeaderSafe(value) {
	if (/[\0-\x08\x0A-\x1F\x7F]/.test(value)) {
		throw new Error("Reddit credential contains invalid header characters");
	}
}

function cleanHeaderValue(value) {
	const cleaned = stripWrappingQuotes(value);
	assertHeaderSafe(cleaned);
	return cleaned;
}

function normalizeAuthorization(value, { allowBare = false } = {}) {
	const cleaned = cleanHeaderValue(value);
	const authorizationMatch = cleaned.match(/^Authorization\s*:\s*(.+)$/i);
	const authValue = authorizationMatch ? authorizationMatch[1].trim() : cleaned;
	const bearerMatch = authValue.match(/^Bearer\s+(.+)$/i);
	const token = bearerMatch
		? bearerMatch[1].trim()
		: allowBare
			? authValue
			: "";

	if (!token) return null;
	if (/\s/.test(token)) {
		throw new Error("Bearer token must not contain whitespace");
	}

	assertHeaderSafe(token);
	return `Bearer ${token}`;
}

function parseCookiePair(name, value) {
	const cookieName = String(name || "").trim();
	if (!COOKIE_NAME_PATTERN.test(cookieName)) return null;
	if (IGNORED_COOKIE_EXPORT_KEYS.has(cookieName.toLowerCase())) return null;

	const cookieValue = cleanHeaderValue(value);
	if (!cookieValue || cookieValue.includes(";")) return null;

	return {
		name: cookieName,
		header: `${cookieName}=${cookieValue}`,
	};
}

function addCookieHeader(value, cookiePairs) {
	let raw = String(value || "").trim();
	const headerMatch = raw.match(/^Cookie\s*:\s*(.+)$/i);
	if (headerMatch) {
		raw = headerMatch[1].trim();
	}

	let added = false;
	for (const part of raw.split(";")) {
		const trimmed = part.trim();
		if (!trimmed || !trimmed.includes("=")) continue;

		const [name, ...valueParts] = trimmed.split("=");
		const parsed = parseCookiePair(name, valueParts.join("="));
		if (!parsed) continue;

		cookiePairs.set(parsed.name, parsed.header);
		added = true;
	}

	return added;
}

function collapseCookieHeaderInput(value) {
	let raw = String(value || "").trim();
	const headerMatch = raw.match(/^Cookie\s*:\s*([\s\S]+)$/i);
	if (headerMatch) {
		raw = headerMatch[1].trim();
	}

	return raw.replace(/[\r\n]+[ \t]*/g, "");
}

function addCookieLine(line, cookiePairs) {
	const trimmed = String(line || "").trim();
	if (!trimmed) return false;
	if (trimmed.includes("=")) {
		return addCookieHeader(trimmed, cookiePairs);
	}

	const colonMatch = trimmed.match(/^([A-Za-z0-9._-]+)\s*:\s*(.+)$/);
	if (!colonMatch) return false;

	const parsed = parseCookiePair(colonMatch[1], colonMatch[2]);
	if (!parsed) return false;

	cookiePairs.set(parsed.name, parsed.header);
	return true;
}

function cookieHeaderFromPairs(cookiePairs) {
	if (cookiePairs.size === 0) return null;
	return Array.from(cookiePairs.values()).join("; ");
}

function normalizeCookieInput(input) {
	const cookiePairs = new Map();
	const raw = String(input || "").trim();
	const multilineCookieHeader =
		/[\r\n]/.test(raw) && (/^Cookie\s*:/i.test(raw) || raw.includes(";"));

	if (multilineCookieHeader) {
		addCookieHeader(collapseCookieHeaderInput(raw), cookiePairs);
	} else {
		for (const line of raw.split(/\r?\n/)) {
			addCookieLine(line, cookiePairs);
		}
	}

	const cookie = cookieHeaderFromPairs(cookiePairs);
	if (!cookie) {
		throw new Error("Reddit cookie input must include cookie name/value pairs");
	}

	return cookie;
}

function normalizeRedditAuthInput(input, type = "auto") {
	const raw = String(input || "").trim();
	if (!raw) return null;
	if (raw.length > MAX_REDDIT_AUTH_INPUT_LENGTH) {
		throw new Error("Reddit credential is too long");
	}

	const authType = VALID_REDDIT_AUTH_TYPES.has(type) ? type : "auto";

	if (authType === "bearer") {
		return { authorization: normalizeAuthorization(raw, { allowBare: true }) };
	}

	if (authType === "cookie") {
		return { cookie: normalizeCookieInput(raw) };
	}

	if (authType === "reddit_session") {
		if (raw.includes("=") || /^Cookie\s*:/i.test(raw)) {
			return { cookie: normalizeCookieInput(raw) };
		}

		const parsed = parseCookiePair("reddit_session", raw);
		if (!parsed) {
			throw new Error("Reddit session cookie value is invalid");
		}
		return { cookie: parsed.header };
	}

	if (/[\r\n]/.test(raw) && (/^Cookie\s*:/i.test(raw) || raw.includes(";"))) {
		return { cookie: normalizeCookieInput(raw) };
	}

	const headers = {};
	const cookiePairs = new Map();

	for (const line of raw.split(/\r?\n/)) {
		const trimmed = line.trim();
		if (!trimmed) continue;

		const authorizationMatch = trimmed.match(/^Authorization\s*:\s*(.+)$/i);
		if (authorizationMatch) {
			headers.authorization = normalizeAuthorization(authorizationMatch[1]);
			continue;
		}

		const bearer = normalizeAuthorization(trimmed);
		if (bearer) {
			headers.authorization = bearer;
			continue;
		}

		addCookieLine(trimmed, cookiePairs);
	}

	const cookie = cookieHeaderFromPairs(cookiePairs);
	if (cookie) {
		headers.cookie = cookie;
	}

	if (!headers.authorization && !headers.cookie) {
		throw new Error(
			"Paste a Bearer authorization header, Cookie header, or cookie name/value pairs",
		);
	}

	return headers;
}

function normalizeStoredRedditAuthHeaders(value) {
	if (!value) return null;

	let parsed = value;
	if (typeof value === "string") {
		try {
			parsed = JSON.parse(value);
		} catch {
			return normalizeRedditAuthInput(value);
		}
	}

	if (!parsed || typeof parsed !== "object") return null;

	const headers = {};
	if (parsed.authorization) {
		headers.authorization = normalizeAuthorization(parsed.authorization);
	}
	if (parsed.cookie) {
		headers.cookie = normalizeCookieInput(parsed.cookie);
	}

	if (!headers.authorization && !headers.cookie) return null;
	return headers;
}

function serializeRedditAuthHeaders(headers) {
	const normalized = normalizeStoredRedditAuthHeaders(headers);
	return normalized ? JSON.stringify(normalized) : null;
}

function getRedditAuthHeaders(value) {
	return normalizeStoredRedditAuthHeaders(value);
}

function describeRedditAuthHeaders(value) {
	const headers = normalizeStoredRedditAuthHeaders(value);
	if (!headers) return "not configured";

	const parts = [];
	if (headers.authorization) {
		parts.push("bearer token");
	}
	if (headers.cookie) {
		const cookieNames = headers.cookie
			.split(";")
			.map((part) => part.trim().split("=")[0])
			.filter(Boolean);
		parts.push(`cookies (${cookieNames.join(", ")})`);
	}

	return parts.join(" and ");
}

function getRedditAuthStatus(value) {
	const headers = normalizeStoredRedditAuthHeaders(value);
	return {
		configured: Boolean(headers),
		description: headers
			? describeRedditAuthHeaders(headers)
			: "not configured",
	};
}

module.exports = {
	describeRedditAuthHeaders,
	getRedditAuthHeaders,
	getRedditAuthStatus,
	normalizeRedditAuthInput,
	serializeRedditAuthHeaders,
};
