const express = require("express");
const rateLimit = require("express-rate-limit");
const geddit = require("../geddit.js");
const { db } = require("../db");
const logger = require("../logger");
const {
	getApiSourceIp,
	redactApiKey,
	requireApiAccess,
	requireApiKey,
} = require("../apiAuth");
const { getRedditAuthHeaders } = require("../redditAuth");
const { unescapeSelfText } = require("../utils/redditHtml");
const {
	buildCommentsFeed,
	buildSearchFeed,
	buildSubmissionsFeed,
	flattenComments,
} = require("../utils/redditFeed");

const router = express.Router();
const G = new geddit.Geddit();

const ALLOWED_SORTS = new Set([
	"best",
	"controversial",
	"hot",
	"new",
	"rising",
	"top",
]);
const ALLOWED_TIMES = new Set(["hour", "day", "week", "month", "year", "all"]);
const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 25;
// Feed pollers hit this far more often than a browsing human, so the API gets
// its own budget instead of sharing the UI's 100/15min.
const API_RATE_LIMIT = Number(process.env.API_RATE_LIMIT) || 600;

router.use(requireApiAccess);

router.use(
	rateLimit({
		windowMs: 15 * 60 * 1000,
		max: API_RATE_LIMIT,
		standardHeaders: true,
		legacyHeaders: false,
		// Key on the real peer, matching the whitelist. req.ip would honour
		// X-Forwarded-For, letting a caller rotate the header to evade the limit.
		keyGenerator: (req) => req.apiSourceIp || getApiSourceIp(req),
		validate: { xForwardedForHeader: false, keyGeneratorIpFallback: false },
		message: {
			error: "rate_limited",
			message: "Too many API requests, please try again later.",
		},
	}),
);

// Unauthenticated (but still whitelisted) probe so scripts can verify their
// address passes the gate before worrying about keys.
router.get("/health", (req, res) => {
	res.json({ ok: true, service: "lurker", source: req.apiSourceIp });
});

router.use(requireApiKey);

function firstValue(value) {
	return Array.isArray(value) ? value[0] : value;
}

function sanitizeSubredditPath(value) {
	const raw = firstValue(value);
	if (typeof raw !== "string") return "";
	return raw
		.split("+")
		.map((part) => part.trim().replace(/^r\//i, ""))
		.filter((part) => /^[A-Za-z0-9_]{1,21}$/.test(part))
		.join("+");
}

function sanitizeThingId(value) {
	const raw = firstValue(value);
	if (typeof raw !== "string") return "";
	const trimmed = raw.trim().replace(/^t3_/, "");
	return /^[A-Za-z0-9_]+$/.test(trimmed) ? trimmed : "";
}

function sanitizeSort(value, fallback = "hot") {
	const raw = firstValue(value);
	if (typeof raw !== "string") return fallback;
	const sort = raw.trim().toLowerCase();
	return ALLOWED_SORTS.has(sort) ? sort : fallback;
}

// Only forward listing params Reddit understands; anything else is dropped so
// callers cannot smuggle arbitrary query strings upstream.
function listingOptions(query = {}) {
	const options = {};

	const limit = Number.parseInt(firstValue(query.limit), 10);
	options.limit = Number.isInteger(limit)
		? Math.min(Math.max(limit, 1), MAX_LIMIT)
		: DEFAULT_LIMIT;

	const after = firstValue(query.after);
	if (typeof after === "string" && /^[A-Za-z0-9_]+$/.test(after)) {
		options.after = after;
	}

	const before = firstValue(query.before);
	if (typeof before === "string" && /^[A-Za-z0-9_]+$/.test(before)) {
		options.before = before;
	}

	const time = firstValue(query.t);
	if (typeof time === "string" && ALLOWED_TIMES.has(time.toLowerCase())) {
		options.t = time.toLowerCase();
	}

	return options;
}

function getRedditRequestOptions(req) {
	try {
		const authHeaders = getRedditAuthHeaders(req.user?.redditAuthHeaders);
		return authHeaders ? { authHeaders } : {};
	} catch (err) {
		logger.warn("Ignoring invalid stored Reddit credential", {
			userId: req.user?.id,
			error: err?.message || String(err),
		});
		return {};
	}
}

// The self link is stored by feed readers, so never echo the key back into it.
function getSelfUrl(req) {
	// req.secure honours the app's trust-proxy config, so the self link stays
	// https when lurker sits behind a TLS-terminating reverse proxy.
	const protocol = req.secure || req.socket?.encrypted ? "https" : "http";
	const host = req.get("host") || "localhost";
	const url = new URL(req.originalUrl, `${protocol}://${host}`);
	url.searchParams.delete("api_key");
	url.searchParams.delete("key");
	return url.toString();
}

function sendFeed(res, xml) {
	res.setHeader("Content-Type", "application/atom+xml; charset=utf-8");
	res.setHeader("Cache-Control", "no-store");
	res.send(xml);
}

function upstreamFailure(res) {
	return res.status(502).json({
		error: "upstream_error",
		message: "Reddit request failed or returned no data.",
	});
}

function serializePost(post) {
	const data = post?.data || post;
	if (!data) return null;

	return {
		id: data.id,
		name: data.name,
		title: data.title,
		author: data.author,
		subreddit: data.subreddit,
		permalink: data.permalink
			? `https://www.reddit.com${data.permalink}`
			: null,
		url: data.url_overridden_by_dest || data.url || null,
		domain: data.domain || null,
		created_utc: data.created_utc,
		created_iso: Number.isFinite(Number(data.created_utc))
			? new Date(Number(data.created_utc) * 1000).toISOString()
			: null,
		score: data.score,
		upvote_ratio: data.upvote_ratio,
		num_comments: data.num_comments,
		over_18: Boolean(data.over_18),
		spoiler: Boolean(data.spoiler),
		stickied: Boolean(data.stickied),
		is_self: Boolean(data.is_self),
		link_flair_text: data.link_flair_text || null,
		thumbnail: /^https?:\/\//i.test(data.thumbnail || "")
			? data.thumbnail
			: null,
		selftext: data.selftext || "",
		selftext_html: data.selftext_html || null,
	};
}

function serializeComment(comment) {
	const data = comment?.data || comment;
	if (!data) return null;

	return {
		id: data.id,
		name: data.name,
		author: data.author,
		body: data.body || "",
		body_html: data.body_html || null,
		score: data.score,
		created_utc: data.created_utc,
		created_iso: Number.isFinite(Number(data.created_utc))
			? new Date(Number(data.created_utc) * 1000).toISOString()
			: null,
		depth: data.depth ?? null,
		is_submitter: Boolean(data.is_submitter),
		stickied: Boolean(data.stickied),
		permalink: data.permalink
			? `https://www.reddit.com${data.permalink}`
			: null,
	};
}

function wantsRaw(req) {
	const raw = firstValue(req.query?.raw);
	return raw === "1" || raw === "true";
}

// Registers .rss/.atom/.json variants plus a bare path defaulting to JSON.
function registerFormats(path, handler) {
	const wrap = (format) => async (req, res) => {
		try {
			await handler(req, res, format);
		} catch (err) {
			logger.error(`API request failed: ${redactApiKey(req.originalUrl)}`, err);
			if (!res.headersSent) {
				res.status(500).json({
					error: "internal_error",
					message: "Failed to handle API request.",
				});
			}
		}
	};

	router.get(`${path}.rss`, wrap("rss"));
	router.get(`${path}.atom`, wrap("rss"));
	router.get(`${path}.json`, wrap("json"));
	router.get(path, (req, res) => {
		const format = firstValue(req.query?.format);
		const wanted = format === "rss" || format === "atom" ? "rss" : "json";
		return wrap(wanted)(req, res);
	});
}

function getSubscribedMulti(userId) {
	const subs = db
		.query("SELECT subreddit FROM subscriptions WHERE user_id = $id")
		.all({ id: userId });
	return (
		subs
			.map((sub) => sanitizeSubredditPath(sub.subreddit))
			.filter(Boolean)
			.join("+") || "all"
	);
}

async function respondWithSubmissions(req, res, format, { subreddit, sort }) {
	const options = listingOptions(req.query);
	const requestOptions = getRedditRequestOptions(req);

	const needsAbout = format === "rss" && !subreddit.includes("+");
	const [listing, about] = await Promise.all([
		G.getSubmissions(sort, subreddit, options, requestOptions),
		needsAbout
			? G.getSubreddit(subreddit, requestOptions)
			: Promise.resolve(null),
	]);

	if (!listing?.posts) return upstreamFailure(res);

	// Feed builders decode `selftext_html` themselves; decoding here too would
	// unescape the post body twice and turn quoted markup into live markup.
	if (format === "rss") {
		return sendFeed(
			res,
			buildSubmissionsFeed({
				posts: listing.posts,
				subreddit,
				sort,
				about,
				selfUrl: getSelfUrl(req),
			}),
		);
	}

	listing.posts.forEach(unescapeSelfText);
	return res.json({
		kind: "listing",
		subreddit,
		sort,
		after: listing.after || null,
		count: listing.posts.length,
		posts: wantsRaw(req)
			? listing.posts
			: listing.posts.map(serializePost).filter(Boolean),
	});
}

// GET /api/v1/whoami
router.get("/whoami", (req, res) => {
	res.json({
		id: req.user.id,
		username: req.user.username,
		isAdmin: Boolean(req.user.isAdmin),
		source: req.apiSourceIp,
	});
});

// GET /api/v1/subscriptions
router.get("/subscriptions", (req, res) => {
	const subs = db
		.query(
			"SELECT subreddit FROM subscriptions WHERE user_id = $id ORDER BY LOWER(subreddit)",
		)
		.all({ id: req.user.id })
		.map((sub) => sub.subreddit);

	res.json({ count: subs.length, subscriptions: subs });
});

// GET /api/v1/home[.rss|.json] - the caller's subscription multireddit
registerFormats("/home", async (req, res, format) => {
	const subreddit = getSubscribedMulti(req.user.id);
	const sort = sanitizeSort(req.query?.sort, "hot");
	return respondWithSubmissions(req, res, format, { subreddit, sort });
});

// GET /api/v1/comments/:id[.rss|.json]
registerFormats("/comments/:id", async (req, res, format) => {
	const id = sanitizeThingId(req.params.id);
	if (!id) {
		return res
			.status(400)
			.json({ error: "bad_request", message: "Invalid submission id." });
	}

	const options = listingOptions(req.query);
	const response = await G.getSubmissionComments(
		id,
		{ limit: options.limit ?? DEFAULT_LIMIT },
		getRedditRequestOptions(req),
	);

	if (!response?.submission) return upstreamFailure(res);

	if (format === "rss") {
		return sendFeed(
			res,
			buildCommentsFeed({
				submission: response.submission,
				comments: response.comments,
				selfUrl: getSelfUrl(req),
				id,
			}),
		);
	}

	unescapeSelfText(response.submission);
	return res.json({
		kind: "comments",
		id,
		submission: wantsRaw(req)
			? response.submission
			: serializePost(response.submission),
		comments: wantsRaw(req)
			? response.comments
			: flattenComments(response.comments)
					.map(serializeComment)
					.filter(Boolean),
	});
});

// GET /api/v1/search[.rss|.json]?q=...&subreddit=...
registerFormats("/search", async (req, res, format) => {
	const q = firstValue(req.query?.q);
	if (typeof q !== "string" || !q.trim()) {
		return res
			.status(400)
			.json({ error: "bad_request", message: "Missing search query `q`." });
	}

	const subreddit = sanitizeSubredditPath(req.query?.subreddit);
	const options = listingOptions(req.query);
	const sort = firstValue(req.query?.sort);
	if (typeof sort === "string" && /^[a-z]{1,20}$/.test(sort)) {
		options.sort = sort;
	}
	if (subreddit) {
		options.restrict_sr = "on";
		// searchAll defaults to type=sr,link,user; without this the results mix
		// subreddits and users into what callers read as a post listing.
		options.type = "link";
	}

	const requestOptions = getRedditRequestOptions(req);
	const results = subreddit
		? await G.searchAll(q.trim(), subreddit, options, requestOptions)
		: await G.searchSubmissions(q.trim(), options, requestOptions);

	if (!results?.items) return upstreamFailure(res);

	if (format === "rss") {
		return sendFeed(
			res,
			buildSearchFeed({
				items: results.items,
				query: q.trim(),
				subreddit,
				selfUrl: getSelfUrl(req),
			}),
		);
	}

	results.items.forEach(unescapeSelfText);
	return res.json({
		kind: "search",
		query: q.trim(),
		subreddit: subreddit || null,
		after: results.after || null,
		count: results.items.length,
		results: wantsRaw(req)
			? results.items
			: results.items.map(serializePost).filter(Boolean),
	});
});

// GET /api/v1/r/:subreddit/about[.json] - json only, there is no feed form
async function respondWithAbout(req, res) {
	const subreddit = sanitizeSubredditPath(req.params.subreddit);
	if (!subreddit || subreddit.includes("+")) {
		return res
			.status(400)
			.json({ error: "bad_request", message: "Invalid subreddit." });
	}

	try {
		const about = await G.getSubreddit(subreddit, getRedditRequestOptions(req));
		if (!about) return upstreamFailure(res);

		if (wantsRaw(req)) return res.json(about);
		return res.json({
			kind: "about",
			name: about.display_name || subreddit,
			title: about.title || null,
			public_description: about.public_description || null,
			subscribers: about.subscribers ?? null,
			active_user_count: about.active_user_count ?? null,
			over18: Boolean(about.over18),
			created_utc: about.created_utc ?? null,
			url: about.url ? `https://www.reddit.com${about.url}` : null,
		});
	} catch (err) {
		logger.error(`API request failed: ${redactApiKey(req.originalUrl)}`, err);
		return res.status(500).json({
			error: "internal_error",
			message: "Failed to handle API request.",
		});
	}
}

router.get("/r/:subreddit/about", respondWithAbout);
router.get("/r/:subreddit/about.json", respondWithAbout);

// GET /api/v1/r/:subreddit/:sort[.rss|.json]
registerFormats("/r/:subreddit/:sort", async (req, res, format) => {
	const subreddit = sanitizeSubredditPath(req.params.subreddit);
	if (!subreddit) {
		return res
			.status(400)
			.json({ error: "bad_request", message: "Invalid subreddit." });
	}

	// A sort in the path is explicit, so reject an unknown one rather than
	// quietly serving a different listing than the caller asked for.
	const sort = firstValue(req.params.sort);
	if (typeof sort !== "string" || !ALLOWED_SORTS.has(sort.toLowerCase())) {
		return res.status(400).json({
			error: "bad_request",
			message: `Unknown sort "${sort}". Use one of: ${[...ALLOWED_SORTS].join(", ")}.`,
		});
	}

	return respondWithSubmissions(req, res, format, {
		subreddit,
		sort: sort.toLowerCase(),
	});
});

// GET /api/v1/r/:subreddit[.rss|.json]
registerFormats("/r/:subreddit", async (req, res, format) => {
	const subreddit = sanitizeSubredditPath(req.params.subreddit);
	if (!subreddit) {
		return res
			.status(400)
			.json({ error: "bad_request", message: "Invalid subreddit." });
	}
	return respondWithSubmissions(req, res, format, {
		subreddit,
		sort: sanitizeSort(req.query?.sort),
	});
});

router.use((req, res) => {
	res.status(404).json({
		error: "not_found",
		message: `Unknown API endpoint: ${req.method} ${redactApiKey(req.originalUrl)}`,
	});
});

module.exports = router;
