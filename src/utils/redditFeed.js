const he = require("he");

// Recreates the Atom documents Reddit serves at /r/<sub>/<sort>.rss and
// /comments/<id>.rss, built from the JSON listings lurker already fetches, so
// feed consumers can poll lurker instead of hammering reddit.com directly.
const REDDIT_BASE = "https://www.reddit.com";
const REDDIT_ICON = "https://www.redditstatic.com/icon.png/";
const INVALID_XML_CHARS = /[\0-\x08\x0B\x0C\x0E-\x1F]/g;

function escapeXml(value) {
	return String(value ?? "")
		.replace(INVALID_XML_CHARS, "")
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&apos;");
}

// Escaping applied *inside* <content type="html">, before the whole blob is XML
// escaped. Reddit double-escapes the same way (&amp;quot; in raw feed bytes).
function escapeHtml(value) {
	return String(value ?? "")
		.replace(INVALID_XML_CHARS, "")
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;");
}

function toFeedDate(value) {
	let date;
	if (value instanceof Date) {
		date = value;
	} else if (typeof value === "number" && Number.isFinite(value)) {
		// Reddit timestamps are epoch seconds.
		date = new Date(value * 1000);
	} else {
		date = new Date();
	}
	if (Number.isNaN(date.getTime())) date = new Date();
	return date.toISOString().replace(/\.\d{3}Z$/, "+00:00");
}

function redditUrl(pathOrUrl) {
	if (!pathOrUrl || typeof pathOrUrl !== "string") return "";
	if (/^https?:\/\//i.test(pathOrUrl)) return pathOrUrl;
	return `${REDDIT_BASE}${pathOrUrl.startsWith("/") ? "" : "/"}${pathOrUrl}`;
}

function decodeUrl(value) {
	// Reddit JSON returns preview/media urls with HTML-encoded separators.
	return typeof value === "string" ? value.replace(/&amp;/g, "&") : "";
}

function getSubmissionData(post) {
	const data = post?.data && typeof post.data === "object" ? post.data : post;
	return data && typeof data === "object" ? data : null;
}

function authorUrl(author) {
	return `${REDDIT_BASE}/user/${encodeURIComponent(author)}`;
}

function feedThumbnail(post) {
	const preview = post?.preview?.images?.[0];
	if (preview) {
		const resolutions = Array.isArray(preview.resolutions)
			? preview.resolutions
			: [];
		const best = resolutions.length
			? resolutions[resolutions.length - 1]
			: null;
		const url = decodeUrl(best?.url || preview.source?.url);
		if (url) return url;
	}

	const thumbnail = post?.thumbnail;
	if (typeof thumbnail === "string" && /^https?:\/\//i.test(thumbnail)) {
		return decodeUrl(thumbnail);
	}

	return "";
}

function submittedByHtml(post) {
	const author = post.author || "[deleted]";
	const permalink = redditUrl(post.permalink);
	const linkUrl =
		redditUrl(post.url_overridden_by_dest || post.url) || permalink;

	return [
		" submitted by ",
		`<a href="${escapeHtml(authorUrl(author))}"> /u/${escapeHtml(author)} </a>`,
		"<br/>",
		`<span><a href="${escapeHtml(linkUrl)}">[link]</a></span>`,
		`<span><a href="${escapeHtml(permalink)}">[comments]</a></span>`,
	].join(" ");
}

function submissionContentHtml(post) {
	const submitted = submittedByHtml(post);
	const selfHtml = post.selftext_html ? he.decode(post.selftext_html) : "";
	if (selfHtml) {
		return `${selfHtml}${submitted}`;
	}

	const thumbnail = feedThumbnail(post);
	if (!thumbnail) return submitted;

	const permalink = redditUrl(post.permalink);
	const title = escapeHtml(post.title || "");
	return [
		"<table> <tr><td>",
		`<a href="${escapeHtml(permalink)}">`,
		`<img src="${escapeHtml(thumbnail)}" alt="${title}" title="${title}" />`,
		"</a>",
		"</td><td>",
		submitted,
		"</td></tr></table>",
	].join(" ");
}

function submissionEntry(post) {
	const data = getSubmissionData(post);
	if (!data) return null;

	const author = data.author || "[deleted]";
	const subreddit = data.subreddit || "";
	const created = Number(data.created_utc);

	return {
		id: data.name || (data.id ? `t3_${data.id}` : redditUrl(data.permalink)),
		title: data.title || "",
		author,
		authorUri: authorUrl(author),
		link: redditUrl(data.permalink),
		category: subreddit,
		thumbnail: feedThumbnail(data),
		content: submissionContentHtml(data),
		updated: created,
		published: created,
	};
}

function commentContentHtml(comment, submissionTitle) {
	const author = comment.author || "[deleted]";
	const permalink = redditUrl(comment.permalink);
	const bodyHtml = comment.body_html
		? he.decode(comment.body_html)
		: `<div class="md"><p>${escapeHtml(comment.body || "")}</p></div>`;

	return [
		bodyHtml,
		" submitted by ",
		`<a href="${escapeHtml(authorUrl(author))}"> /u/${escapeHtml(author)} </a>`,
		`to <a href="${escapeHtml(redditUrl(comment.link_permalink || permalink))}">${escapeHtml(submissionTitle || "")}</a>`,
		"<br/>",
		`<span><a href="${escapeHtml(permalink)}">[link]</a></span>`,
	].join(" ");
}

function commentEntry(comment, submissionTitle) {
	const data = getSubmissionData(comment);
	if (!data || !data.id) return null;

	const author = data.author || "[deleted]";
	const created = Number(data.created_utc);

	return {
		id: data.name || `t1_${data.id}`,
		title: `/u/${author} on ${submissionTitle || ""}`.trim(),
		author,
		authorUri: authorUrl(author),
		link: redditUrl(data.permalink),
		category: data.subreddit || "",
		thumbnail: "",
		content: commentContentHtml(data, submissionTitle),
		updated: created,
		published: created,
	};
}

// Reddit's comment feed is flat; listings nest replies under `data.replies`.
function flattenComments(children, out = []) {
	if (!Array.isArray(children)) return out;

	for (const child of children) {
		if (!child || child.kind === "more") continue;
		const data = child.data || child;
		if (!data) continue;

		out.push(child);
		const replies = data.replies?.data?.children;
		if (Array.isArray(replies)) flattenComments(replies, out);
	}

	return out;
}

function renderEntry(entry) {
	const lines = [
		"<entry>",
		"<author>",
		`<name>/u/${escapeXml(entry.author)}</name>`,
		`<uri>${escapeXml(entry.authorUri)}</uri>`,
		"</author>",
	];

	if (entry.category) {
		lines.push(
			`<category term="${escapeXml(entry.category)}" label="r/${escapeXml(entry.category)}"/>`,
		);
	}

	lines.push(`<content type="html">${escapeXml(entry.content)}</content>`);
	lines.push(`<id>${escapeXml(entry.id)}</id>`);

	if (entry.thumbnail) {
		lines.push(`<media:thumbnail url="${escapeXml(entry.thumbnail)}"/>`);
	}

	lines.push(`<link href="${escapeXml(entry.link)}"/>`);
	lines.push(`<updated>${toFeedDate(entry.updated)}</updated>`);
	lines.push(`<published>${toFeedDate(entry.published)}</published>`);
	lines.push(`<title>${escapeXml(entry.title)}</title>`);
	lines.push("</entry>");

	return lines.join("\n");
}

function latestTimestamp(entries) {
	const timestamps = entries
		.map((entry) => Number(entry.updated))
		.filter((value) => Number.isFinite(value) && value > 0);
	return timestamps.length ? Math.max(...timestamps) : new Date();
}

function renderAtomFeed({
	id,
	title,
	subtitle,
	category,
	selfUrl,
	alternateUrl,
	icon = REDDIT_ICON,
	logo,
	entries = [],
}) {
	const lines = [
		'<?xml version="1.0" encoding="UTF-8"?>',
		'<feed xmlns="http://www.w3.org/2005/Atom" xmlns:media="http://search.yahoo.com/mrss/">',
	];

	if (category) {
		lines.push(
			`<category term="${escapeXml(category)}" label="r/${escapeXml(category)}"/>`,
		);
	}

	lines.push(`<updated>${toFeedDate(latestTimestamp(entries))}</updated>`);
	lines.push(`<icon>${escapeXml(icon)}</icon>`);
	lines.push(`<id>${escapeXml(id)}</id>`);

	if (selfUrl) {
		lines.push(
			`<link rel="self" href="${escapeXml(selfUrl)}" type="application/atom+xml"/>`,
		);
	}
	if (alternateUrl) {
		lines.push(
			`<link rel="alternate" href="${escapeXml(alternateUrl)}" type="text/html"/>`,
		);
	}
	if (logo) {
		lines.push(`<logo>${escapeXml(logo)}</logo>`);
	}
	if (subtitle) {
		lines.push(`<subtitle>${escapeXml(subtitle)}</subtitle>`);
	}

	lines.push(`<title>${escapeXml(title)}</title>`);

	for (const entry of entries) {
		lines.push(renderEntry(entry));
	}

	lines.push("</feed>");
	return `${lines.join("\n")}\n`;
}

const SORT_TITLES = {
	best: "best submissions",
	controversial: "controversial submissions",
	hot: "hot submissions",
	new: "newest submissions",
	rising: "rising submissions",
	top: "top submissions",
};

function buildSubmissionsFeed({
	posts = [],
	subreddit = "",
	sort = "hot",
	about = null,
	selfUrl = "",
	title = "",
}) {
	const entries = posts.map(submissionEntry).filter(Boolean);
	const feedPath = subreddit ? `/r/${subreddit}/${sort}.rss` : `/${sort}.rss`;
	const alternatePath = subreddit ? `/r/${subreddit}/${sort}` : `/${sort}`;
	const sortTitle = SORT_TITLES[sort] || `${sort} submissions`;
	const isMulti = subreddit.includes("+");

	return renderAtomFeed({
		id: feedPath,
		title: title || (subreddit ? `${sortTitle} : ${subreddit}` : sortTitle),
		subtitle: isMulti ? "" : about?.public_description || about?.title || "",
		category: isMulti ? "" : subreddit,
		selfUrl,
		alternateUrl: redditUrl(alternatePath),
		logo: isMulti ? "" : decodeUrl(about?.icon_img || about?.community_icon),
		entries,
	});
}

function buildCommentsFeed({
	submission = null,
	comments = [],
	selfUrl = "",
	id = "",
}) {
	const submissionData = getSubmissionData(submission);
	const submissionTitle = submissionData?.title || "";
	const subreddit = submissionData?.subreddit || "";
	const permalink = redditUrl(submissionData?.permalink || `/comments/${id}`);
	const entries = flattenComments(comments)
		.map((comment) => commentEntry(comment, submissionTitle))
		.filter(Boolean);

	return renderAtomFeed({
		id: `/comments/${id}.rss`,
		title: submissionTitle
			? `comments for ${submissionTitle}`
			: `comments for ${id}`,
		subtitle: "",
		category: subreddit,
		selfUrl,
		alternateUrl: permalink,
		entries,
	});
}

function buildSearchFeed({
	items = [],
	query = "",
	subreddit = "",
	selfUrl = "",
}) {
	const entries = items.map(submissionEntry).filter(Boolean);
	const searchPath = subreddit
		? `/r/${subreddit}/search.rss?q=${encodeURIComponent(query)}`
		: `/search.rss?q=${encodeURIComponent(query)}`;

	return renderAtomFeed({
		id: searchPath,
		title: subreddit
			? `search results for "${query}" : ${subreddit}`
			: `search results for "${query}"`,
		category: subreddit.includes("+") ? "" : subreddit,
		selfUrl,
		alternateUrl: redditUrl(searchPath.replace(".rss", "")),
		entries,
	});
}

module.exports = {
	buildCommentsFeed,
	buildSearchFeed,
	buildSubmissionsFeed,
	escapeXml,
	flattenComments,
	submissionEntry,
	toFeedDate,
};
