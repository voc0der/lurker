const { describe, expect, test } = require("bun:test");
const {
	buildCommentsFeed,
	buildSubmissionsFeed,
	flattenComments,
	toFeedDate,
} = require("./redditFeed");

const linkPost = {
	kind: "t3",
	data: {
		id: "1vi0whp",
		name: "t3_1vi0whp",
		author: "just_IT_guy",
		subreddit: "buildapcsales",
		title: "[CPU] AMD Ryzen 7 9850X3D - $439.99",
		permalink: "/r/buildapcsales/comments/1vi0whp/cpu_amd_ryzen_7_9850x3d/",
		url: "https://www.microcenter.com/product/706001/amd-ryzen-7-9850x3d",
		created_utc: 1786217886,
		thumbnail: "default",
	},
};

const thumbnailPost = {
	kind: "t3",
	data: {
		id: "1vhtdm3",
		name: "t3_1vhtdm3",
		author: "DanDanDannn",
		subreddit: "buildapcsales",
		title: 'RAIDMAX i802 "bundle" & cooler',
		permalink: "/r/buildapcsales/comments/1vhtdm3/case_raidmax_i802/",
		url: "https://www.newegg.com/raidmax-mid-tower",
		created_utc: 1786194099,
		preview: {
			images: [
				{
					resolutions: [
						{ url: "https://preview.redd.it/a.jpeg?width=320&amp;s=abc" },
						{ url: "https://preview.redd.it/a.jpeg?width=640&amp;s=def" },
					],
				},
			],
		},
	},
};

describe("buildSubmissionsFeed", () => {
	test("renders a reddit-shaped atom feed", () => {
		const xml = buildSubmissionsFeed({
			posts: [linkPost],
			subreddit: "buildapcsales",
			sort: "new",
			about: { public_description: "pc sales" },
			selfUrl: "https://lurker.local/api/v1/r/buildapcsales/new.rss",
		});

		expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
		expect(xml).toContain(
			'<feed xmlns="http://www.w3.org/2005/Atom" xmlns:media="http://search.yahoo.com/mrss/">',
		);
		expect(xml).toContain(
			'<category term="buildapcsales" label="r/buildapcsales"/>',
		);
		expect(xml).toContain("<id>/r/buildapcsales/new.rss</id>");
		expect(xml).toContain(
			'<link rel="self" href="https://lurker.local/api/v1/r/buildapcsales/new.rss" type="application/atom+xml"/>',
		);
		expect(xml).toContain(
			'<link rel="alternate" href="https://www.reddit.com/r/buildapcsales/new" type="text/html"/>',
		);
		expect(xml).toContain("<title>newest submissions : buildapcsales</title>");
		expect(xml).toContain("<subtitle>pc sales</subtitle>");
		expect(xml).toContain("<name>/u/just_IT_guy</name>");
		expect(xml).toContain("<uri>https://www.reddit.com/user/just_IT_guy</uri>");
		expect(xml).toContain("<id>t3_1vi0whp</id>");
		expect(xml).toContain(
			'<link href="https://www.reddit.com/r/buildapcsales/comments/1vi0whp/cpu_amd_ryzen_7_9850x3d/"/>',
		);
		expect(xml).toContain("<published>2026-08-08T19:38:06+00:00</published>");
		expect(xml.trimEnd().endsWith("</feed>")).toBe(true);
	});

	test("escapes entry content as html inside a text node", () => {
		const xml = buildSubmissionsFeed({
			posts: [linkPost],
			subreddit: "buildapcsales",
			sort: "new",
		});

		expect(xml).toContain('<content type="html">');
		// Markup inside content is escaped, exactly like reddit's own feed.
		expect(xml).toContain("&lt;a href=&quot;https://www.reddit.com/user/");
		expect(xml).toContain("[link]&lt;/a&gt;");
		expect(xml).toContain("[comments]&lt;/a&gt;");
		expect(xml).not.toContain("<a href=");
	});

	test("uses the preview image for thumbnailed posts", () => {
		const xml = buildSubmissionsFeed({
			posts: [thumbnailPost],
			subreddit: "buildapcsales",
			sort: "new",
		});

		expect(xml).toContain(
			'<media:thumbnail url="https://preview.redd.it/a.jpeg?width=640&amp;s=def"/>',
		);
		expect(xml).toContain("&lt;table&gt;");
		// Titles are double-escaped inside content, matching reddit.
		expect(xml).toContain("&amp;quot;bundle&amp;quot;");
	});

	test("omits subreddit metadata for multireddits", () => {
		const xml = buildSubmissionsFeed({
			posts: [linkPost],
			subreddit: "buildapcsales+hardwareswap",
			sort: "hot",
			about: { public_description: "should be ignored" },
		});

		expect(xml).toContain("<id>/r/buildapcsales+hardwareswap/hot.rss</id>");
		expect(xml).not.toContain("should be ignored");
		expect(xml).not.toContain('<category term="buildapcsales+hardwareswap"');
	});

	test("renders an empty but valid feed with no posts", () => {
		const xml = buildSubmissionsFeed({
			posts: [],
			subreddit: "buildapcsales",
			sort: "new",
		});

		expect(xml).toContain("<title>newest submissions : buildapcsales</title>");
		expect(xml).not.toContain("<entry>");
	});
});

describe("buildCommentsFeed", () => {
	const submission = {
		kind: "t3",
		data: {
			id: "1vi0whp",
			title: "a deal",
			subreddit: "buildapcsales",
			permalink: "/r/buildapcsales/comments/1vi0whp/a_deal/",
		},
	};

	const comments = [
		{
			kind: "t1",
			data: {
				id: "c1",
				name: "t1_c1",
				author: "alice",
				body: "top level",
				body_html: "&lt;div&gt;top level&lt;/div&gt;",
				created_utc: 1786217900,
				permalink: "/r/buildapcsales/comments/1vi0whp/a_deal/c1/",
				replies: {
					data: {
						children: [
							{
								kind: "t1",
								data: {
									id: "c2",
									name: "t1_c2",
									author: "bob",
									body: "reply",
									created_utc: 1786217950,
									permalink: "/r/buildapcsales/comments/1vi0whp/a_deal/c2/",
								},
							},
							{ kind: "more", data: { id: "_" } },
						],
					},
				},
			},
		},
	];

	test("flattens nested replies and skips `more` stubs", () => {
		const flat = flattenComments(comments);
		expect(flat.map((c) => c.data.id)).toEqual(["c1", "c2"]);
	});

	test("renders one entry per comment", () => {
		const xml = buildCommentsFeed({
			submission,
			comments,
			id: "1vi0whp",
			selfUrl: "https://lurker.local/api/v1/comments/1vi0whp.rss",
		});

		expect(xml).toContain("<id>/comments/1vi0whp.rss</id>");
		expect(xml).toContain("<title>comments for a deal</title>");
		expect(xml).toContain("<id>t1_c1</id>");
		expect(xml).toContain("<id>t1_c2</id>");
		expect(xml).toContain("<title>/u/alice on a deal</title>");
		// body_html arrives escaped from reddit and is decoded before embedding.
		expect(xml).toContain("&lt;div&gt;top level&lt;/div&gt;");
	});
});

describe("toFeedDate", () => {
	test("formats epoch seconds the way reddit does", () => {
		expect(toFeedDate(1786217886)).toBe("2026-08-08T19:38:06+00:00");
	});

	test("falls back to now for unusable values", () => {
		expect(toFeedDate(undefined)).toMatch(
			/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$/,
		);
	});
});
