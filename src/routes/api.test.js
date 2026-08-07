const {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	test,
} = require("bun:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

// Point the database at a throwaway directory before anything requires it.
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "lurker-api-test-"));
process.env.LURKER_DATA_DIR = dataDir;
Reflect.deleteProperty(process.env, "API_WHITELIST");

const express = require("express");
const { db } = require("../db");
const apiRouter = require("./api");

const API_KEY = "lurker_test_key";
const realFetch = globalThis.fetch;

function listingResponse(posts, after = null) {
	return {
		data: {
			after,
			children: posts,
		},
	};
}

const POST = {
	kind: "t3",
	data: {
		id: "1vi0whp",
		name: "t3_1vi0whp",
		author: "just_IT_guy",
		subreddit: "buildapcsales",
		title: "[CPU] AMD Ryzen 7 9850X3D - $439.99",
		permalink: "/r/buildapcsales/comments/1vi0whp/cpu/",
		url: "https://www.microcenter.com/product/706001",
		created_utc: 1786217886,
		score: 42,
		num_comments: 7,
		thumbnail: "default",
		selftext: "",
	},
};

// Reddit escapes user markup once inside selftext_html; a feed must not
// unescape it far enough to make it live again.
const SELF_POST = {
	kind: "t3",
	data: {
		id: "1self",
		name: "t3_1self",
		author: "poster",
		subreddit: "buildapcsales",
		title: "a text post",
		permalink: "/r/buildapcsales/comments/1self/a_text_post/",
		url: "https://www.reddit.com/r/buildapcsales/comments/1self/a_text_post/",
		created_utc: 1786217886,
		is_self: true,
		selftext: "<script>alert(1)</script>",
		selftext_html:
			'&lt;!-- SC_OFF --&gt;&lt;div class="md"&gt;&lt;p&gt;&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;&lt;/p&gt;&lt;/div&gt;&lt;!-- SC_ON --&gt;',
	},
};

let server;
let baseUrl;
let requestedUrls = [];
let requestedHeaders = [];

beforeAll(async () => {
	db.query(
		"INSERT INTO users (username, password_hash, apiKey) VALUES ($username, $hash, $apiKey)",
	).run({ username: "apitester", hash: "x", apiKey: API_KEY });

	globalThis.fetch = async (input, init) => {
		const url = String(input);
		requestedUrls.push(url);
		requestedHeaders.push(init?.headers || {});

		let body;
		if (url.includes("/about.json")) {
			body = { data: { public_description: "pc sales" } };
		} else if (url.includes("/comments/")) {
			body = [
				listingResponse([POST]),
				listingResponse([
					{
						kind: "t1",
						data: {
							id: "c1",
							name: "t1_c1",
							author: "alice",
							body: "nice",
							body_html: "&lt;p&gt;nice&lt;/p&gt;",
							created_utc: 1786217900,
							permalink: "/r/buildapcsales/comments/1vi0whp/cpu/c1/",
						},
					},
				]),
			];
		} else if (url.includes("1self")) {
			body = listingResponse([SELF_POST], null);
		} else {
			body = listingResponse([POST], "t3_next");
		}

		return new Response(JSON.stringify(body), {
			headers: { "content-type": "application/json" },
		});
	};

	const app = express();
	app.use("/api/v1", apiRouter);
	server = app.listen(0, "127.0.0.1");
	await new Promise((resolve) => server.once("listening", resolve));
	baseUrl = `http://127.0.0.1:${server.address().port}`;
});

afterEach(() => {
	requestedUrls = [];
	requestedHeaders = [];
	Reflect.deleteProperty(process.env, "API_WHITELIST");
});

afterAll(() => {
	globalThis.fetch = realFetch;
	server?.close();
	db.close();
	fs.rmSync(dataDir, { recursive: true, force: true });
});

function get(path, { key = API_KEY, headers = {} } = {}) {
	return realFetch(`${baseUrl}${path}`, {
		headers: key ? { "X-API-Key": key, ...headers } : headers,
	});
}

describe("API whitelist gate", () => {
	test("rejects sources outside API_WHITELIST before checking the key", async () => {
		process.env.API_WHITELIST = "10.2.5.50";
		const res = await get("/api/v1/whoami");

		expect(res.status).toBe(403);
		const body = await res.json();
		expect(body.error).toBe("forbidden");
		expect(body.source).toBe("127.0.0.1");
	});

	test("allows loopback by default", async () => {
		const res = await get("/api/v1/health", { key: null });
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ ok: true, source: "127.0.0.1" });
	});
});

describe("API key authentication", () => {
	test("requires a key", async () => {
		const res = await get("/api/v1/whoami", { key: null });
		expect(res.status).toBe(401);
	});

	test("rejects an unknown key", async () => {
		const res = await get("/api/v1/whoami", { key: "lurker_wrong" });
		expect(res.status).toBe(401);
	});

	test("accepts the key as a header, bearer token, or query param", async () => {
		const header = await get("/api/v1/whoami");
		expect(await header.json()).toMatchObject({ username: "apitester" });

		const bearer = await realFetch(`${baseUrl}/api/v1/whoami`, {
			headers: { Authorization: `Bearer ${API_KEY}` },
		});
		expect(bearer.status).toBe(200);

		const query = await realFetch(
			`${baseUrl}/api/v1/whoami?api_key=${API_KEY}`,
		);
		expect(query.status).toBe(200);
	});
});

describe("feeds", () => {
	test("serves a subreddit atom feed", async () => {
		const res = await get("/api/v1/r/buildapcsales/new.rss?limit=3");

		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe(
			"application/atom+xml; charset=utf-8",
		);

		const xml = await res.text();
		expect(xml).toContain("<title>newest submissions : buildapcsales</title>");
		expect(xml).toContain("<subtitle>pc sales</subtitle>");
		expect(xml).toContain("<id>t3_1vi0whp</id>");
		expect(
			requestedUrls.some((url) =>
				url.includes("/r/buildapcsales/new.json?limit=3"),
			),
		).toBe(true);
	});

	test("keeps the api key out of the feed's self link", async () => {
		const res = await realFetch(
			`${baseUrl}/api/v1/r/buildapcsales/new.rss?api_key=${API_KEY}`,
		);
		const xml = await res.text();

		expect(xml).not.toContain(API_KEY);
		expect(xml).toContain('rel="self"');
	});

	test(".atom is an alias and the bare path defaults to json", async () => {
		const atom = await get("/api/v1/r/buildapcsales/new.atom");
		expect(atom.headers.get("content-type")).toBe(
			"application/atom+xml; charset=utf-8",
		);

		const bare = await get("/api/v1/r/buildapcsales/new");
		expect(bare.headers.get("content-type")).toContain("application/json");
	});

	test("serves a comments feed", async () => {
		const res = await get("/api/v1/comments/1vi0whp.rss");
		const xml = await res.text();

		expect(res.status).toBe(200);
		expect(xml).toContain("<id>t1_c1</id>");
		expect(xml).toContain("&lt;p&gt;nice&lt;/p&gt;");
	});
});

describe("stored reddit credentials", () => {
	function setStoredCredential(value) {
		db.query(
			"UPDATE users SET redditAuthHeaders = $headers WHERE apiKey = $apiKey",
		).run({ headers: value, apiKey: API_KEY });
	}

	afterEach(() => setStoredCredential(null));

	test("sends the key owner's burner credential upstream", async () => {
		setStoredCredential(
			JSON.stringify({
				authorization: "Bearer burner-token",
				cookie: "reddit_session=burner-session",
			}),
		);

		await get("/api/v1/r/buildapcsales/new.json");

		expect(requestedHeaders[0]).toMatchObject({
			Authorization: "Bearer burner-token",
			Cookie: "reddit_session=burner-session",
		});
	});

	test("sends it on feed, comments, and search requests alike", async () => {
		setStoredCredential(JSON.stringify({ authorization: "Bearer burner" }));

		await get("/api/v1/r/buildapcsales/new.rss");
		await get("/api/v1/comments/1vi0whp.json");
		await get("/api/v1/search.json?q=gpu");

		expect(requestedHeaders.length).toBeGreaterThanOrEqual(3);
		for (const headers of requestedHeaders) {
			expect(headers.Authorization).toBe("Bearer burner");
		}
	});

	test("falls back to anonymous requests when none is stored", async () => {
		await get("/api/v1/r/buildapcsales/new.json");

		expect(requestedHeaders[0].Authorization).toBeUndefined();
		expect(requestedHeaders[0].Cookie).toBeUndefined();
		expect(requestedHeaders[0]["User-Agent"]).toContain("Mozilla/5.0");
	});
});

describe("self-text escaping", () => {
	test("keeps quoted markup inert in the feed", async () => {
		const res = await get("/api/v1/r/1self/new.rss");
		const xml = await res.text();

		// One decode yields reddit's wrapper markup...
		expect(xml).toContain("&lt;div class=&quot;md&quot;&gt;");
		// ...but the body text stays escaped, exactly as reddit serves it.
		expect(xml).toContain("&amp;lt;script&amp;gt;");
		expect(xml).not.toContain("&lt;script&gt;alert(1)");
	});

	test("still decodes selftext_html once for json callers", async () => {
		const res = await get("/api/v1/r/1self/new.json");
		const body = await res.json();

		expect(body.posts[0].selftext_html).toContain('<div class="md">');
		expect(body.posts[0].selftext_html).toContain("&lt;script&gt;");
	});
});

describe("json responses", () => {
	test("returns normalized posts", async () => {
		const res = await get("/api/v1/r/buildapcsales/new.json");
		const body = await res.json();

		expect(body).toMatchObject({
			kind: "listing",
			subreddit: "buildapcsales",
			sort: "new",
			after: "t3_next",
			count: 1,
		});
		expect(body.posts[0]).toMatchObject({
			id: "1vi0whp",
			author: "just_IT_guy",
			score: 42,
			permalink: "https://www.reddit.com/r/buildapcsales/comments/1vi0whp/cpu/",
			created_iso: "2026-08-08T19:38:06.000Z",
		});
	});

	test("passes through reddit's raw listing with ?raw=1", async () => {
		const res = await get("/api/v1/r/buildapcsales/new.json?raw=1");
		const body = await res.json();

		expect(body.posts[0].kind).toBe("t3");
		expect(body.posts[0].data.id).toBe("1vi0whp");
	});

	test("returns subreddit metadata", async () => {
		for (const path of [
			"/api/v1/r/buildapcsales/about.json",
			"/api/v1/r/buildapcsales/about",
		]) {
			const res = await get(path);
			expect(res.status).toBe(200);
			expect(await res.json()).toMatchObject({
				kind: "about",
				name: "buildapcsales",
				public_description: "pc sales",
			});
		}
	});

	test("does not serve a hot listing for /about.rss", async () => {
		const res = await get("/api/v1/r/buildapcsales/about.rss");
		expect(res.status).toBe(400);
	});

	test("lists subscriptions for the key's user", async () => {
		const res = await get("/api/v1/subscriptions");
		expect(await res.json()).toEqual({ count: 0, subscriptions: [] });
	});
});

describe("input validation", () => {
	test("rejects an invalid subreddit", async () => {
		const res = await get("/api/v1/r/not%20a%20sub/new.json");
		expect(res.status).toBe(400);
	});

	test("rejects an unknown sort in the path instead of substituting one", async () => {
		const res = await get("/api/v1/r/buildapcsales/bogus.json");

		expect(res.status).toBe(400);
		expect((await res.json()).message).toContain("Unknown sort");
		expect(requestedUrls).toHaveLength(0);
	});

	test("falls back to a safe sort for the ?sort= query param", async () => {
		const res = await get("/api/v1/r/buildapcsales.json?sort=bogus");
		expect((await res.json()).sort).toBe("hot");
	});

	test("clamps limit and drops unknown query params", async () => {
		await get("/api/v1/r/buildapcsales/new.json?limit=9999&evil=1");
		const [url] = requestedUrls;

		expect(url).toContain("limit=100");
		expect(url).not.toContain("evil");
	});

	test("restricts subreddit-scoped search to submissions", async () => {
		await get("/api/v1/search.json?q=gpu&subreddit=buildapcsales");
		const [url] = requestedUrls;

		expect(url).toContain("/r/buildapcsales/search.json");
		expect(url).toContain("type=link");
		expect(url).not.toContain("type=sr");
	});

	test("requires a search query", async () => {
		const res = await get("/api/v1/search.json");
		expect(res.status).toBe(400);
	});

	test("redacts a query-string key from the 404 message", async () => {
		const res = await realFetch(
			`${baseUrl}/api/v1/nonsense?api_key=${API_KEY}`,
		);
		const body = await res.json();

		expect(res.status).toBe(404);
		expect(body.message).not.toContain(API_KEY);
		expect(body.message).toContain("[redacted]");
	});

	test("404s unknown endpoints as json", async () => {
		const res = await get("/api/v1/nonsense");
		expect(res.status).toBe(404);
		expect((await res.json()).error).toBe("not_found");
	});
});
