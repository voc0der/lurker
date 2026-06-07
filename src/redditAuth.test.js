const { describe, expect, test } = require("bun:test");
const {
	getRedditAuthHeaders,
	normalizeRedditAuthInput,
	serializeRedditAuthHeaders,
} = require("./redditAuth");

describe("normalizeRedditAuthInput", () => {
	test("normalizes bearer authorization headers", () => {
		expect(
			normalizeRedditAuthInput("Authorization: Bearer abc123", "auto"),
		).toEqual({
			authorization: "Bearer abc123",
		});

		expect(normalizeRedditAuthInput("abc123", "bearer")).toEqual({
			authorization: "Bearer abc123",
		});

		expect(
			normalizeRedditAuthInput("Authorization: Bearer abc123", "bearer"),
		).toEqual({
			authorization: "Bearer abc123",
		});
	});

	test("normalizes cookie headers and devtools-style cookie lines", () => {
		expect(
			normalizeRedditAuthInput(
				"Cookie: reddit_session=abc; token_v2=def",
				"auto",
			),
		).toEqual({
			cookie: "reddit_session=abc; token_v2=def",
		});

		expect(
			normalizeRedditAuthInput(
				'redesign_out: "true"\nreddit_session: "abc"\ntoken_v2: "def"',
				"auto",
			),
		).toEqual({
			cookie: "redesign_out=true; reddit_session=abc; token_v2=def",
		});
	});

	test("supports a bare reddit_session value when selected", () => {
		expect(normalizeRedditAuthInput("abc.def", "reddit_session")).toEqual({
			cookie: "reddit_session=abc.def",
		});
	});

	test("round trips serialized stored headers", () => {
		const serialized = serializeRedditAuthHeaders({
			authorization: "Bearer abc123",
			cookie: "reddit_session=abc",
		});

		expect(getRedditAuthHeaders(serialized)).toEqual({
			authorization: "Bearer abc123",
			cookie: "reddit_session=abc",
		});
	});

	test("merges stored auth headers into Geddit request headers", async () => {
		const { Geddit } = await import("./geddit.js");
		const reddit = new Geddit();

		expect(
			reddit.getRequestHeaders({
				authHeaders: {
					authorization: "Bearer abc123",
					cookie: "reddit_session=abc",
				},
			}),
		).toMatchObject({
			Accept: "application/json",
			Authorization: "Bearer abc123",
			Cookie: "reddit_session=abc",
		});
	});
});
