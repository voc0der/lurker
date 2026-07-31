const { describe, expect, test } = require("bun:test");
const { unescapeSelfText } = require("./redditHtml");

describe("unescapeSelfText", () => {
	test("decodes direct submissions", () => {
		const post = { selftext_html: "&lt;p&gt;Direct body&lt;/p&gt;" };

		unescapeSelfText(post);

		expect(post.selftext_html).toBe("<p>Direct body</p>");
	});

	test("decodes crosspost parents nested inside listing data", () => {
		const parent = { selftext_html: "&lt;p&gt;Parent body&lt;/p&gt;" };
		const listingPost = {
			data: {
				crosspost_parent_list: [parent],
			},
		};

		unescapeSelfText(listingPost);

		expect(parent.selftext_html).toBe("<p>Parent body</p>");
	});
});
