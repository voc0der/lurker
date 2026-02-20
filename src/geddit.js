class Geddit {
	constructor() {
		this.host = "https://www.reddit.com";
		this.parameters = {
			limit: 25,
			include_over_18: true,
		};
		this.search_params = {
			limit: 25,
			include_over_18: true,
			type: "sr,link,user",
		};
		this.headers = {
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140 Safari/537.36",
		};
	}

	sanitizeSort(sort) {
		const allowedSorts = new Set([
			"best",
			"hot",
			"new",
			"top",
			"rising",
			"controversial",
		]);
		return allowedSorts.has(sort) ? sort : "hot";
	}

	sanitizeSubredditPath(subreddit) {
		if (!subreddit || typeof subreddit !== "string") return "";
		const cleaned = subreddit
			.split("+")
			.map((part) => part.trim().replace(/^r\//i, ""))
			.filter((part) => /^[A-Za-z0-9_]{1,21}$/.test(part));
		return cleaned.join("+");
	}

	sanitizeThingId(id) {
		if (!id || typeof id !== "string") return "";
		const trimmed = id.trim();
		return /^[A-Za-z0-9_]+$/.test(trimmed) ? trimmed : "";
	}

	buildRedditUrl(pathname, options = {}) {
		const url = new URL(pathname, this.host);
		url.search = new URLSearchParams(options).toString();
		return url;
	}

	async getSubmissions(sort = "hot", subreddit = null, options = {}) {
		const params = {
			limit: 20,
			include_over_18: true,
		};

		const safeSort = this.sanitizeSort(sort);
		const safeSubreddit = this.sanitizeSubredditPath(subreddit);
		const subredditStr = safeSubreddit ? `/r/${safeSubreddit}` : "";
		const url = this.buildRedditUrl(
			`${subredditStr}/${encodeURIComponent(safeSort)}.json`,
			Object.assign({}, params, options),
		);

		return await fetch(
			url,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				posts: data.children,
			}))
			.catch((err) => null);
	}

	async getDomainHot(domain, options = this.parameters) {
		return await fetch(
			`${this.host}/domain/${domain}/hot.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				posts: data.children,
			}))
			.catch((err) => null);
	}

	async getDomainBest(domain, options = this.parameters) {
		return await fetch(
			`${this.host}/domain/${domain}/best.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				posts: data.children,
			}))
			.catch((err) => null);
	}

	async getDomainTop(domain, options = this.parameters) {
		return await fetch(
			`${this.host}/domain/${domain}/top.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				posts: data.children,
			}))
			.catch((_) => null);
	}

	async getDomainNew(domain, options = this.parameters) {
		return await fetch(
			`${this.host}/domain/${domain}/new.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				posts: data.children,
			}))
			.catch((err) => null);
	}

	async getDomainRising(domain, options = this.parameters) {
		return await fetch(
			`${this.host}/domain/${domain}/rising.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				posts: data.children,
			}))
			.catch((err) => null);
	}

	async getDomainControversial(domain, options = this.parameters) {
		return await fetch(
			`${this.host}/domain/${domain}/controversial.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				posts: data.children,
			}))
			.catch((err) => null);
	}

	async getSubreddit(subreddit) {
		const safeSubreddit = this.sanitizeSubredditPath(subreddit);
		if (!safeSubreddit) return null;

		return await fetch(`${this.host}/r/${safeSubreddit}/about.json`, {
			headers: this.headers,
		})
			.then((res) => res.json())
			.then((json) => json.data)
			.catch((err) => null);
	}

	async getSubredditRules(subreddit) {
		return await fetch(`${this.host}/r/${subreddit}/about/rules.json`, {
			headers: this.headers,
		})
			.then((res) => res.json())
			.then((json) => json.data)
			.catch((err) => null);
	}

	async getSubredditModerators(subreddit) {
		return await fetch(`${this.host}/r/${subreddit}/about/moderators.json`, {
			headers: this.headers,
		})
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				users: data.children,
			}))
			.catch((err) => null);
	}

	async getSubredditWikiPages(subreddit) {
		return await fetch(`${this.host}/r/${subreddit}/wiki/pages.json`, {
			headers: this.headers,
		})
			.then((res) => res.json())
			.then((json) => json.data)
			.catch((err) => null);
	}

	async getSubredditWikiPage(subreddit, page) {
		return await fetch(`${this.host}/r/${subreddit}/wiki/${page}.json`, {
			headers: this.headers,
		})
			.then((res) => res.json())
			.then((json) => json.data)
			.catch((err) => null);
	}

	async getSubredditWikiPageRevisions(subreddit, page) {
		return await fetch(`${this.host}/r/${subreddit}/wiki/revisions${page}.json`, {
			headers: this.headers,
		})
			.then((res) => res.json())
			.then((json) => json.data.children)
			.catch((err) => null);
	}

	async getPopularSubreddits(options = this.parameters) {
		return await fetch(
			`${this.host}/subreddits/popular.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				subreddits: data.children,
			}))
			.catch((err) => null);
	}

	async getNewSubreddits(options = this.parameters) {
		return await fetch(
			`${this.host}/subreddits/new.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				subreddits: data.children,
			}))
			.catch((err) => null);
	}

	async getPremiumSubreddits(options = this.parameters) {
		return await fetch(
			`${this.host}/subreddits/premium.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				subreddits: data.children,
			}))
			.catch((err) => null);
	}

	async getDefaultSubreddits(options = this.parameters) {
		return await fetch(
			`${this.host}/subreddits/default.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				subreddits: data.children,
			}))
			.catch((err) => null);
	}

	async getPopularUsers(options = this.parameters) {
		return await fetch(
			`${this.host}/users/popular.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				users: data.children,
			}))
			.catch((err) => null);
	}

	async getNewUsers(options = this.parameters) {
		return await fetch(
			`${this.host}/users/new.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				users: data.children,
			}))
			.catch((err) => null);
	}

	async searchSubmissions(query, options = {}) {
		options.q = query;
		options.type = "link";

		return await fetch(
			`${this.host}/search.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				items: data.children,
			}))
			.catch((err) => null);
	}

	async searchSubreddits(query, options = {}) {
		options.q = query;

		const params = {
			limit: 25,
			include_over_18: false,
		};

		return await fetch(
			`${this.host}/subreddits/search.json?${new URLSearchParams(Object.assign(params, options))}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				items: data.children,
			}))
			.catch((err) => null);
	}

	async searchUsers(query, options = {}) {
		options.q = query;

		const params = {
			limit: 25,
			include_over_18: true,
		};

		return await fetch(
			`${this.host}/users/search.json?${new URLSearchParams(Object.assign(params, options))}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				items: data.children,
			}))
			.catch((err) => null);
	}

	async searchAll(query, subreddit = null, options = {}) {
		options.q = query;
		const subredditStr = subreddit ? `/r/${subreddit}` : "";

		const params = {
			limit: 25,
			include_over_18: true,
			type: "sr,link,user",
		};

		return await fetch(
			`${this.host + subredditStr}/search.json?${new URLSearchParams(Object.assign(params, options))}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) =>
				Array.isArray(json)
					? {
							after: json[1].data.after,
							items: json[0].data.children.concat(json[1].data.children),
						}
					: {
							after: json.data.after,
							items: json.data.children,
						},
			)
			.catch((err) => null);
	}

	async getSubmission(id) {
		return await fetch(`${this.host}/by_id/${id}.json`, {
			headers: this.headers,
		})
			.then((res) => res.json())
			.then((json) => json.data.children[0].data)
			.catch((err) => null);
	}

	async getSubmissionComments(id, options = this.parameters) {
		const safeId = this.sanitizeThingId(id);
		if (!safeId) return null;

		return await fetch(
			this.buildRedditUrl(`/comments/${encodeURIComponent(safeId)}.json`, options),
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => ({
				submission: json[0].data.children[0],
				comments: json[1].data.children,
			}))
			.catch((err) => null);
	}

	async getSingleCommentThread(parent_id, child_id, options = this.parameters) {
		const safeParentId = this.sanitizeThingId(parent_id);
		const safeChildId = this.sanitizeThingId(child_id);
		if (!safeParentId || !safeChildId) return null;

		return await fetch(
			this.buildRedditUrl(
				`/comments/${encodeURIComponent(safeParentId)}/comment/${encodeURIComponent(safeChildId)}.json`,
				options,
			),
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => ({
				submission: json[0].data.children[0],
				comments: json[1].data.children,
			}))
			.catch((err) => null);
	}

	async getSubredditComments(subreddit, options = this.parameters) {
		return await fetch(
			`${this.host}/r/${subreddit}/comments.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data.children)
			.catch((err) => null);
	}

	async getUser(username) {
		return await fetch(`${this.host}/user/${username}/about.json`, {
			headers: this.headers,
		})
			.then((res) => res.json())
			.then((json) => json.data)
			.catch((err) => null);
	}

	async getUserOverview(username, options = this.parameters) {
		return await fetch(
			`${this.host}/user/${username}/overview.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				items: data.children,
			}))
			.catch((err) => null);
	}

	async getUserComments(username, options = this.parameters) {
		return await fetch(
			`${this.host}/user/${username}/comments.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				items: data.children,
			}))
			.catch((err) => null);
	}

	async getUserSubmissions(username, options = this.parameters) {
		return await fetch(
			`${this.host}/user/${username}/submitted.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data)
			.then((data) => ({
				after: data.after,
				items: data.children,
			}))
			.catch((err) => null);
	}

	async getLiveThread(id) {
		return await fetch(`${this.host}/live/${id}/about.json`, {
			headers: this.headers,
		})
			.then((res) => res.json())
			.then((json) => json.data)
			.catch((err) => null);
	}

	async getLiveThreadUpdates(id, options = this.parameters) {
		return await fetch(
			`${this.host}/live/${id}.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data.children)
			.catch((err) => null);
	}

	async getLiveThreadContributors(id, options = this.parameters) {
		return await fetch(
			`${this.host}/live/${id}/contributors.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data.children)
			.catch((err) => null);
	}

	async getLiveThreadDiscussions(id, options = this.parameters) {
		return await fetch(
			`${this.host}/live/${id}/discussions.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data.children)
			.catch((err) => null);
	}

	async getLiveThreadsNow(options = this.parameters) {
		return await fetch(
			`${this.host}/live/happening_now.json?${new URLSearchParams(options)}`,
			{ headers: this.headers },
		)
			.then((res) => res.json())
			.then((json) => json.data.children)
			.catch((err) => null);
	}
}

export { Geddit };
