const { afterEach, describe, expect, test } = require("bun:test");
const {
	describeApiWhitelist,
	generateApiKey,
	isApiWhitelisted,
	redactApiKey,
} = require("./apiAuth");

const originalWhitelist = process.env.API_WHITELIST;

function setWhitelist(value) {
	if (value === undefined) {
		// Assigning undefined would store the string "undefined"; remove the key.
		Reflect.deleteProperty(process.env, "API_WHITELIST");
	} else {
		process.env.API_WHITELIST = value;
	}
}

afterEach(() => {
	setWhitelist(originalWhitelist);
});

describe("isApiWhitelisted", () => {
	test("defaults to loopback only", () => {
		setWhitelist(undefined);
		expect(isApiWhitelisted("127.0.0.1")).toBe(true);
		expect(isApiWhitelisted("::1")).toBe(true);
		expect(isApiWhitelisted("::ffff:127.0.0.1")).toBe(true);
		expect(isApiWhitelisted("10.2.5.50")).toBe(false);
		expect(isApiWhitelisted("")).toBe(false);
	});

	test("treats an empty value as unset", () => {
		setWhitelist("   ");
		expect(isApiWhitelisted("127.0.0.1")).toBe(true);
		expect(isApiWhitelisted("10.2.5.50")).toBe(false);
	});

	test("matches explicit addresses", () => {
		setWhitelist("10.2.5.50, 172.28.17.1");
		expect(isApiWhitelisted("10.2.5.50")).toBe(true);
		expect(isApiWhitelisted("::ffff:10.2.5.50")).toBe(true);
		expect(isApiWhitelisted("172.28.17.1")).toBe(true);
		expect(isApiWhitelisted("172.28.17.2")).toBe(false);
		// An explicit list replaces the loopback default.
		expect(isApiWhitelisted("127.0.0.1")).toBe(false);
	});

	test("matches ipv4 cidr ranges", () => {
		setWhitelist("172.28.0.0/16,10.2.5.0/24");
		expect(isApiWhitelisted("172.28.17.103")).toBe(true);
		expect(isApiWhitelisted("172.29.17.103")).toBe(false);
		expect(isApiWhitelisted("10.2.5.255")).toBe(true);
		expect(isApiWhitelisted("10.2.6.1")).toBe(false);
	});

	test("matches ipv6 cidr ranges", () => {
		setWhitelist("fd00::/8,2001:db8:1::/48");
		expect(isApiWhitelisted("fd12:3456::1")).toBe(true);
		expect(isApiWhitelisted("fe80::1")).toBe(false);
		expect(isApiWhitelisted("2001:db8:1:2::5")).toBe(true);
		expect(isApiWhitelisted("2001:db8:2::5")).toBe(false);
		// An ipv4 peer never matches an ipv6 range, or the reverse.
		expect(isApiWhitelisted("10.2.5.50")).toBe(false);

		setWhitelist("10.2.5.0/24");
		expect(isApiWhitelisted("fd12:3456::1")).toBe(false);
	});

	test("supports an explicit allow-all and an explicit off switch", () => {
		setWhitelist("*");
		expect(isApiWhitelisted("8.8.8.8")).toBe(true);

		setWhitelist("off");
		expect(isApiWhitelisted("127.0.0.1")).toBe(false);
		expect(isApiWhitelisted("8.8.8.8")).toBe(false);
	});

	test("rejects malformed entries instead of matching broadly", () => {
		setWhitelist("10.2.5.0/33,fd00::/129,not-an-ip");
		expect(isApiWhitelisted("10.2.5.50")).toBe(false);
		expect(isApiWhitelisted("fd00::1")).toBe(false);
		expect(isApiWhitelisted("not-an-ip")).toBe(true); // exact string match only
	});
});

describe("redactApiKey", () => {
	test("scrubs keys from urls without touching the rest", () => {
		expect(redactApiKey("/api/v1/r/x/new.rss?api_key=lurker_secret")).toBe(
			"/api/v1/r/x/new.rss?api_key=[redacted]",
		);
		expect(redactApiKey("/api/v1/x?limit=5&key=lurker_secret&raw=1")).toBe(
			"/api/v1/x?limit=5&key=[redacted]&raw=1",
		);
		expect(redactApiKey("/api/v1/r/x/new.rss")).toBe("/api/v1/r/x/new.rss");
	});
});

describe("describeApiWhitelist", () => {
	test("reports the effective default", () => {
		setWhitelist(undefined);
		expect(describeApiWhitelist()).toMatchObject({
			configured: false,
			disabled: false,
			unrestricted: false,
			description: "127.0.0.1, ::1",
		});
	});

	test("reports unrestricted and disabled states", () => {
		setWhitelist("*");
		expect(describeApiWhitelist().unrestricted).toBe(true);

		setWhitelist("none");
		expect(describeApiWhitelist()).toMatchObject({
			disabled: true,
			description: "disabled",
		});
	});
});

describe("generateApiKey", () => {
	test("produces distinct, prefixed, high-entropy keys", () => {
		const a = generateApiKey();
		const b = generateApiKey();

		expect(a).toStartWith("lurker_");
		expect(a).not.toBe(b);
		expect(a.length).toBeGreaterThanOrEqual(48);
		expect(a.slice("lurker_".length)).toMatch(/^[A-Za-z0-9_-]+$/);
	});
});
