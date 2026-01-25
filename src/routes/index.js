const express = require("express");
const he = require("he");
const jwt = require("jsonwebtoken");
const crypto = require('crypto');
const geddit = require("../geddit.js");
const { JWT_KEY } = require("../");
const { db } = require("../db");
const { authenticateToken, authenticateAdmin } = require("../auth");
const { validateInviteToken } = require("../invite");
const logger = require("../logger");
const oidc = require("../oidc");

const router = express.Router();
const G = new geddit.Geddit();

function generateRandomPassword(length = 12) {
  const bytes = crypto.randomBytes(length);
  return bytes.toString('base64').slice(0, length);  // Convert to base64 and slice to desired length
}

// Helper function to set the auth token cookie
function setAuthTokenCookie(res, username, userId) {
  const token = jwt.sign({ username, id: userId }, JWT_KEY, { expiresIn: "5d" });
  res.cookie("auth_token", token, {
    httpOnly: true,
    secure: true,
    maxAge: 5 * 24 * 60 * 60 * 1000, // 5 days
    sameSite: 'Strict',
  });
}

// Middleware to check if user is logged in via HTTP headers
async function loginViaHeaders(req, res, next) {
  const remoteUser = req.headers['remote-user'] || req.headers['HTTP_AUTH_USER'];
  const remoteGroups = req.headers['remote-groups'] ? req.headers['remote-groups'].split(',').map(s => s.trim()).filter(Boolean) : [];

  // We need env.REMOTE_HEADER_LOGIN=true to use SSO. Also check if remoteUser header is missing
  if (!(process.env.REMOTE_HEADER_LOGIN || false) || !remoteUser) {
    if(process.env.REMOTE_HEADER_LOGIN) logger.debug("Remote user header missing");
    return res.redirect("/login");  // Redirect to login page if missing
  }

  // If remoteUser is present, set user info and validate
  req.user = {
    username: remoteUser,  // Store username in req.user
    isAdmin: remoteGroups.includes(process.env.ADMIN_GROUP || 'admin'),  // Check if user is an admin
    validated: true,  // Flag to mark user as validated via headers
  };

  // Check if the user already exists in the database
  let existingUser = db.query("SELECT * FROM users WHERE username = $username").get({ username: remoteUser });

  if (!existingUser) {
    // If user does not exist, automatically register them
    try {
      const randomPassword = generateRandomPassword(52);
      const hashedPassword = await Bun.password.hash(randomPassword);  // Hash the random password

      const insertedRecord = db.query(
        "INSERT INTO users (username, password_hash, isAdmin, groups) VALUES ($username, $hashedPassword, $isAdmin, $groups)"
      ).run({
        username: remoteUser,
        hashedPassword,
        isAdmin: req.user.isAdmin ? 1 : 0,
        groups: JSON.stringify(remoteGroups),
      });

      const userId = insertedRecord.lastInsertRowid;
      setAuthTokenCookie(res, remoteUser, userId);

      const redirectTo = req.query.redirect || req.query.direct || '/';
      return res.redirect(redirectTo);
    } catch (error) {
      logger.error("Error creating user from headers:", error);
      return res.render("login", { message: "Error creating account, please try again." });
    }
  } else {
    // Set user id from the database record
    req.user.id = existingUser.id;

    // Keep isAdmin/groups in sync with remote headers
    if (remoteGroups.length > 0) {
      const newGroups = JSON.stringify(remoteGroups);
      const isAdmin = req.user.isAdmin ? 1 : 0;
      if (existingUser.isAdmin !== isAdmin || (existingUser.groups || "[]") !== newGroups) {
        db.query("UPDATE users SET isAdmin = $isAdmin, groups = $groups WHERE id = $id")
          .run({
            isAdmin,
            groups: newGroups,
            id: req.user.id,
          });
      }
    }

    setAuthTokenCookie(res, remoteUser, existingUser.id);
    const redirectTo = req.query.redirect || req.query.direct || '/';
    return res.redirect(redirectTo);
  }
}

const commonRenderOptions = {
	theme: process.env.LURKER_THEME,
};

// GET /
router.get("/", authenticateToken, async (req, res) => {
	const subs = db
		.query("SELECT * FROM subscriptions WHERE user_id = $id")
		.all({ id: req.user.id });

	const query = req.query ? req.query : {};
	if (!query.sort) {
		query.sort = "hot";
	}
	if (!query.view) {
		query.view = "compact";
	}

	// If no subscriptions, redirect to /r/all
	if (subs.length === 0) {
		const qs = "?" + new URLSearchParams(query).toString();
		return res.redirect(`/r/all${qs}`);
	}

	// Build multi-reddit internally (don't put in URL)
	const subreddit = subs.map((s) => s.subreddit).join("+");
	const isMulti = true;
	const isHomePage = true; // Flag to indicate this is the home page

	const postsReq = G.getSubmissions(query.sort, subreddit, query);
	const aboutReq = G.getSubreddit(subreddit);
	const [posts, about] = await Promise.all([postsReq, aboutReq]);

	if (query.view == "card" && posts && posts.posts) {
		posts.posts.forEach(unescape_selftext);
	}

	res.render("index", {
		subreddit,
		posts,
		about,
		query,
		isMulti,
		isHomePage,
		user: req.user,
		isSubbed: false,
		currentUrl: req.url,
		...commonRenderOptions,
	});
});

// GET /r/:id
router.get("/r/:subreddit", authenticateToken, async (req, res) => {
	const subreddit = req.params.subreddit;
	const isMulti = subreddit.includes("+");
	const query = req.query ? req.query : {};
	if (!query.sort) {
		query.sort = "hot";
	}
	if (!query.view) {
		query.view = "compact";
	}

  let isSubbed = false;
  if (!isMulti) {
    isSubbed = db.query("SELECT * FROM subscriptions WHERE user_id = $id AND subreddit = $subreddit")
                 .get({ id: req.user.id, subreddit }) !== null;
  }

  const postsReq = G.getSubmissions(query.sort, subreddit, query);
  const aboutReq = G.getSubreddit(subreddit);
  const [posts, about] = await Promise.all([postsReq, aboutReq]);

	if (query.view == "card" && posts && posts.posts) {
		posts.posts.forEach(unescape_selftext);
	}

	res.render("index", {
		subreddit,
		posts,
		about,
		query,
		isMulti,
		user: req.user,
		isSubbed,
		currentUrl: req.url,
		...commonRenderOptions,
	});
});

// API endpoint to fetch more posts for infinite scroll
router.get("/api/r/:subreddit/posts", authenticateToken, async (req, res) => {
	let subreddit = req.params.subreddit;
	const query = req.query ? req.query : {};
	if (!query.sort) {
		query.sort = "hot";
	}
	if (!query.view) {
		query.view = "compact";
	}

	// Handle "home" as a special case - build multi-reddit from subscriptions
	if (subreddit === "home") {
		const subs = db
			.query("SELECT * FROM subscriptions WHERE user_id = $id")
			.all({ id: req.user.id });
		subreddit = subs.map((s) => s.subreddit).join("+");
	}

	const posts = await G.getSubmissions(query.sort, subreddit, query);

	if (query.view == "card" && posts && posts.posts) {
		posts.posts.forEach(unescape_selftext);
	}

	// Render posts as HTML partial
	const html = await new Promise((resolve, reject) => {
		res.render("posts-partial", {
			posts: posts ? posts.posts : [],
			query,
			currentUrl: req.query.currentUrl || req.originalUrl,
			...commonRenderOptions,
		}, (err, html) => {
			if (err) reject(err);
			else resolve(html);
		});
	});

	// Return JSON with HTML and after cursor
	res.json({
		html,
		after: posts ? posts.after : null,
	});
});

// GET /comments/:id
router.get("/comments/:id", authenticateToken, async (req, res) => {
	const id = req.params.id;

	const params = {
		limit: 50,
	};
	response = await G.getSubmissionComments(id, params);
	res.render("comments", {
		data: unescape_submission(response),
		user: req.user,
		from: req.query.from,
		query: req.query,
		...commonRenderOptions,
	});
});

// GET /comments/:parent_id/comment/:child_id
router.get(
	"/comments/:parent_id/comment/:child_id",
	authenticateToken,
	async (req, res) => {
		const parent_id = req.params.parent_id;
		const child_id = req.params.child_id;

		const params = {
			limit: 50,
		};
		response = await G.getSingleCommentThread(parent_id, child_id, params);
		const comments = response.comments;
		comments.forEach(unescape_comment);
		res.render("single_comment_thread", {
			comments,
			parent_id,
			user: req.user,
			...commonRenderOptions,
		});
	},
);

// GET /subs
router.get("/subs", authenticateToken, async (req, res) => {
	const subs = db
		.query(
			"SELECT * FROM subscriptions WHERE user_id = $id ORDER by LOWER(subreddit)",
		)
		.all({ id: req.user.id });

	res.render("subs", {
		subs,
		user: req.user,
		query: req.query,
		...commonRenderOptions,
	});
});

// GET /search
router.get("/search", authenticateToken, async (req, res) => {
	res.render("search", {
		user: req.user,
		query: req.query,
		...commonRenderOptions,
	});
});

// GET /sub-search
router.get("/sub-search", authenticateToken, async (req, res) => {
	if (!req.query || !req.query.q) {
		res.render("sub-search", { user: req.user, ...commonRenderOptions });
	} else {
		const { items, after } = await G.searchSubreddits(req.query.q);
		const subs = db
			.query("SELECT subreddit FROM subscriptions WHERE user_id = $id")
			.all({ id: req.user.id })
			.map((res) => res.subreddit);
		const message =
			items.length === 0
				? "no results found"
				: `showing ${items.length} results`;
		res.render("sub-search", {
			items,
			subs,
			after,
			message,
			user: req.user,
			original_query: req.query.q,
			query: req.query,
			...commonRenderOptions,
		});
	}
});

// GET /post-search
router.get("/post-search", authenticateToken, async (req, res) => {
	if (!req.query || !req.query.q) {
		res.render("post-search", { user: req.user, ...commonRenderOptions });
	} else {
		const { items, after } = await G.searchSubmissions(req.query.q);
		const message =
			items.length === 0
				? "no results found"
				: `showing ${items.length} results`;

		if (req.query.view == "card" && items) {
			items.forEach(unescape_selftext);
		}

		res.render("post-search", {
			items,
			after,
			message,
			user: req.user,
			original_query: req.query.q,
			currentUrl: req.url,
			query: req.query,
			...commonRenderOptions,
		});
	}
});

// GET /dashboard
router.get("/dashboard", authenticateToken, async (req, res) => {
	logger.debug("Dashboard - req.user from authenticateToken:", req.user);

	let invites = null;
	const isAdmin = db
		.query("SELECT isAdmin FROM users WHERE id = $id and isAdmin = 1")
		.get({
			id: req.user.id,
		});
	if (isAdmin) {
		invites = db
			.query("SELECT * FROM invites")
			.all()
			.map((inv) => ({
				...inv,
				createdAt: Date.parse(inv.createdAt),
				usedAt: Date.parse(inv.usedAt),
			}));
	}

	logger.debug("Dashboard - rendering with user:", {
		infiniteScroll: req.user.infiniteScroll,
		useClassicLayout: req.user.useClassicLayout,
		themePreference: req.user.themePreference
	});

	res.render("dashboard", {
		invites,
		isAdmin,
		user: req.user,
		message: req.query.message,
		query: req.query,
		...commonRenderOptions,
	});
});

// POST /update-preferences
router.post("/update-preferences", authenticateToken, async (req, res) => {
	const { infiniteScroll, useClassicLayout, themePreference, highResThumbnails } = req.body;
	const infiniteScrollValue = infiniteScroll === "1" ? 1 : 0;
	const useClassicLayoutValue = useClassicLayout === "1" ? 1 : 0;
	const highResThumbnailsValue = highResThumbnails === "1" ? 1 : 0;
	const themeValue = themePreference || 'auto';

	logger.debug("Received preferences:", {
		infiniteScroll,
		useClassicLayout,
		themePreference,
		highResThumbnails,
		computed: {
			infiniteScrollValue,
			useClassicLayoutValue,
			themeValue,
			highResThumbnailsValue,
		},
		userId: req.user.id
	});

	try {
		const result = db.query("UPDATE users SET infiniteScroll = $infiniteScroll, useClassicLayout = $useClassicLayout, themePreference = $themePreference, highResThumbnails = $highResThumbnails WHERE id = $id").run({
			infiniteScroll: infiniteScrollValue,
			useClassicLayout: useClassicLayoutValue,
			themePreference: themeValue,
			highResThumbnails: highResThumbnailsValue,
			id: req.user.id,
		});

		logger.debug("Update result:", result);

		// Verify the update
		const updatedUser = db.query("SELECT infiniteScroll, useClassicLayout, themePreference, highResThumbnails FROM users WHERE id = $id").get({ id: req.user.id });
		logger.debug("User after update:", updatedUser);

		return res.redirect("/dashboard");
	} catch (err) {
		logger.error("Error updating preferences:", err);
		return res.redirect("/dashboard?message=Failed to update preferences");
	}
});

router.get("/create-invite", authenticateAdmin, async (req, res) => {
	function generateInviteToken() {
		const hasher = new Bun.CryptoHasher("sha256");
		return hasher.update(Math.random().toString()).digest("hex").slice(0, 10);
	}

	function createInvite() {
		const token = generateInviteToken();
		db.run("INSERT INTO invites (token) VALUES ($token)", { token });
	}

	try {
		createInvite();
		return res.redirect("/dashboard");
	} catch (err) {
		logger.error(err);
		return res.send("failed to create invite");
	}
});

router.get("/delete-invite/:id", authenticateToken, async (req, res) => {
	try {
		db.run("DELETE FROM invites WHERE id = $id", { id: req.params.id });
		return res.redirect("/dashboard");
	} catch (err) {
		return res.send("failed to delete invite");
	}
});

// GET /media
router.get("/media/*", authenticateToken, async (req, res) => {
	const url = req.params[0];
	const ext = url.split(".").pop().toLowerCase();
	const kind = ["jpg", "jpeg", "png", "gif", "webp"].includes(ext)
		? "img"
		: "video";
	res.render("media", { kind, url, ...commonRenderOptions });
});

router.get("/register", validateInviteToken, async (req, res) => {
	res.render("register", {
		isDisabled: false,
		token: req.query.token,
		...commonRenderOptions,
	});
});

router.post("/register", validateInviteToken, async (req, res) => {
	const { username, password, confirm_password } = req.body;

	if (!username || !password || !confirm_password) {
		return res.status(400).send("All fields are required");
	}

	const user = db
		.query("SELECT * FROM users WHERE username = $username")
		.get({ username });
	if (user) {
		return res.render("register", {
			message: `user by the name "${username}" exists, choose a different username`,
			...commonRenderOptions,
		});
	}

	if (password !== confirm_password) {
		return res.render("register", {
			message: "passwords do not match, try again",
			...commonRenderOptions,
		});
	}

	try {
		const hashedPassword = await Bun.password.hash(password);

		if (!req.isFirstUser) {
			db.query(
				"UPDATE invites SET usedAt = CURRENT_TIMESTAMP WHERE id = $id",
			).run({
				id: req.invite.id,
			});
		}

		const insertedRecord = db
			.query(
				"INSERT INTO users (username, password_hash, isAdmin, groups) VALUES ($username, $hashedPassword, $isAdmin, $groups)",
			)
			.run({
			username,
			hashedPassword,
			isAdmin: req.isFirstUser ? 1 : 0,
			groups: "[]",
		});
		const id = insertedRecord.lastInsertRowid;
		setAuthTokenCookie(res, username, id);
		res.status(200).redirect("/");
	} catch (err) {
		return res.render("register", {
			message: "error registering user, try again later",
			...commonRenderOptions,
		});
	}
});



// OIDC routes (PKCE)
router.get("/auth/oidc/login", async (req, res) => {
  logger.debug(`[OIDC] /auth/oidc/login hit, OIDC enabled: ${oidc.isOIDCEnabled()}`);

  if (!oidc.isOIDCEnabled()) {
    logger.warn("[OIDC] OIDC not enabled, redirecting to login with bypass");
    return res.redirect("/login?bypass_oidc=true&message=OIDC not configured");
  }

  const redirectAfterLogin = req.query.redirect || "/";
  logger.debug(`[OIDC] Generating authorization URL, redirectAfterLogin: ${redirectAfterLogin}`);

  try {
    const { authorizationUrl, state, nonce, code_verifier, redirectAfterLogin: ra } = await oidc.getAuthorizationUrl({
      redirectAfterLogin,
    });

    logger.debug(`[OIDC] Authorization URL generated: ${authorizationUrl}`);
    logger.debug(`[OIDC] Setting cookies: state, nonce, verifier (length: ${code_verifier.length}), redirect: ${ra}`);

    // IMPORTANT: SameSite must be Lax (not Strict) so cookies are sent on the cross-site callback redirect.
    const cookieOptions = {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      maxAge: 10 * 60 * 1000, // 10 minutes
      path: "/auth/oidc",
    };

    res.cookie("oidc_state", state, cookieOptions);
    res.cookie("oidc_nonce", nonce, cookieOptions);
    res.cookie("oidc_verifier", code_verifier, cookieOptions);
    res.cookie("oidc_redirect", ra, cookieOptions);

    logger.debug(`[OIDC] Redirecting to IdP authorization URL`);
    res.redirect(authorizationUrl);
  } catch (err) {
    logger.error("[OIDC] Failed to start OIDC login:", err);
    return res.redirect("/login?bypass_oidc=true&message=Failed to start OIDC login");
  }
});

router.get("/auth/oidc/callback", async (req, res) => {
  if (!oidc.isOIDCEnabled()) {
    return res.redirect("/login?bypass_oidc=true&message=OIDC not configured");
  }

  const state = req.cookies?.oidc_state;
  const nonce = req.cookies?.oidc_nonce;
  const code_verifier = req.cookies?.oidc_verifier;
  const redirectAfterLogin = req.cookies?.oidc_redirect || "/";

  logger.debug('[OIDC] Callback received - cookies present:', {
    state: !!state,
    nonce: !!nonce,
    code_verifier: !!code_verifier,
  });
  if (code_verifier) {
    logger.debug(`[OIDC] Cookie code_verifier length: ${code_verifier.length}, first 20 chars: ${code_verifier.substring(0, 20)}...`);
  }

  // Clear transient cookies regardless
  res.clearCookie("oidc_state", { path: "/auth/oidc" });
  res.clearCookie("oidc_nonce", { path: "/auth/oidc" });
  res.clearCookie("oidc_verifier", { path: "/auth/oidc" });
  res.clearCookie("oidc_redirect", { path: "/auth/oidc" });

  try {
    if (!state || !nonce || !code_verifier) {
      logger.warn('OIDC callback missing cookies - state:', !!state, 'nonce:', !!nonce, 'code_verifier:', !!code_verifier);
      return res.redirect("/login?bypass_oidc=true&message=OIDC session expired, try again");
    }

    const { tokenSet, claims } = await oidc.handleCallback(req, {
      state,
      nonce,
      code_verifier,
    });

    // handleCallback already validates that sub exists, so we can use it directly
    const sub = claims.sub;
    logger.info(`[OIDC] Callback successful for sub: ${sub}`);

    const groups = oidc.extractGroupsFromClaims(claims);
    if (!oidc.isAllowedByGroups(groups)) {
      return res.redirect("/login?bypass_oidc=true&message=Not allowed (missing required group)");
    }

    const isFirstUser = db.query("SELECT 1 FROM users LIMIT 1").get() === null;
    const firstUserAdmin = process.env.OIDC_FIRST_USER_ADMIN === undefined
      ? true
      : String(process.env.OIDC_FIRST_USER_ADMIN).toLowerCase() === "true" || process.env.OIDC_FIRST_USER_ADMIN === "1";

    let isAdmin = oidc.isAdminFromClaims(claims, groups) ? 1 : 0;
    if (isFirstUser && firstUserAdmin) isAdmin = 1;

    const autoRegister = process.env.OIDC_AUTO_REGISTER === undefined
      ? true
      : String(process.env.OIDC_AUTO_REGISTER).toLowerCase() === "true" || process.env.OIDC_AUTO_REGISTER === "1";

    let user = db.query("SELECT * FROM users WHERE oidc_sub = $sub").get({ sub });

    const expiresAt = oidc.computeExpiresAtSeconds(tokenSet);
    const encRefresh = tokenSet.refresh_token ? oidc.encryptRefreshToken(tokenSet.refresh_token) : null;

    if (!user) {
      // Check if there's an existing user with matching username (account linking)
      let desiredUsername = oidc.resolveUsernameFromClaims(claims) || sub;
      desiredUsername = String(desiredUsername).trim();

      const existingByUsername = db.query("SELECT * FROM users WHERE username = $username").get({
        username: desiredUsername,
      });

      if (existingByUsername) {
        // Link existing password account to OIDC
        logger.info(`Linking existing user '${desiredUsername}' to OIDC sub: ${sub}`);

        db.query(
          "UPDATE users SET oidc_sub = $sub, oidc_refresh_token = $rt, oidc_token_expires_at = $exp, isAdmin = $isAdmin, groups = $groups WHERE id = $id"
        ).run({
          sub,
          rt: encRefresh,
          exp: expiresAt,
          isAdmin,
          groups: JSON.stringify(groups),
          id: existingByUsername.id,
        });

        setAuthTokenCookie(res, existingByUsername.username, existingByUsername.id);
        return res.redirect(redirectAfterLogin);
      }

      // No existing user - create new if auto-register enabled
      if (!autoRegister) {
        return res.redirect("/login?bypass_oidc=true&message=Account not registered");
      }

      const randomPassword = generateRandomPassword(52);
      const hashedPassword = await Bun.password.hash(randomPassword);

      const insertedRecord = db.query(
        "INSERT INTO users (username, password_hash, isAdmin, oidc_sub, oidc_refresh_token, oidc_token_expires_at, groups) VALUES ($username, $hashedPassword, $isAdmin, $oidc_sub, $oidc_refresh_token, $oidc_token_expires_at, $groups)"
      ).run({
        username: desiredUsername,
        hashedPassword,
        isAdmin,
        oidc_sub: sub,
        oidc_refresh_token: encRefresh,
        oidc_token_expires_at: expiresAt,
        groups: JSON.stringify(groups),
      });

      const userId = insertedRecord.lastInsertRowid;
      logger.info(`Created new OIDC user '${desiredUsername}' with sub: ${sub}`);
      setAuthTokenCookie(res, desiredUsername, userId);
      return res.redirect(redirectAfterLogin);
    }

    // Existing OIDC user: update admin/groups and rotate refresh token if provided
    const baseSql = "UPDATE users SET isAdmin = $isAdmin, groups = $groups, oidc_token_expires_at = $exp";
    const sql = encRefresh ? (baseSql + ", oidc_refresh_token = $rt WHERE id = $id") : (baseSql + " WHERE id = $id");

    const params = {
      isAdmin,
      groups: JSON.stringify(groups),
      exp: expiresAt,
      id: user.id,
    };
    if (encRefresh) params.rt = encRefresh;

    db.query(sql).run(params);

    setAuthTokenCookie(res, user.username, user.id);
    return res.redirect(redirectAfterLogin);
  } catch (err) {
    logger.error("OIDC callback failed", err);
    return res.redirect("/login?bypass_oidc=true&message=OIDC login failed");
  }
});

// GET /login
router.get("/login", async (req, res, next) => {
  const token = req.cookies.auth_token;
  if (token) {
    return res.redirect("/");
  }

  const redirectTo = req.query.redirect || req.query.direct || "/";
  const bypassOidc = String(req.query.bypass_oidc || "").toLowerCase() === "true" || req.query.bypass_oidc === "1";

  // Priority 1: OIDC
  if (oidc.isOIDCEnabled() && !bypassOidc) {
    logger.debug(`[LOGIN] OIDC enabled, redirecting to /auth/oidc/login with redirect=${redirectTo}`);
    return res.redirect(`/auth/oidc/login?redirect=${encodeURIComponent(redirectTo)}`);
  }

  // Priority 2: Remote Header SSO
  if (req.headers['remote-user']) {
    return loginViaHeaders(req, res, next);
  }

  // Priority 3: Manual login
  return res.render("login", {
    message: req.query.message,
    oidcEnabled: oidc.isOIDCEnabled(),
    redirect: redirectTo,
    bypassOidc,
    ...commonRenderOptions,
  });
});

// POST /login (form submission)
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render("login", { message: "Both username and password are required." });
  }

  const user = db.query("SELECT * FROM users WHERE username = $username").get({ username });

  if (user && (await Bun.password.verify(password, user.password_hash))) {
    try {
      setAuthTokenCookie(res, username, user.id);
      const redirectTo = req.query.redirect || req.query.direct || '/';
      return res.redirect(redirectTo);
    } catch (error) {
      logger.error("Error signing JWT:", error);
      res.render("login", { message: "Something went wrong, try again later." });
    }
  } else {
    // Invalid credentials
    res.render("login", { message: "Invalid credentials, try again." });
  }
});

// GET /logout (clear JWT and log out user)
router.get("/logout", (req, res) => {
  res.clearCookie("auth_token", { httpOnly: true, secure: true });
  res.redirect("/login");
});

// POST /subscribe
router.post("/subscribe", authenticateToken, async (req, res) => {
	const { subreddit } = req.body;
	const user = req.user;
	const existingSubscription = db
		.query(
			"SELECT * FROM subscriptions WHERE user_id = $id AND subreddit = $subreddit",
		)
		.get({ id: user.id, subreddit });
	if (existingSubscription) {
		res.status(400).send("Already subscribed to this subreddit");
	} else {
		db.query(
			"INSERT INTO subscriptions (user_id, subreddit) VALUES ($id, $subreddit)",
		).run({ id: user.id, subreddit });
		res.status(201).send("Subscribed successfully");
	}
});

router.post("/unsubscribe", authenticateToken, async (req, res) => {
	const { subreddit } = req.body;
	const user = req.user;
	const existingSubscription = db
		.query(
			"SELECT * FROM subscriptions WHERE user_id = $id AND subreddit = $subreddit",
		)
		.get({ id: user.id, subreddit });
	if (existingSubscription) {
		db.query(
			"DELETE FROM subscriptions WHERE user_id = $id AND subreddit = $subreddit",
		).run({ id: user.id, subreddit });
		res.status(200).send("Unsubscribed successfully");
	} else {
		res.status(400).send("Subscription not found");
	}
});

// Unsubscribe from all subreddits
router.post("/unsubscribe-all", authenticateToken, async (req, res) => {
	const user = req.user;
	try {
		const result = db
			.query("DELETE FROM subscriptions WHERE user_id = $id")
			.run({ id: user.id });

		res.status(200).json({
			message: "All subscriptions removed",
			count: result.changes,
		});
	} catch (error) {
		console.error("Error removing all subscriptions:", error);
		res.status(500).send("Failed to remove subscriptions");
	}
});

// Bulk subscribe to multiple subreddits
router.post("/subscribe-bulk", authenticateToken, async (req, res) => {
	const { subreddits } = req.body;
	const user = req.user;

	if (!Array.isArray(subreddits) || subreddits.length === 0) {
		return res.status(400).json({
			error: "Invalid request: subreddits must be a non-empty array",
		});
	}

	const results = {
		added: [],
		skipped: [], // Already subscribed
		failed: [],
	};

	for (const subreddit of subreddits) {
		try {
			const existingSubscription = db
				.query(
					"SELECT * FROM subscriptions WHERE user_id = $id AND subreddit = $subreddit",
				)
				.get({ id: user.id, subreddit });

			if (existingSubscription) {
				results.skipped.push(subreddit);
			} else {
				db.query(
					"INSERT INTO subscriptions (user_id, subreddit) VALUES ($id, $subreddit)",
				).run({ id: user.id, subreddit });
				results.added.push(subreddit);
			}
		} catch (error) {
			console.error(`Error subscribing to ${subreddit}:`, error);
			results.failed.push(subreddit);
		}
	}

	res.status(200).json(results);
});

// PWA Support Routes
const { generateIcon } = require("../utils/iconGenerator");

// Serve app icons for PWA
router.get("/icon-:size.png", (req, res) => {
	const size = parseInt(req.params.size);
	const validSizes = [72, 96, 128, 144, 152, 180, 192, 384, 512];

	if (!validSizes.includes(size)) {
		return res.status(404).send("Invalid icon size");
	}

	const svg = generateIcon(size);

	// For now, serve as SVG (browsers will handle it)
	// In production, you might want to convert to PNG
	res.setHeader('Content-Type', 'image/svg+xml');
	res.setHeader('Cache-Control', 'public, max-age=31536000'); // Cache for 1 year
	res.send(svg);
});

// Serve web app manifest
router.get("/manifest.json", (_req, res) => {
	const manifest = {
		name: "Lurker",
		short_name: "Lurker",
		description: "A private, minimal Reddit client",
		start_url: "/",
		display: "standalone",
		background_color: "#ffffff",
		theme_color: "#29BC9B",
		orientation: "portrait-primary",
		icons: [
			{
				src: "/icon-72.png",
				sizes: "72x72",
				type: "image/svg+xml"
			},
			{
				src: "/icon-96.png",
				sizes: "96x96",
				type: "image/svg+xml"
			},
			{
				src: "/icon-128.png",
				sizes: "128x128",
				type: "image/svg+xml"
			},
			{
				src: "/icon-144.png",
				sizes: "144x144",
				type: "image/svg+xml"
			},
			{
				src: "/icon-152.png",
				sizes: "152x152",
				type: "image/svg+xml"
			},
			{
				src: "/icon-192.png",
				sizes: "192x192",
				type: "image/svg+xml",
				purpose: "any maskable"
			},
			{
				src: "/icon-384.png",
				sizes: "384x384",
				type: "image/svg+xml"
			},
			{
				src: "/icon-512.png",
				sizes: "512x512",
				type: "image/svg+xml",
				purpose: "any maskable"
			}
		]
	};

	res.setHeader('Content-Type', 'application/json');
	res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour
	res.json(manifest);
});

// Offline fallback page
router.get("/offline", (req, res) => {
	const user = req.user || { themePreference: 'auto', useClassicLayout: 0 };
	res.render("offline", { user });
});

module.exports = router;

function unescape_submission(response) {
	const post = response.submission.data;
	const comments = response.comments;

	unescape_selftext(post);
	comments.forEach(unescape_comment);

	return { post, comments };
}

function unescape_selftext(post) {
	// If called after getSubmissions
	if (post.data && post.data.selftext_html) {
		post.data.selftext_html = he.decode(post.data.selftext_html);
	}
	// If called after getSubmissionComments
	if (post.selftext_html) {
		post.selftext_html = he.decode(post.selftext_html);
	}
	// Also unescape crosspost parent selftext if present
	if (post.crosspost_parent_list && post.crosspost_parent_list.length > 0) {
		unescape_selftext(post.crosspost_parent_list[0]);
	}
}

function unescape_comment(comment) {
	if (comment.data.body_html) {
		comment.data.body_html = he.decode(comment.data.body_html);
	}
	if (comment.data.replies) {
		if (comment.data.replies.data) {
			if (comment.data.replies.data.children) {
				comment.data.replies.data.children.forEach(unescape_comment);
			}
		}
	}
}
