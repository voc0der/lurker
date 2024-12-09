const express = require("express");
const he = require("he");
const jwt = require("jsonwebtoken");
const geddit = require("../geddit.js");
const { JWT_KEY } = require("../");
const { db } = require("../db");
const { authenticateToken, authenticateAdmin } = require("../auth");
const { validateInviteToken } = require("../invite");

const router = express.Router();
const G = new geddit.Geddit();

// Middleware to authenticate using JWT token (from cookies)
function authenticateToken(req, res, next) {
  const token = req.cookies.auth_token;

  if (!token) {
    return res.redirect("/login");  // Redirect to login if no token found
  }

  jwt.verify(token, JWT_KEY, (err, user) => {
    if (err) {
      return res.redirect("/login");  // If token is invalid, redirect to login
    }

    req.user = user;  // Attach user data to the request object
    next();  // Continue to the next middleware
  });
}

// Middleware to check if user is logged in via HTTP headers
function loginViaHeaders(req, res, next) {
  const remoteUser = req.headers['remote-user'];
  const remoteGroups = req.headers['remote-groups'] ? req.headers['remote-groups'].split(',') : [];

  if (remoteUser) {
    req.user = {
      id: remoteUser,
      isAdmin: remoteGroups.includes('admins'),  // Check if user is an admin
      validated: true,  // Flag to mark user as validated via headers
    };

    // Redirect to the originally requested page or home if no `direct` query
    const redirectTo = req.query.direct || '/';
    return res.redirect(redirectTo);
  }

  // If headers don't exist, proceed to the next middleware
  next();
}

// GET /
router.get("/", authenticateToken, async (req, res) => {
  const subs = db.query("SELECT * FROM subscriptions WHERE user_id = $id").all({ id: req.user.id });
  if (subs.length === 0) {
    res.redirect("/r/all");
  } else {
    const p = subs.map((s) => s.subreddit).join("+");
    res.redirect(`/r/${p}`);
  }
});

// GET /r/:id
router.get("/r/:subreddit", authenticateToken, async (req, res) => {
  const subreddit = req.params.subreddit;
  const isMulti = subreddit.includes("+");
  const query = req.query || {};
  query.sort = query.sort || "hot";

  let isSubbed = false;
  if (!isMulti) {
    isSubbed = db.query("SELECT * FROM subscriptions WHERE user_id = $id AND subreddit = $subreddit")
                 .get({ id: req.user.id, subreddit }) !== null;
  }

  const postsReq = G.getSubmissions(query.sort, subreddit, query);
  const aboutReq = G.getSubreddit(subreddit);
  const [posts, about] = await Promise.all([postsReq, aboutReq]);

  res.render("index", {
    subreddit,
    posts,
    about,
    query,
    isMulti,
    user: req.user,
    isSubbed,
  });
});

// Other routes ...

// GET /login (use loginViaHeaders for login via HTTP headers)
router.get("/login", loginViaHeaders, (req, res) => {
  if (req.user && req.user.validated) {
    // If logged in via headers, redirect to home
    return res.redirect('/');
  }
  
  // If not logged in, render the login form
  res.render("login", { message: req.query.message });
});

// POST /login (form submission)
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render("login", { message: "Both username and password are required." });
  }

  const user = db.query("SELECT * FROM users WHERE username = $username").get({ username });

  if (user && (await Bun.password.verify(password, user.password_hash))) {
    // Password matches, create JWT token and store it in the cookie
    const token = jwt.sign({ username, id: user.id }, JWT_KEY, { expiresIn: "5d" });
    res.cookie("auth_token", token, { httpOnly: true, maxAge: 5 * 24 * 60 * 60 * 1000 });  // Store JWT in cookies

    // Redirect to the page user was originally trying to visit, or home if not provided
    const redirectTo = req.query.direct || '/';
    return res.redirect(redirectTo);
  } else {
    // Invalid credentials, show error message
    res.render("login", { message: "Invalid credentials, try again." });
  }
});

// GET /logout (clear JWT and log out user)
router.get("/logout", (req, res) => {
  res.clearCookie("auth_token", { httpOnly: true, secure: true });
  res.redirect("/login");
});

// Other routes ...

module.exports = router;

// Helper functions for unescaping posts/comments
function unescape_submission(response) {
  const post = response.submission.data;
  const comments = response.comments;

  if (post.selftext_html) {
    post.selftext_html = he.decode(post.selftext_html);
  }
  comments.forEach(unescape_comment);

  return { post, comments };
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
