const jwt = require("jsonwebtoken");
const { db } = require("./db");
const { JWT_KEY } = require("./");

function authenticateToken(req, res, next) {
  if (!req.cookies || !req.cookies.auth_token) {
    return res.redirect(
      `/login?redirect=${encodeURIComponent(req.originalUrl)}`
    );
  }

  const token = req.cookies.auth_token;

  if (!token) {
    return res.redirect(
      `/login?redirect=${encodeURIComponent(req.originalUrl)}`
    );
  }

  try {
    const user = jwt.verify(token, JWT_KEY);
    req.user = user;
    next();
  } catch (error) {
    res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
  }
}

function authenticateAdmin(req, res, next) {
	if (!req.cookies || !req.cookies.auth_token) {
		return res.redirect(
			`/login?redirect=${encodeURIComponent(req.originalUrl)}`,
		);
	}

	const token = req.cookies.auth_token;

	// If no token, deny access
	if (!token) {
		return res.redirect(
			`/login?redirect=${encodeURIComponent(req.originalUrl)}`,
		);
	}

	try {
		const user = jwt.verify(token, JWT_KEY);
		req.user = user;
		const isAdmin = db
			.query("SELECT isAdmin FROM users WHERE id = $id and isAdmin = 1")
			.get({
				id: req.user.id,
			});
		if (isAdmin) {
			next();
		} else {
			res.status(400).send("only admins can invite");
		}
	} catch (error) {
		res.send(`failed to authenticate as admin: ${error}`);
	}
}

module.exports = { authenticateToken, authenticateAdmin };
