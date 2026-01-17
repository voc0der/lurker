const jwt = require("jsonwebtoken");
const { db } = require("./db");
const { JWT_KEY } = require("./");
const logger = require("./logger");

// Helper function to log token issues
function logTokenError(message, error) {
  logger.error(message, error);
}

// Middleware to authenticate using JWT token (from cookies)
function authenticateToken(req, res, next) {
  const token = req.cookies && req.cookies.auth_token;
  const remoteGroups = req.headers['remote-groups'] ? req.headers['remote-groups'].split(',') : [];
  const isAdmin = remoteGroups.includes(process.env.ADMIN_GROUP || 'admin') ? 1 : 0;

  if (!token) {
    logger.debug("No token found, redirecting to login.");
    return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
  }

  try {
    logger.debug("Verifying token...");
    const decoded = jwt.verify(token, JWT_KEY);
    logger.debug("Token verified for user:", decoded);

    let dbUser;
    try {
      dbUser = db.query("SELECT * FROM users WHERE username = $username").get({ username: decoded.username });
      logger.debug("authenticateToken - loaded user from DB:", {
        id: dbUser?.id,
        username: dbUser?.username,
        infiniteScroll: dbUser?.infiniteScroll,
        useClassicLayout: dbUser?.useClassicLayout,
        themePreference: dbUser?.themePreference
      });
    } catch (err) {
      logger.error("Database error:", err);
      return res.redirect("/login?message=Database error.");
    }

    if (!dbUser) {
      logger.debug("User not found in database for token:", decoded.username);
      return res.redirect("/login?message=User not found.");
    } else {
      if ((process.env.REMOTE_HEADER_LOGIN || false) && remoteGroups.length > 0 && dbUser.isAdmin !== isAdmin) {
        db.query("UPDATE users SET isAdmin = $isAdmin WHERE id = $id")
          .run({
            isAdmin: isAdmin,
            id: dbUser.id,
          });
        logger.debug(`Updated isAdmin=${isAdmin} for ${decoded.username} - ${dbUser.id} in database.`);
      }
    }

    req.user = dbUser; // Attach the actual user object to the request
    next(); // Proceed to next middleware
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      logger.debug("Token expired:", error);
      return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}&message=Session expired`);
    }
    logTokenError("Token verification failed:", error);
    res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
  }
}

// Middleware to authenticate admin (checks if user has admin privileges)
function authenticateAdmin(req, res, next) {
  const token = req.cookies && req.cookies.auth_token;
  const remoteGroups = req.headers['remote-groups'] ? req.headers['remote-groups'].split(',') : [];
  const isAdmin = remoteGroups.includes(process.env.ADMIN_GROUP || 'admin') ? 1 : 0;

  if (!token) {
    logger.debug("No token found, redirecting to login for admin.");
    return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
  }

  try {
    logger.debug("Verifying token for admin...");
    const decoded = jwt.verify(token, JWT_KEY);
    logger.debug("Admin token verified for user:", decoded);

    let dbUser;
    try {
      dbUser = db.query("SELECT * FROM users WHERE username = $username").get({ username: decoded.username });
    } catch (err) {
      logger.error("Database error:", err);
      return res.redirect("/login?message=Database error.");
    }

    if (!dbUser) {
      logger.debug("Admin user not found in database for token:", decoded.username);
      return res.redirect("/login?message=Admin user not found.");
    } else {
      if ((process.env.REMOTE_HEADER_LOGIN || false) && remoteGroups.length > 0 && dbUser.isAdmin !== isAdmin) {
        db.query("UPDATE users SET isAdmin = $isAdmin WHERE id = $id")
          .run({
            isAdmin: isAdmin,  // Update to 1 for admin, 0 for non-admin
            id: dbUser.id,
          });
        logger.debug(`Updated isAdmin=${isAdmin} for ${decoded.username} - ${dbUser.id} in database.`);
      }
    }

    req.user = dbUser;
    if (dbUser.isAdmin) {
      return next();
    } else {
      logger.debug("User is not an admin:", dbUser.username);
      return res.status(403).send("Only admins can access this route.");
    }
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      logger.debug("Admin token expired:", error);
      return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}&message=Session expired`);
    }
    logTokenError("Admin token verification failed:", error);
    res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
  }
}

module.exports = { authenticateToken, authenticateAdmin };
