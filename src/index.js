const express = require("express");
const rateLimit = require("express-rate-limit");
const path = require("node:path");
const cookieParser = require("cookie-parser");
const https = require("https");
const fs = require("fs");
const app = express();
const hasher = new Bun.CryptoHasher("sha256", "secret-key");
const JWT_KEY = process.env.JWT_SECRET_KEY || hasher.update(Math.random().toString()).digest("hex");
const trustedProxyIPs = (process.env.REVERSE_PROXY_WHITELIST || '').split(',').map(ip => ip.trim());

console.log("JWT_SECRET_KEY:", process.env.JWT_SECRET_KEY);
console.log("Using JWT_KEY:", JWT_KEY);  // This is the key that will be used for signing and verifying the JWT

module.exports = { JWT_KEY };

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");

const routes = require("./routes/index");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname, "assets")));
app.use(cookieParser());
if ((process.env.REMOTE_HEADER_LOGIN || false)) {
    // Set trust proxy dynamically based on trustedProxyIPs, fallback to '1'
    if (trustedProxyIPs.some(ip => ip)) {
        const trustProxyRanges = trustedProxyIPs.join(",");
        console.log("Trusting proxies in range:", trustProxyRanges);
        app.set('trust proxy', trustProxyRanges);
    } else {
        console.warn('No valid IPs in REVERSE_PROXY_WHITELIST. Falling back to trust proxy: 1.');
        app.set('trust proxy', 1);
    }
}
app.use(
    rateLimit({
        windowMs: 15 * 60 * 1000,
        max: (process.env.RATE_LIMIT || 100),
        message: "Too many requests from this IP, please try again later.",
        standardHeaders: true,
        legacyHeaders: false,
    }),
);
app.use("/", routes);

const sslCertPath = process.env.LURKER_SSL_CERT_PATH;
const sslKeyPath = process.env.LURKER_SSL_KEY_PATH;

if (sslCertPath && sslKeyPath) {
    try {
        const sslCert = fs.readFileSync(sslCertPath, "utf8");
        const sslKey = fs.readFileSync(sslKeyPath, "utf8");

        // Create HTTPS server
        const httpsServer = https.createServer({ 
            key: sslKey,
            cert: sslCert
        }, app);

        const port = process.env.LURKER_PORT || 3000;
        httpsServer.listen(port, () => {
            console.log(`HTTPS server started on port ${port}`);
        });
    } catch (err) {
        console.error("Failed to load SSL certificate or key:", err.message);
        process.exit(1); // Exit if the SSL setup fails
    }
} else {
    console.warn("SSL_CERT_PATH or SSL_KEY_PATH not provided. Falling back to HTTP.");
    const port = process.env.LURKER_PORT || 3000;
    const server = app.listen(port, () => {
        console.log(`HTTP server started on port ${server.address().port}`);
    });
}
