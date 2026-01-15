const { Database } = require("bun:sqlite");
const path = require("path");

// Use /data directory for database (where volume is mounted)
const dbPath = path.join("/data", "lurker.db");
const db = new Database(dbPath, {
	strict: true,
});

function runMigration(name, migrationFn) {
	const exists = db
		.query("SELECT * FROM migrations WHERE name = $name")
		.get({ name });

	if (!exists) {
		migrationFn();
		db.query("INSERT INTO migrations (name) VALUES ($name)").run({ name });
	}
}

// users table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  )
`);

// subs table
db.run(`
  CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    subreddit TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(user_id, subreddit)
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    usedAt TIMESTAMP
  )
`);

// migrations table
db.query(`
  CREATE TABLE IF NOT EXISTS migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE
  )
`).run();

runMigration("add-isAdmin-column", () => {
	db.query(`
    ALTER TABLE users
    ADD COLUMN isAdmin INTEGER DEFAULT 0
  `).run();

	// first user is admin
	db.query(`
    UPDATE users
    SET isAdmin = 1
    WHERE id = (SELECT MIN(id) FROM users)
  `).run();
});

module.exports = { db };
