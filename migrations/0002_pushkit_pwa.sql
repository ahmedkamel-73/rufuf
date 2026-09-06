CREATE TABLE IF NOT EXISTS push_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint TEXT UNIQUE, subscription_json TEXT NOT NULL, created_at INTEGER);
