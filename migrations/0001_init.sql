CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL,
 name TEXT,
 role TEXT DEFAULT 'reader',
 is_publisher INTEGER DEFAULT 0,
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS books (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 author TEXT,
 description TEXT,
 cover_url TEXT,
 file_url TEXT,
 owner_id INTEGER,
 status TEXT DEFAULT 'published',
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(owner_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS articles (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 content TEXT NOT NULL,
 cover_url TEXT,
 author_id INTEGER,
 status TEXT DEFAULT 'published',
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(author_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS ads (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT,
 placement TEXT NOT NULL,
 type TEXT DEFAULT 'image_link',
 custom_html TEXT,
 image_url TEXT,
 link_url TEXT,
 owner_id INTEGER,
 is_active INTEGER DEFAULT 1,
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(owner_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS publisher_requests (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 name TEXT,
 reason TEXT,
 samples TEXT,
 status TEXT DEFAULT 'pending',
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS forum_messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 room TEXT,
 user_id INTEGER,
 message TEXT,
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Admin user will be created by setup.sh with secure hash - no hardcoded credentials


-- SECURITY: Rate limiting table
CREATE TABLE IF NOT EXISTS rate_limits (
  ip TEXT PRIMARY KEY,
  count INTEGER DEFAULT 1,
  window_start INTEGER
);

-- SECURITY: Audit log
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT,
  details TEXT,
  ip TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- SECURITY: File metadata for validation
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE,
  original_name TEXT,
  mime_type TEXT,
  size INTEGER,
  owner_id INTEGER,
  is_public INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(owner_id) REFERENCES users(id)
);

-- Index for performance
CREATE INDEX IF NOT EXISTS idx_books_owner ON books(owner_id);
CREATE INDEX IF NOT EXISTS idx_articles_author ON articles(author_id);
CREATE INDEX IF NOT EXISTS idx_ads_placement ON ads(placement);
CREATE INDEX IF NOT EXISTS idx_ads_owner ON ads(owner_id);
