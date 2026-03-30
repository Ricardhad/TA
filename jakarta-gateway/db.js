import Database from 'better-sqlite3';
const db = new Database('vault.db');

// Enable Foreign Key support (SQLite disables this by default!)
db.pragma('foreign_keys = ON');

// Initialize tables with "Zero Trust" rows
db.exec(`
  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,            -- 🔒 For Public URLs (Anti-Enumeration)
    filename TEXT NOT NULL,
    content_type TEXT,                   -- 📄 e.g., 'image/png' for UI preview
    bucket_name TEXT DEFAULT 'default',
    owner_id TEXT NOT NULL,              -- 👤 Auth0 User ID,
    mime_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER,
    version_num INTEGER NOT NULL,
    physical_path TEXT NOT NULL,         -- 📦 Encrypted name on Surabaya disk
    size INTEGER,
    checksum TEXT,                       -- ✅ SHA-256 for Integrity Verification
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT,
    action TEXT,
    status TEXT,
    ip_address TEXT,                     -- 📍 For Security Forensics
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`);

export default db;