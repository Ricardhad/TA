import Database from 'better-sqlite3';
const db = new Database('vault.db');

// Enable Foreign Key support (SQLite disables this by default!)
db.pragma('foreign_keys = ON');

// Initialize tables with "Zero Trust" rows
db.exec(`
  -- 1. THE NAMESPACE LAYER (Buckets)
  CREATE TABLE IF NOT EXISTS buckets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,           -- 📦 Public Bucket ID (e.g., bkt_882j...)
    name TEXT NOT NULL,                  -- 🏷️ User-friendly name
    region TEXT DEFAULT 'sub-01',        -- 📍 Location: Surabaya, Jakarta, etc.
    owner_id TEXT NOT NULL,              -- 👤 Creator's Auth0 ID
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );

  -- 2. THE POLICY LAYER (RBAC)
  CREATE TABLE IF NOT EXISTS bucket_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_id INTEGER NOT NULL,
    grantee_id TEXT NOT NULL,            -- 👥 Collaborator's Auth0 ID
    permission TEXT NOT NULL,            -- ⚖️ 'READ', 'WRITE', or 'ADMIN'
    FOREIGN KEY(bucket_id) REFERENCES buckets(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,            -- 🔒 For Public URLs (Anti-Enumeration)
    filename TEXT NOT NULL,
    content_type TEXT,                   -- 📄 e.g., 'image/png' for UI preview
    bucket_id INTEGER,
    owner_id TEXT NOT NULL,              -- 👤 Auth0 User ID,
    mime_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(bucket_id) REFERENCES buckets(id) ON DELETE SET NULL
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
  CREATE TABLE IF NOT EXISTS file_access (
    file_uuid TEXT,
    user_id TEXT, -- The Auth0 'sub' ID
    role TEXT,    -- 'EDITOR' or 'VIEWER'
    PRIMARY KEY (file_uuid, user_id),
    FOREIGN KEY (file_uuid) REFERENCES files(uuid)
  );

`);

export default db;