import Database from 'better-sqlite3';
const db = new Database('vault.db');
db.pragma('foreign_keys = ON ');
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  sub TEXT PRIMARY KEY,
  email TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS buckets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT UNIQUE NOT NULL,           
  name TEXT NOT NULL,                
  region TEXT DEFAULT 'sub-01',       
  owner_id TEXT NOT NULL,            
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMP DEFAULT NULL,
  FOREIGN KEY(owner_id) REFERENCES users(sub) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bucket_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bucket_id INTEGER NOT NULL,
  grantee_id TEXT NOT NULL,           
  permission TEXT NOT NULL,           
  UNIQUE(bucket_id, grantee_id),
  FOREIGN KEY(bucket_id) REFERENCES buckets(id) ON DELETE CASCADE,
  FOREIGN KEY(grantee_id) REFERENCES users(sub) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT UNIQUE NOT NULL,           
  filename TEXT NOT NULL,
  mime_type TEXT,                   
  bucket_id INTEGER NOT NULL,       
  owner_id TEXT NOT NULL,              
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMP DEFAULT NULL,
  FOREIGN KEY(bucket_id) REFERENCES buckets(id) ON DELETE CASCADE,
  FOREIGN KEY(owner_id) REFERENCES users(sub) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL,
  version_num INTEGER NOT NULL,
  physical_path TEXT NOT NULL,       
  size INTEGER,
  checksum TEXT,                   
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bucket_uuid TEXT,
  user_email TEXT,
  action TEXT,
  status TEXT,
  ip_address TEXT,                    
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,               -- Target user's Auth0 ID
  message TEXT NOT NULL,               -- Teks notifikasi
  is_read BOOLEAN DEFAULT 0,           -- 0 = Unread, 1 = Read
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(sub) ON DELETE CASCADE
);
`);

export default db;