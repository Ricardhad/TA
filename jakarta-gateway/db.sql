-- 1. USERS LAYER (Shadow Table untuk Auth0 Identity Mapping)
CREATE TABLE IF NOT EXISTS users (
  sub TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL
);

-- 2. THE NAMESPACE LAYER (Buckets)
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

-- 3. THE POLICY LAYER (RBAC - Bucket Level)
CREATE TABLE IF NOT EXISTS bucket_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bucket_id INTEGER NOT NULL,
  grantee_id TEXT NOT NULL,           
  permission TEXT NOT NULL,           
  UNIQUE(bucket_id, grantee_id),
  FOREIGN KEY(bucket_id) REFERENCES buckets(id) ON DELETE CASCADE,
  FOREIGN KEY(grantee_id) REFERENCES users(sub) ON DELETE CASCADE
);

-- 4. FILES LAYER
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

-- 5. VERSIONS LAYER
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

-- 6. AUDIT LAYER (Tanpa FK agar log tidak hilang saat user dihapus)
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_email TEXT,
  action TEXT,
  status TEXT,
  ip_address TEXT,                    
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 7. NOTIFICATIONS LAYER
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,               -- Target user's Auth0 ID
  message TEXT NOT NULL,               -- Teks notifikasi
  is_read BOOLEAN DEFAULT 0,           -- 0 = Unread, 1 = Read
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(sub) ON DELETE CASCADE
);