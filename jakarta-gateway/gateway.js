import https from 'https';
import fs from 'fs';
import express from 'express';
import dotenv from 'dotenv';
import { auth } from 'express-oauth2-jwt-bearer';
import cors from 'cors';
import db from './db.js';
import { randomUUID } from 'crypto';
import crypto from 'crypto';
import helmet from 'helmet';
import Busboy from 'busboy';
import { Readable } from 'node:stream';
import rateLimit from 'express-rate-limit';
import { authorizeVault, validateFileSecurity, permitGlobalRole, authorizeBucket } from './middleware.js';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PUBLIC_PORT = 8080;
const apiRouter = express.Router();

const LOCAL_SPOKE_IP = process.env.SPOKE_IP;
const LOCAL_PORT = process.env.GATEWAY_PORT;
const namespace = process.env.NAMESPACE || 'unknown_namespace';

// ==========================================
// 1. BASIC MIDDLEWARE & SECURITY
// ==========================================
// app.use(helmet());
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            // Izinkan React menghubungi backend sendiri DAN peladen Auth0 Anda
            "connect-src": ["'self'", "https://richard-ztna-project.jp.auth0.com"],
            // Izinkan React mengeksekusi skripnya sendiri
            "script-src": ["'self'", "'unsafe-inline'"],
            // Izinkan React menggunakan CSS bawaannya
            "style-src": ["'self'", "'unsafe-inline'"],
            // Izinkan pemuatan gambar/avatar (dari Auth0, Google, dll)
            "img-src": ["'self'", "data:", "https:"]
        },
    },
}));
app.use(cors({
    origin: ['http://localhost:5173', 'https://richardgatewayta.duckdns.org:8080'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-bucket-uuid', 'x-file-prefix'],
    credentials: true
}));

app.use(express.json({ limit: '1mb', strict: true }));

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1500,
    message: { error: "Too many requests. Please try again later." },
    standardHeaders: true,
    legacyHeaders: false,
});

const strictLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 50,
    message: { error: "Action rate limit exceeded." }
});

const bouncer = auth({
    audience: namespace,
    issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}/`,
    tokenSigningAlg: 'RS256'
});

// ==========================================
// 2. M2M AUTH & HEALTH CHECKS
// ==========================================
let cachedM2MToken = null;
let tokenExpiry = 0;
// 🆕 Tambahkan variabel kunci
let tokenPromise = null; 

async function getSpokeToken() {
    const now = Math.floor(Date.now() / 1000);

    if (cachedM2MToken && now < tokenExpiry) {
        return cachedM2MToken;
    }

    if (tokenPromise) {
        return await tokenPromise;
    }

    console.log("[AUTH] Fetching fresh M2M token from Auth0...");
    
    tokenPromise = (async () => {
        try {
            const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({
                    client_id: process.env.M2M_CLIENT_ID,
                    client_secret: process.env.M2M_CLIENT_SECRET,
                    audience: process.env.NAMESPACE,
                    grant_type: 'client_credentials'
                })
            });

            const data = await response.json();
            
            if (!data.access_token) {
                console.error("[AUTH ERROR] Auth0 denied the request:", data);
                throw new Error(`Auth0 Authentication Failed: ${data.error_description || data.error}`);
            }

            cachedM2MToken = data.access_token;
            tokenExpiry = now + data.expires_in - 60; // Potong 60 detik sebagai buffer aman

            console.log(`[AUTH] New token issued ending in: ...${cachedM2MToken.slice(-5)}`);
            return cachedM2MToken;
        } finally {
            // 4. Setelah selesai (berhasil atau gagal), buka kembali kuncinya
            tokenPromise = null;
        }
    })();

    return await tokenPromise;
}

async function spokeFetch(path, options = {}) {
    const token = await getSpokeToken();
    const url = `http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}${path}`;
    const headers = { ...options.headers, 'Authorization': `Bearer ${token}` };
    return fetch(url, { ...options, headers });
}

async function checkSpokeHealth() {
    try {
        const response = await spokeFetch('/internal/health');
        if (response.ok) console.log("[TELEMETRY] Spoke is Healthy");
    } catch (err) {
        console.error("[TELEMETRY] Spoke Unreachable!");
    }
}
setInterval(checkSpokeHealth, 5 * 60 * 1000);

app.get('/health', (req, res) => res.send("OK"));

// ==========================================
// 3. API ROUTER DEFINITIONS (The "Kitchen")
// ==========================================
apiRouter.use('/vault/', apiLimiter);
apiRouter.use('/vault/files', strictLimiter);

// Global API Audit Log (Fires AFTER bouncer authenticates the user)
apiRouter.use((req, res, next) => {
    const userEmail = req.auth?.payload[`${namespace}/email`] || 'anonymous';
    const log = db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)');
    log.run(userEmail, `${req.method} ${req.path}`, 'AUTHORIZED');
    next();
});

// --- PUBLIC ROUTE (No Bouncer Needed) ---
apiRouter.get('/vault/view/:uuid', async (req, res) => {
    const { uuid } = req.params;
    const { expires, sig, permission } = req.query;
    try {
        if (Math.floor(Date.now() / 1000) > parseInt(expires)) return res.status(403).send("This link has expired.");
        const secret = process.env.URL_SIGNING_SECRET;
        const expectedSig = crypto.createHmac('sha256', secret).update(`${uuid}:${expires}:${permission}`).digest('hex');
        if (sig !== expectedSig) return res.status(403).send("Invalid signature.");
        
        const fileMeta = db.prepare(`SELECT f.filename, f.mime_type, v.physical_path, v.size FROM files f JOIN versions v ON f.id = v.file_id WHERE f.uuid = ? ORDER BY v.version_num DESC LIMIT 1`).get(uuid);
        if (!fileMeta) return res.status(404).send("File no longer exists.");

        const spokeResponse = await spokeFetch(`/internal/files/${fileMeta.physical_path}`);
        if (!spokeResponse.ok) throw new Error("Spoke failed to provide file.");

        res.setHeader('Content-Type', fileMeta.mime_type || 'application/octet-stream');
        if (permission === 'viewable') res.setHeader('Content-Disposition', 'inline');
        else res.setHeader('Content-Disposition', `attachment; filename="${fileMeta.filename}"`);
        
        Readable.fromWeb(spokeResponse.body).pipe(res);
    } catch (err) {
        console.error("[VIEW ERROR]", err.message);
        res.status(500).send("Secure viewing failed.");
    }
});

// --- PROTECTED ROUTES (Requires Bouncer) ---
apiRouter.get('/vault/identity', (req, res) => {
    const userEmail = req.auth?.payload[`${namespace}/email`] || 'anonymous';
    const userRoles = req.auth?.payload[`${namespace}/roles`] || 'anonymous';
    const userSub = req.auth?.payload.sub;
    try {
        if (userSub && userEmail !== 'anonymous') {
            db.prepare(`INSERT INTO users (sub, email) VALUES (?, ?) ON CONFLICT(sub) DO UPDATE SET email = excluded.email`).run(userSub, userEmail);
        }
        res.json({ message: "username retrieved", user: userEmail, roles: userRoles });
    } catch (err) { res.status(500).json({ error: "Database query failed" }); }
});

apiRouter.get('/vault/usage', permitGlobalRole('standard_user'), (req, res) => {
    const userId = req.auth.payload.sub;
    const ADMIN_QUOTA_LIMIT = 50 * 1024 * 1024 * 1024; 
    const QUOTA_LIMIT = 5 * 1024 * 1024 * 1024; 
    const activeLimit = (req.globalRole === 'admin') ? ADMIN_QUOTA_LIMIT : QUOTA_LIMIT;
    try {
        const usage = db.prepare(`SELECT SUM(v.size) as total_used FROM versions v JOIN files f ON v.file_id = f.id WHERE f.owner_id = ?`).get(userId);
        const totalUsed = usage.total_used || 0;
        res.json({ used_bytes: totalUsed, quota_bytes: activeLimit, percent_used: ((totalUsed / activeLimit) * 100).toFixed(2) });
    } catch (err) { res.status(500).json({ error: "Could not calculate usage." }); }
});

apiRouter.get('/vault/files', permitGlobalRole('standard_user'), (req, res) => {
    const userId = req.auth.payload.sub;
    const search = req.query.search ? `%${req.query.search}%` : '%';
    const bucketUuid = req.headers['x-bucket-uuid']; 
    try {
        let query, params;
        if (req.globalRole === 'admin' && !bucketUuid) {
            query = db.prepare(`SELECT f.uuid, f.filename, f.bucket_id, f.mime_type, v.size, v.timestamp FROM files f JOIN versions v ON f.id = v.file_id WHERE f.filename LIKE ? AND v.id IN (SELECT MAX(id) FROM versions GROUP BY file_id) AND f.deleted_at IS NULL`);
            params = [search];
        } else if (bucketUuid) {
            query = db.prepare(`SELECT f.uuid, f.filename, f.bucket_id, f.mime_type, v.size, v.timestamp FROM files f JOIN versions v ON f.id = v.file_id JOIN buckets b ON f.bucket_id = b.id LEFT JOIN bucket_policies bp ON b.id = bp.bucket_id AND bp.grantee_id = ? WHERE b.uuid = ? AND (b.owner_id = ? OR bp.permission IS NOT NULL) AND f.filename LIKE ? AND v.id IN (SELECT MAX(id) FROM versions GROUP BY file_id) AND f.deleted_at IS NULL`);
            params = [userId, bucketUuid, userId, search];
        } else { return res.json([]); }
        res.json(query.all(...params));
    } catch (err) { res.status(500).json({ error: "Database query failed" }); }
});

apiRouter.post('/vault/files', permitGlobalRole('standard_user'), authorizeBucket('WRITE'), (req, res) => {
    const ADMIN_QUOTA = 50 * 1024 * 1024 * 1024;
    const USER_QUOTA = 5 * 1024 * 1024 * 1024;
    const MAX_SIZE = 1 * 1024 * 1024 * 1024; 
    const contentType = req.headers['content-type'];
    const contentLength = req.headers['content-length'];
    const activeLimit = (req.globalRole === 'admin') ? ADMIN_QUOTA : USER_QUOTA;

    if (!contentType || !contentType.includes('multipart/form-data')) return res.status(400).json({ error: "Invalid Request" });
    if (contentLength && parseInt(contentLength) > MAX_SIZE) return res.status(413).json({ error: "File Too Large" });

    const busboy = Busboy({ headers: req.headers, limits: { fileSize: MAX_SIZE, files: 1 } });
    const userId = req.auth.payload.sub;
    const bucketUuid = req.headers['x-bucket-uuid'];
    const folderPrefix = req.headers['x-file-prefix'] || '';
    const bucket = db.prepare('SELECT id FROM buckets WHERE uuid = ?').get(bucketUuid);
    
    if (!bucket) return res.status(404).json({ error: "Target bucket does not exist." });

    let isProcessing = false;
    let limitReached = false; 

    busboy.on('file', async (name, file, info) => {
        if (isProcessing) return; 
        isProcessing = true;
        const { filename, mimeType: headerMime } = info;
        const fullVirtualFilename = folderPrefix + filename;
        const { isSpoofed, finalMime } = validateFileSecurity(filename, headerMime);

        file.on('limit', () => { limitReached = true; });

        try {
            const usage = db.prepare(`SELECT SUM(v.size) as total_used FROM versions v JOIN files f ON v.file_id = f.id WHERE f.owner_id = ?`).get(userId);
            if ((usage.total_used || 0) >= activeLimit) return res.status(403).json({ error: "Quota Exceeded" });
            if (isSpoofed) { file.resume(); return res.status(403).json({ error: "Security Violation" }); }

            const spokeResponse = await spokeFetch(`/internal/files`, {
                method: 'POST', body: file, duplex: 'half', headers: { 'x-original-name': filename }
            });

            if (limitReached) return res.status(413).json({ error: "File Too Large" });
            if (!spokeResponse.ok) throw new Error(`Spoke rejected upload`);

            const data = await spokeResponse.json();
            const { physical_path, size ,checksum} = data;

            let fileRecord = db.prepare('SELECT id, uuid FROM files WHERE filename = ? AND bucket_id = ?').get(fullVirtualFilename, bucket.id);
            if (!fileRecord) {
                const uuid = randomUUID();
                const info = db.prepare('INSERT INTO files (uuid, filename, owner_id, mime_type, bucket_id) VALUES (?, ?, ?, ?, ?)').run(uuid, fullVirtualFilename, userId, finalMime, bucket.id);
                fileRecord = { id: info.lastInsertRowid, uuid: uuid };
            } else {
                db.prepare('UPDATE files SET mime_type = ? WHERE id = ?').run(finalMime, fileRecord.id);
            }

            let versions = db.prepare('SELECT id, physical_path FROM versions WHERE file_id = ? ORDER BY version_num ASC').all(fileRecord.id);
            while (versions.length >= 5) {
                try {
                    await spokeFetch(`/vault/delete/${versions[0].physical_path}`, { method: 'DELETE' });
                    db.prepare('DELETE FROM versions WHERE id = ?').run(versions[0].id);
                    versions = db.prepare('SELECT id, physical_path FROM versions WHERE file_id = ? ORDER BY version_num ASC').all(fileRecord.id);
                } catch (e) { console.error("Cleanup failed"); }
            }

            const lastVersion = db.prepare('SELECT MAX(version_num) as v FROM versions WHERE file_id = ?').get(fileRecord.id);
            const newVersion = (lastVersion.v || 0) + 1;
            db.prepare("INSERT INTO versions (file_id, version_num, physical_path, size, checksum, timestamp) VALUES (?, ?, ?, ?, ?, datetime('now'))").run(fileRecord.id, newVersion, physical_path, size, checksum);

            res.json({ status: "Vaulted", version: newVersion, uuid: fileRecord.uuid, finalMime });
        } catch (err) { file.resume(); res.status(500).json({ error: "Gateway stream interrupted." }); }
    });
    req.pipe(busboy);
});

apiRouter.get('/vault/files/:uuid/versions', authorizeVault('READ'), (req, res) => {
    try {
        res.json(db.prepare(`SELECT v.version_num, v.timestamp, v.size, v.physical_path FROM versions v JOIN files f ON f.id = v.file_id WHERE f.uuid = ? ORDER BY v.version_num DESC`).all(req.params.uuid));
    } catch (err) { res.status(500).json({ error: "Failed to retrieve history" }); }
});

apiRouter.get('/vault/files/:uuid/content', authorizeVault('READ'), async (req, res) => {
    const { uuid } = req.params;
    const requestedVersion = req.query.v;
    try {
        const fileInfo = db.prepare(`SELECT f.filename,f.mime_type, v.physical_path, v.size FROM files f JOIN versions v ON f.id = v.file_id WHERE f.uuid = ? ${requestedVersion ? 'AND v.version_num = ?' : ''} ORDER BY v.version_num DESC LIMIT 1`).get(requestedVersion ? [uuid, requestedVersion] : [uuid]);
        if (!fileInfo) return res.status(404).json({ error: "Version not found." });

        const spokeResponse = await spokeFetch(`/internal/files/${fileInfo.physical_path}`);
        if (!spokeResponse.ok) throw new Error("Spoke failed to provide file stream.");

        res.setHeader('Content-Type', fileInfo.mime_type || 'application/octet-stream');
        const actualSize = spokeResponse.headers.get('content-length');
        if (actualSize) res.setHeader('Content-Length', actualSize);
        
        let downloadName = fileInfo.filename;
        if (requestedVersion) downloadName = fileInfo.filename.includes('.') ? fileInfo.filename.replace(/(\.[^.]+)$/, `_v${requestedVersion}$1`) : `${fileInfo.filename}_v${requestedVersion}`;
        res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);

        Readable.fromWeb(spokeResponse.body).pipe(res);
    } catch (err) { if (!res.headersSent) res.status(500).json({ error: "Could not retrieve file." }); }
});

apiRouter.get('/vault/files/:uuid/links', authorizeVault('WRITE'), (req, res) => {
    const fileUuid = req.params.uuid;
    const ttl = parseInt(req.query.ttl) || 60; 
    const permission = req.query.permission === 'downloadable' ? 'downloadable' : 'viewable';
    try {
        const file = db.prepare('SELECT filename FROM files WHERE uuid = ?').get(fileUuid);
        if (!file) return res.status(404).json({ error: "File not found" });
        const expires = Math.floor(Date.now() / 1000) + (ttl * 60);
        const signature = crypto.createHmac('sha256', process.env.URL_SIGNING_SECRET).update(`${fileUuid}:${expires}:${permission}`).digest('hex');
        res.json({ share_url: `${namespace}:${PUBLIC_PORT}/vault/view/${fileUuid}?expires=${expires}&sig=${signature}`, expires_at: new Date(expires * 1000).toISOString() });
    } catch (err) { res.status(500).json({ error: "Failed to generate share link" }); }
});

apiRouter.delete('/vault/files/:uuid', authorizeVault('WRITE'), async (req, res) => {
    const { uuid } = req.params;
    const requestedVersion = req.query.v;
    try {
        if (!requestedVersion) {
            const allVersions = db.prepare(`SELECT v.physical_path, f.id as file_id FROM files f JOIN versions v ON f.id = v.file_id WHERE f.uuid = ?`).all(uuid);
            if (allVersions.length === 0) return res.status(404).json({ error: "File not found." });
            for (const v of allVersions) { await spokeFetch(`/internal/files/${v.physical_path}`, { method: 'DELETE' }); }
            db.prepare('DELETE FROM files WHERE id = ?').run(allVersions[0].file_id);
            return res.status(200).json({ status: "File completely purged." });
        } else {
            const fileInfo = db.prepare(`SELECT f.filename, v.id as v_id, v.physical_path FROM files f JOIN versions v ON f.id = v.file_id WHERE f.uuid = ? AND v.version_num = ?`).get(uuid, requestedVersion);
            if (!fileInfo) return res.status(404).json({ error: "Version not found." });
            const spokeResponse = await spokeFetch(`/internal/files/${fileInfo.physical_path}`, { method: 'DELETE' });
            if (!spokeResponse.ok) throw new Error("Spoke refused to delete.");
            db.prepare('DELETE FROM versions WHERE id = ?').run(fileInfo.v_id);
            return res.status(200).json({ status: `Version purged.` });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

apiRouter.post('/vault/files/:uuid/restore', authorizeVault('WRITE'), async (req, res) => {
    try {
        const fileMeta = db.prepare(`SELECT f.id, f.filename, v.physical_path FROM files f JOIN versions v ON f.id = v.file_id WHERE f.uuid = ? AND v.version_num = ?`).get(req.params.uuid, req.query.v);
        if (!fileMeta) return res.status(404).json({ error: "Version not found." });
        const spokeResponse = await spokeFetch(`/internal/files/copy`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ source_path: fileMeta.physical_path }) });
        if (!spokeResponse.ok) throw new Error("Copy failed.");
        const { new_physical_path, size, checksum } = await spokeResponse.json();
        const lastVersion = db.prepare('SELECT MAX(version_num) as v FROM versions WHERE file_id = ?').get(fileMeta.id);
        const newVersionNum = (lastVersion.v || 0) + 1;
        db.prepare(`INSERT INTO versions (file_id, version_num, physical_path, size, checksum, timestamp) VALUES (?, ?, ?, ?, ?, datetime('now'))`).run(fileMeta.id, newVersionNum, new_physical_path, size, checksum);
        res.json({ status: "Restored", new_version: newVersionNum });
    } catch (err) { res.status(500).json({ error: "Restore failed." }); }
});

apiRouter.post('/vault/buckets', (req, res) => {
    const { name, region } = req.body || {};
    const userId = req.auth.payload.sub;
    const bucketUuid = randomUUID();
    try {
        db.transaction(() => {
            const info = db.prepare(`INSERT INTO buckets (uuid, name, owner_id, region) VALUES (?, ?, ?, ?)`).run(bucketUuid, name, userId, region || 'sub-01');
            db.prepare(`INSERT INTO bucket_policies (bucket_id, grantee_id, permission) VALUES (?, ?, 'ADMIN')`).run(info.lastInsertRowid, userId);
        })();
        res.json({ status: "Bucket Created", uuid: bucketUuid });
    } catch (err) { res.status(500).json({ error: "Could not create bucket." }); }
});

apiRouter.get('/vault/buckets', (req, res) => {
    try {
        res.json({ buckets: db.prepare(`SELECT b.uuid, b.name, b.region, bp.permission, b.owner_id, u.email as owner_email FROM buckets b JOIN bucket_policies bp ON b.id = bp.bucket_id LEFT JOIN users u ON b.owner_id = u.sub WHERE bp.grantee_id = ? AND b.deleted_at IS NULL`).all(req.auth.payload.sub) });
    } catch (err) { res.status(500).json({ error: "Could not fetch buckets." }); }
});

apiRouter.get('/vault/buckets/:bucketUuid/members', authorizeBucket('ADMIN'), (req, res) => {
    try {
        const bucket = db.prepare('SELECT id FROM buckets WHERE uuid = ?').get(req.params.bucketUuid);
        if (!bucket) return res.status(404).json({ error: "Bucket not found." });
        res.json(db.prepare(`SELECT u.sub as user_id, u.email, bp.permission FROM bucket_policies bp JOIN users u ON bp.grantee_id = u.sub WHERE bp.bucket_id = ?`).all(bucket.id));
    } catch (err) { res.status(500).json({ error: "Failed to fetch members." }); }
});

apiRouter.post('/vault/buckets/:bucketUuid/share', permitGlobalRole('standard_user'), authorizeBucket('ADMIN'), (req, res) => {
    const { email, permission } = req.body;
    if (!email || !['READ', 'WRITE'].includes(permission)) return res.status(400).json({ error: "Invalid payload." });
    try {
        const targetUser = db.prepare('SELECT sub FROM users WHERE email = ?').get(email);
        if (!targetUser) return res.status(404).json({ error: "User not found." });
        const bucket = db.prepare('SELECT id, name FROM buckets WHERE uuid = ?').get(req.params.bucketUuid);
        if (!bucket) return res.status(404).json({ error: "Bucket not found." });
        db.prepare(`INSERT INTO bucket_policies (bucket_id, grantee_id, permission) VALUES (?, ?, ?) ON CONFLICT(bucket_id, grantee_id) DO UPDATE SET permission = excluded.permission`).run(bucket.id, targetUser.sub, permission);
        res.json({ status: "Invitation Successful" });
    } catch (err) { res.status(500).json({ error: "Failed to invite user." }); }
});

apiRouter.delete('/vault/buckets/:bucketUuid/share/:userId', authorizeBucket('ADMIN'), (req, res) => {
    try {
        const bucket = db.prepare('SELECT id, owner_id FROM buckets WHERE uuid = ?').get(req.params.bucketUuid);
        if (req.params.userId === bucket.owner_id) return res.status(400).json({ error: "Cannot revoke access from the bucket owner." });
        db.prepare('DELETE FROM bucket_policies WHERE bucket_id = ? AND grantee_id = ?').run(bucket.id, req.params.userId);
        res.json({ status: "Access revoked successfully." });
    } catch (err) { res.status(500).json({ error: "Failed to remove member." }); }
});

apiRouter.put('/vault/buckets/:bucketUuid', authorizeBucket('ADMIN'), (req, res) => {
    try {
        const bucket = db.prepare('SELECT id FROM buckets WHERE uuid = ?').get(req.params.bucketUuid);
        if (!bucket) return res.status(404).json({ error: "Bucket not found." });
        db.prepare('UPDATE buckets SET name = ?, region = ? WHERE id = ?').run(req.body.name, req.body.region, bucket.id);
        res.json({ status: "Bucket updated successfully." });
    } catch (err) { res.status(500).json({ error: "Failed to update bucket." }); }
});

apiRouter.delete('/vault/buckets/:bucketUuid', permitGlobalRole('standard_user'), (req, res) => {
    try {
        const bucket = db.prepare('SELECT id, name, owner_id FROM buckets WHERE uuid = ?').get(req.params.bucketUuid);
        if (!bucket) return res.status(404).json({ error: "Bucket not found." });
        if (bucket.owner_id !== req.auth.payload.sub && req.globalRole !== 'admin') return res.status(403).json({ error: "Access Denied." });
        const fileCount = db.prepare('SELECT COUNT(*) as count FROM files WHERE bucket_id = ?').get(bucket.id);
        if (fileCount.count > 0) return res.status(409).json({ error: "Bucket is not empty." });
        db.prepare('DELETE FROM buckets WHERE id = ?').run(bucket.id);
        res.json({ status: "Bucket Deleted" });
    } catch (err) { res.status(500).json({ error: "Failed to delete bucket." }); }
});

apiRouter.get('/vault/users/search', permitGlobalRole('standard_user'), (req, res) => {
    if (!req.query.q || req.query.q.length < 2) return res.json([]);
    try {
        res.json(db.prepare(`SELECT sub as user_id, email FROM users WHERE email LIKE ? AND sub != ? LIMIT 5`).all(`%${req.query.q}%`, req.auth.payload.sub));
    } catch (err) { res.status(500).json({ error: "Search failed." }); }
});

apiRouter.get('/vault/notifications', permitGlobalRole('standard_user'), (req, res) => {
    try {
        res.json(db.prepare(`SELECT id, message, timestamp FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY timestamp DESC`).all(req.auth.payload.sub));
    } catch (err) { res.status(500).json({ error: "Failed to fetch notifications." }); }
});

apiRouter.post('/vault/notifications/clear', permitGlobalRole('standard_user'), (req, res) => {
    try {
        db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(req.auth.payload.sub);
        res.json({ status: "Cleared." });
    } catch (err) { res.status(500).json({ error: "Clear failed." }); }
});

apiRouter.get('/vault/audit', permitGlobalRole('admin'), (req, res) => {
    try {
        res.json(db.prepare(`SELECT id, user_email, action, status, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 100`).all());
    } catch (err) { res.status(500).json({ error: "Failed." }); }
});

apiRouter.get('/vault/admin/sync', permitGlobalRole('admin'), async (req, res) => {
    try {
        const dbFiles = db.prepare(`SELECT v.physical_path, f.filename FROM versions v JOIN files f ON v.file_id = f.id`).all();
        const spokeResponse = await spokeFetch(`/internal/inventory`);
        if (!spokeResponse.ok) throw new Error("Spoke unreachable");
        const physicalFiles = await spokeResponse.json();
        if (!Array.isArray(physicalFiles)) return res.status(502).json({ error: "Invalid format." });
        res.json({
            status: "Audit Complete",
            results: {
                missingFromDisk: dbFiles.filter(dbFile => !physicalFiles.includes(dbFile.physical_path)),
                orphanedOnDisk: physicalFiles.filter(pPath => !dbFiles.some(dbFile => dbFile.physical_path === pPath))
            }
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

apiRouter.post('/vault/admin/sync', permitGlobalRole('admin'), async (req, res) => {
    const { missingFromDisk, orphanedOnDisk } = req.body;
    if (!Array.isArray(missingFromDisk) || !Array.isArray(orphanedOnDisk)) return res.status(400).json({ error: "Invalid payload." });
    const report = { pruned: 0, purged: 0, skipped: 0 };
    try {
        if (missingFromDisk.length > 0) {
            const checkStmt = db.prepare('SELECT id FROM versions WHERE physical_path = ?');
            const deleteStmt = db.prepare('DELETE FROM versions WHERE physical_path = ?');
            for (const file of missingFromDisk) {
                if (checkStmt.get(file.physical_path)) { deleteStmt.run(file.physical_path); report.pruned++; }
                else { report.skipped++; }
            }
        }
        if (orphanedOnDisk.length > 0) {
            const checkDB = db.prepare('SELECT id FROM versions WHERE physical_path = ?');
            const validOrphans = orphanedOnDisk.filter(path => !checkDB.get(path));
            if (validOrphans.length > 0) {
                const spokeResponse = await spokeFetch(`/internal/maintenance/purge`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ files: validOrphans }) });
                if (spokeResponse.ok) report.purged = (await spokeResponse.json()).success;
            }
        }
        res.json({ message: "Sync Complete", report });
    } catch (err) { res.status(500).json({ error: "Sync failed." }); }
});

apiRouter.post('/vault/admin/test/performance', permitGlobalRole('admin'), async (req, res) => {
    try {
        const spokeResponse = await spokeFetch(`/internal/files/test/upload`, { method: 'POST', body: req, duplex: 'half' });
        res.json({ message: "Benchmark Complete", spoke_received_gb: (await spokeResponse.json()).size_gb });
    } catch (err) { res.status(500).json({ error: "Benchmark Interrupted" }); }
});

apiRouter.post('/vault/admin/bitrot/report', permitGlobalRole('admin'), (req, res) => {
    let corruptedFiles = 0;
    for (const item of req.body) {
        const dbRecord = db.prepare('SELECT checksum, id FROM versions WHERE physical_path = ?').get(item.path);
        if (dbRecord && dbRecord.checksum !== item.hash) {
            corruptedFiles++;
            db.prepare('INSERT INTO audit_logs (action, status) VALUES (?, ?)').run(`BIT_ROT_DETECTED_${item.path}`, 'CRITICAL');
        }
    }
    res.json({ message: "Scan complete", corrupted: corruptedFiles });
});

apiRouter.post('/vault/admin/bitrot/scan', permitGlobalRole('admin'), async (req, res) => {
    try {
        const spokeResponse = await spokeFetch(`/internal/maintenance/bitrot/scan`, { method: 'POST' });
        if (!spokeResponse.ok) throw new Error("Spoke rejected the command.");
        res.json({ message: "Scan initiated." });
    } catch (err) { res.status(500).json({ error: "Failed." }); }
});

// ==========================================
// 4. ATTACH THE API ROUTER TO EXPRESS
// ==========================================
// Apply the bouncer middleware BEFORE all /api/v1 routes
app.use('/api/v1', bouncer, apiRouter);


// ==========================================
// 5. HOSTING FRONTEND REACT (The "Lobby")
// ==========================================
app.use(express.static(path.join(__dirname, 'dist'))); 

app.get(/.*/, (req, res, next) => {
    if (req.path.startsWith('/api')) {
        return next(); 
    }
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

// ==========================================
// 6. CATCH-ALL ROUTE & ERROR HANDLING
// ==========================================
app.use((req, res) => {
    console.warn(`[SECURITY] Blocked unauthorized path: ${req.path}`);
    const log = db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)');
    log.run(req.auth?.payload?.sub || 'unknown', `UNAUTHORIZED_ACCESS: ${req.path}`, 'BLOCKED');
    res.status(403).json({ error: "Access Denied" });
});

app.use((err, req, res, next) => {
    if (err.name === 'UnauthorizedError') {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        console.warn(`[SECURITY] Failed Auth attempt on ${req.path} from IP: ${ip}`);
        try {
            db.prepare('INSERT INTO audit_logs (user_email, action, status, ip_address) VALUES (?, ?, ?, ?)')
                .run('unauthenticated_user', `BLOCKED_AUTH: ${req.path}`, 'FAILED', ip);
        } catch (dbErr) { console.error("Log fail:", dbErr.message); }
        return res.status(401).json({ error: "Unauthorized" });
    }
    console.error("[SERVER ERROR]", err);
    res.status(500).json({ error: "Internal Error" });
});

// ==========================================
// 7. START SERVER
// ==========================================
const sslOptions = {
    key: fs.readFileSync('/etc/letsencrypt/live/richardgatewayta.duckdns.org/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/richardgatewayta.duckdns.org/fullchain.pem')
};

https.createServer(sslOptions, app).listen(PUBLIC_PORT, '0.0.0.0', () => {
    console.log('--- Zero Trust Architecture Active ---');
    console.log(`Public Entry: https://richardgatewayta.duckdns.org:${PUBLIC_PORT}`);
    console.log(`Internal Destination: ${LOCAL_SPOKE_IP}:${LOCAL_PORT}`);
    console.log('--------------------------------------');
});