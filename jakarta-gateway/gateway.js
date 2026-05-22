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
import { Agent, setGlobalDispatcher } from 'undici';
import { fileTypeFromStream } from 'file-type';
import { PassThrough } from 'stream';
import { fileTypeFromBuffer } from 'file-type';

const THIRTY_MINUTES = 30 * 60 * 1000;
const customAgent = new Agent({
    connectTimeout: THIRTY_MINUTES,
    headersTimeout: THIRTY_MINUTES,
    bodyTimeout: THIRTY_MINUTES,
    keepAliveTimeout: THIRTY_MINUTES
});
const autoPurgeTrash = async () => {
    console.log("Running scheduled maintenance: Checking for expired files in trash...");
    try {
        // 1. Cari berkas yang deleted_at sudah lebih dari 30 hari
        const expiredFiles = db.prepare(`
            SELECT f.id, f.uuid, v.physical_path 
            FROM files f
            JOIN versions v ON f.id = v.file_id
            WHERE f.deleted_at <= datetime('now', '-30 days')
        `).all();

        for (const file of expiredFiles) {
            // 2. Perintahkan Spoke Surabaya untuk hapus fisik
            const spokeRes = await fetch(`${SPOKE_URL}/internal/files/${file.physical_path}`, {
                method: 'DELETE',
                headers: { 'x-m2m-token': M2M_TOKEN }
            });

            if (spokeRes.ok) {
                // 3. Jika fisik sukses dihapus, hapus metadata secara permanen
                db.prepare("DELETE FROM versions WHERE file_id = ?").run(file.id);
                db.prepare("DELETE FROM files WHERE id = ?").run(file.id);
                console.log(`Permanently purged expired file: ${file.uuid}`);
            }
        }
    } catch (err) {
        console.error("Auto-purge failed:", err);
    }
};

setGlobalDispatcher(customAgent);
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

            "img-src": ["'self'", "data:", "https:", "blob:"],

            "frame-src": ["'self'", "blob:"],

            "worker-src": ["'self'", "blob:"]
        },
    },
}));

app.use(cors({
    origin: ['http://localhost:5173', 'https://richardgatewayta.duckdns.org:8080'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-bucket-uuid', 'x-file-prefix'],
    credentials: true
}));


app.use((req, res, next) => {
    // KECUALIKAN rute Upload DAN rute Benchmark agar req tetap berupa Stream murni!
    if (req.method === 'POST' && (
        req.path === '/api/v1/vault/files' ||
        req.path === '/api/v1/vault/admin/test/performance'
    )) {
        return next();
    }

    // Untuk rute lain, gunakan JSON parser dengan limit kecil
    express.json({ limit: '5mb', strict: true })(req, res, (err) => {
        if (err) return next(err);
        express.urlencoded({ extended: true, limit: '50mb' })(req, res, next);
    });
});
// app.use(express.json({ limit: '50mb', strict: true }));
// app.use(express.raw({ type: 'application/octet-stream', limit: '50mb' })); 

// app.use(express.urlencoded({ extended: true, limit: '50mb' }));

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
setInterval(autoPurgeTrash, 86400000);

app.get('/health', async (req, res) => {
    let spokeStatus = "offline";
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1500); // Timeout pendek

        // const spokeRes = await fetch(`http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}/internal/health`, { signal: controller.signal });
        const spokeRes = await spokeFetch('/internal/health', { signal: controller.signal });
        if (spokeRes.ok) spokeStatus = "online";
    } catch (err) {
        console.warn("[HEALTH CHECK] Spoke health check failed:", err.message);
        spokeStatus = "offline";
    }

    res.json({
        status: "ok",
        gateway: "online",
        spoke: spokeStatus, // Ini yang akan dibaca oleh dot di navbar
        timestamp: new Date().toISOString()
    });
});

// ==========================================
// 3. API ROUTER DEFINITIONS (The "Kitchen")
// ==========================================
apiRouter.use('/vault/', apiLimiter);
apiRouter.use('/vault/files', strictLimiter);
apiRouter.use('/vault/files', strictLimiter);

// Global API Audit Log (Fires AFTER bouncer authenticates the user)
apiRouter.use((req, res, next) => {
    const userEmail = req.auth?.payload[`${namespace}/email`] || 'anonymous';
    const log = db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)');
    log.run(userEmail, `${req.method} ${req.path}`, 'AUTHORIZED');
    next();
});

// --- PUBLIC ROUTE (No Bouncer Needed) ---
app.get('/api/v1/vault/view/:uuid', async (req, res) => {
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
    const VIDEO_MAX_SIZE = 50 * 1024 * 1024; // 50 MB
    const DEFAULT_MAX_SIZE = 5 * 1024 * 1024;  // 5 MB untuk dokumen
    const contentType = req.headers['content-type'];
    const contentLength = req.headers['content-length'];
    const activeLimit = (req.globalRole === 'admin') ? ADMIN_QUOTA : USER_QUOTA;
    const controller = new AbortController();
    // 2. Pasang pendengar jika koneksi klien (browser) terputus
    req.on('error', (err) => {
        console.warn(`[UPLOAD-GATEWAY] Stream Error: ${err.message}`);
        controller.abort();
    });
    req.on('aborted', () => {
        console.warn(`[UPLOAD-GATEWAY] User membatalkan unggahan.`);
        controller.abort();
    });

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
        const pass = new PassThrough();
        file.pipe(pass);
        file.on('end', () => {
            pass.end(); // INI PENTING: Memberi sinyal EOF ke Spoke
        });
        // 2. Gunakan 'file' untuk type check, dan 'pass    ' untuk upload ke Spoke
        const stream = file;
        const buffer = await new Promise((resolve, reject) => {
            const chunks = [];
            stream.once('data', (chunk) => {
                chunks.push(chunk);
                // Cukup baca header pertama
                resolve(Buffer.concat(chunks));
            });
            stream.on('error', reject);
        });

        const type = await fileTypeFromBuffer(buffer);
        const { isSpoofed, finalMime } = validateFileSecurity(filename, headerMime, type, buffer);
        const lastDotIndex = filename.lastIndexOf('.');
        const ext = lastDotIndex !== -1 ? filename.toLowerCase().substring(lastDotIndex) : '';
        const isVideo = ['.mp4', '.mov', '.webm'].includes(ext);
        const limit = isVideo ? VIDEO_MAX_SIZE : DEFAULT_MAX_SIZE;

        if (info.size > limit) { // Pastikan busboy mengirim info size
            return res.status(413).json({ error: `File terlalu besar. Limit untuk ${ext} adalah ${limit / 1024 / 1024}MB` });
        }

        // console.log(`[DEBUG] Filename: ${info.filename}`);
        // console.log(`[DEBUG] Header MIME: ${info.mimeType}`);
        // console.log(`[DEBUG] Detected MIME (Magic Numbers): ${type ? type.mime : 'Unknown'}`);
        // console.log(`[DEBUG] Is Spoofed: ${isSpoofed}`);
        // console.log(`[DEBUG] Final MIME to use: ${finalMime}`);
        // console.log(`[DEBUG] type: ${type ? JSON.stringify(type) : 'null'}`);
        // const isShFile = (type && type.mime === 'application/x-sh') ||
        //     (info.mimeType === 'application/x-sh');

        // if (isShFile) {
        //     console.warn(`[SECURITY] BLOCKED: File ${info.filename} adalah skrip shell!`);
        //     // ... blokir file
        //     return res.status(403).json({ error: "Security Violation: Shell scripts are not allowed." });
        // }

        file.on('limit', () => { limitReached = true; });
        (async () => {
            try {
                if (isSpoofed) { file.resume(); return res.status(403).json({ error: "Security Violation" }); }
                // const type = await fileTypeFromStream(file);

                // if (type && type.mime === 'application/x-sh') {
                //     file.resume(); // Buang file
                //     return res.status(403).json({ error: "Security Violation: Content Mismatch" });
                // }

                const usage = db.prepare(`SELECT SUM(v.size) as total_used FROM versions v JOIN files f ON v.file_id = f.id WHERE f.owner_id = ?`).get(userId);
                if ((usage.total_used || 0) >= activeLimit) {
                    file.resume();
                    return res.status(403).json({ error: "Quota Exceeded" });
                }

                const spokeResponse = await spokeFetch(`/internal/files`, {
                    method: 'POST', body: pass
                    , duplex: 'half',
                    signal: controller.signal,
                    headers: {
                        'x-original-name': filename,
                        'content-type': headerMime
                    }
                });

                if (limitReached) return res.status(413).json({ error: "File Too Large" });
                if (!spokeResponse.ok) throw new Error(`Spoke rejected upload`);

                const data = await spokeResponse.json();
                const { physical_path, size, checksum } = data;

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
                setImmediate(() => { req.destroy(); });
            } catch (err) {
                file.resume();
                if (err.name === 'AbortError') {
                    console.warn("[UPLOAD] Streaming ke Spoke dihentikan karena pembatalan user.");
                }
                console.error("[UPLOAD ERROR]", err.message);
                res.status(500).json({ error: "Gateway stream interrupted.", error_detail: err.message });
            }
        })();
    });
    busboy.on('finish', () => {
        if (!isProcessing) {
            console.warn("[SECURITY ALERT] Request Multipart masuk tanpa menyertakan part file.");
            return res.status(400).json({ error: "Bad Request", message: "No file payload detected in multipart form data." });
        }
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
        res.json({
            share_url: `https://richardgatewayta.duckdns.org:${PUBLIC_PORT}/api/v1/vault/view/${fileUuid}?expires=${expires}&permission=${permission}&sig=${signature}`,
            expires_at: new Date(expires * 1000).toISOString()
        });
    } catch (err) { res.status(500).json({ error: "Failed to generate share link" }); }
});

// 3. HARD DELETE (Purge Full File OR Specific Version)
apiRouter.delete('/vault/files/:uuid/purge', permitGlobalRole('standard_user'), authorizeVault('ADMIN'), async (req, res) => {
    const { uuid } = req.params;

    const requestedVersion = req.query.v ? parseInt(req.query.v, 10) : null;
    const currentUserId = req.auth.payload.sub;
    const currentUserRole = req.globalRole;
    // console.log(`[PURGE INITIATED] User: ${currentUserId} | Role: ${currentUserRole} | UUID: ${uuid} | Requested Version: ${requestedVersion || 'ALL'}`);
    console.log(`[PURGE REQUEST] UUID: ${uuid} | Target Version: ${requestedVersion || 'ALL'}`);

    try {
        const fileContext = db.prepare(`
            SELECT id, bucket_id FROM files WHERE uuid = ?
        `).get(uuid);

        if (!fileContext) {
            return res.status(404).json({ error: "File not found." });
        }

        // Jika BUKAN global admin, cek hak akses di tabel bucket_policies
        // Ganti blok ini:
        if (currentUserRole !== 'admin') {
            const hasAccess = db.prepare(`
                SELECT id FROM bucket_policies 
                WHERE bucket_id = ? AND grantee_id = ? AND permission IN ('WRITE', 'ADMIN')
            `).get(fileContext.bucket_id, currentUserId); // grantee_id = user yang mengakses, permission = kolom role di db kamu

            if (!hasAccess) {
                return res.status(403).json({ error: "Access Denied." });
            }
        }

        if (!requestedVersion) {
            const allVersions = db.prepare(`SELECT v.physical_path, f.id as file_id FROM files f JOIN versions v ON f.id = v.file_id WHERE f.uuid = ?`).all(uuid);

            if (allVersions.length === 0) return res.status(404).json({ error: "File not found." });

            // 1. Hapus fisik di Spoke
            for (const v of allVersions) {
                await spokeFetch(`/internal/files/${v.physical_path}`, { method: 'DELETE' });
            }

            // 2. Hapus DB dengan aman (anak dulu, baru induk)
            const purgeTransaction = db.transaction((fileId) => {
                db.prepare('DELETE FROM versions WHERE file_id = ?').run(fileId);
                db.prepare('DELETE FROM files WHERE id = ?').run(fileId);
            });

            purgeTransaction(allVersions[0].file_id);
            return res.status(200).json({ status: "File completely purged." });
        } else {
            // LOGIKA B: Hapus HANYA VERSI SPESIFIK

            // --- KACAMATA X-RAY: Tampilkan semua versi yang ADA di DB untuk UUID ini ---
            const availableVersions = db.prepare(`SELECT v.id, v.version_num FROM files f JOIN versions v ON f.id = v.file_id WHERE f.uuid = ?`).all(uuid);
            console.log(`[PURGE X-RAY] Available versions in DB for this UUID:`, availableVersions);
            // ---------------------------------------------------------------------------

            // Gunakan CAST ke TEXT untuk menghindari masalah beda tipe data (String vs Integer)
            const fileInfo = db.prepare(`
                SELECT v.id as v_id, v.physical_path 
                FROM files f 
                JOIN versions v ON f.id = v.file_id 
                WHERE f.uuid = ? AND CAST(v.version_num AS TEXT) = ?
            `).get(uuid, String(requestedVersion));

            if (!fileInfo) {
                console.error(`[PURGE ERROR] Version ${requestedVersion} not found for UUID ${uuid}.`);
                return res.status(404).json({ error: `Version ${requestedVersion} not found.` });
            }

            const spokeResponse = await spokeFetch(`/internal/files/${fileInfo.physical_path}`, { method: 'DELETE' });
            if (!spokeResponse.ok) throw new Error("Spoke refused to delete physically.");

            db.prepare('DELETE FROM versions WHERE id = ?').run(fileInfo.v_id);
            return res.status(200).json({ status: `Version ${requestedVersion} purged.` });
        }
    } catch (err) {
        console.error("[PURGE FATAL ERROR]", err);
        res.status(500).json({ error: err.message });
    }
});
// gateway.js - Soft Delete
// apiRouter.delete('/vault/files/:uuid', authorizeVault('WRITE'), async (req, res) => {
//     const { uuid } = req.params;
//     try {
//         const file = db.prepare('SELECT id FROM files WHERE uuid = ?').get(uuid);
//         if (!file) return res.status(404).json({ error: "File not found." });

//         // Ubah status: isi deleted_at dengan timestamp saat ini
//         db.prepare("UPDATE files SET deleted_at = datetime('now') WHERE id = ?").run(file.id);

//         res.status(200).json({ 
//             status: "Success", 
//             message: "File moved to trash bin." 
//         });
//     } catch (err) {
//         res.status(500).json({ error: "Failed to move file to trash." });
//     }
// });
apiRouter.put('/vault/files/:uuid', authorizeVault('WRITE'), async (req, res) => {
    const { uuid } = req.params;
    const { newName } = req.body;

    if (!newName) return res.status(400).json({ error: "New name is required." });

    try {
        db.prepare('UPDATE files SET filename = ? WHERE uuid = ?').run(newName, uuid);
        res.json({ status: "Success", message: "File renamed." });
    } catch (err) {
        res.status(500).json({ error: "Failed to rename file." });
    }
});
apiRouter.delete('/vault/files/:uuid', permitGlobalRole('standard_user'), authorizeVault('WRITE'), async (req, res) => {
    const { uuid } = req.params;
    try {
        // 1. BARU: Ambil ID file dan TIMESTAMP dari versi komit paling terakhir (tertinggi)
        const file = db.prepare(`
            SELECT f.id, v.timestamp
            FROM files f
            JOIN versions v ON f.id = v.file_id
            WHERE f.uuid = ? AND f.deleted_at IS NULL
            ORDER BY v.version_num DESC
            LIMIT 1
        `).get(uuid);

        if (!file) return res.status(404).json({ error: "File not found." });

        let dbTime = file.timestamp; // Sekarang mengambil kolom timestamp milik tabel versions
        if (!dbTime.includes('Z')) {
            dbTime = dbTime.replace(' ', 'T') + 'Z';
        }

        const MINIMUM_RETENTION_MINUTES = 5;
        const latestVersionTime = new Date(dbTime); // Node.js membaca ini sebagai objek UTC/ZULU
        const now = new Date();

        const diffMinutes = Math.floor((now - latestVersionTime) / (1000 * 60));

        console.log(`[WORM DEBUG] Latest Version Time: ${latestVersionTime.toISOString()} | Now: ${now.toISOString()} | Age: ${diffMinutes} mins`);

        if (diffMinutes < MINIMUM_RETENTION_MINUTES) {
            return res.status(403).json({
                error: "Object Locked",
                message: `Data integrity policy: File cannot be deleted within ${MINIMUM_RETENTION_MINUTES} minutes of its latest version modification. Please try again in ${MINIMUM_RETENTION_MINUTES - diffMinutes} minutes.`
            });
        }

        console.log(`[OBJECT LOCK PASS] File ID: ${file.id} passed lock enforcement. Latest version age: ${diffMinutes} minutes`);

        db.prepare("UPDATE files SET deleted_at = datetime('now') WHERE id = ?").run(file.id);

        res.status(200).json({ status: "Success", message: "File moved to trash bin." });
    } catch (err) {
        console.error("DELETE ERROR DETAIL:", err);
        res.status(500).json({ error: "Failed to move file to trash.", details: err.message });
    }
});
// gateway.js - List Trash
apiRouter.get('/vault/trash', (req, res) => {
    const userId = req.auth.payload.sub; // ID dari Auth0
    try {
        const trashFiles = db.prepare(`
            SELECT f.uuid, f.filename, f.mime_type, v.size, f.deleted_at, b.name as bucket_name
            FROM files f
            JOIN versions v ON f.id = v.file_id
            JOIN buckets b ON f.bucket_id = b.id
            WHERE f.owner_id = ? AND f.deleted_at IS NOT NULL
            AND v.id IN (SELECT MAX(id) FROM versions GROUP BY file_id)
            ORDER BY f.deleted_at DESC
        `).all(userId);

        res.json(trashFiles);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch trash bin." });
    }
});
// gateway.js - Empty Trash (Batch Purge)
apiRouter.delete('/vault/trash', permitGlobalRole('standard_user'), async (req, res) => {
    try {
        const userId = req.auth.payload.sub;
        const trashedFiles = db.prepare(`
            SELECT f.id, v.physical_path 
            FROM files f
            JOIN versions v ON f.id = v.file_id
            WHERE f.deleted_at IS NOT NULL AND f.owner_id = ?
        `).all(userId);

        if (trashedFiles.length === 0) return res.status(400).json({ error: "Trash bin is already empty." });

        // Hapus fisik di Spoke
        for (const file of trashedFiles) {
            await spokeFetch(`/internal/files/${file.physical_path}`, { method: 'DELETE' });
        }

        // Hapus dari database Gateway
        const stmt = db.prepare('DELETE FROM files WHERE id = ?');
        const deleteMany = db.transaction((files) => {
            for (const file of files) stmt.run(file.id);
        });
        deleteMany(trashedFiles);

        res.json({ status: "Success", message: `Successfully purged ${trashedFiles.length} files.` });
    } catch (err) {
        res.status(500).json({ error: "Failed to empty trash bin." });
    }
});
apiRouter.post('/vault/files/:uuid/restore', authorizeVault('WRITE'), async (req, res) => {
    const { uuid } = req.params;
    const requestedVersion = req.query.v;
    try {
        if (!requestedVersion) {
            const result = db.prepare("UPDATE files SET deleted_at = NULL WHERE uuid = ?").run(uuid);
            if (result.changes === 0) return res.status(404).json({ error: "File not found in trash." });
            res.status(200).json({ status: "Success", message: "File restored successfully." });
        } else {
            const fileMeta = db.prepare(`SELECT f.id, f.filename, v.physical_path FROM files f JOIN versions v ON f.id = v.file_id WHERE f.uuid = ? AND v.version_num = ?`).get(req.params.uuid, req.query.v);
            if (!fileMeta) return res.status(404).json({ error: "Version not found." });
            const spokeResponse = await spokeFetch(`/internal/files/copy`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ source_path: fileMeta.physical_path }) });
            if (!spokeResponse.ok) throw new Error("Copy failed.");
            const { new_physical_path, size, checksum } = await spokeResponse.json();
            const lastVersion = db.prepare('SELECT MAX(version_num) as v FROM versions WHERE file_id = ?').get(fileMeta.id);
            const newVersionNum = (lastVersion.v || 0) + 1;
            db.prepare(`INSERT INTO versions (file_id, version_num, physical_path, size, checksum, timestamp) VALUES (?, ?, ?, ?, ?, datetime('now'))`).run(fileMeta.id, newVersionNum, new_physical_path, size, checksum);
            res.json({ status: "Restored", new_version: newVersionNum });
        }
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

// apiRouter.delete('/vault/buckets/:bucketUuid', permitGlobalRole('standard_user'), (req, res) => {
//     try {
//         const bucket = db.prepare('SELECT id, name, owner_id FROM buckets WHERE uuid = ?').get(req.params.bucketUuid);
//         if (!bucket) return res.status(404).json({ error: "Bucket not found." });
//         if (bucket.owner_id !== req.auth.payload.sub && req.globalRole !== 'admin') return res.status(403).json({ error: "Access Denied." });
//         const fileCount = db.prepare('SELECT COUNT(*) as count FROM files WHERE bucket_id = ?').get(bucket.id);
//         if (fileCount.count > 0) return res.status(409).json({ error: "Bucket is not empty." });
//         db.prepare('DELETE FROM buckets WHERE id = ?').run(bucket.id);
//         res.json({ status: "Bucket Deleted" });
//     } catch (err) { res.status(500).json({ error: "Failed to delete bucket." }); }
// });
// gateway.js - Hard Delete Bucket
apiRouter.delete('/vault/buckets/:uuid', authorizeBucket('ADMIN'), async (req, res) => {
    const { uuid } = req.params;
    try {
        const bucket = db.prepare('SELECT id FROM buckets WHERE uuid = ?').get(uuid);

        // Cek apakah ada file (termasuk yang di soft delete)
        const fileCount = db.prepare('SELECT COUNT(*) as count FROM files WHERE bucket_id = ?').get(bucket.id);

        if (fileCount.count > 0) {
            return res.status(409).json({
                error: "Bucket not empty",
                message: "Please purge all files in trash bin before deleting the bucket."
            });
        }

        db.prepare('DELETE FROM buckets WHERE id = ?').run(bucket.id);
        res.json({ status: "Bucket deleted permanently." });
    } catch (err) {
        res.status(500).json({ error: "Failed to delete bucket." });
    }
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

    // 1. BUAT "TOMBOL PANIK" (AbortController)
    const controller = new AbortController();

    req.on('error', (err) => {
        console.warn(`[GATEWAY SAFE-CATCH] Stream Error: ${err.message}`);
        controller.abort(); // 2. TEKAN TOMBOL PANIK UNTUK MEMUTUS FETCH KE SPOKE
    });

    req.on('aborted', () => {
        console.warn(`[GATEWAY SAFE-CATCH] Klien membatalkan unggahan secara sepihak.`);
        controller.abort(); // 2. TEKAN TOMBOL PANIK UNTUK MEMUTUS FETCH KE SPOKE
    });

    try {
        const spokeResponse = await spokeFetch(`/internal/files/test/upload`, {
            method: 'POST',
            body: req,
            duplex: 'half',
            signal: controller.signal, // 3. SAMBUNGKAN TOMBOL PANIK KE FETCH
            headers: {
                'Content-Type': req.headers['content-type'] || 'application/octet-stream'
            }
        });

        const data = await spokeResponse.json();

        res.json({
            message: "Benchmark Complete",
            spoke_received_gb: data.size_gb,
            note: data.note || "Stress test successful"
        });
        req.destroy();
    } catch (err) {
        // 4. TANGANI GALAT JIKA ABORT DILAKUKAN
        if (err.name === 'AbortError') {
            console.warn("[GATEWAY] Fetch ke Spoke dibatalkan karena klien terputus.");
        } else {
            console.error("[GATEWAY] Benchmark route error:", err.message);
        }

        // Pastikan kita hanya membalas jika header belum terkirim
        if (!res.headersSent) {
            res.status(500).json({ error: "Stream Interrupted: " + err.message });
        }
    }
});
// apiRouter.post('/vault/admin/test/performance', permitGlobalRole('admin'), async (req, res) => {
//     try {
//         const spokeResponse = await spokeFetch(`/internal/files/test/upload`, { 
//             method: 'POST', 
//             body: req,            // <-- Alirkan request mentah langsung ke Surabaya
//             duplex: 'half',       // <-- Syarat wajib Node.js fetch untuk aliran (Stream)
//             headers: {
//                 'Content-Type': req.headers['content-type'] || 'application/octet-stream'
//             }
//         });
//         const data = await spokeResponse.json();

//         res.json({ 
//             message: "Benchmark Complete", 
//             spoke_received_gb: data.size_gb,
//             note: data.note || "Stress test successful"
//         });
//     } catch (err) { 
//         console.error("Benchmark route error:", err);
//         res.status(500).json({ error: err.message }); 
//     }
// });
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
    if (err.status === 401 || err.name === 'UnauthorizedError') {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        console.warn(`[SECURITY] Failed Auth attempt on ${req.path} from IP: ${ip}`);
        try {
            db.prepare('INSERT INTO audit_logs (user_email, action, status, ip_address) VALUES (?, ?, ?, ?)')
                .run('unauthenticated_user', `BLOCKED_AUTH: ${req.path}`, 'FAILED', ip);
        } catch (dbErr) { console.error("Log fail:", dbErr.message); }
        return res.status(401).json({ error: "Unauthorized", message: err.message });
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

const server = https.createServer(sslOptions, app).listen(PUBLIC_PORT, '0.0.0.0', () => {
    console.log('--- Zero Trust Architecture Active ---');
    console.log(`Public Entry: https://richardgatewayta.duckdns.org:${PUBLIC_PORT}`);
    console.log(`Internal Destination: ${LOCAL_SPOKE_IP}:${LOCAL_PORT}`);
    console.log('--------------------------------------');
});

const SERVER_TIMEOUT = 30 * 60 * 1000;
server.setTimeout(SERVER_TIMEOUT);
server.keepAliveTimeout = SERVER_TIMEOUT;
server.headersTimeout = SERVER_TIMEOUT + 1000; // Standar Node.js: headersTimeout wajib lebih besar dari keepAlive
