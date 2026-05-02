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
// import { permission } from 'node:process';
dotenv.config();
// import axios from 'axios';
// import httpProxy from 'http-proxy';
// import FormData from 'form-data';
// import mime from 'mime-types';
// import e from 'express';

const app = express();
const PUBLIC_PORT = 8080;
const apiRouter = express.Router();
// const proxy = httpProxy.createProxyServer({});
app.use(cors({
    origin: 'http://localhost:5173', // Allow your React app
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-bucket-uuid', 'x-file-prefix'],
    credentials: true
}));

app.use(express.json({
    limit: '1mb',
    strict: true
}));
// Global API Limiter (e.g., max 100 requests per 15 minutes)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Too many requests. Please try again later." },
    standardHeaders: true,
    legacyHeaders: false,
});

// Strict Limiter for Uploads/Shares (e.g., max 10 per minute to prevent spam)
const strictLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 10,
    message: { error: "Action rate limit exceeded." }
});


// app.use('/api/v1/')
apiRouter.use('/vault/', apiLimiter);
apiRouter.use('/vault/files', strictLimiter);
let cachedM2MToken = null;
let tokenExpiry = 0;

async function getSpokeToken() {
    const now = Math.floor(Date.now() / 1000);

    if (cachedM2MToken && now < tokenExpiry) {
        console.log(`[AUTH] Using cached token ending in: ...${cachedM2MToken.slice(-5)}`);
        return cachedM2MToken;
    }

    console.log("[AUTH] Fetching fresh M2M token from Auth0...");
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
    // console.log({data});

    // DIAGNOSTIC: If there is no access_token, Auth0 usually sends an 'error' field
    if (!data.access_token) {
        console.error("[AUTH ERROR] Auth0 denied the request:", data);
        throw new Error(`Auth0 Authentication Failed: ${data.error_description || data.error}`);
    }

    cachedM2MToken = data.access_token;
    tokenExpiry = now + data.expires_in - 60;

    console.log(`[AUTH] New token issued ending in: ...${cachedM2MToken.slice(-5)}`);
    return cachedM2MToken;
}

// const m2mToken = await getSpokeToken();

async function spokeFetch(path, options = {}) {
    const token = await getSpokeToken(); // Automatically gets cached or fresh token
    const url = `http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}${path}`;

    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`
    };

    return fetch(url, { ...options, headers });
}
async function checkSpokeHealth() {
    try {
        const response = await spokeFetch('/internal/health');
        if (response.ok) {
            console.log("[TELEMETRY] Spoke is Healthy");
            // Optionally update a value in your DB or memory
        }
    } catch (err) {
        console.error("[TELEMETRY] Spoke Unreachable!");
    }
}

// Run every 5 minutes
setInterval(checkSpokeHealth, 5 * 60 * 1000);

const LOCAL_SPOKE_IP = process.env.SPOKE_IP;
const LOCAL_PORT = process.env.GATEWAY_PORT;
const namespace = process.env.NAMESPACE || 'unknown_namespace';


const bouncer = auth({
    audience: namespace,
    issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}/`,
    tokenSigningAlg: 'RS256'
});
app.get('/health', (req, res) => res.send("OK"));

apiRouter.get('/vault/view/:uuid', async (req, res) => {
    const { uuid } = req.params;
    const { expires, sig, permission } = req.query; // FIX: No more node:process!
    try {
        // 1. Verify Expiration
        if (Math.floor(Date.now() / 1000) > parseInt(expires)) {
            return res.status(403).send("This link has expired.");
        }

        // 2. Re-calculate Signature to verify integrity
        const secret = process.env.URL_SIGNING_SECRET;
        const expectedSig = crypto
            .createHmac('sha256', secret)
            .update(`${uuid}:${expires}:${permission}`)
            .digest('hex');

        if (sig !== expectedSig) return res.status(403).send("Invalid signature.");
        const fileMeta = db.prepare(`
            SELECT f.filename, f.mime_type, v.physical_path, v.size 
            FROM files f JOIN versions v ON f.id = v.file_id 
            WHERE f.uuid = ? ORDER BY v.version_num DESC LIMIT 1
        `).get(uuid);

        if (!fileMeta) return res.status(404).send("File no longer exists.");

        // 1. CORRECT FETCH SYNTAX (URL must be a string)
        const spokeResponse = await spokeFetch(`/internal/files/${fileMeta.physical_path}`);

        if (!spokeResponse.ok) throw new Error("Spoke failed to provide file.");

        // 2. CORRECT HEADERS
        res.setHeader('Content-Type', fileMeta.mime_type || 'application/octet-stream');
        // res.setHeader('Content-Disposition', `inline; filename="${fileMeta.filename}"`);
        if (permission === 'viewable') {
            res.setHeader('Content-Disposition', 'inline'); // Open in browser
        } else {
            res.setHeader('Content-Disposition', `attachment; filename="${fileMeta.filename}"`); // Force download
        }
        // 3. CORRECT PIPING (Fetch body is a Web Stream)
        Readable.fromWeb(spokeResponse.body).pipe(res);

    } catch (err) {
        console.error("[VIEW ERROR]", err.message);
        res.status(500).send("Secure viewing failed.");
    }
});


app.use(bouncer);

app.use(helmet());

app.use((req, res, next) => {
    // const user = req.auth?.payload?.email || 'anonymous';
    // const namespace = 'https://richardgatewayta.duckdns.org';
    const userEmail = req.auth?.payload[`${namespace}/email`] || 'anonymous';
    // console.log(`[LOG] User: ${userEmail} | Action: ${req.method} ${req.path}`);
    const log = db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)');
    // log.run(user, `${req.method} ${req.path}`, 'PENDING');
    log.run(userEmail, `${req.method} ${req.path}`, 'AUTHORIZED');
    next();
});
// Jakarta Hub (gateway.js)
apiRouter.get('/vault/usage', permitGlobalRole('standard_user'), (req, res) => {
    const userId = req.auth.payload.sub;
    const ADMIN_QUOTA_LIMIT = 50 * 1024 * 1024 * 1024; // 50gb
    const QUOTA_LIMIT = 5 * 1024 * 1024 * 1024; // 5gb
    const activeLimit = (req.globalRole === 'admin') ? ADMIN_QUOTA_LIMIT : QUOTA_LIMIT;
    try {
        const usage = db.prepare(`
            SELECT SUM(v.size) as total_used 
            FROM versions v 
            JOIN files f ON v.file_id = f.id 
            WHERE f.owner_id = ?
        `).get(userId);

        const totalUsed = usage.total_used || 0;

        res.json({
            used_bytes: totalUsed,
            quota_bytes: activeLimit,
            percent_used: ((totalUsed / activeLimit) * 100).toFixed(2)
        });
    } catch (err) {
        res.status(500).json({ error: "Could not calculate usage." });
    }
});
// get files list
// apiRouter.get('/vault/files', permitGlobalRole('standard_user'), (req, res) => {
//     const userId = req.auth.payload.sub;
//     const search = req.query.search ? `%${req.query.search}%` : '%';

//     try {
//         let query, results;

//         if (req.globalRole === 'admin') {
//             query = db.prepare(`
//                 SELECT f.uuid, f.filename,f.bucket_id, f.mime_type, v.size, v.timestamp 
//                 FROM files f JOIN versions v ON f.id = v.file_id 
//                 WHERE f.filename LIKE ? 
//                 AND v.id IN (SELECT MAX(id) FROM versions GROUP BY file_id) AND f.deleted_at IS NULL
//             `);
//             results = query.all(search);
//         } else {
//             query = db.prepare(`
//                 SELECT DISTINCT f.uuid, f.filename,f.bucket_id, f.mime_type, v.size, v.timestamp 
//                 FROM files f JOIN versions v ON f.id = v.file_id 
//                 WHERE (f.owner_id = ? OR fa.user_id = ?) 
//                 AND f.filename LIKE ?
//                 AND v.id IN (SELECT MAX(id) FROM versions GROUP BY file_id) AND f.deleted_at IS NULL
//             `);
//             results = query.all(userId, userId, search);
//         }

//         res.json(results);
//     } catch (err) {
//         res.status(500).json({ error: "Database query failed" });
//     }
// });
apiRouter.get('/vault/files', permitGlobalRole('standard_user'), (req, res) => {
    const userId = req.auth.payload.sub;
    const search = req.query.search ? `%${req.query.search}%` : '%';
    const bucketUuid = req.headers['x-bucket-uuid']; // Sent by React when opening a bucket

    try {
        let query, params;

        if (req.globalRole === 'admin' && !bucketUuid) {
            // 1. GOD MODE: Global File Explorer (Searches everything)
            query = db.prepare(`
                SELECT f.uuid, f.filename, f.bucket_id, f.mime_type, v.size, v.timestamp 
                FROM files f JOIN versions v ON f.id = v.file_id 
                WHERE f.filename LIKE ? 
                AND v.id IN (SELECT MAX(id) FROM versions GROUP BY file_id) AND f.deleted_at IS NULL
            `);
            params = [search];

        } else if (bucketUuid) {
            // 2. STANDARD MODE: Viewing inside a specific Bucket
            query = db.prepare(`
                SELECT f.uuid, f.filename, f.bucket_id, f.mime_type, v.size, v.timestamp 
                FROM files f 
                JOIN versions v ON f.id = v.file_id 
                JOIN buckets b ON f.bucket_id = b.id
                LEFT JOIN bucket_policies bp ON b.id = bp.bucket_id AND bp.grantee_id = ?
                WHERE b.uuid = ?
                AND (b.owner_id = ? OR bp.permission IS NOT NULL)
                AND f.filename LIKE ?
                AND v.id IN (SELECT MAX(id) FROM versions GROUP BY file_id) AND f.deleted_at IS NULL
            `);
            params = [userId, bucketUuid, userId, search];

        } else {
            // Failsafe: Should not happen based on React UI flow
            return res.json([]);
        }

        res.json(query.all(...params));
    } catch (err) {
        console.error("[FILE LIST ERROR]", err.message);
        res.status(500).json({ error: "Database query failed" });
    }
});
apiRouter.get('/vault/identity', (req, res) => {
    const namespace = process.env.NAMESPACE || 'https://richardgatewayta.duckdns.org';
    const userEmail = req.auth?.payload[`${namespace}/email`] || 'anonymous';
    const userRoles = req.auth?.payload[`${namespace}/roles`] || 'anonymous';
    // const userdat = req.auth?.payload[`${namespace}`] || 'anonymous';
    // const object = req.auth?.payload || 'anonymous';
    const userSub = req.auth?.payload.sub;

    try {
        // db.prepare('INSERT INTO users (sub,email) VALUES (?, ?)').run(userSub,userEmail);
        if (userSub && userEmail !== 'anonymous') {
            db.prepare(`
                INSERT INTO users (sub, email) 
                VALUES (?, ?) 
                ON CONFLICT(sub) DO UPDATE SET email = excluded.email
            `).run(userSub, userEmail);
        }
        res.json({ message: "username retrieved", user: userEmail, roles: userRoles });
    } catch (err) {
        console.error("SQL Error:", err);
        res.status(500).json({ error: "Database query failed" });
    }
});

const sslOptions = {
    key: fs.readFileSync('/etc/letsencrypt/live/richardgatewayta.duckdns.org/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/richardgatewayta.duckdns.org/fullchain.pem')
};

// upload
apiRouter.post('/vault/files', permitGlobalRole('standard_user'), authorizeBucket('WRITE'), (req, res) => {
    const ADMIN_QUOTA = 50 * 1024 * 1024 * 1024;
    const USER_QUOTA = 5 * 1024 * 1024 * 1024; // 5gb Limit 
    const MAX_SIZE = 1 * 1024 * 1024 * 1024; // 1gb Limit 
    const contentType = req.headers['content-type'];
    const contentLength = req.headers['content-length'];
    // const activeLimit = (userRole === 'admin') ? ADMIN_QUOTA : USER_QUOTA;
    const activeLimit = (req.globalRole === 'admin') ? ADMIN_QUOTA : USER_QUOTA;
    if (!contentType || !contentType.includes('multipart/form-data')) {
        console.error(`[GATEWAY] Blocked request with invalid Content-Type: ${contentType}`);
        return res.status(400).json({
            error: "Invalid Request",
            details: "Content-Type must be multipart/form-data"
        });
    }
    const busboy = Busboy({
        headers: req.headers,
        limits: {
            fileSize: MAX_SIZE, // 50MB Limit
            files: 1                    // Only allow 1 file per request
        }
    });
    const userId = req.auth.payload.sub;
    const bucketUuid = req.headers['x-bucket-uuid'];
    const folderPrefix = req.headers['x-file-prefix'] || '';
    const bucket = db.prepare('SELECT id FROM buckets WHERE uuid = ?').get(bucketUuid);

    if (!bucket) {
        return res.status(404).json({ error: "Target bucket does not exist." });
    }
    // We use a flag to ensure we only send one response
    let isProcessing = false;
    let limitReached = false; // Flag to stop SQL logic if file is too big

    // EARLY REJECT: Check the header before even starting Busboy
    if (contentLength && parseInt(contentLength) > MAX_SIZE) {
        console.warn(`[SECURITY] Early Reject: Header claims ${contentLength} bytes.`);
        return res.status(413).json({
            error: "File Too Large",
            message: "Header indicates file exceeds 50MB limit."
        });
    }


    busboy.on('file', async (name, file, info) => {
        if (isProcessing) return; // Only handle one file per request
        isProcessing = true;
        const { filename, mimeType: headerMime } = info;
        const fullVirtualFilename = folderPrefix + filename;
        const { isSpoofed, finalMime } = validateFileSecurity(filename, headerMime);
        file.on('limit', () => {
            limitReached = true;
            console.error(`[SECURITY] File too large: ${filename}`);
            // We don't respond here yet because the 'try' block might be mid-fetch
        });
        try {
            const usage = db.prepare(`
                SELECT SUM(v.size) as total_used 
                FROM versions v 
                JOIN files f ON v.file_id = f.id 
                WHERE f.owner_id = ?
            `).get(userId);

            const currentTotal = usage.total_used || 0;

            if (currentTotal >= activeLimit) {
                return res.status(403).json({
                    error: "Quota Exceeded",
                    message: `You have used ${(currentTotal / 1024 / 1024 / 1024).toFixed(2)} GB of your ${activeLimit / 1024 / 1024 / 1024} GB limit.`
                });
            }
            console.log(`[GATEWAY] Ingesting: ${filename} (${finalMime}) from user ${userId}`);
            if (isSpoofed) {
                console.error(`[SECURITY] Blocked: ${filename}`);
                file.resume();
                return res.status(403).json({ error: "Security Violation" });
            }

            // 1. FORWARD THE STREAM TO SURABAYA
            // We send the 'file' stream from Busboy, NOT the 'req' object
            // const spokeResponse = await axios({
            //     method: 'post',
            //     url: `http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}/receive-file`,
            //     data: file,
            //     headers: {
            //         ...file.headers, // Keep stream headers if any
            //         'x-original-name': filename
            //     },
            //     maxContentLength: Infinity,
            //     maxBodyLength: Infinity,
            //     decompress: false
            // });
            const spokeResponse = await spokeFetch(`/internal/files`, {
                method: 'POST',
                body: file, // This is your Busboy file stream
                // CRITICAL for streaming request bodies in Fetch:
                duplex: 'half',
                headers: {
                    'x-original-name': filename
                },
                //  maxContentLength: Infinity,
                // maxBodyLength: Infinity,
                // decompress: false
            });
            if (limitReached) {
                return res.status(413).json({ error: "File Too Large (Max 50MB)" });
            }
            if (!spokeResponse.ok) {
                const errorText = await spokeResponse.text();
                throw new Error(`Spoke rejected upload: ${errorText}`);
            }

            const data = await spokeResponse.json();
            const { physical_path, size ,checksum} = data;

            // 2. SQL LOGIC: Find or Create the File Entry
            // We include mime_type here!
            // 2. SQL LOGIC: Find or Create the File Entry
            // Make sure we look for the filename inside this specific bucket!
            let fileRecord = db.prepare('SELECT id, uuid FROM files WHERE filename = ? AND bucket_id = ?')
                .get(fullVirtualFilename, bucket.id);

            if (!fileRecord) {
                const uuid = randomUUID();
                const info = db.prepare('INSERT INTO files (uuid, filename, owner_id, mime_type, bucket_id) VALUES (?, ?, ?, ?, ?)')
                    .run(uuid, fullVirtualFilename, userId, finalMime, bucket.id);
                fileRecord = { id: info.lastInsertRowid, uuid: uuid };
            } else {
                // If the file exists, update the mime_type just in case it changed
                db.prepare('UPDATE files SET mime_type = ? WHERE id = ?').run(finalMime, fileRecord.id);
            }

            // 3. VERSION CLEANUP (The 5-Version Limit)
            let versions = db.prepare('SELECT id, physical_path FROM versions WHERE file_id = ? ORDER BY version_num ASC').all(fileRecord.id);

            while (versions.length >= 5) {
                const oldest = versions[0];
                console.log(`[CLEANUP] Purging oldest version: ${oldest.physical_path}`);

                try {
                    // A. Delete from Surabaya
                    // await axios.delete(`http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}/vault/delete/${oldest.physical_path}`);
                    await spokeFetch(`/vault/delete/${oldest.physical_path}`, {
                        method: 'DELETE'
                    });
                    // B. Delete from Jakarta SQL
                    db.prepare('DELETE FROM versions WHERE id = ?').run(oldest.id);

                    // Refresh versions list
                    versions = db.prepare('SELECT id, physical_path FROM versions WHERE file_id = ? ORDER BY version_num ASC').all(fileRecord.id);
                } catch (purgeErr) {
                    console.error("[ERROR] Cleanup failed, continuing upload:", purgeErr.message);
                }
            }

            // 4. INSERT NEW VERSION
            const lastVersion = db.prepare('SELECT MAX(version_num) as v FROM versions WHERE file_id = ?').get(fileRecord.id);
            const newVersion = (lastVersion.v || 0) + 1;

            // db.prepare('INSERT INTO versions (file_id, version_num, physical_path, size, timestamp) VALUES (?, ?, ?, ?, datetime("now"))')
            //     .run(fileRecord.id, newVersion, physical_path, size);
            db.prepare("INSERT INTO versions (file_id, version_num, physical_path, size, checksum, timestamp) VALUES (?, ?, ?, ?, datetime('now'))")
                .run(fileRecord.id, newVersion, physical_path, size,checksum);


            res.json({ status: "Vaulted", version: newVersion, uuid: fileRecord.uuid, finalMime });

        } catch (err) {
            console.error("Streaming Upload Failed:", err.message);
            // If Surabaya fails, we must consume the stream to avoid hanging
            file.resume();
            res.status(500).json({ error: "Gateway stream interrupted." });
        }
    });

    busboy.on('error', (err) => {
        console.error("Busboy Error:", err);
        res.status(500).json({ error: "Form parsing failed" });
    });

    req.pipe(busboy);
});
// get details
apiRouter.get('/vault/files/:uuid/versions', authorizeVault('READ'), (req, res) => {
    const userId = req.auth.payload.sub;
    const fileUuid = req.params.uuid;

    try {
        const query = db.prepare(`
            SELECT v.version_num, v.timestamp, v.size, v.physical_path
            FROM versions v
            JOIN files f ON f.id = v.file_id
            WHERE f.uuid = ? 
            ORDER BY v.version_num DESC
        `);

        const history = query.all(fileUuid);
        res.json(history);
    } catch (err) {
        res.status(500).json({ error: "Failed to retrieve history" });
    }
});
// logging
apiRouter.get('/vault/audit', permitGlobalRole('admin'), (req, res) => {

    try {
        const logs = db.prepare(`
            SELECT 
                id, 
                user_email, 
                action, 
                status, 
                timestamp 
            FROM audit_logs 
            ORDER BY timestamp DESC 
            LIMIT 100
        `).all();

        res.json(logs);
    } catch (err) {
        console.error("Audit Retrieval Failed:", err.message);
        res.status(500).json({ error: "Could not retrieve security logs." });
    }
});
// gateway.js (
// gateway.js (Jakarta VM)

apiRouter.get('/vault/files/:uuid/content', authorizeVault('READ'), async (req, res) => {
    const { uuid } = req.params;
    const userId = req.auth.payload.sub;
    const requestedVersion = req.query.v;
    try {
        // 1. Get metadata (Join files and the LATEST version)
        const fileInfo = db.prepare(`
            SELECT f.filename,f.mime_type, v.physical_path, v.size
            FROM files f JOIN versions v ON f.id = v.file_id
            WHERE f.uuid = ? 
            ${requestedVersion ? 'AND v.version_num = ?' : ''}
            ORDER BY v.version_num DESC LIMIT 1
        `).get(requestedVersion ? [uuid, requestedVersion] : [uuid]);

        if (!fileInfo) return res.status(404).json({ error: "Version not found." });

        console.log(`[GATEWAY] Streaming ${fileInfo.filename} from Surabaya for user ${userId}`);

        // 2. Request the stream from the Surabaya Spoke
        const spokeResponse = await spokeFetch(`/internal/files/${fileInfo.physical_path}`);

        if (!spokeResponse.ok) throw new Error("Spoke failed to provide file stream.");

        // 3. Set headers so the browser knows what to do
        res.setHeader('Content-Type', fileInfo.mime_type || 'application/octet-stream');
        // res.setHeader('Content-Length', fileInfo.size);
        const actualSize = spokeResponse.headers.get('content-length');
        if (actualSize) {
            res.setHeader('Content-Length', actualSize);
        }
        let downloadName = fileInfo.filename;

        // Jika user spesifik meminta versi lama, sisipkan nomor versi ke namanya
        if (requestedVersion) {
            downloadName = fileInfo.filename.includes('.')
                ? fileInfo.filename.replace(/(\.[^.]+)$/, `_v${requestedVersion}$1`)
                : `${fileInfo.filename}_v${requestedVersion}`;
        }
        // This forces the "Save As" dialog with the original filename
        res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);

        // 4. Pipe the bytes: Spoke -> Hub -> User
        // Use Readable.fromWeb because fetch returns a Web Stream

        Readable.fromWeb(spokeResponse.body).pipe(res);

    } catch (err) {
        console.error("Download Error:", err.message);
        if (!res.headersSent) res.status(500).json({ error: "Could not retrieve file." });
    }
});
// apiRouter.get('/vault/download/:uuid', bouncer, async (req, res) => {
//     const userId = req.auth.payload.sub;
//     const fileUuid = req.params.uuid;
//     const requestedVersion = req.query.v;

//     try {
//         let fileMeta;

//         if (requestedVersion) {
//             // A. Specific Version Request
//             console.log(`[GATEWAY] Requesting Version ${requestedVersion} of ${fileUuid}`);
//             fileMeta = db.prepare(`
//                 SELECT f.filename, v.physical_path, v.version_num
//                 FROM files f
//                 JOIN versions v ON f.id = v.file_id
//                 WHERE f.uuid = ? AND f.owner_id = ? AND v.version_num = ?
//             `).get(fileUuid, userId, requestedVersion);
//         } else {
//             // B. Default: Get Latest Version
//             fileMeta = db.prepare(`
//                 SELECT f.filename, v.physical_path, v.version_num
//                 FROM files f
//                 JOIN versions v ON f.id = v.file_id
//                 WHERE f.uuid = ? AND f.owner_id = ?
//                 ORDER BY v.version_num DESC LIMIT 1
//             `).get(fileUuid, userId);
//         }

//         if (!fileMeta) {
//             return res.status(404).json({ error: "Version not found or access denied." });
//         }

//         // 2. Stream from Surabaya (Same as before)
//         const spokeResponse = await axios({
//             method: 'get',
//             url: `http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}/internal/raw/${fileMeta.physical_path}`,
//             responseType: 'stream'
//         });

//         // 3. Set Headers (Include version in the filename for a better UX!)
//         // Example: my_thesis_v3.pdf
//         const downloadName = fileMeta.filename.includes('.')
//             ? fileMeta.filename.replace(/(\.[^.]+)$/, `_v${fileMeta.version_num}$1`)
//             : `${fileMeta.filename}_v${fileMeta.version_num}`;

//         res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);
//         res.setHeader('Content-Type', 'application/octet-stream');

//         // 4. PIPE IT OUT
//         spokeResponse.data.pipe(res);
//         const log = db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)');
//         log.run(userId, `DOWNLOAD ${fileMeta.filename} (v${fileMeta.version_num})`, 'SUCCESS');

//     } catch (err) {
//         console.error("[GATEWAY] Download Failed:", err.message);
//         res.status(500).json({ error: "Secure Tunnel Interrupted" });
//     }
// });
// apiRouter.get('/vault/files', permitGlobalRole('standard_user'), (req, res) => {
//     const userId = req.auth.payload.sub;

//     try {
//         let query, params;
//         console.log(`[GATEWAY] Fetching file list for user ${userId} with role ${req.globalRole}`);
//         if (req.globalRole === 'admin') {
//             query = `SELECT f.uuid, f.filename,f.bucket_id, v.size FROM files f JOIN versions v ON f.id = v.file_id WHERE v.id IN (SELECT MAX(id) FROM versions GROUP BY file_id)`;
//             params = [];
//         } else {
//             query = `SELECT DISTINCT f.uuid, f.filename,f.bucket_id, v.size FROM files f JOIN versions v ON f.id = v.file_id AND v.id IN (SELECT MAX(id) FROM versions GROUP BY file_id)`;
//             params = [userId, userId];
//         }

//         res.json(db.prepare(query).all(...params));
//     } catch (err) {
//         res.status(500).json({ error: "List failed." });
//     }
// }
// );

apiRouter.get('/vault/files/:uuid/links', authorizeVault('WRITE'), (req, res) => {
    const userId = req.auth.payload.sub;
    const fileUuid = req.params.uuid;
    const ttl = parseInt(req.query.ttl) || 60; // Default 60 minutes
    const permission = req.query.permission === 'downloadable' ? 'downloadable' : 'viewable';

    try {
        // 1. Verify ownership
        const file = db.prepare('SELECT filename FROM files WHERE uuid = ?')
            .get(fileUuid);
        if (!file) return res.status(404).json({ error: "File not found" });

        // 2. Create Expiry (Current time + TTL minutes)
        const expires = Math.floor(Date.now() / 1000) + (ttl * 60);

        // 3. Generate HMAC Signature
        const secret = process.env.URL_SIGNING_SECRET;
        const signature = crypto
            .createHmac('sha256', secret)
            .update(`${fileUuid}:${expires}:${permission}`)
            .digest('hex');

        // 4. Construct the Public URL
        const shareLink = `${namespace}:${PUBLIC_PORT}/vault/view/${fileUuid}?expires=${expires}&sig=${signature}`;

        res.json({
            share_url: shareLink,
            expires_at: new Date(expires * 1000).toISOString()
        });

        // Audit Log
        db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)')
            .run(userId, `SHARE_LINK_CREATED: ${file.filename}`, 'SUCCESS');

    } catch (err) {
        res.status(500).json({ error: "Failed to generate share link", details: err.message });
    }
});

apiRouter.delete('/vault/files/:uuid', authorizeVault('WRITE'), async (req, res) => {
    const { uuid } = req.params;
    const userId = req.auth.payload.sub;
    const requestedVersion = req.query.v;

    try {
        if (!requestedVersion) {
            // 1. Tarik SEMUA jalur fisik dari fail ini
            const allVersions = db.prepare(`
                SELECT v.physical_path, f.id as file_id 
                FROM files f JOIN versions v ON f.id = v.file_id 
                WHERE f.uuid = ?
            `).all(uuid);

            if (allVersions.length === 0) return res.status(404).json({ error: "File not found." });

            // 2. Minta Spoke menghapus fisiknya secara massal (satu per satu atau buat rute batch di Spoke)
            for (const v of allVersions) {
                await spokeFetch(`/internal/files/${v.physical_path}`, { method: 'DELETE' });
            }

            // 3. Hapus Induknya di Database (karena ada ON DELETE CASCADE di db.js, tabel versions akan otomatis terhapus!)
            db.prepare('DELETE FROM files WHERE id = ?').run(allVersions[0].file_id);

            return res.status(200).json({ status: "File and all its versions completely purged." });
        } else {

            // 1. Fetch metadata INCLUDING the version ID (v_id)
            const fileInfo = db.prepare(`
            SELECT f.filename, v.id as v_id, v.physical_path 
            FROM files f JOIN versions v ON f.id = v.file_id
            WHERE f.uuid = ? 
            ${requestedVersion ? 'AND v.version_num = ?' : ''}
            ORDER BY v.version_num DESC LIMIT 1
            `).get(uuid, requestedVersion);

            if (!fileInfo) return res.status(404).json({ error: "Version not found." });

            // 2. Physical Purge First (The "Body")
            const spokeResponse = await spokeFetch(`/internal/files/${fileInfo.physical_path}`, { method: 'DELETE' });
            
            if (!spokeResponse.ok) {
                // Log the failure! The file is still there, so don't touch the DB yet.
                db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)')
                .run(userId, `DELETE_FAILED: ${fileInfo.filename}`, 'SPOKE_ERROR');
                throw new Error("Surabaya Spoke refused to delete the bytes.");
            }
            
            // 3. Metadata Purge Second (The "Brain")
            db.prepare('DELETE FROM versions WHERE id = ?').run(fileInfo.v_id);
            
            // 4. Success Audit
            db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)')
            .run(userId, `DELETE_SUCCESS: ${fileInfo.filename}`, 'SUCCESS');
            
            return res.status(200).json({ status: `Version of ${fileInfo.filename} purged.` });
        }
            
    } catch (err) {
        console.error("Delete Error:", err.message);
        res.status(500).json({ error: err.message });
    }
});
apiRouter.post('/vault/files/:uuid/restore', authorizeVault('WRITE'), async (req, res) => {
    const { uuid } = req.params;
    const requestedVersion = req.query.v;

    try {
        // 1. Cari jejak fisik dari versi yang ingin dipulihkan
        const fileMeta = db.prepare(`
            SELECT f.id, f.filename, v.physical_path 
            FROM files f 
            JOIN versions v ON f.id = v.file_id 
            WHERE f.uuid = ? AND v.version_num = ?
        `).get(uuid, requestedVersion);

        if (!fileMeta) return res.status(404).json({ error: "Version not found." });

        // 2. Perintahkan Spoke untuk menggandakan fail fisiknya
        const spokeResponse = await spokeFetch(`/internal/files/copy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source_path: fileMeta.physical_path })
        });

        if (!spokeResponse.ok) throw new Error("Spoke failed to copy file.");
        const { new_physical_path, size, checksum } = await spokeResponse.json();

        // 3. Kebersihan Batas Versi (Sama seperti saat Upload baru, maksimal 5 versi)
        let versions = db.prepare('SELECT id, physical_path FROM versions WHERE file_id = ? ORDER BY version_num ASC').all(fileMeta.id);

        while (versions.length >= 5) {
            const oldest = versions[0];
            try {
                await spokeFetch(`/internal/files/${oldest.physical_path}`, { method: 'DELETE' });
                db.prepare('DELETE FROM versions WHERE id = ?').run(oldest.id);
                versions = db.prepare('SELECT id, physical_path FROM versions WHERE file_id = ? ORDER BY version_num ASC').all(fileMeta.id);
            } catch (e) {
                console.error("Cleanup error during restore");
            }
        }

        // 4. Suntikkan versi baru ke pangkalan data
        const lastVersion = db.prepare('SELECT MAX(version_num) as v FROM versions WHERE file_id = ?').get(fileMeta.id);
        const newVersionNum = (lastVersion.v || 0) + 1;

        db.prepare(`
            INSERT INTO versions (file_id, version_num, physical_path, size, checksum, timestamp) 
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        `).run(fileMeta.id, newVersionNum, new_physical_path, size, checksum);

        // Audit Log
        db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)')
            .run(req.auth.payload[`${process.env.NAMESPACE}/email`] || 'unknown', `RESTORED_${fileMeta.filename}_V${requestedVersion}_TO_V${newVersionNum}`, 'SUCCESS');

        res.json({ status: "Restored", new_version: newVersionNum });

    } catch (err) {
        console.error("Restore Error:", err);
        res.status(500).json({ error: "Restore failed." });
    }
});

apiRouter.post('/vault/buckets', bouncer, (req, res) => {
    const { name, region } = req.body || {};
    const userId = req.auth.payload.sub;
    const bucketUuid = randomUUID();

    try {
        // const info = db.prepare(`
        //     INSERT INTO buckets (uuid, name, owner_id, region) 
        //     VALUES (?, ?, ?, ?)
        // `).run(bucketUuid, name, userId, region || 'sub-01');

        // // Automatically give the owner ADMIN permission
        // db.prepare(`
        //     INSERT INTO bucket_policies (bucket_id, grantee_id, permission) 
        //     VALUES (?, ?, 'ADMIN')
        // `).run(info.lastInsertRowid, userId);
        const createAtomicBucket = db.transaction(() => {
            const info = db.prepare(`INSERT INTO buckets (uuid, name, owner_id, region) VALUES (?, ?, ?, ?)`).run(bucketUuid, name, userId, region || 'sub-01');
            db.prepare(`INSERT INTO bucket_policies (bucket_id, grantee_id, permission) VALUES (?, ?, 'ADMIN')`).run(info.lastInsertRowid, userId);
        });
        createAtomicBucket();

        res.json({ status: "Bucket Created", uuid: bucketUuid });
    } catch (err) {
        res.status(500).json({ error: "Could not create bucket." });
    }
});

apiRouter.get('/vault/buckets', (req, res) => {
    const userId = req.auth.payload.sub;

    try {
        const buckets = db.prepare(`
            SELECT b.uuid, b.name, b.region , bp.permission
            FROM buckets b 
            JOIN bucket_policies bp ON b.id = bp.bucket_id 
            WHERE bp.grantee_id = ? AND b.deleted_at IS NULL
        `).all(userId);
        res.json({ buckets });
    } catch (err) {
        console.error("[BUCKET FETCH ERROR]:", err.message);
        res.status(500).json({ error: "Could not fetch buckets." });
    }
});
// apiRouter.post('/vault/buckets/:bucketUuid/share', permitGlobalRole('standard_user'), authorizeBucket('ADMIN'), (req, res) => {
//     const { bucketUuid } = req.params;
//     const { grantee_id, permission } = req.body; // grantee_id is the guest's Auth0 'sub'

//     // 1. Validation
//     if (!grantee_id || !['READ', 'WRITE'].includes(permission)) {
//         return res.status(400).json({ error: "Invalid request. Need grantee_id and permission (READ/WRITE)." });
//     }

//     try {
//         // 2. Get internal Bucket ID
//         const bucket = db.prepare('SELECT id, name FROM buckets WHERE uuid = ?').get(bucketUuid);

//         // 3. Insert the Policy
//         // Use INSERT OR REPLACE so you can "Update" a user's permission easily
//         db.prepare(`
//             INSERT INTO bucket_policies (bucket_id, grantee_id, permission)
//             VALUES (?, ?, ?)
//             ON CONFLICT(bucket_id, grantee_id) DO UPDATE SET permission = excluded.permission
//         `).run(bucket.id, grantee_id, permission);

//         // 4. Audit Log
//         db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)')
//             .run(req.auth.payload.sub, `INVITED_${grantee_id}_TO_${bucket.name}`, 'SUCCESS');

//         res.json({ status: "Member added", bucket: bucket.name, user: grantee_id, role: permission });
//     } catch (err) {
//         console.error("[SHARE ERROR]", err.message);
//         res.status(500).json({ error: "Failed to share bucket." });
//     }
// });
apiRouter.delete('/vault/buckets/:bucketUuid/share/:userId', authorizeBucket('ADMIN'), (req, res) => {
    const { bucketUuid, userId } = req.params;

    try {
        const bucket = db.prepare('SELECT id FROM buckets WHERE uuid = ?').get(bucketUuid);

        const bucketOwner = db.prepare('SELECT owner_id FROM buckets WHERE id = ?').get(bucket.id);
        if (userId === bucketOwner.owner_id) {
            return res.status(400).json({ error: "Cannot revoke access from the bucket owner." });
        }

        db.prepare('DELETE FROM bucket_policies WHERE bucket_id = ? AND grantee_id = ?')
            .run(bucket.id, userId);

        res.json({ status: "Access revoked successfully." });
    } catch (err) {
        res.status(500).json({ error: "Failed to remove member." });
    }
});

apiRouter.put('/vault/buckets/:bucketUuid', authorizeBucket('ADMIN'), (req, res) => {
    const { bucketUuid } = req.params;
    const { name, region } = req.body;

    try {
        const bucket = db.prepare('SELECT id FROM buckets WHERE uuid = ?').get(bucketUuid);
        if (!bucket) {
            return res.status(404).json({ error: "Bucket not found." });
        }

        db.prepare('UPDATE buckets SET name = ?, region = ? WHERE id = ?')
            .run(name, region, bucket.id);

        res.json({ status: "Bucket updated successfully." });
    } catch (err) {
        res.status(500).json({ error: "Failed to update bucket." });
    }
});
apiRouter.delete('/vault/buckets/:bucketUuid', permitGlobalRole('standard_user'), async (req, res) => {
    const { bucketUuid } = req.params;
    const userId = req.auth.payload.sub;

    try {
        // 1. Verify Bucket & Ownership (Only the true owner or Global Admin can delete)
        const bucket = db.prepare('SELECT id, name, owner_id FROM buckets WHERE uuid = ?').get(bucketUuid);
        
        if (!bucket) {
            return res.status(404).json({ error: "Bucket not found." });
        }

        if (bucket.owner_id !== userId && req.globalRole !== 'admin') {
            return res.status(403).json({ error: "Access Denied: Only the Bucket Owner can delete the bucket." });
        }

        // 2. Safety Check: Is the bucket empty?
        const fileCount = db.prepare('SELECT COUNT(*) as count FROM files WHERE bucket_id = ?').get(bucket.id);
        
        if (fileCount.count > 0) {
            return res.status(409).json({ 
                error: "Bucket is not empty.", 
                message: `You must delete all ${fileCount.count} files inside '${bucket.name}' before deleting the namespace.`
            });
        }

        // 3. Delete the Bucket (SQLite CASCADE will automatically handle the bucket_policies)
        db.prepare('DELETE FROM buckets WHERE id = ?').run(bucket.id);

        // 4. Audit Log
        db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)')
            .run(req.auth.payload[`${process.env.NAMESPACE}/email`], `DELETED_BUCKET: ${bucket.name}`, 'SUCCESS');

        res.json({ status: "Bucket Deleted", message: `Namespace '${bucket.name}' has been permanently destroyed.` });

    } catch (err) {
        console.error("[BUCKET DELETE ERROR]", err.message);
        res.status(500).json({ error: "Failed to delete bucket." });
    }
});

apiRouter.get('/vault/users/search', permitGlobalRole('standard_user'), (req, res) => {
    const searchQuery = req.query.q;
    const currentUserId = req.auth.payload.sub;

    if (!searchQuery || searchQuery.length < 2) {
        return res.json([]);
    }

    try {
        const users = db.prepare(`
            SELECT sub as user_id, email 
            FROM users 
            WHERE email LIKE ? AND sub != ?
            LIMIT 5
        `).all(`%${searchQuery}%`, currentUserId);

        res.json(users);
    } catch (err) {
        console.error("[SEARCH ERROR]", err.message);
        res.status(500).json({ error: "Failed to search users." });
    }
});
apiRouter.get('/vault/notifications', permitGlobalRole('standard_user'), (req, res) => {
    const userId = req.auth.payload.sub;

    try {
        const notes = db.prepare(`
            SELECT id, message, timestamp 
            FROM notifications 
            WHERE user_id = ? AND is_read = 0 
            ORDER BY timestamp DESC
        `).all(userId);

        res.json(notes);
    } catch (err) {
        console.error("[NOTIFY ERROR]", err.message);
        res.status(500).json({ error: "Failed to fetch notifications." });
    }
});

// 2. Clear (mark as read) all notifications for the user
apiRouter.post('/vault/notifications/clear', permitGlobalRole('standard_user'), (req, res) => {
    const userId = req.auth.payload.sub;

    try {
        // We do a soft delete (is_read = 1) instead of a hard DELETE to preserve the audit trail if needed
        db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(userId);
        res.json({ status: "Notifications cleared." });
    } catch (err) {
        console.error("[NOTIFY CLEAR ERROR]", err.message);
        res.status(500).json({ error: "Failed to clear notifications." });
    }
});
apiRouter.post('/vault/buckets/:bucketUuid/share', permitGlobalRole('standard_user'), authorizeBucket('ADMIN'), (req, res) => {
    const { bucketUuid } = req.params;
    const { email, permission } = req.body; // Menerima Email, bukan ID panjang
    const inviterId = req.auth.payload.sub;

    if (!email || !['READ', 'WRITE'].includes(permission)) {
        return res.status(400).json({ error: "Invalid payload. Requires email and permission." });
    }

    try {
        const targetUser = db.prepare('SELECT sub FROM users WHERE email = ?').get(email);

        if (!targetUser) {
            return res.status(404).json({
                error: "User not found.",
                message: "Target user must log into RiccBox at least once before they can be invited."
            });
        }

        const bucket = db.prepare('SELECT id, name FROM buckets WHERE uuid = ?').get(bucketUuid);
        if (!bucket) return res.status(404).json({ error: "Bucket not found." });

        db.prepare(`
            INSERT INTO bucket_policies (bucket_id, grantee_id, permission)
            VALUES (?, ?, ?)
            ON CONFLICT(bucket_id, grantee_id) DO UPDATE SET permission = excluded.permission
        `).run(bucket.id, targetUser.sub, permission);

        db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)')
            .run(req.auth.payload[`${process.env.NAMESPACE}/email`], `INVITED_${email}_TO_${bucket.name}`, 'SUCCESS');
        const message = `Access Granted: You now have ${permission} rights to the namespace '${bucket.name}'.`;

        db.prepare('INSERT INTO notifications (user_id, message) VALUES (?, ?)')
            .run(targetUser.sub, message);
        res.json({
            status: "Invitation Successful",
            bucket: bucket.name,
            invited_user: email,
            role: permission
        });

    } catch (err) {
        console.error("[INVITE ERROR]", err.message);
        res.status(500).json({ error: "Failed to invite user to bucket." });
    }
});

apiRouter.get('/vault/admin/sync', permitGlobalRole('admin'), async (req, res) => {
    try {
        const dbFiles = db.prepare(`
            SELECT v.physical_path, f.filename 
            FROM versions v 
            JOIN files f ON v.file_id = f.id
        `).all();

        const spokeResponse = await spokeFetch(`/internal/inventory`);

        // 1. Check if the Spoke is even awake
        if (!spokeResponse.ok) {
            throw new Error(`Spoke unreachable: ${spokeResponse.status} ${spokeResponse.statusText}`);
        }

        const physicalFiles = await spokeResponse.json();

        // 2. THE FIX: Ensure physicalFiles is an Array
        if (!Array.isArray(physicalFiles)) {
            console.error("[AUDIT] Expected Array but got:", typeof physicalFiles, physicalFiles);
            return res.status(502).json({ error: "Spoke returned invalid data format." });
        }

        // 3. Perform the Set Theory logic
        const missingFromDisk = dbFiles.filter(dbFile => !physicalFiles.includes(dbFile.physical_path));
        const orphanedOnDisk = physicalFiles.filter(pPath => !dbFiles.some(dbFile => dbFile.physical_path === pPath));

        res.json({
            status: "Audit Complete",
            results: { missingFromDisk, orphanedOnDisk }
        });

    } catch (err) {
        console.error("Integrity Audit Failed:", err.message);
        res.status(500).json({ error: err.message });
    }
});
apiRouter.post('/vault/admin/sync', permitGlobalRole('admin'), async (req, res) => {
    const { missingFromDisk, orphanedOnDisk } = req.body;

    // 0. Payload Validation
    if (!Array.isArray(missingFromDisk) || !Array.isArray(orphanedOnDisk)) {
        return res.status(400).json({ error: "Invalid payload: Expected arrays." });
    }

    const report = { pruned: 0, purged: 0, skipped: 0 };

    try {
        if (missingFromDisk.length > 0) {
            const checkStmt = db.prepare('SELECT id FROM versions WHERE physical_path = ?');
            const deleteStmt = db.prepare('DELETE FROM versions WHERE physical_path = ?');

            for (const file of missingFromDisk) {
                // Verify the record STILL exists in the DB before pruning
                const exists = checkStmt.get(file.physical_path);
                if (exists) {
                    deleteStmt.run(file.physical_path);
                    report.pruned++;
                } else {
                    report.skipped++; // Already gone or invalid path
                }
            }
        }

        if (orphanedOnDisk.length > 0) {
            // Sanity Check: Ensure these paths DON'T actually have a record now
            // (To prevent accidental deletion of a file that was JUST uploaded)
            const checkDB = db.prepare('SELECT id FROM versions WHERE physical_path = ?');
            const validOrphans = orphanedOnDisk.filter(path => !checkDB.get(path));

            if (validOrphans.length > 0) {
                const spokeResponse = await spokeFetch(`/internal/maintenance/purge`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ files: validOrphans })
                });

                if (spokeResponse.ok) {
                    const spokeData = await spokeResponse.json();
                    report.purged = spokeData.success;
                }
            }
        }

        res.json({
            message: "Synchronization Complete",
            report,
            details: `Successfully cleaned ${report.pruned} DB records and ${report.purged} disk files.`
        });

    } catch (err) {
        console.error("[SYNC ERROR]", err.message);
        res.status(500).json({ error: "Sync operation failed.", details: err.message });
    }
});

apiRouter.post('/vault/admin/test/performance', permitGlobalRole('admin'), async (req, res) => {
    console.log(`[STRESS TEST] Initiating high-throughput benchmark to Surabaya...`);

    try {
        const spokeResponse = await spokeFetch(`/internal/files/test/upload`, {
            method: 'POST',
            body: req, // Pipe the raw request stream
            duplex: 'half'
        });

        const result = await spokeResponse.json();
        res.json({
            message: "Benchmark Complete",
            spoke_received_gb: result.size_gb,
            note: "Data was processed through the encryption tunnel but discarded at the Spoke to preserve disk health."
        });
    } catch (err) {
        res.status(500).json({ error: "Benchmark Interrupted", details: err.message });
    }
});
apiRouter.post('/vault/admin/bitrot/report', permitGlobalRole('admin'), (req, res) => {
    // req.body looks like: [{ path: "1774...", hash: "abc..." }]
    const reports = req.body;
    let corruptedFiles = 0;

    for (const item of reports) {
        const dbRecord = db.prepare('SELECT checksum, id FROM versions WHERE physical_path = ?').get(item.path);

        if (dbRecord && dbRecord.checksum !== item.hash) {
            corruptedFiles++;
            db.prepare('INSERT INTO audit_logs (action, status) VALUES (?, ?)').run(`BIT_ROT_DETECTED_${item.path}`, 'CRITICAL');
            // Optional: You could update a "status" column in versions to "CORRUPTED"
        }
    }

    res.json({ message: "Scan complete", corrupted: corruptedFiles });
});
// This is the trigger. It just knocks on the Spoke's door and walks away.
apiRouter.post('/vault/admin/bitrot/scan', permitGlobalRole('admin'), async (req, res) => {
    try {
        // Tell the Spoke to start its background job
        const spokeResponse = await spokeFetch(`/internal/maintenance/bitrot/scan`, { 
            method: 'POST' 
        });

        if (!spokeResponse.ok) throw new Error("Spoke rejected the command.");

        // We don't wait for the scan. We immediately tell React it started.
        res.json({ 
            message: "Scan initiated on the Spoke. Results will appear in the Audit Logs once the Spoke finishes." 
        });
    } catch (err) {
        console.error("Trigger Error:", err.message);
        res.status(500).json({ error: "Failed to wake up the Spoke for maintenance." });
    }
});
// const internalOnly = ['/spoke-status', '/spoke-logs'];

// app.all(/^(\/.*)/, bouncer, (req, res, next) => {
//     if (internalOnly.includes(req.path)) {
//         return proxy.web(req, res, { target: `http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}` });
//     }
//     // If it's not internal and didn't match the routes above, it's a 404.
//     res.status(404).json({ error: "Endpoint not found" });
// });
app.use('/api/v1', apiRouter);
app.use((req, res) => {
    console.warn(`[SECURITY] Blocked unauthorized path: ${req.path}`);

    // Log the attempted intrusion
    const log = db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)');
    log.run(req.auth?.payload?.sub || 'unknown', `UNAUTHORIZED_ACCESS: ${req.path}`, 'BLOCKED');

    res.status(403).json({
        error: "Access Denied",
        message: "This endpoint is not exposed via the Secure Gateway."
    });
});
app.use((err, req, res, next) => {
    if (err.name === 'UnauthorizedError') {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        console.warn(`[SECURITY] Failed Auth attempt on ${req.path} from IP: ${ip}`);

        try {
            db.prepare('INSERT INTO audit_logs (user_email, action, status, ip_address) VALUES (?, ?, ?, ?)')
                .run('unauthenticated_user', `BLOCKED_AUTH: ${req.path}`, 'FAILED', ip);
        } catch (dbErr) {
            console.error("Failed to write to audit log:", dbErr.message);
        }

        // Return a clean JSON response instead of the ugly HTML stack trace
        return res.status(401).json({
            error: "Unauthorized",
            message: "Missing, expired, or invalid authentication token."
        });
    }

    // 2. Catch all other unhandled server errors
    console.error("[SERVER ERROR]", err);
    res.status(500).json({ error: "Internal Gateway Error" });
});


https.createServer(sslOptions, app).listen(PUBLIC_PORT, '0.0.0.0', () => {
    console.log('--- Zero Trust Architecture Active ---');
    console.log(`Public Entry: https://richardgatewayta.duckdns.org:${PUBLIC_PORT}`);
    console.log(`Internal Destination: ${LOCAL_SPOKE_IP}:${LOCAL_PORT}`);
    console.log('--------------------------------------');
});
