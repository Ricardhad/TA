dotenv.config();
import https from 'https';
import fs from 'fs';
import express from 'express';
import httpProxy from 'http-proxy';
import dotenv from 'dotenv';
import { auth } from 'express-oauth2-jwt-bearer';
import cors from 'cors';
import db from './db.js';
import axios from 'axios';
// import FormData from 'form-data';
import { randomUUID } from 'crypto';
import crypto from 'crypto';
import helmet from 'helmet';
import Busboy from 'busboy';
import mime from 'mime-types';

const app = express();
const PUBLIC_PORT = 8080;
// const proxy = httpProxy.createProxyServer({});

const LOCAL_SPOKE_IP = process.env.SPOKE_IP;
const LOCAL_PORT = process.env.GATEWAY_PORT;
const namespace = process.env.NAMESPACE || 'unknown_namespace';

app.use(helmet());

const bouncer = auth({
    audience: namespace,
    issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}/`,
    tokenSigningAlg: 'RS256'
})

app.get('/vault/view/:uuid', async (req, res) => {
    const { uuid } = req.params;
    const { expires, sig } = req.query;

    try {
        // 1. Verify Expiration
        if (Math.floor(Date.now() / 1000) > parseInt(expires)) {
            return res.status(403).send("This link has expired.");
        }

        // 2. Re-calculate Signature to verify integrity
        const secret = process.env.URL_SIGNING_SECRET;
        const expectedSig = crypto
            .createHmac('sha256', secret)
            .update(`${uuid}:${expires}`)
            .digest('hex');

        if (sig !== expectedSig) {
            return res.status(403).send("Invalid signature. Link may have been tampered with.");
        }

        // 3. Get the physical path (No owner check needed here, the Sig proves it's valid)
        const fileMeta = db.prepare(`
            SELECT f.filename, v.physical_path 
            FROM files f JOIN versions v ON f.id = v.file_id 
            WHERE f.uuid = ? ORDER BY v.version_num DESC LIMIT 1
        `).get(uuid);

        if (!fileMeta) return res.status(404).send("File no longer exists.");

        // 4. Stream from Surabaya
        const spokeResponse = await axios({
            method: 'get',
            url: `http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}/internal/raw/${fileMeta.physical_path}`,
            responseType: 'stream'
        });

        res.setHeader('Content-Disposition', `inline; filename="${fileMeta.filename}"`);
        spokeResponse.data.pipe(res);

    } catch (err) {
        console.error("[VIEW ERROR]", err.message);
        res.status(500).send("Secure viewing failed.");
    }
});

app.use(bouncer);

app.use(cors({
    origin: 'http://localhost:5173', // Allow your React app
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

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



app.get('/vault/metadata', bouncer, (req, res) => {
    const userId = req.auth.payload.sub; // Get the Auth0 ID

    try {
        const query = db.prepare(`
            SELECT f.uuid, f.filename, v.version_num, v.timestamp, v.size, f.mime_type
            FROM files f
            JOIN versions v ON f.id = v.file_id
            WHERE f.owner_id = ?
            AND v.id IN (SELECT MAX(id) FROM versions GROUP BY file_id)
        `);

        const files = query.all(userId);
        res.json(files);
    } catch (err) {
        console.error("SQL Error:", err);
        res.status(500).json({ error: "Database query failed" });
    }
});
// app.get('/vault/test', bouncer, (req, res) => {
//     const namespace = 'https://richardgatewayta.duckdns.org';
//     const userEmail = req.auth?.payload[`${namespace}/email`] || 'anonymous';
//     try {
//         res.json({ message: "Test successful", user: userEmail });
//     } catch (err) {
//         console.error("SQL Error:", err);
//         res.status(500).json({ error: "Database query failed" });
//     }
// });

const sslOptions = {
    key: fs.readFileSync('/etc/letsencrypt/live/richardgatewayta.duckdns.org/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/richardgatewayta.duckdns.org/fullchain.pem')
};


app.post('/vault/upload', bouncer, (req, res) => {
    const contentType = req.headers['content-type'];

    if (!contentType || !contentType.includes('multipart/form-data')) {
        console.error(`[GATEWAY] Blocked request with invalid Content-Type: ${contentType}`);
        return res.status(400).json({
            error: "Invalid Request",
            details: "Content-Type must be multipart/form-data"
        });
    }

    const busboy = Busboy({ headers: req.headers });
    const userId = req.auth.payload.sub;

    // We use a flag to ensure we only send one response
    let isProcessing = false;

    busboy.on('file', async (name, file, info) => {
        if (isProcessing) return; // Only handle one file per request
        isProcessing = true;

        const { filename, mimeType: headerMime } = info;
        const extensionMime = mime.lookup(filename);
        const dangerousExtensions = ['.exe', '.sh', '.bat', '.php', '.js', '.msi'];
        const isExecutableExt = dangerousExtensions.some(ext => filename.toLowerCase().endsWith(ext));
        const isSpoofed = isExecutableExt && (headerMime.startsWith('image/') || headerMime.startsWith('text/'));

        if (isSpoofed) {
            console.error(`[SECURITY REJECTION] Spoof detected: ${filename} claimed to be ${headerMime}`);

            // CRITICAL: You must consume the stream before sending the error
            file.resume();
            return res.status(403).json({
                error: "Security Policy Violation",
                details: "File extension and content-type mismatch detected."
            });
        }

        // 3. PROCEED IF SAFE
        const finalMime = (headerMime === 'application/octet-stream') ? (extensionMime || headerMime) : headerMime;

        try {
            console.log(`[GATEWAY] Ingesting: ${filename} (${finalMime}) from user ${userId}`);

            // 1. FORWARD THE STREAM TO SURABAYA
            // We send the 'file' stream from Busboy, NOT the 'req' object
            const spokeResponse = await axios({
                method: 'post',
                url: `http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}/receive-file`,
                data: file,
                headers: {
                    ...file.headers, // Keep stream headers if any
                    'x-original-name': filename
                },
                maxContentLength: Infinity,
                maxBodyLength: Infinity,
                decompress: false
            });

            const { physical_path, size } = spokeResponse.data;

            // 2. SQL LOGIC: Find or Create the File Entry
            // We include mime_type here!
            let fileRecord = db.prepare('SELECT id, uuid FROM files WHERE filename = ? AND owner_id = ?')
                .get(filename, userId);

            if (!fileRecord) {
                const uuid = randomUUID();
                const info = db.prepare('INSERT INTO files (uuid, filename, owner_id, mime_type) VALUES (?, ?, ?, ?)')
                    .run(uuid, filename, userId, finalMime);
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
                    await axios.delete(`http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}/vault/delete/${oldest.physical_path}`);
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
            db.prepare("INSERT INTO versions (file_id, version_num, physical_path, size, timestamp) VALUES (?, ?, ?, ?, datetime('now'))")
                .run(fileRecord.id, newVersion, physical_path, size);

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

app.get('/vault/history/:uuid', bouncer, (req, res) => {
    const userId = req.auth.payload.sub;
    const fileUuid = req.params.uuid;

    try {
        const query = db.prepare(`
            SELECT v.version_num, v.timestamp, v.size, v.physical_path
            FROM versions v
            JOIN files f ON f.id = v.file_id
            WHERE f.uuid = ? AND f.owner_id = ?
            ORDER BY v.version_num DESC
        `);

        const history = query.all(fileUuid, userId);
        res.json(history);
    } catch (err) {
        res.status(500).json({ error: "Failed to retrieve history" });
    }
});

app.get('/vault/audit', bouncer, (req, res) => {
    // Thesis Note: In a real app, you'd check if (req.auth.payload.role === 'admin')
    // For now, we'll let the authenticated user see the system logs.

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
app.get('/vault/download/:uuid', bouncer, async (req, res) => {
    const userId = req.auth.payload.sub;
    const fileUuid = req.params.uuid;
    const requestedVersion = req.query.v;

    try {
        let fileMeta;

        if (requestedVersion) {
            // A. Specific Version Request
            console.log(`[GATEWAY] Requesting Version ${requestedVersion} of ${fileUuid}`);
            fileMeta = db.prepare(`
                SELECT f.filename, v.physical_path, v.version_num
                FROM files f
                JOIN versions v ON f.id = v.file_id
                WHERE f.uuid = ? AND f.owner_id = ? AND v.version_num = ?
            `).get(fileUuid, userId, requestedVersion);
        } else {
            // B. Default: Get Latest Version
            fileMeta = db.prepare(`
                SELECT f.filename, v.physical_path, v.version_num
                FROM files f
                JOIN versions v ON f.id = v.file_id
                WHERE f.uuid = ? AND f.owner_id = ?
                ORDER BY v.version_num DESC LIMIT 1
            `).get(fileUuid, userId);
        }

        if (!fileMeta) {
            return res.status(404).json({ error: "Version not found or access denied." });
        }

        // 2. Stream from Surabaya (Same as before)
        const spokeResponse = await axios({
            method: 'get',
            url: `http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}/internal/raw/${fileMeta.physical_path}`,
            responseType: 'stream'
        });

        // 3. Set Headers (Include version in the filename for a better UX!)
        // Example: my_thesis_v3.pdf
        const downloadName = fileMeta.filename.includes('.')
            ? fileMeta.filename.replace(/(\.[^.]+)$/, `_v${fileMeta.version_num}$1`)
            : `${fileMeta.filename}_v${fileMeta.version_num}`;

        res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);
        res.setHeader('Content-Type', 'application/octet-stream');

        // 4. PIPE IT OUT
        spokeResponse.data.pipe(res);
        const log = db.prepare('INSERT INTO audit_logs (user_email, action, status) VALUES (?, ?, ?)');
        log.run(userId, `DOWNLOAD ${fileMeta.filename} (v${fileMeta.version_num})`, 'SUCCESS');

    } catch (err) {
        console.error("[GATEWAY] Download Failed:", err.message);
        res.status(500).json({ error: "Secure Tunnel Interrupted" });
    }
});

app.get('/vault/share/:uuid', bouncer, (req, res) => {
    const userId = req.auth.payload.sub;
    const fileUuid = req.params.uuid;
    const ttl = parseInt(req.query.ttl) || 60; // Default 60 minutes

    try {
        // 1. Verify ownership
        const file = db.prepare('SELECT filename FROM files WHERE uuid = ? AND owner_id = ?')
            .get(fileUuid, userId);
        if (!file) return res.status(404).json({ error: "File not found" });

        // 2. Create Expiry (Current time + TTL minutes)
        const expires = Math.floor(Date.now() / 1000) + (ttl * 60);

        // 3. Generate HMAC Signature
        const secret = process.env.URL_SIGNING_SECRET;
        const signature = crypto
            .createHmac('sha256', secret)
            .update(`${fileUuid}:${expires}`)
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

// const internalOnly = ['/spoke-status', '/spoke-logs'];

// app.all(/^(\/.*)/, bouncer, (req, res, next) => {
//     if (internalOnly.includes(req.path)) {
//         return proxy.web(req, res, { target: `http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}` });
//     }
//     // If it's not internal and didn't match the routes above, it's a 404.
//     res.status(404).json({ error: "Endpoint not found" });
// });

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

https.createServer(sslOptions, app).listen(PUBLIC_PORT, '0.0.0.0', () => {
    console.log('--- Zero Trust Architecture Active ---');
    console.log(`Public Entry: https://richardgatewayta.duckdns.org:${PUBLIC_PORT}`);
    console.log(`Internal Destination: ${LOCAL_SPOKE_IP}:${LOCAL_PORT}`);
    console.log('--------------------------------------');
});
