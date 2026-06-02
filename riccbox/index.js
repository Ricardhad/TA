
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import { promises as fsp } from 'fs';
import { Readable } from 'stream';
import path, { dirname } from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { auth } from 'express-oauth2-jwt-bearer';
import { spawn } from 'child_process';
import { pipeline } from 'stream/promises';
import ffmpegInstaller from '@ffmpeg-installer/ffmpeg';

dotenv.config();

function createVideoSanitizerProcess() {
    const ffmpeg = spawn(ffmpegInstaller.path, [
        '-hide_banner',
        '-loglevel', 'error',

        // 🚨 CONFIGURASI KESABARAN MAKSIMAL
        '-probesize', '500M',
        '-analyzeduration', '500M',

        // Memaksa FFmpeg jangan error kalau ada data sampah/tidak lengkap
        '-err_detect', 'ignore_err',
        '-fflags', '+genpts+discardcorrupt+igndts',

        // Input tanpa format paksaan agar dia auto-detect
        '-i', 'pipe:0',

        '-map_metadata', '-1',
        '-c:v', 'libx264',
        '-preset', 'ultrafast',
        '-tune', 'zerolatency',
        '-c:a', 'aac',

        // Output tetap mp4, tapi dengan flag agar metadata di awal
        '-f', 'mp4',
        '-movflags', 'frag_keyframe+empty_moov+faststart',
        'pipe:1'
    ]);

    // 🚨 WAJIB: Tangkap error agar tidak mati diam-diam
    ffmpeg.stderr.on('data', (data) => {
        console.error(`[FFMPEG ERROR]: ${data.toString()}`);
    });

    ffmpeg.on('error', (err) => {
        console.error(`[FFMPEG FATAL]: ${err.message}`);
    });

    return ffmpeg;
}
const calculateFileHash = (filePath) => {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256');
        const input = fs.createReadStream(filePath);
        input.on('data', (data) => hash.update(data));
        input.on('end', () => resolve(hash.digest('hex')));
        input.on('error', reject);
    });
};

const app = express();
const PORT = 3000;
const SPOKE_IP = process.env.SPOKE_IP || '0.0.0.0';

app.use(express.urlencoded({
    limit: '1mb',
    extended: true
}));

const MASTER_KEY = Buffer.from(process.env.VAULT_KEY, 'hex');

if (MASTER_KEY.length !== 32) {
    throw new Error("VAULT_KEY must be a 64-character hex string (32 bytes)");
}
// --- MANAJEMEN TOKEN M2M UNTUK SPOKE -> GATEWAY ---
let cachedGatewayToken = null;
let gatewayTokenExpiry = 0;

async function getGatewayToken() {
    const now = Math.floor(Date.now() / 1000);

    if (cachedGatewayToken && now < gatewayTokenExpiry) {
        return cachedGatewayToken;
    }

    console.log("[AUTH] Fetching fresh M2M token from Auth0 to contact Gateway...");

    const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
            client_id: process.env.M2M_CLIENT_ID,
            client_secret: process.env.M2M_CLIENT_SECRET,
            audience: process.env.AUTH0_AUDIENCE, 
            grant_type: 'client_credentials'
        })
    });

    const data = await response.json();

    if (!data.access_token) {
        throw new Error(`Auth0 denied Spoke token request: ${data.error_description || data.error}`);
    }

    cachedGatewayToken = data.access_token;
    gatewayTokenExpiry = now + data.expires_in - 60; // Cadangan waktu 1 menit
    return cachedGatewayToken;
}

const checkHubIdentity = auth({
    audience: process.env.AUTH0_AUDIENCE,
    issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}/`,
    tokenSigningAlg: 'RS256'
});

const vpnOnly = (req, res, next) => {
    const incomingIp = req.ip || req.connection.remoteAddress;
    if (process.env.NODE_ENV === 'production' && !incomingIp.includes(process.env.HUB_VPN_IP)) {
        console.warn(`[SECURITY] Blocked unauthorized access attempt from: ${incomingIp}`);
        return res.status(403).json({ error: "Network Isolation Policy Violation" });
    }
    next();
};

// const calculateFileHash = (filePath) => {
//     return new Promise((resolve, reject) => {
//         // Kita menghitung hash dari raw file di disk (sudah terenkripsi + IV + Tag)
//         // karena itu adalah data fisik yang rentan mengalami bit rot.
//         const hash = crypto.createHash('sha256');
//         const stream = fs.createReadStream(filePath);

//         stream.on('data', (chunk) => hash.update(chunk));
//         stream.on('end', () => resolve(hash.digest('hex')));
//         stream.on('error', (err) => reject(err));
//     });
// };

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const STORAGE_DIR = path.join(__dirname, 'vault_storage'); // Pastikan direktori ini konsisten digunakan

// Membuat folder jika belum ada
if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR);
}

app.use('/internal', checkHubIdentity);
app.use(vpnOnly);

app.use((err, req, res, next) => {
    if (err.name === 'UnauthorizedError') {
        console.error("[SECURITY] Token Rejected:", err.message);
        return res.status(401).json({ error: "Invalid Token", detail: err.message });
    }
    next(err);
});

app.post('/internal/files', async (req, res) => {
    const originalName = req.headers['x-original-name'] || 'uploaded-file';
    const isVideo = ['.mp4', '.mov', '.webm'].some(ext => originalName.toLowerCase().endsWith(ext));

    // 1. Tentukan path file sementara untuk proses sanitasi
    const tempFilePath = path.join(STORAGE_DIR, `temp-${Date.now()}.tmp`);
    const safeName = `${Date.now()}-${originalName.replace(/\s+/g, '_')}.enc`;
    const vaultPath = path.join(STORAGE_DIR, safeName);

    try {
        // 2. Buffer file ke disk dulu sampai selesai (Ini menjamin FFmpeg punya data utuh)
        await pipeline(req, fs.createWriteStream(tempFilePath));
        console.log("[SPOKE] Upload selesai, memulai sanitasi...");

        // 3. Konfigurasi Cipher
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
        const writeStream = fs.createWriteStream(vaultPath);
        
        // let encrypted = cipher.update(MASTER_KEY, 'utf8', 'hex');
        // encrypted += cipher.final('hex');
        writeStream.write(iv);
        // writeStream.write(encrypted, 'hex');
        if (isVideo) {
            // Jalankan FFmpeg membaca dari file .tmp
            const sanitizer = spawn(ffmpegInstaller.path, [
                '-hide_banner', '-loglevel', 'error',
                '-i', tempFilePath, // Baca dari file temp yang sudah utuh
                '-map_metadata', '-1',
                '-c:v', 'libx264', '-preset', 'ultrafast', '-tune', 'zerolatency',
                '-c:a', 'aac',
                '-f', 'mp4',
                '-movflags', '+faststart',
                'pipe:1'
            ]);

            await pipeline(sanitizer.stdout, cipher, writeStream);
        } else {
            await pipeline(fs.createReadStream(tempFilePath), cipher, writeStream);
        }

        // Finalisasi
        const authTag = cipher.getAuthTag();
        fs.appendFileSync(vaultPath, authTag);

        // 4. Cleanup
        if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);

        const finalChecksum = await calculateFileHash(vaultPath);
        const stats = fs.statSync(vaultPath);

        res.status(200).json({ status: "Success", physical_path: safeName, size: stats.size, checksum: finalChecksum });

    } catch (err) {
        console.error(`[SPOKE ERROR]: ${err.message}`);
        if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
        if (fs.existsSync(vaultPath)) fs.unlinkSync(vaultPath);
        if (!res.headersSent) res.status(500).json({ error: "Processing Failed" });
    }
});

// ==========================================
// 2. RUTE PERAWATAN DAN BIT ROT
// ==========================================
app.use(express.json({
    limit: '1mb',
    strict: true
}));

app.get('/internal/health', (req, res) => {
    res.json({
        status: "ONLINE",
        timestamp: new Date().toISOString(),
        storage: { free: "450GB", total: "1TB" }
    });
});

app.get('/internal/inventory', async (req, res) => {
    try {
        const files = await fsp.readdir(STORAGE_DIR);
        const physicalFiles = files.filter(f => !f.startsWith('.'));
        res.json(physicalFiles);
    } catch (err) {
        console.error("[SPOKE ERROR] Disk scan failed:", err.message);
        res.status(500).json({ error: "Could not read storage directory." });
    }
});

app.delete('/internal/files/:filename', async (req, res) => {
    const safeName = path.basename(req.params.filename);
    const filePath = path.join(STORAGE_DIR, safeName);
    try {
        await fsp.access(filePath);
        await fsp.unlink(filePath);
        console.log(`[SPOKE] Purged: ${safeName}`);
        res.json({ status: "Deleted" });
    } catch (err) {
        res.status(404).json({ error: "File not found" });
    }
});

app.post('/internal/maintenance/purge', async (req, res) => {
    const { files } = req.body;
    if (!Array.isArray(files)) return res.status(400).send("Invalid list.");
    const results = { success: 0, failed: 0 };
    await Promise.all(files.map(async (filename) => {
        try {
            const safeName = path.basename(filename);
            await fsp.unlink(path.join(STORAGE_DIR, safeName));
            results.success++;
        } catch (err) {
            results.failed++;
        }
    }));
    console.log(`[MAINTENANCE] Bulk Purge Complete: ${results.success} removed.`);
    res.json(results);
});

// AGEN PEMINDAI BIT ROT
app.post('/internal/maintenance/bitrot/scan', async (req, res) => {
    res.json({ status: "Bit Rot scan initiated in the background." });
    console.log(`[MAINTENANCE] Starting Bit Rot Scan on ${STORAGE_DIR}...`);

    try {
        const files = fs.readdirSync(STORAGE_DIR);
        const reportPayload = [];

        for (const file of files) {
            const filePath = path.join(STORAGE_DIR, file);
            const stat = fs.statSync(filePath);

            // Hanya pindai file enkripsi (abaikan folder tersembunyi atau file .keep)
            if (stat.isFile() && file.endsWith('.enc')) {
                const currentHash = await calculateFileHash(filePath);
                reportPayload.push({
                    path: file,
                    hash: currentHash
                });
            }
        }

        console.log(`[MAINTENANCE] Scan complete. Audited ${reportPayload.length} files. Sending to Gateway...`);

        
        const GATEWAY_URL = 'https://richardgatewayta.duckdns.org:8080';
        const token = await getGatewayToken();
        // console.log(token);
        const gatewayResponse = await fetch(`${GATEWAY_URL}/api/v1/vault/admin/bitrot/report`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(reportPayload)
        });
        if (!gatewayResponse.ok) {
            throw new Error(`Gateway rejected the report with status: ${gatewayResponse.status}, detail: ${await gatewayResponse.text()}`);

        }

        console.log("[MAINTENANCE] Report successfully delivered to Gateway.");
    } catch (err) {
        console.error("[MAINTENANCE ERROR] Bit Rot Scan Failed:", err);
    }
});

// ==========================================
// 3. RUTE PENGUNDUHAN DEKRIPSI
// ==========================================
app.get('/internal/files/:filename', (req, res) => {
    const filename = path.basename(req.params.filename);
    const filePath = path.join(STORAGE_DIR, filename);

    if (!fs.existsSync(filePath)) return res.status(404).send("File not found");

    try {
        const stats = fs.statSync(filePath);
        const fd = fs.openSync(filePath, 'r');

        const iv = Buffer.alloc(12);
        fs.readSync(fd, iv, 0, 12, 0);

        const tag = Buffer.alloc(16);
        fs.readSync(fd, tag, 0, 16, stats.size - 16);
        fs.closeSync(fd);

        const finalDecipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, iv);
        finalDecipher.setAuthTag(tag);

        const readStream = fs.createReadStream(filePath, { start: 12, end: stats.size - 17 });

        console.log(`[SPOKE] Decrypting stream: ${filename}`);
        readStream.pipe(finalDecipher).pipe(res);

    } catch (err) {
        console.error("DECRYPTION ERROR:", err.message);
        res.status(500).send("Security Integrity Check Failed.");
    }
});

app.post('/internal/files/copy', async (req, res) => {
    const { source_path } = req.body;

    // Validasi sederhana agar tidak kena Path Traversal
    const safeSource = path.basename(source_path);
    const sourcePathFull = path.join(STORAGE_DIR, safeSource);

    // Buat nama fail fisik yang sepenuhnya baru
    const newSafeName = `${Date.now()}-restored-${crypto.randomUUID()}.enc`;
    const destPathFull = path.join(STORAGE_DIR, newSafeName);

    try {
        // Gandakan fail secara fisik di dalam disk lokal Surabaya
        await fsp.copyFile(sourcePathFull, destPathFull);

        // Dapatkan metadatanya untuk dikembalikan ke Jakarta
        const stats = await fsp.stat(destPathFull);
        const checksum = await calculateFileHash(destPathFull);

        console.log(`[SPOKE] Successfully cloned ${safeSource} -> ${newSafeName}`);

        res.json({
            new_physical_path: newSafeName,
            size: stats.size,
            checksum: checksum
        });
    } catch (err) {
        console.error("Spoke Copy Error:", err);
        res.status(500).json({ error: "Failed to duplicate file physically on Spoke." });
    }
});


app.post('/internal/files/test/upload', (req, res) => {
    let receivedBytes = 0;

    req.on('data', (chunk) => {
        receivedBytes += chunk.length;
    });

    req.on('end', () => {
        const sizeGb = (receivedBytes / (1024 * 1024 * 1024)).toFixed(3);
        console.log(`[BENCHMARK] Sukses menerima ${sizeGb} GB!`);
        res.json({ size_gb: sizeGb, note: "Pure Stream Test Successful" });
        req.destroy();
    });

    req.on('error', (err) => {
        if (err.code === 'ECONNRESET' || err.message === 'aborted') {
            console.warn("[BENCHMARK SAFE-CATCH] Pipa diputus secara sepihak oleh Gateway. (Status: Aman, RAM otomatis dibersihkan oleh Garbage Collector).");
        } else {
            // Jika putusnya karena hal aneh lainnya
            console.error("[BENCHMARK ERROR] Aliran terputus karena galat:", err);
        }

        try {
            if (!res.headersSent) {
                res.status(500).json({ error: "Stream interrupted at Spoke" });
            }
        } catch (resErr) {
            // Abaikan jika memang socketnya sudah benar-benar mati
        }
    });
});

const server = app.listen(PORT, SPOKE_IP, () => {
    console.log(`Surabaya Spoke Active on port ${PORT} at IP ${SPOKE_IP}`);
    console.log(`[SPOKE START] Server running on PID: ${process.pid}`);
});
// const server = app.listen(PORT,'0.0.0.0', () => {
//     console.log(`Surabaya Spoke Active on port ${PORT} at IP ${SPOKE_IP}`);UTC Arrival Time: May 23, 2026 14:30:39.757472600 UTC

// });

const SERVER_TIMEOUT = 30 * 60 * 1000;
server.setTimeout(SERVER_TIMEOUT);
server.keepAliveTimeout = SERVER_TIMEOUT;
server.headersTimeout = SERVER_TIMEOUT + 1000;
