
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import { promises as fsp } from 'fs';
import { Readable } from 'stream';
import path, { dirname } from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { auth } from 'express-oauth2-jwt-bearer';

dotenv.config();

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

    // Gunakan token lama jika belum kedaluwarsa agar tidak membebani limit Auth0
    if (cachedGatewayToken && now < gatewayTokenExpiry) {
        return cachedGatewayToken;
    }

    console.log("[AUTH] Fetching fresh M2M token from Auth0 to contact Gateway...");

    // Spoke meminta token ke Auth0
    const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
            client_id: process.env.M2M_CLIENT_ID,
            client_secret: process.env.M2M_CLIENT_SECRET,
            audience: process.env.AUTH0_AUDIENCE, // Sesuai dengan API Gateway Anda
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

const calculateFileHash = (filePath) => {
    return new Promise((resolve, reject) => {
        // Kita menghitung hash dari raw file di disk (sudah terenkripsi + IV + Tag)
        // karena itu adalah data fisik yang rentan mengalami bit rot.
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(filePath);

        stream.on('data', (chunk) => hash.update(chunk));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', (err) => reject(err));
    });
};

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

// ==========================================
// 1. RUTE UNGGAH DAN ENKRIPSI + HASING
// ==========================================
app.post('/internal/files', (req, res) => {
    const originalName = req.headers['x-original-name'] || 'uploaded-file';
    const safeName = `${Date.now()}-${originalName.replace(/\s+/g, '_')}.enc`;
    const vaultPath = path.join(STORAGE_DIR, safeName);

    console.log(`[SPOKE] Receiving stream: ${originalName}`);

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
    const writeStream = fs.createWriteStream(vaultPath);

    writeStream.write(iv);

    // KITA AKAN MENGHITUNG HASH DARI DATA FISIK YANG TERSIMPAN DI DISK
    // Ini berarti hash mencakup IV + Ciphertext + Tag
    const hash = crypto.createHash('sha256');
    let rawFileSize = 0; // Ukuran sebelum enkripsi (sebagai informasi)

    req.on('data', (chunk) => {
        rawFileSize += chunk.length;
    });

    // Pipa 1: Enkripsi aliran data
    req.pipe(cipher);

    // Pipa 2: Menulis hasil enkripsi ke file
    cipher.on('data', (chunk) => {
        writeStream.write(chunk);
    });

    cipher.on('end', () => {
        const authTag = cipher.getAuthTag();
        writeStream.write(authTag); // Tulis tag di akhir
        writeStream.end(); // Tutup aliran penulisan
    });

    // Pipa 3: Setelah file selesai ditulis, hitung hash-nya
    writeStream.on('finish', async () => {
        try {
            // Setelah file utuh di disk, hitung hash SHA-256-nya
            const finalChecksum = await calculateFileHash(vaultPath);
            const stats = fs.statSync(vaultPath);

            console.log(`[SPOKE] Saved: ${safeName} | Physical Size: ${stats.size} | Hash: ${finalChecksum}`);

            res.status(200).json({
                status: "Success",
                physical_path: safeName,
                size: stats.size, // Menggunakan ukuran fisik file di disk
                checksum: finalChecksum
            });
        } catch (hashErr) {
            console.error("Hashing Error:", hashErr);
            res.status(500).send("Hashing Failure");
        }
    });

    writeStream.on('error', (err) => {
        console.error("Stream Error:", err);
        res.status(500).send("Storage Failure");
    });
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

    // 🆕 FIX: Menggunakan STORAGE_DIR bukan 'vault_data'
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

        // Untuk menembak ke Gateway, kita membutuhkan akses token M2M dari Spoke
        // Anda perlu mereplikasi logika getSpokeToken() di sini jika Gateway mewajibkan autentikasi
        // Asumsi sementara rute Gateway ini dilindungi JWT.

        // --- CONTOH PEMANGGILAN FETCH (Sesuaikan URL) ---
        const GATEWAY_URL = 'https://richardgatewayta.duckdns.org:8080';
        const token = await getGatewayToken();
        const gatewayResponse = await fetch(`${GATEWAY_URL}/api/v1/vault/admin/bitrot/report`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(reportPayload)
        });
        if (!gatewayResponse.ok) {
            throw new Error(`Gateway rejected the report with status: ${gatewayResponse.status}`);
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

// ==========================================
// 4. ALAT PENGUJIAN STRESS
// ==========================================
app.post('/internal/files/test/upload', (req, res) => {
    let bytesReceived = 0;
    req.on('data', (chunk) => bytesReceived += chunk.length);
    req.on('end', () => {
        console.log(`[STRESS TEST] Received and discarded: ${(bytesReceived / 1024 / 1024 / 1024).toFixed(2)} GB`);
        res.json({ status: "Discarded", size_gb: bytesReceived / 1024 / 1024 / 1024 });
    });
    req.on('error', (err) => res.status(500).send("Stream broken"));
});

app.listen(PORT, SPOKE_IP, () => {
    console.log(`Surabaya Spoke Active on port ${PORT} at IP ${SPOKE_IP}`);
});

