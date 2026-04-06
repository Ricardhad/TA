// const multer = require('multer');
// const { get } = require('http');
// const { randomUUID } = require ('crypto');
// import fs from 'fs/promises';
// const newUuid = randomUUID();

// const express = require('express');
// const path = require('path');
// const fs = require('fs/promises');
// const crypto = require('crypto');
// const { Readable } =require ('stream');
// require('dotenv').config();
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
const SPOKE_IP= process.env.SPOKE_IP 

// 2. For standard form data (if you ever use it)
app.use(express.urlencoded({ 
    limit: '1mb', 
    extended: true 
}));
// CONFIG: Ensure VAULT_KEY in .env is exactly 32 characters
// const MASTER_KEY = process.env.VAULT_KEY; 
// const ALGORITHM = 'aes-256-gcm';
// const IV_LENGTH = 12;
// const TAG_LENGTH = 16;
const MASTER_KEY = Buffer.from(process.env.VAULT_KEY, 'hex');

// Check to make sure it's correct
if (MASTER_KEY.length !== 32) {
    throw new Error("VAULT_KEY must be a 64-character hex string (32 bytes)");
}
const checkHubIdentity = auth({
    audience: process.env.AUTH0_AUDIENCE, // https://richardgatewayta.duckdns.org
    issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}/`,
    tokenSigningAlg: 'RS256'
});

// 2. IP FILTER: A secondary check to ensure traffic is coming over the VPN (172.x)
const vpnOnly = (req, res, next) => {
    const incomingIp = req.ip || req.connection.remoteAddress;
    if (process.env.NODE_ENV === 'production' && !incomingIp.includes(process.env.HUB_VPN_IP)) {
        console.warn(`[SECURITY] Blocked unauthorized access attempt from: ${incomingIp}`);
        return res.status(403).json({ error: "Network Isolation Policy Violation" });
    }
    next();
};

// const STORAGE_DIR = path.join(__dirname, 'vault_storage');
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const STORAGE_DIR = path.join(__dirname, 'vault_storage');
app.use('/internal',checkHubIdentity); // 1. Authenticate the Hub's JWT
app.use(vpnOnly); // 2. Ensure it's coming from the VPN IP
// 1. STORAGE: Use MemoryStorage so the raw file never touches your disk
// const upload = multer({ storage: multer.memoryStorage() });
app.use((err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    console.error("[SECURITY] Token Rejected:", err.message); // This will tell us why!
    return res.status(401).json({ error: "Invalid Token", detail: err.message });
  }
  next(err);
});

app.post('/internal/files', (req, res) => {
    // If headers are missing, we use a fallback
    const originalName = req.headers['x-original-name'] || 'uploaded-file';
    const safeName = `${Date.now()}-${originalName.replace(/\s+/g, '_')}.enc`;
    const vaultPath = path.join(__dirname, 'vault_storage', safeName);

    console.log(`[SPOKE] Receiving stream: ${originalName}`);

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
    const writeStream = fs.createWriteStream(vaultPath);

    // Write IV at the start of the file
    writeStream.write(iv);

    // PIPE: User -> Cipher -> Disk
    req.pipe(cipher).pipe(writeStream);

    writeStream.on('finish', () => {
        const authTag = cipher.getAuthTag();
        fs.appendFileSync(vaultPath, authTag); // Append Tag at the end
        
        const stats = fs.statSync(vaultPath);
        res.status(200).json({
            status: "Success",
            physical_path: safeName,
            size: stats.size
        });
    });

    writeStream.on('error', (err) => {
        console.error("Stream Error:", err);
        res.status(500).send("Storage Failure");
    });
});
// Surabaya index.js
app.post('/internal/test/test-upload', (req, res) => {
    let bytesReceived = 0;

    req.on('data', (chunk) => {
        bytesReceived += chunk.length;
    });

    req.on('end', () => {
        console.log(`[STRESS TEST] Received and discarded: ${(bytesReceived / 1024 / 1024 / 1024).toFixed(2)} GB`);
        res.json({ status: "Discarded", size_gb: bytesReceived / 1024 / 1024 / 1024 });
    });

    req.on('error', (err) => {
        console.error("Test stream failed:", err.message);
        res.status(500).send("Stream broken");
    });
});

app.get('/internal/test/test-download', (req, res) => {
    const totalSize = 10 * 1024 * 1024 * 1024; // 10 GB
    let sent = 0;

    const dummyStream = new Readable({
        read(size) {
            const remaining = totalSize - sent;
            if (remaining <= 0) {
                this.push(null); // End of stream
            } else {
                const chunkSize = Math.min(size, remaining);
                this.push(Buffer.alloc(chunkSize, 0)); // Send actual zeros
                sent += chunkSize;
            }
        }
    });

    res.setHeader('Content-Length', totalSize);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="10GB_dummy.dat"');

    console.log(`[STRESS TEST] Starting 10GB generator...`);
    dummyStream.pipe(res);
});

// Surabaya index.js
app.use(express.json({ 
    limit: '1mb', 
    strict: true 
}));
app.get('/internal/health', (req, res) => {
    res.json({
        status: "ONLINE",
        timestamp: new Date().toISOString(),
        storage: {
            free: "450GB",
            total: "1TB"
        }
    });
});
app.get('/internal/inventory', async (req, res) => {

    try {
        const files = await fsp.readdir(STORAGE_DIR);
        
        // Filter out hidden files like .gitignore if necessary
        const physicalFiles = files.filter(f => !f.startsWith('.'));
        
        console.log(`[MAINTENANCE] Reporting ${physicalFiles.length} files to Jakarta Hub.`);
        res.json(physicalFiles);
    } catch (err) {
        console.error("[SPOKE ERROR] Disk scan failed:", err.message);
        res.status(500).json({ error: "Could not read storage directory." });
    }
});


// index.js (Surabaya Spoke)
// 1. SINGLE DELETE (Improved)
app.delete('/internal/files/:filename', async (req, res) => {
    // Sanitize to prevent Path Traversal
    const safeName = path.basename(req.params.filename); 
    const filePath = path.join(STORAGE_DIR, safeName);

    try {
        await fs.access(filePath); // Check if exists
        await fs.unlink(filePath); // Async delete
        console.log(`[SPOKE] Purged: ${safeName}`);
        res.json({ status: "Deleted" });
    } catch (err) {
        res.status(404).json({ error: "File not found" });
    }
});

// 2. BULK PURGE (For your Audit/Sync)
app.post('/internal/maintenance/purge', async (req, res) => {
    const { files } = req.body; // Array of filenames from the Jakarta Audit

    if (!Array.isArray(files)) return res.status(400).send("Invalid list.");

    const results = { success: 0, failed: 0 };

    // Delete everything in parallel!
    await Promise.all(files.map(async (filename) => {
        try {
            const safeName = path.basename(filename);
            await fs.unlink(path.join(STORAGE_DIR, safeName));
            results.success++;
        } catch (err) {
            results.failed++;
        }
    }));

    console.log(`[MAINTENANCE] Bulk Purge Complete: ${results.success} removed.`);
    res.json(results);
});

app.get('/internal/files/:filename', (req, res) => {
    const filename = path.basename(req.params.filename);
    const filePath = path.join(STORAGE_DIR, filename);

    if (!fs.existsSync(filePath)) return res.status(404).send("File not found");

    try {
        const stats = fs.statSync(filePath);
        const fd = fs.openSync(filePath, 'r');

        // 1. Read the IV (First 12 bytes)
        const iv = Buffer.alloc(12);
        fs.readSync(fd, iv, 0, 12, 0);

        // 2. Read the Auth Tag (Last 16 bytes)
        const tag = Buffer.alloc(16);
        fs.readSync(fd, tag, 0, 16, stats.size - 16);
        fs.closeSync(fd);

        const finalDecipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, iv);
        finalDecipher.setAuthTag(tag);

        // 4. THE DECRYPTION PIPE
        // We read from 12 (after IV) to size-16 (before Tag)
        const readStream = fs.createReadStream(filePath, { start: 12, end: stats.size - 17 });
        
        console.log(`[SPOKE] Decrypting stream: ${filename}`);

        // Pipe: Disk -> Decipher -> Jakarta (Response)
        readStream.pipe(finalDecipher).pipe(res);

    } catch (err) {
        console.error("DECRYPTION ERROR:", err.message);
        res.status(500).send("Security Integrity Check Failed.");
    }
});


app.listen(PORT, SPOKE_IP, () => {
    console.log(`Surabaya Spoke Active on port ${PORT} at IP ${SPOKE_IP}`);
});


