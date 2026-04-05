const express = require('express');
// const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');
// const { get } = require('http');
// const { randomUUID } = require ('crypto');
const { Readable } =require ('stream');
// import fs from 'fs/promises';
// const newUuid = randomUUID();
require('dotenv').config();

const app = express();
const PORT = 3000;

app.use(express.json({ 
    limit: '1mb', 
    strict: true 
}));

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

const STORAGE_DIR = path.join(__dirname, 'vault_storage');

// 1. STORAGE: Use MemoryStorage so the raw file never touches your disk
// const upload = multer({ storage: multer.memoryStorage() });

/**
 * Encrypts a buffer into a single [IV][TAG][DATA] blob
 */
// function encryptToVault(buffer, key) {
//     const iv = crypto.randomBytes(IV_LENGTH);
//     const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(key), iv);

//     const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
//     const authTag = cipher.getAuthTag();

//     // The "Vault Header" Strategy
//     return Buffer.concat([iv, authTag, encrypted]);
// }

// function decryptFromVault(vaultBlob, key) {
//     // 0 to 11 (12 bytes)
//     const iv = vaultBlob.subarray(0, 12);

//     // 12 to 27 (16 bytes)
//     const authTag = vaultBlob.subarray(12, 28);

//     // 28 to end
//     const encryptedData = vaultBlob.subarray(28);

//     // Make sure 'key' here is the same Buffer format used in encryption!
//     const keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
//     console.log("Key Length:", keyBuffer.length); // Should be 32
//     console.log("Key Hex:", keyBuffer.toString('hex').substring(0, 10) + "...");
//     const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
//     decipher.setAuthTag(authTag);

//     return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
// }
// const METADATA_PATH = path.join(__dirname, 'vault_metadata.json');

// const getMetadata = () => {
//     try {
//         if (!fs.existsSync(METADATA_PATH)) return {};
//         const content = fs.readFileSync(METADATA_PATH, 'utf8');
//         return content ? JSON.parse(content) : {};
//     } catch (err) {
//         console.error("Metadata Error:", err);
//         return {};
//     }
// }
// const saveMetadata = (data) => fs.writeFileSync(METADATA_PATH, JSON.stringify(data, null, 2));



// app.post('/receive-file', upload.single('payload'), (req, res) => {
//     try {
//         if (!req.file) return res.status(400).json({ error: "No file received" });

//         const originalName = req.file.originalname;
//         // let metadata = getMetadata();

//         // if (!metadata[originalName]) {
//         //     metadata[originalName] = { latest_version: 0, history: [] };
//         // }
//         // const fileEntry = metadata[originalName];
//         const vaultDir = path.join(__dirname, 'vault_storage');
//         console.log(`[VAULT] Current versions for ${originalName}: ${fileEntry.history.length}`);

//         // while (fileEntry.history.length >= 5) {
//         //     const oldest = fileEntry.history.shift(); // Remove from array

//         //     if (oldest && oldest.path) {
//         //         const oldestPath = path.join(vaultDir, oldest.path);
//         //         console.log(`[VAULT] Purging Version ${oldest.version}: ${oldest.path}`);

//         //         if (fs.existsSync(oldestPath)) {
//         //             fs.unlinkSync(oldestPath); // Delete from disk
//         //         }
//         //     }
//         // }

//         // const newVersion = fileEntry.latest_version + 1;
//         const vaultBlob = encryptToVault(req.file.buffer, MASTER_KEY);
//         const safeName = `${Date.now()}-${originalName}.v${newVersion}.enc`;

//         fs.writeFileSync(path.join(vaultDir, safeName), vaultBlob);

//         // fileEntry.latest_version = newVersion;
//         // fileEntry.history.push({
//         //     version: newVersion,
//         //     timestamp: new Date().toISOString(),
//         //     path: safeName,
//         //     size: req.file.size
//         // });

//         // saveMetadata(metadata);

//         console.log(`[VAULT] Success: v${newVersion} stored.`);
//         res.status(200).json({
//             status: "Success",
//             // version: newVersion,
//             physical_path: safeName, // Jakarta needs this for the SQL 'versions' table
//             size: req.file.size
//         });

//     } catch (err) {
//         console.error("CRITICAL ERROR:", err.stack); // stack gives you the line number
//         res.status(500).json({ error: "Vault Process Failed" });
//     }
// });
// index.js (Surabaya Spoke)
// app.post('/receive-file', (req, res) => {
//     const originalName = req.headers['x-original-name'] || 'file';
//     const safeName = `${Date.now()}-${originalName}.enc`;
//     const vaultPath = path.join(__dirname, 'vault_storage', safeName);

//     const writeStream = fs.createWriteStream(vaultPath);
    
//     // THE MAGIC: Pipe the incoming request stream directly into your encryption logic
//     // and then into the writeStream.
//     req.pipe(writeStream); 

//     writeStream.on('finish', () => {
//         const stats = fs.statSync(vaultPath);
//         res.status(200).json({
//             status: "Success",
//             physical_path: safeName,
//             size: stats.size
//         });
//     });

//     writeStream.on('error', (err) => {
//         res.status(500).send("Storage Error");
//     });
// });
// 1. PLACE THIS BEFORE express.json()
app.post('/receive-file', (req, res) => {
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
app.post('/internal/test-upload', (req, res) => {
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
// Surabaya index.js

app.get('/internal/list-files', async (req, res) => {

    try {
        const files = await fs.readdir(STORAGE_DIR);
        
        // Filter out hidden files like .gitignore if necessary
        const physicalFiles = files.filter(f => !f.startsWith('.'));
        
        console.log(`[MAINTENANCE] Reporting ${physicalFiles.length} files to Jakarta Hub.`);
        res.json(physicalFiles);
    } catch (err) {
        console.error("[SPOKE ERROR] Disk scan failed:", err.message);
        res.status(500).json({ error: "Could not read storage directory." });
    }
});

app.get('/internal/test-download', (req, res) => {
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

// app.post('/vault/maintenance', (req, res) => {
//     let metadata = getMetadata();
//     let logs = [];

//     for (let fileName in metadata) {
//         let entry = metadata[fileName];
//         while (entry.history.length > 5) {
//             let purged = entry.history.shift();
//             // ... delete physical file ...
//             logs.push(`Purged ${fileName} v${purged.version}`);
//         }
//     }

//     saveMetadata(metadata);
//     res.json({ status: "Maintenance Complete", actions: logs });
// });
app.get('/hello', (req, res) => {
    res.send("Hello from the Surabaya Spoke! Your secure tunnel is working.");
});
// app.get('/vault/metadata', (req, res) => {
//     try {
//         if (!fs.existsSync(METADATA_PATH)) fs.writeFileSync(METADATA_PATH, '{}');

//         const metadata = getMetadata();
//         res.json(metadata);
//     } catch (err) {
//         console.error("Metadata Retrieval Error:", err);
//         return res.status(500).json({ error: "Failed to retrieve metadata" });
//     }
// });

// index.js (Surabaya Spoke)
// 1. SINGLE DELETE (Improved)
app.delete('/vault/delete/:filename', async (req, res) => {
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
app.post('/internal/purge-orphans', async (req, res) => {
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
// app.get('/serve-file/:filename', (req, res) => {
//     // const filePath = path.join(STORAGE_DIR, req.params.path);
//      const filename = req.params.filename;
//     const filePath = path.join(__dirname, 'vault_storage', filename);

//     // Safety check: ensure the file exists
//     if (!fs.existsSync(filePath)) return res.status(404).send("Not found");

//     // Send the file directly
//     res.sendFile(filePath);
// });
// index.js (Surabaya Spoke)
// Add this route ABOVE your express.json()
// index.js (Surabaya Spoke)
app.get('/serve-file/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'vault_storage', filename);

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

// app.get('/vault/download/:filename', (req, res) => {

//     try {

//         const fileName = req.params.filename;
//         const filePath = path.join(__dirname, 'vault_storage', fileName);

//         if (!fs.existsSync(filePath)) {
//             return res.status(404).json({ error: "File not found in vault." });
//         }
//         // 1. Read the encrypted blob from disk
//         const vaultBlob = fs.readFileSync(filePath);

//         // 2. Decrypt it
//         console.log(`[VAULT] Decrypting ${fileName}...`);
//         const decryptedBuffer = decryptFromVault(vaultBlob, process.env.VAULT_KEY);


//         // 3. Clean up the filename (Remove the timestamp and .enc extension)
//         // Example: 1711012345-my-thesis.pdf.enc -> my-thesis.pdf
//         const originalName = fileName.split('-').slice(1).join('-').replace('.enc', '');

//         // 4. Send to user
//         res.setHeader('Content-Disposition', `attachment; filename="${originalName}"`);
//         res.setHeader('Content-Type', 'application/octet-stream');
//         res.send(decryptedBuffer);

//         console.log(`[VAULT] Successfully served: ${originalName}`);

//     } catch (err) {
//         // If GCM detects tampering, it lands here!
//         console.error("DECRYPTION FAILURE:", err.message);
//         res.status(403).json({
//             error: "Security Alert: Integrity check failed. File may be corrupted or tampered with."
//         });
//     }
// });

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Surabaya Spoke Active on port ${PORT}`);
});


