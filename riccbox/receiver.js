// const express = require('express');
// const multer  = require('multer');
// const path = require('path');
// const fs = require('fs');

// const app = express();
// const PORT = 3000;

// // 1. Setup Storage Location
// const uploadDir = path.join(__dirname, 'vault_storage');
// if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// const storage = multer.diskStorage({
//     destination: (req, file, cb) => cb(null, uploadDir),
//     filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
// });

// const upload = multer({ storage: storage });

// // 2. The "Vault Entry" Route
// app.post('/receive-file', upload.single('payload'), (req, res) => {
//     console.log(`[VAULT] Received file: ${req.file.filename} via Secure Tunnel`);
//     res.status(200).json({ 
//         status: "Stored in Vault", 
//         location: "Surabaya Spoke" 
//     });
// });

// app.listen(PORT, '0.0.0.0', () => {
//     console.log(`[VAULT] Receiver active on port ${PORT} (Listening via OpenVPN)`);
// });


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
// app.get('/hello', (req, res) => {
//     res.send("Hello from the Surabaya Spoke! Your secure tunnel is working.");
// });
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
