const express = require('express');
const multer  = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// 1. Setup Storage Location
const uploadDir = path.join(__dirname, 'vault_storage');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ storage: storage });

// 2. The "Vault Entry" Route
app.post('/receive-file', upload.single('payload'), (req, res) => {
    console.log(`[VAULT] Received file: ${req.file.filename} via Secure Tunnel`);
    res.status(200).json({ 
        status: "Stored in Vault", 
        location: "Surabaya Spoke" 
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`[VAULT] Receiver active on port ${PORT} (Listening via OpenVPN)`);
});