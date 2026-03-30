// import crypto from 'crypto';
const crypto = require('crypto');
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // Standard for GCM
const TAG_LENGTH = 16;

/**
 * Encrypts a buffer and returns a single combined Buffer
 * @param {Buffer} data 
 * @param {string} masterKey - Must be 32 characters
 */
export const encryptToVault = (data, masterKey) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(masterKey), iv);

    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Combine: IV + TAG + DATA into one single blob
    return Buffer.concat([iv, authTag, encrypted]);
};

/**
 * Decrypts a vault blob
 */
export const decryptFromVault = (vaultBlob, masterKey) => {
    // Extract the pieces
    const iv = vaultBlob.subarray(0, IV_LENGTH);
    const authTag = vaultBlob.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const encryptedData = vaultBlob.subarray(IV_LENGTH + TAG_LENGTH);

    const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(masterKey), iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
};