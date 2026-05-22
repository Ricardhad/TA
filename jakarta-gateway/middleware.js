
import mime from 'mime-types';
import db from './db.js';

export const permitGlobalRole = (requiredRole) => {
    return (req, res, next) => {
        if (req.auth && req.auth.payload && req.auth.payload.gty === 'client-credentials') {
            console.log("[RBAC] Machine-to-Machine token detected. Granting Admin bypass.");
            req.globalRole = 'admin'; // Berikan Spoke hak akses penuh
            return next();
        }
        const namespace = process.env.NAMESPACE || 'https://richardgatewayta.duckdns.org';
        const userRolesArray = req.auth.payload[`${namespace}/roles`] || [];
        const primaryRole = userRolesArray.includes('admin') ? 'admin' : 'standard_user';

        const hierarchy = { 'standard_user': 1, 'admin': 2 };

        if (hierarchy[primaryRole] < hierarchy[requiredRole]) {
            return res.status(403).json({ error: `Forbidden: Requires ${requiredRole} clearance.` });
        }
        req.globalRole = primaryRole;
        next();
    };
};
// export const authorizeVault = (requiredRole = 'VIEWER') => {
//     return (req, res, next) => {
//         const userId = req.auth.payload.sub;
//         const fileUuid = req.params.uuid;

//         // 1. Check if they are the OWNER
//         const ownerCheck = db.prepare('SELECT owner_id FROM files WHERE uuid = ?').get(fileUuid);

//         if (ownerCheck && ownerCheck.owner_id === userId) {
//             req.userRole = 'OWNER';
//             return next(); // Owners can do everything
//         }

//         // 2. Check if they are an INVITED GUEST
//         const guestCheck = db.prepare('SELECT role FROM file_access WHERE file_uuid = ? AND user_id = ?')
//             .get(fileUuid, userId);

//         if (!guestCheck) {
//             return res.status(403).json({ error: "Access Denied: You are not invited to this vault." });
//         }

//         // 3. Check if their guest role is high enough
//         const hierarchy = { 'VIEWER': 1, 'EDITOR': 2, 'OWNER': 3 };
//         if (hierarchy[guestCheck.role] < hierarchy[requiredRole]) {
//             return res.status(403).json({ error: `Forbidden: This action requires ${requiredRole} status.` });
//         }

//         req.userRole = guestCheck.role;
//         next();
//     };
// };
// export const authorizeVault = (requiredPermission = 'READ') => {
//     return (req, res, next) => {
//         const userId = req.auth.payload.sub;
//         const fileUuid = req.params.uuid;

//         // 1. Global Admin Bypass
//         if (req.globalRole === 'admin') {
//             req.bucket_permission = 'ADMIN';
//             return next();
//         }

//         // 2. Find the file AND its parent bucket
//         const fileData = db.prepare(`
//             SELECT f.bucket_id, b.owner_id as bucket_owner
//             FROM files f
//             JOIN buckets b ON f.bucket_id = b.id
//             WHERE f.uuid = ?
//         `).get(fileUuid);

//         if (!fileData) return res.status(404).json({ error: "File not found." });

//         // 3. Check Bucket-Level RBAC
//         let finalPermission = null;

//         if (fileData.bucket_owner === userId) {
//             finalPermission = 'ADMIN'; // Owner of the bucket has ultimate power
//         } else {
//             const policy = db.prepare('SELECT permission FROM bucket_policies WHERE bucket_id = ? AND grantee_id = ?')
//                 .get(fileData.bucket_id, userId);

//             if (policy) finalPermission = policy.permission;
//         }

//         if (!finalPermission) {
//             return res.status(403).json({ error: "Access Denied: You are not invited to this namespace." });
//         }

//         // 4. Weight Check
//         const weights = { 'READ': 1, 'WRITE': 2, 'ADMIN': 3 };
//         if (weights[finalPermission] < weights[requiredPermission]) {
//             return res.status(403).json({ error: `Forbidden: Action requires ${requiredPermission} permission.` });
//         }

//         req.bucket_permission = finalPermission;
//         next();
//     };
// };
export const validateFileSecurity = (filename, headerMime, detectedType, buffer) => {
    const dangerousMimes = ['application/x-sh', 'application/x-shellscript', 'text/x-shellscript'];
    // 1. Ekstraksi Ekstensi yang Aman
    const lastDotIndex = filename.lastIndexOf('.');
    if (lastDotIndex === -1) {
        return { isSpoofed: true, finalMime: 'BLOCKED' };
    }
    const ext = filename.toLowerCase().substring(lastDotIndex);

    // 2. Blacklist Statis (Mutlak)
    const dangerousExtensions = ['.sh', '.exe', '.bat', '.php', '.js', '.msi', '.vbs', '.scr', '.ps1'];
    if (dangerousExtensions.includes(ext)) {
        console.warn(`[SECURITY] BLOCKED: Ekstensi berbahaya terdeteksi: ${ext}`);
        return { isSpoofed: true, finalMime: 'BLOCKED' };
    }
    // 1. Cek isi file (Magic Numbers) - PALING PENTING
    if (detectedType && dangerousMimes.includes(detectedType.mime)) {
        return { isSpoofed: true, finalMime: 'BLOCKED' };
    }

    // 2. Cek Header MIME (jika client mengaku-ngaku)
    if (dangerousMimes.includes(headerMime)) {
        return { isSpoofed: true, finalMime: 'BLOCKED' };
    }

    // 3. MIME Matching (Fail-safe)
    const detectedMime = mime.lookup(filename);

    // Jika MIME tidak diketahui, kita izinkan jika bukan file biner berbahaya, 
    // tapi jika MIME terdeteksi dan sangat berbeda, maka kita blokir.
    if (detectedMime && headerMime !== 'application/octet-stream') {
        // Abaikan perbedaan jika headerMime adalah tipe generik
        if (headerMime !== detectedMime) {
            console.warn(`[SECURITY] BLOCKED: MIME Mismatch! Expected ${detectedMime}, got ${headerMime}`);
            return { isSpoofed: true, finalMime: 'BLOCKED' };
        }
    }
    const content = buffer.toString().toLowerCase();
    const dangerousKeywords = ['#!/bin/', 'echo ', 'eval(', 'base64_decode', 'cmd.exe', 'powershell'];
    if (dangerousKeywords.some(keyword => content.includes(keyword))) {
        return { isSpoofed: true, finalMime: 'BLOCKED' };
    }
    const allowedExtensions = {
        '.jpg': 'image/jpeg',
        '.png': 'image/png',
        '.txt': 'text/plain',
        '.pdf': 'application/pdf',
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.xls': 'application/vnd.ms-excel',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.ppt': 'application/vnd.ms-powerpoint',
        '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        '.mp4': 'video/mp4',
        '.webm': 'video/webm',
        '.mov': 'video/quicktime'
    };
    if (!allowedExtensions[ext]) return { isSpoofed: true, finalMime: 'BLOCKED' };
    if (ext === '.mp4' && detectedType && detectedType.mime !== 'video/mp4') {
        return { isSpoofed: true, finalMime: 'BLOCKED' };
    }
    // Validasi MIME: Apakah headerMime yang dikirim klien sesuai dengan ekstensi yang diklaim?
    if (headerMime !== allowedExtensions[ext]) {
        // Pengecualian: kadang browser kirim 'image/pjpeg' untuk 'image/jpeg'
        if (!(ext === '.jpg' && headerMime.includes('jpeg'))) {
            return { isSpoofed: true, finalMime: 'BLOCKED' };
        }
    }
    return { isSpoofed: false, finalMime: allowedExtensions[ext] };

};
export const authorizeVault = (requiredPermission = 'READ') => {
    return (req, res, next) => {
        // 1. Ambil identitas user dari JWT
        if (!req.auth || !req.auth.payload) {
            return res.status(401).json({ error: "Unauthorized: No token provided." });
        }

        const userId = req.auth.payload.sub;
        const fileUuid = req.params.uuid;

        // Pastikan globalRole ada (default ke 'standard_user' jika belum diset)
        const role = req.globalRole || 'standard_user';

        console.log(`[AUTH CHECK] User: ${userId} | Role: ${role} | Required: ${requiredPermission} | File: ${fileUuid}`);

        // 2. Find File & Bucket
        const fileData = db.prepare(`
            SELECT f.bucket_id, b.owner_id as bucket_owner
            FROM files f
            JOIN buckets b ON f.bucket_id = b.id
            WHERE f.uuid = ?
        `).get(fileUuid);

        if (!fileData) return res.status(404).json({ error: "File not found." });

        // 3. Menentukan Permission
        let finalPermission = null;

        // A. Owner Bucket = ADMIN
        if (fileData.bucket_owner === userId) {
            finalPermission = 'ADMIN';
        } else {
            // B. Cek Policy di DB
            const policy = db.prepare('SELECT permission FROM bucket_policies WHERE bucket_id = ? AND grantee_id = ?')
                .get(fileData.bucket_id, userId);

            if (policy) finalPermission = policy.permission;
        }

        // 4. Admin Bypass (Logic for Global Admin)
        if (role === 'admin') {
            console.log(`[AUTH] Admin bypass granted for ${userId}`);
            req.bucket_permission = 'ADMIN';
            return next();
        }

        // 5. Check Denied
        if (!finalPermission) {
            return res.status(403).json({ error: "Access Denied: You are not invited to this namespace." });
        }

        // 6. Weight Check
        const weights = { 'READ': 1, 'WRITE': 2, 'ADMIN': 3 };
        if (weights[finalPermission] < weights[requiredPermission]) {
            return res.status(403).json({ error: `Forbidden: Action requires ${requiredPermission} permission.` });
        }

        req.bucket_permission = finalPermission;
        next();
    };
};

export function authorizeBucket(requiredPermission) {
    console.log(`[AUTH CHECK] Authorizing bucket access with permission: ${requiredPermission}`);
    return (req, res, next) => {
        const userId = req.auth.payload.sub;
        const bucketUuid = req.headers['x-bucket-uuid'] || req.params.bucketUuid;

        if (!bucketUuid) return res.status(400).json({ error: "Bucket UUID is required" });

        const bucketData = db.prepare(`
            SELECT b.owner_id, p.permission 
            FROM buckets b
            LEFT JOIN bucket_policies p ON b.id = p.bucket_id AND p.grantee_id = ?
            WHERE b.uuid = ?
        `).get(userId, bucketUuid);

        if (!bucketData) return res.status(404).json({ error: "Bucket not found" });

        let finalPermission = bucketData.permission;

        if (bucketData.owner_id === userId) {
            finalPermission = 'ADMIN';
        }

        // Evalusi Keamanan (Admin Global Bypass Dihapus!)
        if (!finalPermission) {
            return res.status(403).json({
                error: "Access Denied: No policy found for this user.",
                debug: { owner: bucketData.owner_id, requester: userId }
            });
        }

        const weights = { 'READ': 1, 'WRITE': 2, 'ADMIN': 3 };
        if (weights[finalPermission] < weights[requiredPermission]) {
            return res.status(403).json({
                error: "Insufficient Permissions",
                required: requiredPermission,
                current: finalPermission
            });
        }

        req.bucket_permission = finalPermission;
        next();
    };
}