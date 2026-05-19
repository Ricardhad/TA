
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

export const validateFileSecurity = (filename, headerMime) => {
    const extensionMime = mime.lookup(filename);
    const dangerousExtensions = ['.exe', '.sh', '.bat', '.php', '.js', '.msi'];

    const isExecutableExt = dangerousExtensions.some(ext =>
        filename.toLowerCase().endsWith(ext)
    );

    const isSpoofed = isExecutableExt && (
        headerMime.startsWith('image/') || headerMime.startsWith('text/')
    );

    return {
        isSpoofed,
        finalMime: (headerMime === 'application/octet-stream')
            ? (extensionMime || headerMime)
            : headerMime
    };
};


export const authorizeVault = (requiredPermission = 'READ') => {
    return (req, res, next) => {
        const userId = req.auth.payload.sub;
        const fileUuid = req.params.uuid;

        // 1. Find the file AND its parent bucket
        const fileData = db.prepare(`
            SELECT f.bucket_id, b.owner_id as bucket_owner
            FROM files f
            JOIN buckets b ON f.bucket_id = b.id
            WHERE f.uuid = ?
        `).get(fileUuid);

        if (!fileData) return res.status(404).json({ error: "File not found." });

        // 2. Check Bucket-Level RBAC
        let finalPermission = null;

        if (fileData.bucket_owner === userId) {
            finalPermission = 'ADMIN'; // Owner of the bucket has ultimate power
        } else {
            const policy = db.prepare('SELECT permission FROM bucket_policies WHERE bucket_id = ? AND grantee_id = ?')
                .get(fileData.bucket_id, userId);
            
            if (policy) finalPermission = policy.permission;
        }

        // 3. Evalusi Keamanan (Admin Global Bypass Dihapus!)
        if (!finalPermission) {
            // Pengecualian SATU-SATUNYA: Jika Admin Global ingin menghapus fail dari "Global File Explorer" (Force Purge)
            if (req.globalRole === 'admin' && requiredPermission === 'WRITE' && req.path.includes(fileUuid)) {
                 return next();
            }
            return res.status(403).json({ error: "Access Denied: You are not invited to this namespace." });
        }

        // 4. Weight Check
        const weights = { 'READ': 1, 'WRITE': 2, 'ADMIN': 3 };
        if (weights[finalPermission] < weights[requiredPermission]) {
            return res.status(403).json({ error: `Forbidden: Action requires ${requiredPermission} permission.` });
        }

        req.bucket_permission = finalPermission;
        next();
    };
};

export function authorizeBucket(requiredPermission) {
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