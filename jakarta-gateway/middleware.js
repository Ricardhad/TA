
import mime from 'mime-types';
import db from './db.js';

export const permitGlobalRole = (requiredRole) => {
    return (req, res, next) => {
        const namespace = process.env.NAMESPACE || 'https://richardgatewayta.duckdns.org';
        const userRolesArray = req.auth.payload[`${namespace}/roles`] || [];
        
        // 1. Get the "best" role the user has
        const primaryRole = userRolesArray.find(r => ['admin', 'standard_user'].includes(r));

        if (!primaryRole) {
            return res.status(403).json({ error: "Access Denied: No valid global role found." });
        }

        // 2. Compare using your hierarchy
        const hierarchy = { 'standard_user': 1, 'admin': 2 };
        
        if (hierarchy[primaryRole] < hierarchy[requiredRole]) {
            return res.status(403).json({ error: `Forbidden: Requires ${requiredRole} clearance.` });
        }
        req.globalRole = primaryRole;
        next();
    };
};
export const authorizeVault = (requiredRole = 'VIEWER') => {
    return (req, res, next) => {
        const userId = req.auth.payload.sub;
        const fileUuid = req.params.uuid;

        // 1. Check if they are the OWNER
        const ownerCheck = db.prepare('SELECT owner_id FROM files WHERE uuid = ?').get(fileUuid);
        
        if (ownerCheck && ownerCheck.owner_id === userId) {
            req.userRole = 'OWNER';
            return next(); // Owners can do everything
        }

        // 2. Check if they are an INVITED GUEST
        const guestCheck = db.prepare('SELECT role FROM file_access WHERE file_uuid = ? AND user_id = ?')
                             .get(fileUuid, userId);

        if (!guestCheck) {
            return res.status(403).json({ error: "Access Denied: You are not invited to this vault." });
        }

        // 3. Check if their guest role is high enough
        const hierarchy = { 'VIEWER': 1, 'EDITOR': 2, 'OWNER': 3 };
        if (hierarchy[guestCheck.role] < hierarchy[requiredRole]) {
            return res.status(403).json({ error: `Forbidden: This action requires ${requiredRole} status.` });
        }

        req.userRole = guestCheck.role;
        next();
    };
};

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

export function authorizeBucket(requiredPermission) {
    return (req, res, next) => {
        const userId = req.auth.payload.sub;
        const bucketUuid = req.headers['x-bucket-uuid'] || req.params.bucketUuid;

        if (!bucketUuid) {
            return res.status(400).json({ error: "Bucket UUID is required" });
        }

        const policy = db.prepare(`
            SELECT p.permission 
            FROM bucket_policies p
            JOIN buckets b ON p.bucket_id = b.id
            WHERE b.uuid = ? AND p.grantee_id = ?
        `).get(bucketUuid, userId);

        if (!policy) {
            return res.status(403).json({ error: "Access Denied: No policy found for this user." });
        }

        // 🏆 The Hierarchy Map
        const weights = {
            'READ': 1,
            'WRITE': 2,
            'ADMIN': 3
        };

        const userWeight = weights[policy.permission] || 0;
        const requiredWeight = weights[requiredPermission] || 0;

        // If user's level is lower than required, kick them out
        if (userWeight < requiredWeight) {
            return res.status(403).json({ 
                error: "Insufficient Permissions",
                required: requiredPermission,
                current: policy.permission
            });
        }

        // Add to request object for use in the next function
        req.bucket_permission = policy.permission; 
        next();
    };
}