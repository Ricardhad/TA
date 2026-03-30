
import mime from 'mime-types';
import db from './db.js';

export const permitGlobalRole = (requiredRole) => {
    return (req, res, next) => {
        // Auth0 usually puts roles in a custom claim via an 'Action'
        // Replace 'NAMESPACE' with your DuckDNS string
        const namespace = process.env.NAMESPACE || 'https://richardgatewayta.duckdns.org';
        const userRoles = req.auth.payload[`${namespace}/roles`] || [];

        if (userRoles.includes(requiredRole)) {
            return next();
        }

        console.warn(`[SECURITY] Audit Access Denied: User ${req.auth.payload.sub} is not a ${requiredRole}`);
        res.status(403).json({ error: "Forbidden: System Admin Clearance Required." });
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
