const checkRole = (requiredRole) => {
    return (req, res, next) => {
        const userId = req.auth.payload.sub;

        // 1. Find user's role in local SQLite
        const mapping = db.prepare(`
            SELECT r.role_name 
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = ?
        `).get(userId);

        if (!mapping || (requiredRole && mapping.role_name !== requiredRole)) {
            console.error(`[SECURITY] Access Denied for ${userId}. Missing role: ${requiredRole}`);
            return res.status(403).json({ error: "Insufficient Permissions" });
        }

        req.userRole = mapping.role_name;
        next();
    };
};
const validateFileSecurity = (filename, headerMime) => {
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
export { checkRole, validateFileSecurity };
