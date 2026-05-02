// app.get('/download/:fileId', (req, res) => {
//     const user = req.user; // From your SAML/OIDC check
//     const currentHour = new Date().getHours();

//     // The Zero Trust Conditions
//     const isOwner = fileDatabase.getOwner(req.params.fileId) === user.sub;
//     const isWorkTime = currentHour >= 9 && currentHour <= 17;
//     const isInternalVPN = req.ip === '172.27.232.1';

//     if (isOwner && isWorkTime && isInternalVPN) {
//         // ONLY NOW do we allow decryption and streaming
//         streamDecryptedFile(req.params.fileId, res);
//     } else {
//         res.status(403).send("Access Denied: Zero Trust Policy Violation.");
//     }
// });