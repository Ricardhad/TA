dotenv.config();
import https from 'https';
import fs from 'fs';
import express from 'express';
import httpProxy from 'http-proxy';
import dotenv from 'dotenv';
import {auth} from 'express-oauth2-jwt-bearer';
import cors from 'cors';

const app = express();
const PUBLIC_PORT = 8080;
const proxy = httpProxy.createProxyServer({});

const LOCAL_SPOKE_IP = process.env.SPOKE_IP; 
const LOCAL_PORT = process.env.GATEWAY_PORT;

// const token = await getAccessTokenSilently();
// const response = await fetch('http://richardgatewayta.duckdns.org:8080/vault/download/file.enc', {
//   headers: {
//     Authorization: `Bearer ${token}`
//   }
// });
app.use(cors({
    origin: 'http://localhost:5173', // Allow your React app
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

const bouncer = auth({
    audience: 'https://richardgatewayta.duckdns.org',
    issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}/`,
    tokenSigningAlg: 'RS256'
})



const sslOptions = {
  key: fs.readFileSync('/etc/letsencrypt/live/richardgatewayta.duckdns.org/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/richardgatewayta.duckdns.org/fullchain.pem')
};

// app.all(/^(\/.*)/, (req, res) => {
//     console.log(`[LOG] Forwarding: ${req.method} ${req.url} -> Surabaya`);

//     proxy.web(req, res, { 
//         target: `http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}`,
//         changeOrigin: true, // Key for cross-network routing
//         xfwd: true          // Passes the original IP for your logs
//     }, (err) => {
//         console.error(`[ERROR] Proxy Failed: ${err.message}`);
//         if (!res.headersSent) {
//             res.status(502).send("Gateway Error: Spoke Timeout.");
//         }
//     });
// });
app.all(/^(\/.*)/,bouncer, (req, res) => {
    console.log(`[LOG] Forwarding: ${req.method} ${req.url} -> Surabaya`);

    proxy.web(req, res, { 
        target: `http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}`,
        changeOrigin: true, // Key for cross-network routing
        xfwd: true          // Passes the original IP for your logs
    }, (err) => {
        console.error(`[ERROR] Proxy Failed: ${err.message}`);
        if (!res.headersSent) {
            res.status(502).send("Gateway Error: Spoke Timeout.");
        }
    });
});

https.createServer(sslOptions, app).listen(PUBLIC_PORT, '0.0.0.0', () => {
    console.log('--- Zero Trust Architecture Active ---');
    console.log(`Public Entry: https://richardgatewayta.duckdns.org:${PUBLIC_PORT}`);
    console.log(`Internal Destination: ${LOCAL_SPOKE_IP}:${LOCAL_PORT}`);
    console.log('--------------------------------------');
});
