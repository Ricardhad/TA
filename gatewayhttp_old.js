// Jakarta Gateway: gateway.js
import http from 'http';
import httpProxy from 'http-proxy';


const server = http.createServer((req, res) => {

    const proxy = httpProxy.createProxyServer({});
    const PUBLIC_PORT = 8080; // The port people will hit on your VM
    const LOCAL_SPOKE_IP = '172.27.232.2'; // Your Surabaya PC VPN IP
    const LOCAL_PORT = 3000;

    console.log(`[LOG] Forwarding request: ${req.url} -> Surabaya`);

    // Forward the request to your local home server
    proxy.web(req, res, { target: `http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}` }, (e) => {
        res.writeHead(500);
        res.end("Gateway Error: Could not reach the Surabaya Spoke.");
    });
});

server.listen(PUBLIC_PORT, '0.0.0.0', () => {
    console.log(`Gateway API is live on port ${PUBLIC_PORT}`);
    console.log(`Tunneling to http://${LOCAL_SPOKE_IP}:${LOCAL_PORT}`);
});