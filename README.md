# 🛡️ Zero Trust Hub-and-Spoke Storage Architecture

![Node.js](https://img.shields.io/badge/Node.js-43853D?style=for-the-badge&logo=node.js&logoColor=white)
![Express.js](https://img.shields.io/badge/Express.js-404D59?style=for-the-badge)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)
![Auth0](https://img.shields.io/badge/Auth0-EB5424?style=for-the-badge&logo=auth0&logoColor=white)
![OpenVPN](https://img.shields.io/badge/OpenVPN-EA7E20?style=for-the-badge&logo=openvpn&logoColor=white)

A highly secure, Zero Trust self-hosting architecture designed to solve the fundamental vulnerabilities of local data exposure. This project bridges the gap between Data Sovereignty (keeping data physically on-premise) and public accessibility by utilizing a Hub-and-Spoke network topology.

## ⚠️ The Problem
When enterprises require absolute Data Sovereignty, they must host their data locally. However, making this local data accessible over the internet introduces major dilemmas:
1. **The CGNAT Barrier:** ISPs block incoming connections, isolating the local server.
2. **Vulnerable Port Forwarding:** Bypassing CGNAT traditionally requires opening firewall ports, exposing the physical machine to botnets and brute-force attacks.
3. **Data-at-Rest Vulnerability:** Physical breaches instantly expose plaintext data.

## 💡 The Solution
This architecture resolves these issues through three core pillars:
* **Dark Cloud (ZTNA):** The local server remains completely invisible from the public internet. Zero inbound ports are opened.
* **Reverse Tunneling:** Utilizes OpenVPN to establish a secure, outbound-only connection to a public Cloud Gateway (Hub), securely bypassing CGNAT.
* **Purpose-Built API:** A custom Node.js REST API optimized for secure stream processing, minimizing memory overhead and eliminating generic COTS bloatware.

---

## 🏗️ System Architecture

The system enforces strict Separation of Concerns across three main entities:

1. **Identity Provider (Auth0):** Handles user authentication and issues JWT tokens.
2. **The Hub (GCP Gateway):** The public-facing entry point. It acts as a security bouncer handling RBAC/ABAC authorization, Rate Limiting, payload sanitization, and metadata logging (SQLite).
3. **The Spoke (Local Vault):** The isolated local server. Its sole responsibility is cryptographic operations (AES-256-GCM encryption/decryption) and physical file storage.

### 🌊 Pure Stream Processing (Memory Efficient)
The Gateway utilizes `Busboy` to process file uploads purely via streams with a 16KB high-water mark. Incoming files are heavily inspected (MIME sniffing) at the first chunk, and if validated, immediately piped (`PassThrough`) to the Spoke via the VPN tunnel. The Gateway handles up to 50GB file limits without ever overloading its RAM.

---

## 🔒 Comprehensive Security Validation

This system has been rigorously tested and mathematically validated:

- **Network Isolation:** `Nmap` scans confirm 0 open inbound ports on the local server.
- **Application Security:** `OWASP ZAP` Authenticated Active Scans validate 0 High/Critical risks.
- **Anti-Discovery:** The API enforces a strict "Catch-All 403 Forbidden" policy for unmapped routes, neutralizing endpoint discovery attempts.
- **DDoS Protection:** Concurrent brute-force attacks are silently neutralized by dynamic Rate Limiters (429 Too Many Requests).
- **Data-in-Transit:** `Wireshark` packet analysis proves all Hub-to-Spoke communication is strictly encapsulated within the OpenVPN protocol (`P_DATA_V2`).
- **Data-at-Rest:** Forensic hex inspection and **Shannon Entropy** mathematical analysis prove the AES-256 encrypted physical files achieve near-perfect randomness (close to 8.0), rendering them mathematically undecipherable without the master key.

---

## ⚙️ Core Features
* **Zero Trust Network Access (ZTNA)**
* **Anti-Session Hijacking (Device Fingerprinting)**
* **Object Versioning & Auto-Purging:** Maintains up to 5 versions per file.
* **WORM (Write Once, Read Many) Lock:** Soft-delete retention policies prevent immediate tampering.
* **Data Integrity Checks:** Bit-rot detection modules to ensure file health.
* **Granular RBAC/ABAC Authorization:** Strict bucket-level and global admin policies.

## 👨‍💻 Author
**Richard Hadiyanto** *Informatics Engineering - Institut Sains dan Teknologi Terpadu Surabaya (ISTTS)* Developed as a Final Project (Tugas Akhir) demonstrating advanced backend engineering, stream processing, and network security.
