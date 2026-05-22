const BASE_URL     = pm.environment.get("base_url");
const AUTH0_DOMAIN = pm.environment.get("auth0_domain");
const CLIENT_ID    = pm.environment.get("auth0_client_id");
// const CLIENT_ID    = pm.environment.get("auth0_client_id");

// =========================================================================
// SIKLUS UTAMA: AMBIL REFRESH TOKEN LAMA UNTUK DIUJI
// =========================================================================
const currentRefreshToken = pm.environment.get("current_refresh_token");

// REPLAY ATTACK SIMULATION (Memicu RTR Auth0)
if (currentRefreshToken) {
    pm.sendRequest({
        url: `https://${AUTH0_DOMAIN}/oauth/token`,
        method: 'POST',
        header: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: {
            mode: 'urlencoded',
            urlencoded: [
                { key: 'grant_type', value: 'refresh_token' },
                { key: 'client_id', value: CLIENT_ID },
                { key: 'refresh_token', value: currentRefreshToken }
            ]
        }
    }, function (err, res) {
        if (res.code === 200) {
            const data = res.json();
            
            // 🌟 DI SINI FUNGSIMU BEKERJA!
            // Otomatis menimpa access_token lama dengan yang baru di UI Environment
            pm.environment.set("access_token", data.access_token);
            
            // Simpan refresh token baru untuk putaran tes berikutnya
            pm.environment.set("current_refresh_token", data.refresh_token);
            
            console.log("✔ [POSTMAN ENV] Access Token & Refresh Token baru berhasil diset otomatis!");
            
            // Jalankan pengujian dependensi setelah token berhasil diperbarui
            jalankanTesLanjutan();
        } else if (res.code === 400) {
            pm.test("TC-03: Mekanisme RTR Valid - Replay Attack Ditolak Auth0 (400)", function () {
                pm.expect(res.json().error).to.eql("invalid_grant");
                pm.expect(res.json().error_description).to.include("Refresh token rotated");
            });
        }
    });
}

// =========================================================================
// FUNGSI DEPENDENSI: BARU BERJALAN SETELAH TOKEN TERBARU DI-SET
// =========================================================================
function jalankanTesLanjutan() {
    const tokenTerbaru = pm.environment.get("access_token");
    const fileUuid     = pm.environment.get("active_file_uuid");

    // TC-01: Proteksi Perimeter Zero Trust (Auth Enforcement)
    pm.sendRequest({
        url: `${BASE_URL}/api/v1/vault/identity`,
        method: 'GET' // Sengaja tanpa header Authorization
    }, function (err, res) {
        pm.test("TC-01: Perimeter Terkunci - Server Wajib Menolak Tanpa Token (401)", function () {
            pm.expect(res.code).to.eql(401);
        });
    });

    // TC-02: DDoS & L7 Rate Limiting (Pengeboman Berbasis Token Terbaru)
    const jumlahBomber = 55; 
    for (let i = 1; i <= jumlahBomber; i++) {
        pm.sendRequest({
            url: `${BASE_URL}/api/v1/vault/files`,
            method: 'GET',
            header: { 'Authorization': `Bearer ${tokenTerbaru}` }
        }, function (err, res) {
            if (i === jumlahBomber) {
                pm.test("TC-02: Mitigasi DDoS Berhasil - IP Penyerang Diisolasi (429)", function () {
                    pm.expect(res.code).to.eql(429);
                });
            }
        });
    }

    // TC-04: Integritas Data WORM Policy (Object Lock Berkas)
    if (fileUuid) {
        pm.sendRequest({
            url: `${BASE_URL}/api/v1/vault/files/${fileUuid}`,
            method: 'DELETE',
            header: { 'Authorization': `Bearer ${tokenTerbaru}` }
        }, function (err, res) {
            pm.test("TC-04: Kebijakan WORM Aktif - Berkas Terkunci < 5 Menit (403)", function () {
                pm.expect(res.code).to.eql(403);
                pm.expect(res.json().error).to.eql("Object Locked");
            });
        });
    }
}