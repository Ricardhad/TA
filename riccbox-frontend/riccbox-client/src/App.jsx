import { useState } from 'react'
import './App.css'
import { useAuth0 } from "@auth0/auth0-react";

function App() {
  const {
    isLoading,
    isAuthenticated,
    error,
    user,
    loginWithRedirect: login,
    logout: auth0Logout,
    getAccessTokenSilently
  } = useAuth0();

  const [vaultData, setVaultData] = useState(null);
  const [isFetching, setIsFetching] = useState(false);

  const logout = () =>
    auth0Logout({ logoutParams: { returnTo: window.location.origin } });

  // --- LOGIC 1: FETCH METADATA ---
  const fetchFiles = async () => {
    setIsFetching(true);
    try {
      const token = await getAccessTokenSilently({
        authorizationParams: { audience: 'https://richardgatewayta.duckdns.org' }
      });

      const response = await fetch('https://richardgatewayta.duckdns.org:8080/vault/metadata', {
        headers: { Authorization: `Bearer ${token}` }
      });

      const data = await response.json();
      setVaultData(data); // 🟢 This updates the UI!
    } catch (err) {
      console.error("Vault Access Denied:", err.message);
    } finally {
      setIsFetching(false);
    }
  };
const downloadFile = async (fileName, version) => {
  try {
    const token = await getAccessTokenSilently({
      authorizationParams: { audience: 'https://richardgatewayta.duckdns.org' }
    });

    // 1. Locate the correct version object in the history array
    const fileHistory = vaultData[fileName].history;
    const targetVersion = fileHistory.find(item => item.version === version);

    if (!targetVersion) throw new Error("Version not found in history");

    // 2. Use the 'path' field from your JSON (e.g., 1774227161335-faust.png.v18.enc)
    const physicalPath = targetVersion.path;

    // 3. Request the file from the Jakarta Gateway
    const response = await fetch(`https://richardgatewayta.duckdns.org:8080/vault/download/${physicalPath}`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!response.ok) throw new Error("File not found on Surabaya Spoke");

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    
    // 4. Trigger the browser save
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName; // Saves it as the encrypted filename
    document.body.appendChild(a);
    a.click();
    a.remove();
    
    console.log(`[SUCCESS] Downloaded: ${physicalPath}`);
  } catch (err) {
    alert("Zero Trust Download Error: " + err.message);
  }
};

  if (isLoading) return <div className="loading">Checking Zero Trust Status...</div>;

  return (
    <div className="App">
      <h1>RiccBox: Secure Dark Cloud</h1>

      {!isAuthenticated ? (
        <div className="login-gate">
          {error && <p className="error">Error: {error.message}</p>}
          <button onClick={login}>Login to Access Vault</button>
        </div>
      ) : (
        <div className="vault-interface">
          <header style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
            <p>Logged in as: <strong>{user.email}</strong></p>
            <button onClick={logout}>Logout</button>
          </header>

          <div className="vault-container">
            <h2>Secure Storage: Surabaya Spoke</h2>
            <button onClick={fetchFiles} disabled={isFetching}>
              {isFetching ? "Syncing..." : "Refresh Vault Contents"}
            </button>

            {vaultData && (
              <table className="vault-table">
                <thead>
                  <tr>
                    <th>File Name</th>
                    <th>Latest Version</th>
                    <th>History</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(vaultData).map(([fileName, details]) => (
                    <tr key={fileName}>
                      <td><strong>{fileName}</strong></td>
                      <td>v{details.latest_version}</td>
                      <td>{details.history.length} versions</td>
                      <td>
                        <button onClick={() => downloadFile(fileName, details.latest_version)}>
                          Download
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;