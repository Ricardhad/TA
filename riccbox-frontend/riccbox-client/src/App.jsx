import { useState, useRef, useEffect } from 'react';
import './App.css';
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

  // --- Core State ---
  const [activeView, setActiveView] = useState('lobby'); 
  const [userRole, setUserRole] = useState('standard_user');
  const [isFetching, setIsFetching] = useState(false);
  const [usage, setUsage] = useState(null);
  
  // --- Data State ---
  const [buckets, setBuckets] = useState([]);
  const [files, setFiles] = useState([]);
  const [activeBucket, setActiveBucket] = useState(null);
  
  // --- Admin State ---
  const [adminSyncReport, setAdminSyncReport] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [benchmarkResult, setBenchmarkResult] = useState(null);

  // --- Modal States ---
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newBucketName, setNewBucketName] = useState('');
  const [shareBucketModal, setShareBucketModal] = useState({ open: false, bucket: null });
  const [shareEmail, setShareEmail] = useState('');
  const [sharePermission, setSharePermission] = useState('READ');

  // --- Inspector State ---
  const [inspectorModal, setInspectorModal] = useState({ open: false, file: null });
  const [fileVersions, setFileVersions] = useState([]);
  const [previewData, setPreviewData] = useState({ url: null, isLoading: false, versionNum: null });

  const fileInputRef = useRef(null);

  const API_BASE = 'https://richardgatewayta.duckdns.org:8080';
  const AUDIENCE = 'https://richardgatewayta.duckdns.org';

  useEffect(() => {
    if (isAuthenticated) {
      checkIdentity();
      fetchBuckets();
      fetchUsage();
    }
  }, [isAuthenticated]);

  // ==========================================
  // IDENTITY & QUOTA
  // ==========================================
  const checkIdentity = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/identity`, { headers: { Authorization: `Bearer ${token}` }});
      const data = await res.json();
      if (data.roles && data.roles.includes('admin')) setUserRole('admin');
    } catch (err) { console.error(err); }
  };

  const fetchUsage = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/usage`, { headers: { Authorization: `Bearer ${token}` }});
      if(res.ok) setUsage(await res.json());
    } catch (err) { console.error("Quota fetch failed", err); }
  }

  const logout = () => auth0Logout({ logoutParams: { returnTo: window.location.origin } });

  // ==========================================
  // BUCKETS (LOBBY)
  // ==========================================
  const fetchBuckets = async () => {
    setIsFetching(true);
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/buckets`, { headers: { Authorization: `Bearer ${token}` }});
      const data = await res.json();
      setBuckets(data.buckets || []); 
    } catch (err) { console.error(err); } finally { setIsFetching(false); }
  };

  const handleCreateBucket = async (e) => {
    e.preventDefault();
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      await fetch(`${API_BASE}/vault/buckets`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newBucketName, region: 'sub-01' })
      });
      setNewBucketName(''); setShowCreateModal(false); fetchBuckets();
    } catch (err) { alert(err.message); }
  };

  const handleRenameBucket = async (bucket) => {
    const newName = prompt(`Enter new name for '${bucket.name}':`);
    if (!newName) return;
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      await fetch(`${API_BASE}/vault/buckets/${bucket.uuid}`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newName, region: bucket.region })
      });
      fetchBuckets();
    } catch (err) { alert(err.message); }
  }

  const handleShareBucket = async (e) => {
    e.preventDefault();
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      await fetch(`${API_BASE}/vault/buckets/${shareBucketModal.bucket.uuid}/share`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ grantee_id: shareEmail, permission: sharePermission }) 
      });
      alert("User successfully invited to Vault!");
      setShareBucketModal({ open: false, bucket: null });
    } catch (err) { alert(err.message); }
  };

  const handleRevokeAccess = async (bucket) => {
    const targetId = prompt(`Enter Auth0 ID (sub) to kick from ${bucket.name}:`);
    if (!targetId) return;
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/buckets/${bucket.uuid}/share/${targetId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      });
      if(!res.ok) throw new Error("Revocation failed. Are they the owner?");
      alert("Access revoked.");
    } catch (err) { alert(err.message); }
  }

  // ==========================================
  // FILES (VAULT)
  // ==========================================
  const openBucket = async (bucket) => {
    setActiveBucket(bucket);
    setActiveView('vault');
    fetchFiles(bucket.uuid);
  };

  const fetchFiles = async (bucketUuid) => {
    setIsFetching(true);
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/files`, {
        headers: { 'Authorization': `Bearer ${token}`, 'x-bucket-uuid': bucketUuid }
      });
      const data = await res.json();
      setFiles(data);
    } catch (err) { console.error(err); } finally { setIsFetching(false); }
  };

  const handleUpload = async (e) => {
    const file = e.target.files[0];
    if (!file || !activeBucket) return;
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch(`${API_BASE}/vault/files`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'x-bucket-uuid': activeBucket.uuid },
        body: formData 
      });
      if (!res.ok) throw new Error("Upload rejected by Gateway");
      alert("File securely vaulted!");
      fetchFiles(activeBucket.uuid);
      fetchUsage(); // Update quota
    } catch (err) { alert(err.message); } finally { e.target.value = null; }
  };

  const deleteFile = async (uuid, filename) => {
    if(!confirm(`WARNING: Are you sure you want to permanently delete '${filename}'? This triggers a physical wipe on the Spoke.`)) return;
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/files/${uuid}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!res.ok) throw new Error("Deletion failed.");
      alert("File permanently purged.");
      fetchFiles(activeBucket.uuid);
      fetchUsage(); // Update quota
    } catch (err) { alert(err.message); }
  }

  const downloadFile = async (uuid, fileName, versionNum = null) => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const url = versionNum ? `${API_BASE}/vault/files/${uuid}/content?v=${versionNum}` : `${API_BASE}/vault/files/${uuid}/content`;
      const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` }});
      if (!res.ok) throw new Error("Access denied.");
      const blob = await res.blob();
      const objUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = objUrl; a.download = versionNum ? `v${versionNum}_${fileName}` : fileName; 
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => window.URL.revokeObjectURL(objUrl), 1000); 
    } catch (err) { alert("Download Error: " + err.message); }
  };

  const generateFileLink = async (uuid) => {
    const ttl = prompt("Minutes until link expires:", "60");
    if (!ttl) return;
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/files/${uuid}/links?ttl=${ttl}&permission=downloadable`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await res.json();
      prompt("Copy secure link:", data.share_url);
    } catch (err) { alert("Error: " + err.message); }
  };

  // ==========================================
  // INSPECTOR & PREVIEW LOGIC
  // ==========================================
  const openInspector = async (file) => {
    setInspectorModal({ open: true, file });
    setFileVersions([]);
    setPreviewData({ url: null, isLoading: false, versionNum: null });
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/files/${file.uuid}/versions`, { headers: { Authorization: `Bearer ${token}` }});
      const data = await res.json();
      setFileVersions(data);
      if (data.length > 0) loadPreview(file, data[0].version_num);
    } catch (err) { console.error(err); }
  };

  const closeInspector = () => {
    if (previewData.url) window.URL.revokeObjectURL(previewData.url); 
    setInspectorModal({ open: false, file: null });
  };

  const loadPreview = async (file, versionNum) => {
    if (previewData.url) window.URL.revokeObjectURL(previewData.url);
    setPreviewData({ url: null, isLoading: true, versionNum });
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/files/${file.uuid}/content?v=${versionNum}`, { headers: { Authorization: `Bearer ${token}` }});
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      setPreviewData({ url, isLoading: false, versionNum });
    } catch (err) { setPreviewData({ url: null, isLoading: false, versionNum }); }
  };

  // ==========================================
  // ADMIN LOGIC (GOD MODE)
  // ==========================================
  const loadAdminData = async () => {
    setActiveView('admin');
    setIsFetching(true);
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/audit`, { headers: { Authorization: `Bearer ${token}` }});
      if(res.ok) setAuditLogs(await res.json());
    } catch (err) { console.error(err); } finally { setIsFetching(false); }
  }

  const runAdminAudit = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/admin/sync`, { headers: { Authorization: `Bearer ${token}` }});
      const data = await res.json();
      setAdminSyncReport(data.results);
    } catch (err) { alert("Audit Failed: " + err.message); }
  };

  const executeAdminPurge = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/admin/sync`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(adminSyncReport)
      });
      const data = await res.json();
      alert(data.details);
      setAdminSyncReport(null); 
    } catch (err) { alert(err.message); }
  };

  const triggerBenchmark = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      // Sends a dummy stream to trigger the rate limiter/benchmark
      const res = await fetch(`${API_BASE}/vault/admin/performance-test`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        body: "DUMMY_STRESS_PAYLOAD" 
      });
      setBenchmarkResult(await res.json());
    } catch (err) { alert("Benchmark Failed. Spoke unreachable?"); }
  }

  const simulateBitRot = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const dummyPayload = [{ path: "demo-path.enc", hash: "invalid-hash-123" }];
      const res = await fetch(`${API_BASE}/vault/admin/bitrot-report`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(dummyPayload)
      });
      const data = await res.json();
      alert(`Simulation Complete: ${data.corrupted} files marked corrupted. Check Audit Logs.`);
      loadAdminData(); // Refresh logs
    } catch (err) { alert(err.message); }
  }

  // ==========================================
  // UI HELPERS
  // ==========================================
  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024, sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const isPreviewable = (mimeType) => mimeType && (mimeType.startsWith('image/') || mimeType.startsWith('text/') || mimeType === 'application/pdf');

  if (isLoading) return <div className="loading">Initializing Secure Protocol...</div>;

  return (
    <div className="App">
      <h1>RiccBox: Secure Dark Cloud</h1>

      {!isAuthenticated ? (
        <div className="login-gate">
          {error && <p className="error">Auth Error: {error.message}</p>}
          <button onClick={login}>Authenticate M2M Protocol</button>
        </div>
      ) : (
        <div className="vault-interface">
          {/* HEADER & QUOTA */}
          <header style={{ marginBottom: '20px', borderBottom: '1px solid #444', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <p>Identity: <strong>{user.email}</strong> <span className="badge">{userRole.toUpperCase()}</span></p>
              <button onClick={logout} style={{background: 'transparent', border: '1px solid #888'}}>End Session</button>
            </div>
            
            {/* Quota Progress Bar */}
            {usage && (
              <div style={{ fontSize: '0.8rem', color: '#aaa' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span>Storage Quota</span>
                  <span>{formatBytes(usage.used_bytes)} / {formatBytes(usage.quota_bytes)} ({usage.percent_used}%)</span>
                </div>
                <div style={{ width: '100%', background: '#333', height: '8px', borderRadius: '4px', marginTop: '5px', overflow: 'hidden' }}>
                  <div style={{ height: '100%', background: usage.percent_used > 80 ? '#f44336' : '#4CAF50', width: `${usage.percent_used}%` }}></div>
                </div>
              </div>
            )}

            {/* Nav Tabs */}
            <div style={{ marginTop: '15px', display: 'flex', gap: '10px' }}>
              <button onClick={() => setActiveView('lobby')} style={{ opacity: activeView === 'lobby' ? 1 : 0.5 }}>Namespaces (Lobby)</button>
              {userRole === 'admin' && (
                <button onClick={loadAdminData} style={{ opacity: activeView === 'admin' ? 1 : 0.5, backgroundColor: '#d32f2f', color: 'white' }}>
                  God Mode (Admin)
                </button>
              )}
            </div>
          </header>

          {/* VIEW 1: LOBBY */}
          {activeView === 'lobby' && (
            <div className="vault-container">
              <h2>Data Namespaces</h2>
              <div className="toolbar" style={{ display: 'flex', gap: '10px', marginBottom: '15px' }}>
                <button onClick={fetchBuckets} disabled={isFetching}>Refresh</button>
                <button onClick={() => setShowCreateModal(!showCreateModal)} style={{ backgroundColor: '#4CAF50', color: 'white' }}>+ Provison Bucket</button>
              </div>

              {showCreateModal && (
                <form onSubmit={handleCreateBucket} className="inline-form" style={{ background: '#222', padding: '10px', marginBottom: '15px' }}>
                  <input type="text" placeholder="Bucket Name" value={newBucketName} onChange={(e) => setNewBucketName(e.target.value)} required />
                  <button type="submit">Deploy</button>
                </form>
              )}

              {shareBucketModal.open && (
                <div className="modal" style={{ padding: '15px', background: '#333', marginBottom: '15px', borderLeft: '4px solid #ff9800' }}>
                  <h3>RBAC Policy: '{shareBucketModal.bucket.name}'</h3>
                  <form onSubmit={handleShareBucket}>
                    <input type="text" placeholder="User Auth0 sub" value={shareEmail} onChange={(e) => setShareEmail(e.target.value)} required />
                    <select value={sharePermission} onChange={(e) => setSharePermission(e.target.value)}>
                      <option value="READ">Viewer (Read Only)</option>
                      <option value="WRITE">Editor (Read / Write)</option>
                    </select>
                    <button type="submit">Attach Policy</button>
                    <button type="button" onClick={() => setShareBucketModal({open: false, bucket: null})}>Cancel</button>
                  </form>
                </div>
              )}

              {buckets.length > 0 ? (
                <table className="vault-table">
                  <thead><tr><th>Name</th><th>Region</th><th>UUID</th><th>Management</th></tr></thead>
                  <tbody>
                    {buckets.map((bucket) => (
                      <tr key={bucket.uuid}>
                        <td><strong>{bucket.name}</strong></td>
                        <td><span className="badge">{bucket.region}</span></td>
                        <td><small>{bucket.uuid.split('-')[0]}</small></td>
                        <td>
                          <button onClick={() => openBucket(bucket)}>Enter</button>
                          <button onClick={() => handleRenameBucket(bucket)} style={{ marginLeft: '5px' }}>✎ Edit</button>
                          <button onClick={() => setShareBucketModal({ open: true, bucket })} style={{ marginLeft: '5px', backgroundColor: '#ff9800', color: 'white' }}>Add Guest</button>
                          <button onClick={() => handleRevokeAccess(bucket)} style={{ marginLeft: '5px', backgroundColor: '#d32f2f', color: 'white' }}>Kick</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : <p>No buckets provisioned.</p>}
            </div>
          )}

          {/* VIEW 2: VAULT */}
          {activeView === 'vault' && activeBucket && (
            <div className="vault-container">
              <div style={{ display: 'flex', alignItems: 'center', gap: '15px', marginBottom: '15px' }}>
                <button onClick={() => setActiveView('lobby')}>← Exit Vault</button>
                <h2>{activeBucket.name}</h2>
              </div>
              <div className="toolbar" style={{ display: 'flex', gap: '10px', marginBottom: '15px' }}>
                <button onClick={() => fetchFiles(activeBucket.uuid)} disabled={isFetching}>Refresh</button>
                <input type="file" ref={fileInputRef} style={{ display: 'none' }} onChange={handleUpload} />
                <button onClick={() => fileInputRef.current.click()} style={{ backgroundColor: '#2196F3', color: 'white' }}>Upload Encrypted</button>
              </div>

              {files.length > 0 ? (
                <table className="vault-table">
                  <thead><tr><th>File</th><th>Size</th><th>Created</th><th>Actions</th></tr></thead>
                  <tbody>
                    {files.map((file) => (
                      <tr key={file.uuid}>
                        <td><strong style={{ cursor: 'pointer', color: '#2196F3' }} onClick={() => openInspector(file)}>{file.filename}</strong></td>
                        <td>{formatBytes(file.size)}</td>
                        <td>{new Date(file.timestamp).toLocaleDateString()}</td>
                        <td>
                          <button onClick={() => downloadFile(file.uuid, file.filename)}>↓</button>
                          <button onClick={() => generateFileLink(file.uuid)} style={{ marginLeft: '5px', backgroundColor: '#673ab7', color: 'white' }}>🔗</button>
                          <button onClick={() => deleteFile(file.uuid, file.filename)} style={{ marginLeft: '5px', backgroundColor: '#f44336', color: 'white' }}>Nuke</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : <p>Vault is empty.</p>}
            </div>
          )}

          {/* INSPECTOR MODAL */}
          {inspectorModal.open && inspectorModal.file && (
            <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.9)', display: 'flex', padding: '40px', zIndex: 1000 }}>
              <div className="modal-content" style={{ background: '#111', width: '100%', display: 'flex', borderRadius: '8px', border: '1px solid #444' }}>
                <div style={{ flex: 2, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', borderRight: '1px solid #444', padding: '20px' }}>
                  {previewData.isLoading ? <p>Decrypting Stream...</p> : previewData.url && isPreviewable(inspectorModal.file.mime_type) ? (
                      <iframe src={previewData.url} style={{ width: '100%', height: '100%', border: 'none', background: 'white' }} />
                  ) : <div style={{ textAlign: 'center' }}><h1>🔒</h1><h3>No preview available</h3><button onClick={() => downloadFile(inspectorModal.file.uuid, inspectorModal.file.filename, previewData.versionNum)}>Download Securely</button></div>}
                </div>
                <div style={{ flex: 1, padding: '20px', overflowY: 'auto' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
                    <h3 style={{ margin: 0 }}>Versions</h3>
                    <button onClick={closeInspector}>Close</button>
                  </div>
                  {fileVersions.map((v) => (
                      <div key={v.version_num} onClick={() => loadPreview(inspectorModal.file, v.version_num)} style={{ background: previewData.versionNum === v.version_num ? '#2196F3' : '#333', padding: '15px', marginBottom: '10px', cursor: 'pointer' }}>
                          <strong>v{v.version_num}</strong> - {formatBytes(v.size)} <br/>
                          <small>{new Date(v.timestamp).toLocaleString()}</small>
                      </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* VIEW 3: ADMIN PANEL */}
          {activeView === 'admin' && (
            <div className="vault-container admin-panel">
              <h2>Telemetry & Security Console</h2>
              
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
                {/* Audit & Sync */}
                <div style={{ padding: '20px', background: '#2c2c2c', borderLeft: '4px solid #f44336' }}>
                  <h3>Database/Disk Integrity Sync</h3>
                  <button onClick={runAdminAudit} style={{ backgroundColor: '#f44336', color: 'white' }}>Run Set Theory Audit</button>
                  {adminSyncReport && (
                    <div style={{ marginTop: '15px', padding: '10px', background: '#111' }}>
                      <p>Missing (DB only): {adminSyncReport.missingFromDisk.length}</p>
                      <p>Orphans (Disk only): {adminSyncReport.orphanedOnDisk.length}</p>
                      <button onClick={executeAdminPurge} style={{ marginTop: '10px' }}>Execute Physical Purge</button>
                    </div>
                  )}
                </div>

                {/* Network & Bitrot */}
                <div style={{ padding: '20px', background: '#2c2c2c', borderLeft: '4px solid #2196F3' }}>
                  <h3>System Stress & Security</h3>
                  <button onClick={triggerBenchmark} style={{ marginBottom: '10px', width: '100%' }}>Run Network Benchmark</button>
                  {benchmarkResult && <p style={{ fontSize: '0.8rem', color: '#4CAF50' }}>{benchmarkResult.message}: {benchmarkResult.spoke_received_gb}GB transferred.</p>}
                  
                  <button onClick={simulateBitRot} style={{ backgroundColor: '#ff9800', color: 'white', width: '100%' }}>Simulate Bit-Rot Detection</button>
                </div>
              </div>

              {/* Audit Logs */}
              <div style={{ padding: '20px', background: '#2c2c2c', borderTop: '4px solid #4CAF50' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <h3>Live Audit Logs</h3>
                  <button onClick={loadAdminData}>Refresh Logs</button>
                </div>
                <div style={{ maxHeight: '300px', overflowY: 'auto', marginTop: '10px' }}>
                  <table className="vault-table" style={{ fontSize: '0.85rem' }}>
                    <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Status</th></tr></thead>
                    <tbody>
                      {auditLogs.map(log => (
                        <tr key={log.id}>
                          <td>{new Date(log.timestamp).toLocaleTimeString()}</td>
                          <td>{log.user_email}</td>
                          <td style={{ fontFamily: 'monospace' }}>{log.action}</td>
                          <td style={{ color: log.status === 'FAILED' || log.status === 'BLOCKED' ? '#f44336' : '#4CAF50' }}>{log.status}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          )}

        </div>
      )}
    </div>
  );
}

export default App;