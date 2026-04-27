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
  
  // --- Notifications State ---
  const [notifications, setNotifications] = useState([]);
  const [showNotifications, setShowNotifications] = useState(false);

  // --- Data State ---
  const [buckets, setBuckets] = useState([]);
  const [files, setFiles] = useState([]);
  const [activeBucket, setActiveBucket] = useState(null);
  
  // --- Admin State ---
  const [adminTab, setAdminTab] = useState('telemetry'); // 'telemetry' or 'global_files'
  const [adminSyncReport, setAdminSyncReport] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [benchmarkResult, setBenchmarkResult] = useState(null);
  const [globalFiles, setGlobalFiles] = useState([]); // 🆕 For Global Explorer
  const [globalSearch, setGlobalSearch] = useState('');

  // --- Modal & Dialog States ---
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newBucketName, setNewBucketName] = useState('');
  
  // Share/Invite States
  const [shareBucketModal, setShareBucketModal] = useState({ open: false, bucket: null });
  const [shareEmail, setShareEmail] = useState('');
  const [sharePermission, setSharePermission] = useState('READ');
  const [searchResults, setSearchResults] = useState([]); 

  const [inspectorModal, setInspectorModal] = useState({ open: false, file: null });
  const [fileVersions, setFileVersions] = useState([]);
  const [previewData, setPreviewData] = useState({ url: null, isLoading: false, versionNum: null });

  // THE UNIVERSAL DIALOG STATE
  const [dialog, setDialog] = useState({
    open: false, type: '', title: '', message: '', inputValue: '', targetData: null
  });

  const fileInputRef = useRef(null);

  const API_BASE = 'https://richardgatewayta.duckdns.org:8080';
  const AUDIENCE = 'https://richardgatewayta.duckdns.org';

  useEffect(() => {
    if (isAuthenticated) {
      checkIdentity();
      fetchBuckets();
      fetchUsage();
      fetchNotifications();
    }
  }, [isAuthenticated]);

  // ==========================================
  // IDENTITY, QUOTA & NOTIFICATIONS
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
    } catch (err) { console.error(err); }
  };

  const fetchNotifications = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/notifications`, { headers: { Authorization: `Bearer ${token}` }});
      if(res.ok) setNotifications(await res.json());
    } catch (err) { console.error(err); }
  };

  const clearNotifications = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      await fetch(`${API_BASE}/vault/notifications/clear`, { method: 'POST', headers: { Authorization: `Bearer ${token}` }});
      setNotifications([]);
      setShowNotifications(false);
    } catch (err) { console.error(err); }
  };

  const logout = () => auth0Logout({ logoutParams: { returnTo: window.location.origin } });

  // ==========================================
  // UNIVERSAL DIALOG EXECUTOR
  // ==========================================
  const closeDialog = () => setDialog({ open: false, type: '', title: '', message: '', inputValue: '', targetData: null });

  const executeDialogAction = async (e) => {
    e?.preventDefault();
    const { type, inputValue, targetData } = dialog;
    
    if (type === 'ALERT' || type === 'SHOW_LINK') return closeDialog();

    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});

      if (type === 'RENAME_BUCKET') {
        if (!inputValue) return;
        await fetch(`${API_BASE}/vault/buckets/${targetData.uuid}`, {
          method: 'PUT',
          headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: inputValue, region: targetData.region })
        });
        fetchBuckets();
        closeDialog();
      } 
      else if (type === 'REVOKE_ACCESS') {
        if (!inputValue) return;
        const res = await fetch(`${API_BASE}/vault/buckets/${targetData.uuid}/share/${inputValue}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${token}` }
        });
        if(!res.ok) throw new Error("Revocation failed. Are they the owner?");
        fetchBuckets();
        closeDialog();
        setDialog({ open: true, type: 'ALERT', title: 'Success', message: 'Access revoked successfully.' });
      }
      else if (type === 'DELETE_FILE') {
        const res = await fetch(`${API_BASE}/vault/files/${targetData.uuid}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!res.ok) throw new Error("Deletion failed.");
        
        // Refresh appropriate view
        if (activeView === 'admin') fetchGlobalFiles(globalSearch);
        else fetchFiles(activeBucket.uuid);
        
        fetchUsage();
        closeDialog();
      }
      else if (type === 'GENERATE_LINK') {
        if (!inputValue) return;
        const res = await fetch(`${API_BASE}/vault/files/${targetData}/links?ttl=${inputValue}&permission=downloadable`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!res.ok) throw new Error("Failed to generate link.");
        const data = await res.json();
        setDialog({ 
          open: true, type: 'SHOW_LINK', title: 'Secure Link Generated', 
          message: 'Copy your secure, temporary link below:', inputValue: data.share_url 
        });
      }
    } catch (err) {
      setDialog({ open: true, type: 'ALERT', title: 'Error', message: err.message });
    }
  };

  // ==========================================
  // BUCKETS (LOBBY) & INVITATION SYSTEM
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
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Deployment Error', message: err.message }); }
  };
const handleEmailSearch = async (e) => {
    const query = e.target.value;
    setShareEmail(query);
    
    // Don't search if they haven't typed at least 2 characters
    if (query.length < 2) {
      setSearchResults([]);
      return;
    }
    
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      
      // 🆕 FIX: We added ?q=${encodeURIComponent(query)} to the URL
      const res = await fetch(`${API_BASE}/vault/users/search?q=${encodeURIComponent(query)}`, { 
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (res.ok) {
        // The backend already filtered the results using SQL 'LIKE', so we just set them directly!
        const matchingUsers = await res.json();
        setSearchResults(matchingUsers);
      }
    } catch (err) { 
      console.error("Search failed", err); 
    }
  };

  const handleShareBucket = async (e) => {
    e.preventDefault();
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/buckets/${shareBucketModal.bucket.uuid}/share`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: shareEmail, permission: sharePermission })
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.message || errData.error);
      }
      setShareBucketModal({ open: false, bucket: null });
      setShareEmail('');
      setSearchResults([]);
      setDialog({ open: true, type: 'ALERT', title: 'Access Granted', message: `Invitation sent to ${shareEmail}.` });
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Sharing Error', message: err.message }); }
  };

  const triggerRenameBucket = (bucket) => setDialog({ open: true, type: 'RENAME_BUCKET', title: `Rename '${bucket.name}'`, message: 'Enter new bucket name:', inputValue: '', targetData: bucket });
  const triggerRevokeAccess = (bucket) => setDialog({ open: true, type: 'REVOKE_ACCESS', title: `Kick from '${bucket.name}'`, message: 'Enter Auth0 ID (sub) to kick:', inputValue: '', targetData: bucket });

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
      fetchFiles(activeBucket.uuid);
      fetchUsage();
      setDialog({ open: true, type: 'ALERT', title: 'Upload Success', message: 'File securely vaulted!' });
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Upload Failed', message: err.message }); } finally { e.target.value = null; }
  };

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
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Download Error', message: err.message }); }
  };

  const triggerDeleteFile = (uuid, filename) => setDialog({ open: true, type: 'DELETE_FILE', title: `Purge '${filename}'?`, message: 'WARNING: This triggers a physical wipe on the Spoke. Are you absolutely sure?', targetData: {uuid, filename} });
  const triggerGenerateLink = (uuid) => setDialog({ open: true, type: 'GENERATE_LINK', title: 'Secure Expiration Link', message: 'Minutes until link expires:', inputValue: '60', targetData: uuid });

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
    } catch (err) { setPreviewData({ url: null, isLoading: false, versionNum ,detail :err.message}); }
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
      
      // Load Global files if they open the explorer
      if(adminTab === 'global_files') fetchGlobalFiles();
    } catch (err) { console.error(err); } finally { setIsFetching(false); }
  }

  // 🆕 GLOBAL FILE EXPLORER FETCH
  const fetchGlobalFiles = async (searchQuery = '') => {
    setIsFetching(true);
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      // The backend 'GET /vault/files' endpoint handles admin fetching globally based on req.globalRole
      const res = await fetch(`${API_BASE}/vault/files?search=${encodeURIComponent(searchQuery)}`, { 
        headers: { Authorization: `Bearer ${token}` } 
      });
      if(res.ok) setGlobalFiles(await res.json());
    } catch (err) { console.error("Global fetch failed", err); } finally { setIsFetching(false); }
  };

  const runAdminAudit = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/admin/sync`, { headers: { Authorization: `Bearer ${token}` }});
      const data = await res.json();
      setAdminSyncReport(data.results);
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Audit Failed', message: err.message }); }
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
      setDialog({ open: true, type: 'ALERT', title: 'Purge Complete', message: data.details });
      setAdminSyncReport(null); 
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Purge Error', message: err.message }); }
  };

  const triggerBenchmark = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const res = await fetch(`${API_BASE}/vault/admin/performance-test`, {
        method: 'POST', headers: { 'Authorization': `Bearer ${token}` }, body: "DUMMY_STRESS_PAYLOAD" 
      });
      setBenchmarkResult(await res.json());
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Test Failed', message: "Spoke unreachable?" ,detail :err.message }); }
  }

  const simulateBitRot = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE }});
      const dummyPayload = [{ path: "demo-path.enc", hash: "invalid-hash-123" }];
      const res = await fetch(`${API_BASE}/vault/admin/bitrot-report`, {
        method: 'POST', headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(dummyPayload)
      });
      const data = await res.json();
      setDialog({ open: true, type: 'ALERT', title: 'Simulation Complete', message: `${data.corrupted} files marked corrupted. Check Audit Logs.` });
      loadAdminData();
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Simulation Error', message: err.message }); }
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
      <h1>RiccBox</h1>

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
              <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                <p style={{ margin: 0 }}>Identity: <strong>{user.email}</strong> <span className="badge"><br /> role: {userRole.toUpperCase()}</span></p>
                
                {/* THE NOTIFICATION BELL */}
                <div style={{ position: 'relative' }}>
                  <button onClick={() => setShowNotifications(!showNotifications)} style={{ background: 'transparent', border: 'none', fontSize: '1.5rem', cursor: 'pointer', padding: 0 }}>
                    🔔 {notifications.length > 0 && <span style={{ position: 'absolute', top: '-5px', right: '-10px', background: 'red', color: 'white', borderRadius: '50%', padding: '2px 6px', fontSize: '0.7rem', fontWeight: 'bold' }}>{notifications.length}</span>}
                  </button>
                  
                  {showNotifications && (
                    <div style={{ position: 'absolute', top: '35px', left: 0, background: '#e2e2e2', border: '1px solid #555', borderRadius: '4px', width: '300px', zIndex: 100, boxShadow: '0 4px 12px rgba(0,0,0,0.5)', padding: '10px' }}>
                      <h4 style={{ margin: '0 0 10px 0', borderBottom: '1px solid #555', paddingBottom: '5px' }}>Inbox</h4>
                      {notifications.length === 0 ? <p style={{ fontSize: '0.85rem', color: '#aaa', margin: 0 }}>No new messages.</p> : (
                        <>
                          <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 10px 0', maxHeight: '200px', overflowY: 'auto' }}>
                            {notifications.map(note => (
                              <li key={note.id} style={{ fontSize: '0.85rem', marginBottom: '10px', paddingBottom: '10px', borderBottom: '1px solid #444' }}>
                                <strong>{new Date(note.timestamp).toLocaleTimeString()}</strong><br/>
                                {note.message}
                              </li>
                            ))}
                          </ul>
                          <button onClick={clearNotifications} style={{ width: '100%', padding: '5px', fontSize: '0.8rem', background: '#c6bfbf' }}>Clear All</button>
                        </>
                      )}
                    </div>
                  )}
                </div>
              </div>

              <button onClick={logout} style={{background: 'transparent', border: '1px solid #888'}}>End Session</button>
            </div>
            
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
                <button onClick={() => { fetchBuckets(); fetchNotifications(); }} disabled={isFetching}>Refresh</button>
                <button onClick={() => setShowCreateModal(!showCreateModal)} style={{ backgroundColor: '#4CAF50', color: 'white' }}>+ Provison Bucket</button>
              </div>

              {showCreateModal && (
                <form onSubmit={handleCreateBucket} className="inline-form" style={{ background: '#c4c4c4', padding: '10px', marginBottom: '15px' }}>
                  <input type="text" placeholder="Bucket Name" value={newBucketName} onChange={(e) => setNewBucketName(e.target.value)} required />
                  <button type="submit">Deploy</button>
                </form>
              )}

              {shareBucketModal.open && (
                <div className="modal" style={{ padding: '15px', background: '#c4c4c4', marginBottom: '15px', borderLeft: '4px solid #ff9800', color: '#000' }}>
                  <h3 style={{ marginTop: 0 }}>RBAC Policy: '{shareBucketModal.bucket.name}'</h3>
                  <form onSubmit={handleShareBucket}>
                    
                    <div style={{ position: 'relative', marginBottom: '10px' }}>
                      <input 
                        type="email" 
                        placeholder="Search employee email..." 
                        value={shareEmail} 
                        onChange={handleEmailSearch} 
                        autoComplete="off"
                        required 
                        style={{ width: '100%', padding: '10px', boxSizing: 'border-box' }}
                      />
                      {searchResults.length > 0 && (
                        <ul style={{ position: 'absolute', top: '100%', left: 0, right: 0, background: '#fff', border: '1px solid #ccc', margin: 0, padding: 0, listStyle: 'none', zIndex: 10 }}>
                          {searchResults.map(res => (
                            <li 
                              key={res.user_id} 
                              onClick={() => { setShareEmail(res.email); setSearchResults([]); }}
                              style={{ padding: '10px', cursor: 'pointer', borderBottom: '1px solid #eee' }}
                            >
                              {res.email}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>

                    <select value={sharePermission} onChange={(e) => setSharePermission(e.target.value)} style={{ width: '100%', padding: '10px', marginBottom: '10px', boxSizing: 'border-box' }}>
                      <option value="READ">Viewer (Read Only)</option>
                      <option value="WRITE">Editor (Read / Write)</option>
                    </select>
                    
                    <div style={{ display: 'flex', gap: '10px' }}>
                      <button type="submit" style={{ flex: 1, backgroundColor: '#2196F3', color: 'white' }}>Invite User</button>
                      <button type="button" onClick={() => { setShareBucketModal({open: false, bucket: null}); setSearchResults([]); setShareEmail(''); }} style={{ flex: 1 }}>Cancel</button>
                    </div>
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
                          <button onClick={() => triggerRenameBucket(bucket)} style={{ marginLeft: '5px' }}>✎ Edit</button>
                          <button onClick={() => setShareBucketModal({ open: true, bucket })} style={{ marginLeft: '5px', backgroundColor: '#ff9800', color: 'white' }}>Add Guest</button>
                          <button onClick={() => triggerRevokeAccess(bucket)} style={{ marginLeft: '5px', backgroundColor: '#d32f2f', color: 'white' }}>Kick</button>
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
                          <button onClick={() => triggerGenerateLink(file.uuid)} style={{ marginLeft: '5px', backgroundColor: '#673ab7', color: 'white' }}>🔗</button>
                          <button onClick={() => triggerDeleteFile(file.uuid, file.filename)} style={{ marginLeft: '5px', backgroundColor: '#f44336', color: 'white' }}>Nuke</button>
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

          {/* VIEW 3: ADMIN PANEL (GOD MODE) */}
          {activeView === 'admin' && (
             <div className="vault-container admin-panel">
               <div style={{ display: 'flex', gap: '15px', marginBottom: '20px', borderBottom: '2px solid #555', paddingBottom: '10px' }}>
                 <button onClick={() => { setAdminTab('telemetry'); loadAdminData(); }} style={{ background: adminTab === 'telemetry' ? '#2196F3' : 'transparent', color: adminTab === 'telemetry' ? 'white' : '#aaa' }}>Telemetry & Health</button>
                 <button onClick={() => { setAdminTab('global_files'); fetchGlobalFiles(); }} style={{ background: adminTab === 'global_files' ? '#673ab7' : 'transparent', color: adminTab === 'global_files' ? 'white' : '#aaa' }}>Global File Explorer</button>
               </div>

               {/* TAB A: TELEMETRY & AUDIT */}
               {adminTab === 'telemetry' && (
                 <>
                   <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
                     <div style={{ padding: '20px', background: '#d1d1d1', borderLeft: '4px solid #f44336', color: '#000' }}>
                       <h3 style={{ marginTop: 0 }}>Database/Disk Integrity Sync</h3>
                       <button onClick={runAdminAudit} style={{ backgroundColor: '#f44336', color: 'white' }}>Run Set Theory Audit</button>
                       {adminSyncReport && (
                         <div style={{ marginTop: '15px', padding: '10px', background: '#c4c4c4', border: '1px solid #aaa' }}>
                           <p style={{ margin: '0 0 5px 0' }}><strong>Missing (DB only):</strong> {adminSyncReport.missingFromDisk.length}</p>
                           <p style={{ margin: '0 0 10px 0' }}><strong>Orphans (Disk only):</strong> {adminSyncReport.orphanedOnDisk.length}</p>
                           <button onClick={executeAdminPurge} style={{ backgroundColor: '#222', color: 'white' }}>Execute Physical Purge</button>
                         </div>
                       )}
                     </div>
                     <div style={{ padding: '20px', background: '#c4c4c4', borderLeft: '4px solid #2196F3', color: '#000' }}>
                       <h3 style={{ marginTop: 0 }}>System Stress & Security</h3>
                       <button onClick={triggerBenchmark} style={{ marginBottom: '10px', width: '100%', backgroundColor: '#2196F3', color: 'white' }}>Run Network Benchmark</button>
                       {benchmarkResult && <p style={{ fontSize: '0.85rem', color: '#000', fontWeight: 'bold' }}>{benchmarkResult.message}: {benchmarkResult.spoke_received_gb}GB transferred.</p>}
                       <button onClick={simulateBitRot} style={{ backgroundColor: '#ff9800', color: 'white', width: '100%' }}>Simulate Bit-Rot Detection</button>
                     </div>
                   </div>
                   <div style={{ padding: '20px', background: '#c4c4c4', borderTop: '4px solid #4CAF50', color: '#000' }}>
                     <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                       <h3 style={{ margin: 0 }}>Live Audit Logs</h3>
                       <button onClick={loadAdminData} style={{ backgroundColor: '#4CAF50', color: 'white' }}>Refresh Logs</button>
                     </div>
                     <div style={{ maxHeight: '300px', overflowY: 'auto', marginTop: '15px', background: '#e0e0e0', border: '1px solid #aaa' }}>
                       <table className="vault-table" style={{ fontSize: '0.85rem', color: '#000', width: '100%' }}>
                         <thead style={{ background: '#d1d1d1' }}><tr><th>Time</th><th>User</th><th>Action</th><th>Status</th></tr></thead>
                         <tbody>
                           {auditLogs.map(log => (
                             <tr key={log.id} style={{ borderBottom: '1px solid #ccc' }}>
                               <td style={{ padding: '8px' }}>{new Date(log.timestamp).toLocaleTimeString()}</td>
                               <td style={{ padding: '8px' }}>{log.user_email}</td>
                               <td style={{ fontFamily: 'monospace', padding: '8px' }}>{log.action}</td>
                               <td style={{ color: log.status === 'FAILED' || log.status === 'BLOCKED' ? '#d32f2f' : '#388e3c', padding: '8px', fontWeight: 'bold' }}>{log.status}</td>
                             </tr>
                           ))}
                         </tbody>
                       </table>
                     </div>
                   </div>
                 </>
               )}

               {/* 🆕 TAB B: GLOBAL FILE EXPLORER */}
               {adminTab === 'global_files' && (
                 <div style={{ background: '#1e1e1e', padding: '20px', borderRadius: '8px' }}>
                   <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
                     <h3 style={{ margin: 0, color: '#673ab7' }}>Global Data Index</h3>
                     <div style={{ display: 'flex', gap: '10px' }}>
                       <input 
                         type="text" 
                         placeholder="Search all files..." 
                         value={globalSearch} 
                         onChange={(e) => setGlobalSearch(e.target.value)} 
                         onKeyDown={(e) => e.key === 'Enter' && fetchGlobalFiles(globalSearch)}
                         style={{ padding: '8px', borderRadius: '4px', border: '1px solid #555', background: '#333', color: 'white' }}
                       />
                       <button onClick={() => fetchGlobalFiles(globalSearch)} style={{ background: '#673ab7', color: 'white' }}>Search</button>
                     </div>
                   </div>

                   {globalFiles.length > 0 ? (
                     <table className="vault-table">
                       <thead><tr><th>Filename</th><th>Bucket ID</th><th>Size</th><th>UUID</th><th>Admin Action</th></tr></thead>
                       <tbody>
                         {globalFiles.map((file) => (
                           <tr key={file.uuid}>
                             <td><strong style={{ color: '#673ab7' }}>{file.filename}</strong></td>
                             <td>{file.bucket_id}</td>
                             <td>{formatBytes(file.size)}</td>
                             <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{file.uuid.substring(0, 13)}...</td>
                             <td>
                               <button onClick={() => triggerDeleteFile(file.uuid, file.filename)} style={{ backgroundColor: '#f44336', color: 'white', padding: '4px 8px', fontSize: '0.8rem' }}>Force Purge</button>
                             </td>
                           </tr>
                         ))}
                       </tbody>
                     </table>
                   ) : <p style={{ color: '#aaa' }}>No files found in the global index.</p>}
                 </div>
               )}
             </div>
          )}

          {/* UNIVERSAL THEMED DIALOG MODAL */}
          {dialog.open && (
            <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 2000 }}>
              <div style={{ background: '#222', padding: '25px', borderRadius: '8px', border: '1px solid #555', width: '400px', maxWidth: '90%', boxShadow: '0 4px 20px rgba(0,0,0,0.5)' }}>
                <h3 style={{ marginTop: 0, color: '#fff', borderBottom: '1px solid #444', paddingBottom: '10px' }}>{dialog.title}</h3>
                <p style={{ color: dialog.type === 'DELETE_FILE' ? '#ff5252' : '#ccc', margin: '15px 0', lineHeight: '1.5' }}>{dialog.message}</p>
                
                <form onSubmit={executeDialogAction}>
                  {['RENAME_BUCKET', 'REVOKE_ACCESS', 'GENERATE_LINK', 'SHOW_LINK'].includes(dialog.type) && (
                    <input 
                      type="text" 
                      value={dialog.inputValue} 
                      onChange={(e) => setDialog({...dialog, inputValue: e.target.value})}
                      autoFocus
                      readOnly={dialog.type === 'SHOW_LINK'}
                      style={{ 
                        width: '100%', padding: '12px', marginBottom: '20px', 
                        background: '#111', color: '#fff', border: '1px solid #555', 
                        borderRadius: '4px', boxSizing: 'border-box' 
                      }}
                    />
                  )}
                  
                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
                    <button type="button" onClick={closeDialog} style={{ background: 'transparent', color: '#aaa', border: '1px solid #555' }}>
                      {dialog.type === 'SHOW_LINK' || dialog.type === 'ALERT' ? 'Close' : 'Cancel'}
                    </button>
                    
                    {dialog.type !== 'SHOW_LINK' && dialog.type !== 'ALERT' && (
                      <button type="submit" style={{ background: dialog.type === 'DELETE_FILE' ? '#f44336' : '#2196F3', color: 'white' }}>
                        {dialog.type === 'DELETE_FILE' ? 'Yes, Purge File' : 'Confirm'}
                      </button>
                    )}
                  </div>
                </form>
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
}

export default App;