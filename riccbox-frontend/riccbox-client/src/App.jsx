import { useState, useRef, useEffect, useMemo } from 'react';
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
  const [currentPrefix, setCurrentPrefix] = useState(''); // State untuk Virtual Folder
  const [uploadProgress, setUploadProgress] = useState(null);
  // --- Admin State ---
  const [adminTab, setAdminTab] = useState('telemetry');
  const [adminSyncReport, setAdminSyncReport] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [benchmarkResult, setBenchmarkResult] = useState(null);
  const [globalFiles, setGlobalFiles] = useState([]);
  const [globalSearch, setGlobalSearch] = useState('');

  // --- Modal & Dialog States ---
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newBucketName, setNewBucketName] = useState('');

  // Share/Invite States
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
  // --- MANAGE ACCESS STATES ---
  const [manageAccessModal, setManageAccessModal] = useState({ open: false, bucket: null, members: [], isLoading: false });

  // Buka Modal & Ambil Daftar Anggota
  const openManageAccess = async (bucket) => {
    setManageAccessModal({ open: true, bucket, members: [], isLoading: true });
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/buckets/${bucket.uuid}/members`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const members = await res.json();
        setManageAccessModal({ open: true, bucket, members, isLoading: false });
      }
    } catch (err) { console.error(err); }
  };

  // Undang / Ubah Akses Anggota
  const handleShareBucket = async (e, directEmail = null, directPermission = null) => {
    if (e) e.preventDefault();
    const targetEmail = directEmail || shareEmail;
    const targetPermission = directPermission || sharePermission;

    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/buckets/${manageAccessModal.bucket.uuid}/share`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: targetEmail, permission: targetPermission })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.message || errData.error);
      }

      // Bersihkan input dan segarkan daftar anggota
      setShareEmail('');
      setSearchResults([]);
      openManageAccess(manageAccessModal.bucket);
      if (!directEmail) setDialog({ open: true, type: 'ALERT', title: 'Access Granted', message: `Invitation sent to ${targetEmail}.` });
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Sharing Error', message: err.message }); }
  };

  // Tendang Anggota (Kick)
  const handleKickMember = async (userId) => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/buckets/${manageAccessModal.bucket.uuid}/share/${userId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!res.ok) throw new Error("Revocation failed.");

      openManageAccess(manageAccessModal.bucket); // Segarkan daftar
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Revoke Error', message: err.message }); }
  };
  const fileInputRef = useRef(null);

  const API_BASE = 'https://richardgatewayta.duckdns.org:8080';
  const AUDIENCE = 'https://richardgatewayta.duckdns.org';

  // ==========================================
  // PRESENTATION LOGIC: VIRTUAL FOLDER ENGINE
  // ==========================================
  const displayItems = useMemo(() => {
    const items = [];
    const folderSet = new Set();

    files.forEach(file => {
      if (file.filename.startsWith(currentPrefix)) {
        const relativePath = file.filename.substring(currentPrefix.length);
        const slashIndex = relativePath.indexOf('/');

        if (slashIndex === -1) {
          // Jangan tampilkan fail "hantu" S3 (.keep) ke user
          if (relativePath !== '.keep') {
            items.push({ type: 'file', ...file, displayName: relativePath });
          }
        } else {
          // Buat folder virtual
          const folderName = relativePath.substring(0, slashIndex);
          if (!folderSet.has(folderName)) {
            folderSet.add(folderName);
            items.push({ type: 'folder', displayName: folderName, uuid: `folder-${folderName}` });
          }
        }
      }
    });

    return items.sort((a, b) => {
      if (a.type === b.type) return a.displayName.localeCompare(b.displayName);
      return a.type === 'folder' ? -1 : 1;
    });
  }, [files, currentPrefix]);

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
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/identity`, { headers: { Authorization: `Bearer ${token}` } });
      const data = await res.json();
      if (data.roles && data.roles.includes('admin')) setUserRole('admin');
    } catch (err) { console.error(err); }
  };

  const fetchUsage = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/usage`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) setUsage(await res.json());
    } catch (err) { console.error(err); }
  };

  const fetchNotifications = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/notifications`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) setNotifications(await res.json());
    } catch (err) { console.error(err); }
  };

  const clearNotifications = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      await fetch(`${API_BASE}/api/v1/vault/notifications/clear`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
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
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });

      if (type === 'RENAME_BUCKET') {
        if (!inputValue) return;
        await fetch(`${API_BASE}/api/v1/vault/buckets/${targetData.uuid}`, {
          method: 'PUT',
          headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: inputValue, region: targetData.region })
        });
        fetchBuckets();
        closeDialog();
      }
      else if (type === 'REVOKE_ACCESS') {
        if (!inputValue) return;
        const res = await fetch(`${API_BASE}/api/v1/vault/buckets/${targetData.uuid}/share/${inputValue}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!res.ok) throw new Error("Revocation failed. Are they the owner?");
        fetchBuckets();
        closeDialog();
        setDialog({ open: true, type: 'ALERT', title: 'Success', message: 'Access revoked successfully.' });
      }
      else if (type === 'DELETE_FILE') {
        const res = await fetch(`${API_BASE}/api/v1/vault/files/${targetData.uuid}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!res.ok) throw new Error("Deletion failed.");

        if (activeView === 'admin') fetchGlobalFiles(globalSearch);
        else fetchFiles(activeBucket.uuid);

        fetchUsage();
        closeDialog();
      }
      else if (type === 'DELETE_BUCKET') {
        // Panggil endpoint DELETE Gateway
        const res = await fetch(`${API_BASE}/api/v1/vault/buckets/${targetData.uuid}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${token}` }
        });

        const data = await res.json();

        // Jika backend menolak (misal: bucket belum kosong)
        if (!res.ok) throw new Error(data.message || data.error);

        // Jika sukses: Segarkan daftar di Lobby, tutup dialog lama, dan tampilkan notifikasi sukses
        fetchBuckets();
        closeDialog();
        setDialog({ open: true, type: 'ALERT', title: 'Namespace Destroyed', message: data.message });
      }
      else if (type === 'GENERATE_LINK') {
        if (!inputValue) return;
        const res = await fetch(`${API_BASE}/api/v1/vault/files/${targetData}/links?ttl=${inputValue}&permission=downloadable`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!res.ok) throw new Error("Failed to generate link.");
        const data = await res.json();
        setDialog({
          open: true, type: 'SHOW_LINK', title: 'Secure Link Generated',
          message: 'Copy your secure, temporary link below:', inputValue: data.share_url
        });
      }
      else if (type === 'CREATE_FOLDER') {
        if (!inputValue) return;

        // Buat fail kosong (0 bytes) bernama .keep sebagai pancingan prefix (Standar S3)
        const dummyFile = new File([""], ".keep", { type: "text/plain" });
        const formData = new FormData();
        formData.append('file', dummyFile);

        const newPrefix = currentPrefix + inputValue + '/';

        const res = await fetch(`${API_BASE}/api/v1/vault/files`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'x-bucket-uuid': activeBucket.uuid,
            'x-file-prefix': newPrefix
          },
          body: formData
        });

        if (!res.ok) throw new Error("Failed to create folder.");
        fetchFiles(activeBucket.uuid);
        closeDialog();
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
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/buckets`, { headers: { Authorization: `Bearer ${token}` } });
      const data = await res.json();
      setBuckets(data.buckets || []);
    } catch (err) { console.error(err); } finally { setIsFetching(false); }
  };

  const handleCreateBucket = async (e) => {
    e.preventDefault();
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      await fetch(`${API_BASE}/api/v1/vault/buckets`, {
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

    if (query.length < 2) {
      setSearchResults([]);
      return;
    }

    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/users/search?q=${encodeURIComponent(query)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (res.ok) {
        const matchingUsers = await res.json();
        setSearchResults(matchingUsers);
      }
    } catch (err) {
      console.error("Search failed", err);
    }
  };


  const triggerRenameBucket = (bucket) => setDialog({ open: true, type: 'RENAME_BUCKET', title: `Rename '${bucket.name}'`, message: 'Enter new bucket name:', inputValue: '', targetData: bucket });

  // ==========================================
  // FILES (VAULT)
  // ==========================================
  const openBucket = async (bucket) => {
    // MENYIMPAN PERMISSION BUCKET SAAT DIBUKA (Fallback default to READ)
    const activePerm = bucket.permission || 'READ';
    setActiveBucket({ ...bucket, permission: activePerm });
    setActiveView('vault');
    setCurrentPrefix('');
    fetchFiles(bucket.uuid);
  };

  const fetchFiles = async (bucketUuid) => {
    setIsFetching(true);
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/files`, {
        headers: { 'Authorization': `Bearer ${token}`, 'x-bucket-uuid': bucketUuid }
      });
      const data = await res.json();
      setFiles(data);
    } catch (err) { console.error(err); } finally { setIsFetching(false); }
  };

  const handleUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    try {
      const token = await getAccessTokenSilently();
      const formData = new FormData();
      formData.append('file', file); // Nama field 'file' harus cocok dengan yang ditangkap Busboy di Gateway

      const xhr = new XMLHttpRequest();

      // 1. Tentukan rute tujuan API Anda
      // Pastikan API_URL Anda sesuai, misalnya: "https://richardgatewayta.duckdns.org:8080"
      const uploadUrl = `/api/v1/vault/files`;
      xhr.open('POST', uploadUrl, true);

      // 2. Pasang semua Header Keamanan (Sangat Penting untuk Zero Trust!)
      xhr.setRequestHeader('Authorization', `Bearer ${token}`);
      xhr.setRequestHeader('x-bucket-uuid', activeBucket.uuid);
      if (currentPrefix) {
        xhr.setRequestHeader('x-file-prefix', currentPrefix);
      }

      // 3. PANTAU KEMAJUAN DI SINI!
      xhr.upload.onprogress = (progressEvent) => {
        if (progressEvent.lengthComputable) {
          const percentComplete = Math.round((progressEvent.loaded / progressEvent.total) * 100);
          // Perbarui state yang sudah kita siapkan sebelumnya
          setUploadProgress({
            filename: file.name,
            percent: percentComplete,
            loaded: progressEvent.loaded,
            total: progressEvent.total
          });
        }
      };

      // 4. Tangani saat unggahan selesai
      xhr.onload = () => {
        if (xhr.status === 200 || xhr.status === 201) {
          console.log("Upload Success!");
          fetchFiles(activeBucket.uuid); // Segarkan tabel fail
          fetchUsage(); // Segarkan kuota
        } else {
          try {
            const errResponse = JSON.parse(xhr.responseText);
            alert(`Upload Failed: ${errResponse.error || errResponse.message}`);
          } catch (e) {
            alert(`Upload Failed: Server Error (${xhr.status},${e})`);
          }
        }
        // Bersihkan state progress dan reset input file
        setTimeout(() => setUploadProgress(null), 1000); // Jeda 1 detik agar animasi 100% terlihat
        if (fileInputRef.current) fileInputRef.current.value = '';
      };

      // 5. Tangani jika koneksi internet terputus
      xhr.onerror = () => {
        alert("Network Error: Could not reach the Gateway.");
        setUploadProgress(null);
        if (fileInputRef.current) fileInputRef.current.value = '';
      };

      // 6. Eksekusi pengiriman data!
      xhr.send(formData);

    } catch (err) {
      console.error("Upload preparation failed:", err);
      alert("Failed to start upload. Please try again.");
    }
  };

  const downloadFile = async (uuid, fileName, versionNum = null) => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const url = versionNum ? `${API_BASE}/api/v1/vault/files/${uuid}/content?v=${versionNum}` : `${API_BASE}/api/v1/vault/files/${uuid}/content`;
      const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) throw new Error("Access denied.");
      const blob = await res.blob();

      const contentDisposition = res.headers.get('Content-Disposition');
      let finalFileName = fileName;
      if (contentDisposition) {
        const fileNameMatch = contentDisposition.match(/filename="(.+)"/);
        if (fileNameMatch && fileNameMatch.length === 2) {
          finalFileName = fileNameMatch[1];
        }
      }

      const objUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = objUrl; a.download = finalFileName;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => window.URL.revokeObjectURL(objUrl), 1000);
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Download Error', message: err.message }); }
  };

  const triggerDeleteFile = (uuid, filename) => setDialog({ open: true, type: 'DELETE_FILE', title: `Purge '${filename}'?`, message: 'WARNING: This triggers a physical wipe on the Spoke. Are you absolutely sure?', targetData: { uuid, filename } });
  const triggerGenerateLink = (uuid) => setDialog({ open: true, type: 'GENERATE_LINK', title: 'Secure Expiration Link', message: 'Minutes until link expires:', inputValue: '60', targetData: uuid });

  // ==========================================
  // INSPECTOR & PREVIEW LOGIC
  // ==========================================
  const openInspector = async (file) => {
    setInspectorModal({ open: true, file });
    setFileVersions([]);
    setPreviewData({ url: null, isLoading: false, versionNum: null }); // Reset preview
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/files/${file.uuid}/versions`, { headers: { Authorization: `Bearer ${token}` } });
      const data = await res.json();
      setFileVersions(data);
      // HAPUS BARIS INI: if (data.length > 0) loadPreview(file, data[0].version_num);
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
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/files/${file.uuid}/content?v=${versionNum}`, { headers: { Authorization: `Bearer ${token}` } });
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      setPreviewData({ url, isLoading: false, versionNum });
    } catch (err) { setPreviewData({ url: null, isLoading: false, versionNum, detail: err.message }); }
  };
  const restoreVersion = async (file, versionNum) => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/files/${file.uuid}/restore?v=${versionNum}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      // Beri notifikasi, lalu segarkan file list dan inspector
      setDialog({ open: true, type: 'ALERT', title: 'Restore Success', message: `Version ${versionNum} has been restored as the newest version (v${data.new_version}).` });

      // Refresh layar
      fetchFiles(activeBucket.uuid);
      openInspector(file); // Refresh versi di modal

    } catch (err) {
      setDialog({ open: true, type: 'ALERT', title: 'Restore Error', message: err.message });
    }
  };

  // ==========================================
  // ADMIN LOGIC (GOD MODE)
  // ==========================================
  const loadAdminData = async () => {
    setActiveView('admin');
    setIsFetching(true);
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/audit`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) setAuditLogs(await res.json());

      if (adminTab === 'global_files') fetchGlobalFiles();
    } catch (err) { console.error(err); } finally { setIsFetching(false); }
  }

  const fetchGlobalFiles = async (searchQuery = '') => {
    setIsFetching(true);
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/files?search=${encodeURIComponent(searchQuery)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) setGlobalFiles(await res.json());
    } catch (err) { console.error("Global fetch failed", err); } finally { setIsFetching(false); }
  };

  const runAdminAudit = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/admin/sync`, { headers: { Authorization: `Bearer ${token}` } });
      const data = await res.json();
      setAdminSyncReport(data.results);
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Audit Failed', message: err.message }); }
  };

  const executeAdminPurge = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
      const res = await fetch(`${API_BASE}/api/v1/vault/admin/sync`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(adminSyncReport)
      });
      const data = await res.json();
      setDialog({ open: true, type: 'ALERT', title: 'Purge Complete', message: data.details });
      setAdminSyncReport(null);
    } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Purge Error', message: err.message }); }
  };

  // const runNetworkBenchmark = async () => {
  //   try {
  //     const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });
  //     const res = await fetch(`${API_BASE}/api/v1/vault/admin/test/performance`, {
  //       method: 'POST', headers: { 'Authorization': `Bearer ${token}` }, body: "DUMMY_STRESS_PAYLOAD"
  //     });
  //     setBenchmarkResult(await res.json());
  //   } catch (err) { setDialog({ open: true, type: 'ALERT', title: 'Test Failed', message: "Spoke unreachable?", detail: err.message }); }
  // }
  const runNetworkBenchmark = async () => {
    try {
      const token = await getAccessTokenSilently();

      console.log("Generating 1GB of dummy payload...");
      const payloadSize = 1 * 1024 * 1024 * 1024; // 1 GB
      const dummyPayload = new Uint8Array(payloadSize);

      console.log("Transmitting payload through Jakarta Gateway to Surabaya Spoke...");

      const startTime = performance.now();

      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${API_BASE}/api/v1/vault/admin/test/performance`, true);

      xhr.setRequestHeader('Authorization', `Bearer ${token}`);
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');

      xhr.upload.onprogress = (progressEvent) => {
        if (progressEvent.lengthComputable) {
          const percentComplete = Math.round((progressEvent.loaded / progressEvent.total) * 100);
          setUploadProgress({
            filename: "BENCHMARK_1GB_STRESS_TEST.bin", // Nama samaran untuk UI
            percent: percentComplete,
            loaded: progressEvent.loaded,
            total: progressEvent.total
          });
        }
      };

      xhr.onload = () => {
        const endTime = performance.now();

        // Bersihkan progres bar setelah 1 detik
        setTimeout(() => setUploadProgress(null), 1000);

        let result = {};
        try {
          result = JSON.parse(xhr.responseText);
        } catch (parseError) {
          console.error("Server Response (Not JSON):", xhr.responseText);
          alert(`Server returned an error: ${xhr.status} ${xhr.statusText} ${parseError.message}`);
          return;
        }

        if (xhr.status === 200 || xhr.status === 201) {
          const durationInSeconds = (endTime - startTime) / 1000;
          const speedMBps = (1024 / durationInSeconds).toFixed(2); // Megabytes per second
          const speedMbps = (speedMBps * 8).toFixed(2);

          setBenchmarkResult({
            sent: "1 GB",
            received: `${result.spoke_received_gb} GB`,
            duration: `${durationInSeconds.toFixed(2)} s`,
            speed: `${speedMBps} MB/s (${speedMbps} Mbps)`,
            note: result.note
          });

          alert(` STRESS TEST SUCCESS!\n\nPayload Sent: 1 GB \nSpoke Received: ${result.spoke_received_gb} GB\n\nNote: ${result.note}`);
        } else {
          alert(`Test Failed: ${result.error || 'Unknown Error'}`);
        }
      };

      xhr.onerror = () => {
        console.error("XHR Error Triggered");
        setUploadProgress(null); // Menghapus progres bar dari layar
        alert("Koneksi terputus (Network Error / Timeout). Peladen tetap aman, silakan klik tombol lagi untuk Retry.");
      };

      xhr.onabort = () => {
        console.warn("XHR Aborted");
        setUploadProgress(null); // Menghapus progres bar dari layar
      };

      xhr.send(dummyPayload);

    } catch (err) {
      console.error("Benchmark error:", err);
      alert(`Benchmark interrupted: ${err.message}`);
      setUploadProgress(null);
    }
  };
  const triggerBitRotScan = async () => {
    try {
      const token = await getAccessTokenSilently({ authorizationParams: { audience: AUDIENCE } });

      // 🆕 Tembak endpoint /bitrot/scan yang baru
      const res = await fetch(`${API_BASE}/api/v1/vault/admin/bitrot/scan`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      // Tampilkan notifikasi bahwa pemindaian telah dimulai di latar belakang
      setDialog({ open: true, type: 'ALERT', title: 'Scan Initiated', message: data.message });

    } catch (err) {
      setDialog({ open: true, type: 'ALERT', title: 'Simulation Error', message: err.message });
    }
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
      {/* ========================================== */}
      {/* FLOATING UPLOAD PROGRESS BAR */}
      {/* ========================================== */}
      {uploadProgress && (
        <div style={{
          position: 'fixed',
          bottom: '25px',
          right: '25px',
          background: '#1f2937', // Warna gelap modern
          color: 'white',
          padding: '20px',
          borderRadius: '12px',
          boxShadow: '0 10px 25px rgba(0,0,0,0.5)',
          width: '320px',
          zIndex: 9999, // Pastikan selalu di paling depan
          border: '1px solid #374151'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '10px' }}>
            <span style={{ fontSize: '1.2rem', marginRight: '10px' }}>☁️</span>
            <h4 style={{ margin: '0', fontSize: '1rem', fontWeight: '600' }}>Encrypting & Uploading</h4>
          </div>

          <p style={{ margin: '0 0 15px 0', fontSize: '0.85rem', color: '#9ca3af', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={uploadProgress.filename}>
            {uploadProgress.filename}
          </p>

          {/* Track (Latar Belakang Bar) */}
          <div style={{ width: '100%', background: '#374151', borderRadius: '8px', overflow: 'hidden', height: '12px' }}>
            {/* Fill (Animasi Bar yang berjalan) */}
            <div style={{
              width: `${uploadProgress.percent}%`,
              background: uploadProgress.percent === 100 ? '#10b981' : '#3b82f6', // Berubah hijau saat 100%
              height: '100%',
              transition: 'width 0.3s ease-in-out, background-color 0.3s ease'
            }}></div>
          </div>

          {/* Angka Statistik (MB dan Persentase) */}
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '10px', fontSize: '0.8rem', color: '#9ca3af', fontWeight: '500' }}>
            <span>{uploadProgress.percent}%</span>
            <span>
              {(uploadProgress.loaded / 1024 / 1024).toFixed(2)} MB / {(uploadProgress.total / 1024 / 1024).toFixed(2)} MB
            </span>
          </div>
        </div>
      )}

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
                      <h4 style={{ margin: '0 0 10px 0', borderBottom: '1px solid #555', paddingBottom: '5px', color: '#000' }}>Inbox</h4>
                      {notifications.length === 0 ? <p style={{ fontSize: '0.85rem', color: '#aaa', margin: 0 }}>No new messages.</p> : (
                        <>
                          <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 10px 0', maxHeight: '200px', overflowY: 'auto' }}>
                            {notifications.map(note => (
                              <li key={note.id} style={{ fontSize: '0.85rem', marginBottom: '10px', paddingBottom: '10px', borderBottom: '1px solid #444', color: '#000' }}>
                                <strong>{new Date(note.timestamp).toLocaleTimeString()}</strong><br />
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

              <button onClick={logout} style={{ background: 'transparent', border: '1px solid #888' }}>End Session</button>
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
                  Admin mode
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

              {/* 🆕 PANEL MANAGE ACCESS MODERN */}
              {manageAccessModal.open && (
                <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(17, 24, 39, 0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
                  <div className="modal-content" style={{ background: '#ffffff', width: '500px', maxWidth: '90%', borderRadius: '12px', border: '1px solid #e5e7eb', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)', overflow: 'hidden' }}>

                    {/* Header */}
                    <div style={{ padding: '20px 25px', borderBottom: '1px solid #f3f4f6', display: 'flex', justifyContent: 'space-between', alignItems: 'center', backgroundColor: '#f9fafb' }}>
                      <h3 style={{ margin: 0, color: '#111827' }}>Manage Access: {manageAccessModal.bucket.name}</h3>
                      <button onClick={() => { setManageAccessModal({ open: false, bucket: null, members: [] }); setSearchResults([]); setShareEmail(''); }} style={{ background: 'transparent', border: 'none', color: '#9ca3af', fontSize: '1.2rem', cursor: 'pointer' }}>✖</button>
                    </div>

                    <div style={{ padding: '25px' }}>
                      {/* Form Tambah Orang */}
                      <form onSubmit={(e) => handleShareBucket(e)} style={{ display: 'flex', gap: '10px', marginBottom: '25px' }}>
                        <div style={{ position: 'relative', flex: 2 }}>
                          <input type="email" placeholder="Add email address..." value={shareEmail} onChange={handleEmailSearch} autoComplete="off" required style={{ width: '100%', padding: '10px 14px', boxSizing: 'border-box' }} />
                          {searchResults.length > 0 && (
                            <ul style={{ position: 'absolute', top: '100%', left: 0, right: 0, background: '#fff', border: '1px solid #d1d5db', borderRadius: '8px', margin: '5px 0 0 0', padding: 0, listStyle: 'none', zIndex: 10, boxShadow: '0 4px 6px rgba(0,0,0,0.1)' }}>
                              {searchResults.map(res => (
                                <li key={res.user_id} onClick={() => { setShareEmail(res.email); setSearchResults([]); }} style={{ padding: '10px 14px', cursor: 'pointer', borderBottom: '1px solid #f3f4f6', color: '#374151' }}>
                                  {res.email}
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>
                        <select value={sharePermission} onChange={(e) => setSharePermission(e.target.value)} style={{ flex: 1, padding: '10px' }}>
                          <option value="READ">Viewer</option>
                          <option value="WRITE">Editor</option>
                        </select>
                        <button type="submit" style={{ backgroundColor: '#3b82f6', color: 'white', border: 'none' }}>Invite</button>
                      </form>

                      {/* Daftar Anggota */}
                      <h4 style={{ margin: '0 0 15px 0', color: '#6b7280', fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>People with Access</h4>

                      {manageAccessModal.isLoading ? (
                        <p style={{ color: '#9ca3af', textAlign: 'center' }}>Loading members...</p>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', maxHeight: '250px', overflowY: 'auto' }}>
                          {manageAccessModal.members.map(member => {
                            const isOwner = member.permission === 'ADMIN';
                            return (
                              <div key={member.user_id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px', backgroundColor: '#f9fafb', borderRadius: '8px', border: '1px solid #f3f4f6' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                  <div style={{ width: '36px', height: '36px', borderRadius: '50%', backgroundColor: isOwner ? '#e0e7ff' : '#f3f4f6', color: isOwner ? '#4338ca' : '#6b7280', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold', fontSize: '1.2rem' }}>
                                    {member.email.charAt(0).toUpperCase()}
                                  </div>
                                  <div>
                                    <div style={{ color: '#111827', fontWeight: '600', fontSize: '0.95rem' }}>{member.email}</div>
                                    <div style={{ color: '#6b7280', fontSize: '0.8rem' }}>{isOwner ? 'Workspace Owner' : 'Guest Member'}</div>
                                  </div>
                                </div>

                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                  {isOwner ? (
                                    <span style={{ color: '#9ca3af', fontSize: '0.85rem', paddingRight: '10px' }}>Owner</span>
                                  ) : (
                                    <>
                                      <select
                                        value={member.permission}
                                        onChange={(e) => handleShareBucket(null, member.email, e.target.value)}
                                        style={{ padding: '6px', fontSize: '0.85rem', backgroundColor: 'transparent', border: '1px solid #d1d5db', cursor: 'pointer' }}
                                      >
                                        <option value="READ">Viewer</option>
                                        <option value="WRITE">Editor</option>
                                      </select>
                                      <button onClick={() => handleKickMember(member.user_id)} style={{ backgroundColor: 'transparent', color: '#ef4444', border: 'none', fontSize: '1.2rem', padding: '4px 8px' }} title="Remove Access">
                                        🗑
                                      </button>
                                    </>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
              {buckets.length > 0 ? (
                <table className="vault-table" style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr>
                      <th style={{ padding: '12px' }}>Name</th>
                      <th style={{ padding: '12px' }}>Region</th>
                      <th style={{ padding: '12px' }}>Access</th>
                      <th style={{ padding: '12px' }}>UUID</th>
                      <th style={{ padding: '12px', textAlign: 'right' }}>Management</th>
                    </tr>
                  </thead>
                  <tbody>
                    {buckets.map((bucket) => {
                      // Menentukan apakah pengguna adalah pemilik asli (ADMIN) atau tamu
                      const isOwner = bucket.permission === 'ADMIN';

                      return (
                        <tr key={bucket.uuid}>
                          <td style={{ padding: '12px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <strong style={{ color: '#111827' }}>{bucket.name}</strong>
                            {isOwner ? (
                              <span style={{ fontSize: '0.7rem', backgroundColor: '#e0e7ff', color: '#4338ca', padding: '4px 8px', borderRadius: '12px', fontWeight: 'bold' }}>OWNER</span>
                            ) : (
                              <span style={{ fontSize: '0.7rem', backgroundColor: '#fef3c7', color: '#d97706', padding: '4px 8px', borderRadius: '12px', fontWeight: 'bold' }}>GUEST</span>
                            )}
                          </td>
                          <td style={{ padding: '12px' }}>
                            <span className="badge" style={{ background: '#f3f4f6', color: '#4b5563', border: '1px solid #e5e7eb' }}>
                              {bucket.region}
                            </span>
                          </td>
                          <td style={{ padding: '12px' }}>
                            <span style={{
                              background: bucket.permission === 'ADMIN' ? '#fee2e2' : bucket.permission === 'WRITE' ? '#fef3c7' : '#dcfce7',
                              color: bucket.permission === 'ADMIN' ? '#991b1b' : bucket.permission === 'WRITE' ? '#92400e' : '#166534',
                              padding: '6px 12px', borderRadius: '12px', fontSize: '0.75rem', fontWeight: 'bold'
                            }}>
                              {bucket.permission}
                            </span>
                          </td>
                          <td style={{ padding: '12px', fontFamily: 'monospace', color: '#6b7280' }}>
                            <small>{bucket.uuid.split('-')[0]}</small>
                          </td>
                          <td style={{ padding: '12px', textAlign: 'right' }}>
                            <button onClick={() => openBucket(bucket)} style={{ background: '#3b82f6', color: '#fff', border: 'none' }}>Enter</button>

                            {/* 🔒 RBAC LOBBY: HANYA ADMIN BUCKET YANG BISA MENGUBAH / MENGUNDANG */}
                            {isOwner && (
                              <>
                                <button onClick={() => triggerRenameBucket(bucket)} style={{ marginLeft: '5px', backgroundColor: '#f3f4f6', color: '#374151', border: '1px solid #d1d5db' }}>✎ Rename</button>

                                {/* 🆕 TOMBOL SAKTI MANAGE ACCESS */}
                                <button onClick={() => openManageAccess(bucket)} style={{ marginLeft: '5px', backgroundColor: '#8b5cf6', color: 'white', border: 'none' }}>
                                  👥 Manage Access
                                </button>

                                <button
                                  onClick={() => setDialog({ open: true, type: 'DELETE_BUCKET', title: `Destroy Namespace '${bucket.name}'?`, message: 'WARNING: This action is irreversible. The namespace must be completely empty before it can be destroyed.', targetData: bucket })}
                                  style={{ marginLeft: '15px', backgroundColor: '#7f1d1d', color: 'white', padding: '6px 10px', borderRadius: '8px', border: 'none', cursor: 'pointer', fontWeight: 'bold' }}
                                >
                                  ☢ Nuke
                                </button>
                              </>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <div style={{ textAlign: 'center', padding: '40px', color: '#6b7280', border: '1px dashed #d1d5db', borderRadius: '8px' }}>
                  <span style={{ fontSize: '3rem', display: 'block', marginBottom: '10px' }}>📦</span>
                  No namespaces provisioned yet.
                </div>
              )}
            </div>
          )}

          {/* VIEW 2: VAULT (VIRTUAL FOLDER VIEW) */}
          {activeView === 'vault' && activeBucket && (
            <div className="vault-container" style={{ background: '#ffffff', padding: '25px', borderRadius: '8px' }}>

              {/* BREADCRUMB NAVIGATION */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px', fontSize: '1.2rem' }}>
                <button onClick={() => setActiveView('lobby')} style={{ background: '#333', border: 'none', padding: '8px 12px', borderRadius: '4px', cursor: 'pointer', color: '#fff' }}>← Lobby</button>
                <span style={{ color: '#aaa', margin: '0 5px' }}>|</span>
                <strong style={{ cursor: 'pointer', color: currentPrefix === '' ? '#000000' : '#2196F3' }} onClick={() => setCurrentPrefix('')}>
                  {activeBucket.name}
                </strong>

                {/* Render alur folder */}
                {currentPrefix.split('/').filter(Boolean).map((part, index, array) => {
                  const pathSoFar = array.slice(0, index + 1).join('/') + '/';
                  return (
                    <span key={pathSoFar} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{ color: '#555' }}>/</span>
                      <strong
                        style={{ cursor: 'pointer', color: pathSoFar === currentPrefix ? '#000' : '#2196F3' }}
                        onClick={() => setCurrentPrefix(pathSoFar)}
                      >
                        {part}
                      </strong>
                    </span>
                  );
                })}
              </div>
              <div style={{ textAlign: 'right', backgroundColor: '#f9fafb', padding: '8px 12px', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
                <div style={{ fontSize: '0.75rem', color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '2px' }}>
                  Namespace Metadata
                </div>
                <div style={{ fontSize: '0.9rem', color: '#111827', display: 'flex', alignItems: 'center', gap: '8px', justifyContent: 'flex-end' }}>
                  {/* Tampilkan Email Pemilik */}
                  <span title="Bucket Owner">
                    👤 {activeBucket.permission === 'ADMIN' ? 'You (Owner)' : activeBucket.owner_email || 'Unknown Owner'}
                  </span>
                  <span style={{ color: '#d1d5db' }}>|</span>
                  {/* Tampilkan Izin Pengguna Saat Ini */}
                  <span title="Your Access Level">
                    🔑 Access: <strong style={{ color: activeBucket.permission === 'READ' ? '#166534' : '#92400e' }}>{activeBucket.permission}</strong>
                  </span>
                </div>
              </div>


              <div className="toolbar" style={{ display: 'flex', gap: '10px', marginBottom: '20px', borderBottom: '1px solid #444', paddingBottom: '15px' }}>
                <button onClick={() => fetchFiles(activeBucket.uuid)} disabled={isFetching} style={{ background: '#333', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}>↻ Refresh</button>

                {/* 🔒 RBAC VAULT: HANYA MUNCUL JIKA BUKAN READ */}
                {activeBucket.permission !== 'READ' && (
                  <>
                    <button
                      onClick={() => setDialog({ open: true, type: 'CREATE_FOLDER', title: 'New Folder', message: 'Enter new folder name:' })}
                      style={{ backgroundColor: '#2196F3', color: 'white', fontWeight: 'bold', border: 'none', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}>
                      + New Folder
                    </button>

                    <input type="file" ref={fileInputRef} style={{ display: 'none' }} onChange={handleUpload} />
                    <button onClick={() => fileInputRef.current.click()} style={{ backgroundColor: '#4CAF50', color: 'white', fontWeight: 'bold', border: 'none', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}>
                      + Upload to {currentPrefix === '' ? 'Root' : currentPrefix.split('/').slice(-2, -1)[0]}
                    </button>
                  </>
                )}
              </div>

              {displayItems.length > 0 ? (
                <table className="vault-table" style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
                  <thead style={{ borderBottom: '2px solid #444', color: '#aaa', fontSize: '0.9rem' }}>
                    <tr>
                      <th style={{ padding: '12px', color: '#000' }}>Name</th>
                      <th style={{ padding: '12px', color: '#000' }}>Size</th>
                      <th style={{ padding: '12px', color: '#000' }}>Modified</th>
                      <th style={{ padding: '12px', textAlign: 'right', color: '#000' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayItems.map((item) => (
                      <tr key={item.uuid} style={{ borderBottom: '1px solid #e0e0e0' }}>
                        <td style={{ padding: '12px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                          {item.type === 'folder' ? (
                            <>
                              <span style={{ fontSize: '1.5rem' }}>📁</span>
                              <strong style={{ cursor: 'pointer', color: '#000' }} onClick={() => setCurrentPrefix(currentPrefix + item.displayName + '/')}>
                                {item.displayName}
                              </strong>
                            </>
                          ) : (
                            <>
                              <span style={{ fontSize: '1.5rem' }}>📄</span>
                              <span style={{ cursor: 'pointer', color: '#2196F3' }} onClick={() => openInspector(item)}>
                                {item.displayName}
                              </span>
                            </>
                          )}
                        </td>
                        <td style={{ padding: '12px', color: '#555' }}>{item.type === 'folder' ? '-' : formatBytes(item.size)}</td>
                        <td style={{ padding: '12px', color: '#555' }}>{item.type === 'folder' ? '-' : new Date(item.timestamp).toLocaleDateString()}</td>
                        <td style={{ padding: '12px', textAlign: 'right' }}>
                          {item.type === 'file' && (
                            <>
                              <button title="Download File securely" onClick={() => downloadFile(item.uuid, item.filename)} style={{ background: '#e0e0e0', border: '1px solid #aaa', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer', color: '#000' }}>↓</button>

                              {/* 🔒 RBAC VAULT: SEMBUNYIKAN UNTUK VIEWER */}
                              {activeBucket.permission !== 'READ' && (
                                <>
                                  <button title="Generate Shareable Link" onClick={() => triggerGenerateLink(item.uuid)} style={{ marginLeft: '5px', backgroundColor: '#673ab7', color: 'white', padding: '4px 8px', borderRadius: '4px', border: 'none', cursor: 'pointer' }}>🔗</button>
                                  <button title="Delete File" onClick={() => triggerDeleteFile(item.uuid, item.filename)} style={{ marginLeft: '5px', backgroundColor: '#f44336', color: 'white', padding: '4px 8px', borderRadius: '4px', border: 'none', cursor: 'pointer' }}>🗑</button>
                                </>
                              )}
                            </>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div style={{ textAlign: 'center', padding: '40px', color: '#000', border: '1px dashed #444', borderRadius: '8px' }}>
                  <span style={{ fontSize: '3rem', display: 'block', marginBottom: '10px' }}>📭</span>
                  {currentPrefix === '' ? 'Bucket is empty.' : 'Folder is empty.'} {activeBucket.permission !== 'READ' && 'Drop files here to upload.'}
                </div>
              )}
            </div>
          )}

          {/* INSPECTOR MODAL */}
          {inspectorModal.open && inspectorModal.file && (
            <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', padding: '40px', zIndex: 1000 }}>
              <div className="modal-content" style={{ display: 'flex', flexWrap: 'wrap', background: '#ffffff', width: '100%', borderRadius: '12px', border: '1px solid #e5e7eb', overflow: 'hidden' }}>

                {/* PANEL KIRI (PRATILIK) */}
                <div style={{ flex: '2 1 300px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', borderRight: '1px solid #e5e7eb', padding: '20px', backgroundColor: '#f9fafb' }}>
                  {previewData.isLoading ? (
                    <div className="loading">Decrypting Stream...</div>
                  ) : previewData.url && isPreviewable(inspectorModal.file.mime_type) ? (
                    <iframe src={previewData.url} style={{ width: '100%', height: '100%', border: 'none', background: 'white', borderRadius: '8px', boxShadow: '0 4px 6px rgba(0,0,0,0.05)' }} />
                  ) : previewData.url ? (
                    <div style={{ textAlign: 'center', color: '#374151' }}>
                      <span style={{ fontSize: '4rem', display: 'block', marginBottom: '15px' }}>🔒</span>
                      <h3 style={{ margin: '0 0 15px 0' }}>No visual preview available</h3>
                      <button onClick={() => downloadFile(inspectorModal.file.uuid, inspectorModal.file.filename, previewData.versionNum)} style={{ backgroundColor: '#3b82f6', color: 'white', fontWeight: 'bold' }}>
                        Download Securely
                      </button>
                    </div>
                  ) : (
                    <div style={{ flex: '1 1 300px', textAlign: 'center', color: '#6b7280' }}>
                      <span style={{ fontSize: '4rem', display: 'block', marginBottom: '15px' }}>👁️</span>
                      <h3 style={{ margin: '0 0 10px 0' }}>Preview Hidden</h3>
                      <p style={{ margin: 0, fontSize: '0.9rem' }}>Select a version and click "Preview" to load the encrypted stream.</p>
                    </div>
                  )}
                </div>

                {/* PANEL KANAN (DAFTAR VERSI) */}
                <div style={{ flex: 1, padding: '25px', overflowY: 'auto', backgroundColor: '#ffffff' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '25px', borderBottom: '1px solid #e5e7eb', paddingBottom: '15px' }}>
                    <h3 style={{ margin: 0, color: '#111827' }}>Version History</h3>
                    <button onClick={closeInspector} style={{ background: 'transparent', color: '#6b7280', border: '1px solid #d1d5db' }}>Close</button>
                  </div>

                  {fileVersions.map((v, index) => {
                    const isLatest = index === 0;
                    const isBeingPreviewed = previewData.versionNum === v.version_num;

                    return (
                      <div key={v.version_num} style={{
                        background: isBeingPreviewed ? '#eff6ff' : '#ffffff',
                        border: `1px solid ${isBeingPreviewed ? '#3b82f6' : '#e5e7eb'}`,
                        padding: '15px',
                        marginBottom: '12px',
                        borderRadius: '8px',
                        transition: 'all 0.2s ease',
                        boxShadow: isBeingPreviewed ? '0 2px 4px rgba(59, 130, 246, 0.1)' : 'none'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '10px' }}>
                          <div>
                            <strong style={{ color: '#111827', fontSize: '1.1rem' }}>v{v.version_num}</strong>
                            {isLatest && <span style={{ marginLeft: '8px', fontSize: '0.7rem', background: '#dcfce7', color: '#166534', padding: '2px 6px', borderRadius: '4px', fontWeight: 'bold' }}>LATEST</span>}
                            <br />
                            <small style={{ color: '#6b7280' }}>{formatBytes(v.size)} • {new Date(v.timestamp).toLocaleString()}</small>
                          </div>
                        </div>

                        {/* TOMBOL AKSI UNTUK MASING-MASING VERSI */}
                        <div style={{ display: 'flex', gap: '8px', marginTop: '15px' }}>
                          <button
                            onClick={() => loadPreview(inspectorModal.file, v.version_num)}
                            style={{ flex: 1, backgroundColor: isBeingPreviewed ? '#3b82f6' : '#f3f4f6', color: isBeingPreviewed ? 'white' : '#374151', padding: '6px', fontSize: '0.8rem', border: 'none' }}>
                            {previewData.isLoading && isBeingPreviewed ? 'Loading...' : 'Preview'}
                          </button>

                          {/* 🔒 RBAC: Tombol Restore hanya muncul jika pengguna punya akses WRITE atau ADMIN */}
                          {activeBucket.permission !== 'READ' && !isLatest && (
                            <button
                              onClick={() => restoreVersion(inspectorModal.file, v.version_num)}
                              style={{ flex: 1, backgroundColor: '#10b981', color: 'white', padding: '6px', fontSize: '0.8rem', border: 'none' }}>
                              Restore
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
          {/* VIEW 3: ADMIN PANEL (GOD MODE) */}
          {activeView === 'admin' && (
            <div className="vault-container admin-panel">
              <div style={{ display: 'flex', gap: '15px', marginBottom: '20px', borderBottom: '2px solid #555', paddingBottom: '10px' }}>
                <button onClick={() => { setAdminTab('telemetry'); loadAdminData(); }} style={{ background: adminTab === 'telemetry' ? '#2196F3' : 'transparent', color: adminTab === 'telemetry' ? 'white' : '#aaa', border: 'none', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}>Telemetry & Health</button>
                <button onClick={() => { setAdminTab('global_files'); fetchGlobalFiles(); }} style={{ background: adminTab === 'global_files' ? '#673ab7' : 'transparent', color: adminTab === 'global_files' ? 'white' : '#aaa', border: 'none', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}>Global File Explorer</button>
              </div>

              {/* TAB A: TELEMETRY & AUDIT */}
              {adminTab === 'telemetry' && (
                <>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
                    <div style={{ padding: '20px', background: '#2a2a2a', borderLeft: '4px solid #f44336', borderRadius: '4px' }}>
                      <h3 style={{ marginTop: 0, color: '#fff' }}>Database/Disk Integrity Sync</h3>
                      <button onClick={runAdminAudit} style={{ backgroundColor: '#f44336', color: 'white', padding: '8px 16px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>Run Set Theory Audit</button>
                      {adminSyncReport && (
                        <div style={{ marginTop: '15px', padding: '10px', background: '#333', border: '1px solid #555', borderRadius: '4px' }}>
                          <p style={{ margin: '0 0 5px 0', color: '#fff' }}><strong>Missing (DB only):</strong> {adminSyncReport.missingFromDisk.length}</p>
                          <p style={{ margin: '0 0 10px 0', color: '#fff' }}><strong>Orphans (Disk only):</strong> {adminSyncReport.orphanedOnDisk.length}</p>
                          <button onClick={executeAdminPurge} style={{ backgroundColor: '#f44336', color: 'white', padding: '8px 16px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>Execute Physical Purge</button>
                        </div>
                      )}
                    </div>
                    <div style={{ padding: '20px', background: '#2a2a2a', borderLeft: '4px solid #2196F3', borderRadius: '4px' }}>
                      <h3 style={{ marginTop: 0, color: '#fff' }}>System Stress & Security</h3>
                      <button onClick={runNetworkBenchmark} style={{ marginBottom: '10px', width: '100%', backgroundColor: '#2196F3', color: 'white', padding: '8px 16px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>Run Network Benchmark</button>
                      {benchmarkResult && (
                        <div style={{ marginTop: '10px', padding: '10px', background: '#a4a4a4', borderRadius: '8px' }}>
                          <p>Last Test - Sent: {benchmarkResult.sent} | Received: {benchmarkResult.received}| duration: {benchmarkResult.duration} | speed: {benchmarkResult.speed}</p>
                        </div>
                      )}
                      <button onClick={triggerBitRotScan} style={{ backgroundColor: '#ff9800', color: 'white', width: '100%', padding: '8px 16px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                        Run Bit-Rot Detection
                      </button> </div>
                  </div>
                  <div style={{ padding: '20px', background: '#2a2a2a', borderTop: '4px solid #4CAF50', borderRadius: '4px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <h3 style={{ margin: 0, color: '#fff' }}>Live Audit Logs</h3>
                      <button onClick={loadAdminData} style={{ backgroundColor: '#4CAF50', color: 'white', padding: '8px 16px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>Refresh Logs</button>
                    </div>
                    <div style={{ maxHeight: '300px', overflowY: 'auto', marginTop: '15px', background: '#1e1e1e', border: '1px solid #444', borderRadius: '4px' }}>
                      <table className="vault-table" style={{ fontSize: '0.85rem', color: '#fff', width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                        <thead style={{ background: '#333' }}><tr><th style={{ padding: '8px' }}>Time</th><th style={{ padding: '8px' }}>User</th><th style={{ padding: '8px' }}>Action</th><th style={{ padding: '8px' }}>Status</th></tr></thead>
                        <tbody>
                          {auditLogs.map(log => (
                            <tr key={log.id} style={{ borderBottom: '1px solid #333' }}>
                              <td style={{ padding: '8px' }}>{new Date(log.timestamp).toLocaleTimeString()}</td>
                              <td style={{ padding: '8px', color: '#aaa' }}>{log.user_email}</td>
                              <td style={{ fontFamily: 'monospace', padding: '8px', color: '#2196F3' }}>{log.action}</td>
                              <td style={{ color: log.status === 'FAILED' || log.status === 'BLOCKED' ? '#f44336' : '#4CAF50', padding: '8px', fontWeight: 'bold' }}>{log.status}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </>
              )}

              {/* TAB B: GLOBAL FILE EXPLORER */}
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
                      <button onClick={() => fetchGlobalFiles(globalSearch)} style={{ background: '#673ab7', color: 'white', padding: '8px 16px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>Search</button>
                    </div>
                  </div>

                  {globalFiles.length > 0 ? (
                    <div style={{ overflowX: 'auto', width: '100%' }}>
                      <table className="vault-table" style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
                        <thead style={{ borderBottom: '2px solid #444', color: '#aaa' }}><tr><th style={{ padding: '12px' }}>Filename</th><th style={{ padding: '12px' }}>Bucket ID</th><th style={{ padding: '12px' }}>Size</th><th style={{ padding: '12px' }}>UUID</th><th style={{ padding: '12px', textAlign: 'right' }}>Admin Action</th></tr></thead>
                        <tbody>
                          {globalFiles.map((file) => (
                            <tr key={file.uuid} style={{ borderBottom: '1px solid #333' }}>
                              <td style={{ padding: '12px' }}><strong style={{ color: '#673ab7' }}>{file.filename}</strong></td>
                              <td style={{ padding: '12px', color: '#aaa' }}>{file.bucket_id}</td>
                              <td style={{ padding: '12px', color: '#aaa' }}>{formatBytes(file.size)}</td>
                              <td style={{ padding: '12px', fontFamily: 'monospace', fontSize: '0.8rem', color: '#aaa' }}>{file.uuid.substring(0, 13)}...</td>
                              <td style={{ padding: '12px', textAlign: 'right' }}>
                                <button onClick={() => triggerDeleteFile(file.uuid, file.filename)} style={{ backgroundColor: '#f44336', color: 'white', padding: '4px 8px', fontSize: '0.8rem', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>Force Purge</button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : <p style={{ color: '#aaa' }}>No files found in the global index.</p>}
                </div>
              )}
            </div>
          )}

          {/* UNIVERSAL THEMED DIALOG MODAL */}
          {dialog.open && (() => {
            // Evaluasi logika khusus untuk fitur "Type to Confirm"
            const isDeleteAction = dialog.type === 'DELETE_FILE' || dialog.type === 'DELETE_BUCKET';

            // 🌟 UX FIX: Untuk BUCKET, wajib ketik namanya. Untuk FILE, cukup ketik "DELETE"
            let expectedConfirmation = '';
            if (dialog.type === 'DELETE_BUCKET') {
              expectedConfirmation = dialog.targetData?.name;
            } else if (dialog.type === 'DELETE_FILE') {
              expectedConfirmation = 'DELETE'; // Kata kunci generik yang lebih mudah
            }
            // Mengubah input menjadi huruf besar semua agar pengguna tidak bingung soal kapitalisasi
            const currentInput = dialog.inputValue ? dialog.inputValue.toUpperCase() : '';
            const targetConfirm = expectedConfirmation ? expectedConfirmation.toUpperCase() : '';

            const isConfirmDisabled = isDeleteAction && currentInput !== targetConfirm;
            return (
              <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 2000 }}>
                <div style={{ background: '#222', padding: '25px', borderRadius: '8px', border: '1px solid #555', width: '400px', maxWidth: '90%', boxShadow: '0 4px 20px rgba(0,0,0,0.5)' }}>
                  <h3 style={{ marginTop: 0, color: '#fff', borderBottom: '1px solid #444', paddingBottom: '10px' }}>{dialog.title}</h3>
                  <p style={{ color: isDeleteAction ? '#ff5252' : '#ccc', margin: '15px 0', lineHeight: '1.5' }}>
                    {dialog.message}
                    {isDeleteAction && (
                      <span style={{ display: 'block', marginTop: '10px', color: '#fff' }}>
                        Please type <strong style={{ userSelect: 'none', color: '#ff5252' }}>{expectedConfirmation}</strong> to confirm.
                      </span>
                    )}
                  </p>

                  <form onSubmit={executeDialogAction}>
                    {/* Tambahkan DELETE_FILE dan DELETE_BUCKET agar input text muncul */}
                    {['RENAME_BUCKET', 'REVOKE_ACCESS', 'GENERATE_LINK', 'SHOW_LINK', 'CREATE_FOLDER', 'DELETE_FILE', 'DELETE_BUCKET'].includes(dialog.type) && (
                      <input
                        type="text"
                        value={dialog.inputValue}
                        onChange={(e) => setDialog({ ...dialog, inputValue: e.target.value })}
                        autoFocus
                        readOnly={dialog.type === 'SHOW_LINK'}
                        placeholder={isDeleteAction ? expectedConfirmation : ''}
                        style={{
                          width: '100%', padding: '12px', marginBottom: '20px',
                          background: '#111', color: '#fff', border: '1px solid #555',
                          borderRadius: '4px', boxSizing: 'border-box'
                        }}
                      />
                    )}

                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
                      <button type="button" onClick={closeDialog} style={{ background: 'transparent', color: '#aaa', border: '1px solid #555', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}>
                        {dialog.type === 'SHOW_LINK' || dialog.type === 'ALERT' ? 'Close' : 'Cancel'}
                      </button>

                      {dialog.type !== 'SHOW_LINK' && dialog.type !== 'ALERT' && (
                        <button
                          type="submit"
                          disabled={isConfirmDisabled}
                          style={{
                            background: isDeleteAction ? (isConfirmDisabled ? '#555' : '#f44336') : '#2196F3',
                            color: isConfirmDisabled ? '#888' : 'white',
                            padding: '8px 16px', border: 'none', borderRadius: '4px',
                            cursor: isConfirmDisabled ? 'not-allowed' : 'pointer',
                            transition: 'background 0.3s'
                          }}
                        >
                          {isDeleteAction ? 'Yes, Execute' : 'Confirm'}
                        </button>
                      )}
                    </div>
                  </form>
                </div>
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}

export default App;