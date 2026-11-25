// SmartConnect IndexedDB Offline Scan Queue & Auto-Sync
const SC_DB_NAME = "smartconnect_offline";
const SC_STORE = "scan_queue";

function openQueueDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(SC_DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(SC_STORE)) {
        db.createObjectStore(SC_STORE, { keyPath: "local_id", autoIncrement: true });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function queueOfflineScan(item) {
  const db = await openQueueDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SC_STORE, "readwrite");
    const req = tx.objectStore(SC_STORE).add({
      qr_data: item.qr_data,
      action: item.action || "auto",
      gate_id: item.gate_id || null,
      queued_at: new Date().toISOString(),
    });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function getQueuedScans() {
  const db = await openQueueDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SC_STORE, "readonly");
    const req = tx.objectStore(SC_STORE).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

async function clearQueuedIds(ids) {
  if (!ids.length) return;
  const db = await openQueueDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SC_STORE, "readwrite");
    const store = tx.objectStore(SC_STORE);
    ids.forEach((id) => store.delete(id));
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function syncOfflineQueue(csrfToken, onComplete) {
  const items = await getQueuedScans();
  if (!items.length) {
    if (onComplete) onComplete({ synced: 0, results: [] });
    return;
  }
  const resp = await fetch("/api/sync", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken,
    },
    body: JSON.stringify({ items }),
  });
  if (!resp.ok) throw new Error("Sync failed (" + resp.status + ")");
  const data = await resp.json();
  const syncedIds = (data.results || []).map((r) => r.local_id).filter(Boolean);
  await clearQueuedIds(syncedIds);
  if (onComplete) onComplete(data);
  return data;
}

window.SmartConnectOffline = {
  queueOfflineScan,
  getQueuedScans,
  syncOfflineQueue,
};
