/**
 * OwLance API client.
 *
 * Thin wrapper over the FastAPI backend. Every call is time-boxed and throws
 * a plain Error on failure, so the UI can decide whether to degrade to its
 * built-in sample dataset rather than showing a broken screen.
 */

export const API_BASE =
  (import.meta.env && import.meta.env.VITE_API_URL) || 'http://127.0.0.1:8000';

const DEFAULT_TIMEOUT_MS = 60000;
const TOKEN_KEY = 'owlance.token';

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------
// The token lives in localStorage so a refresh does not sign the user out.
// Every access is guarded: private-mode browsers and embedded webviews can
// make localStorage throw rather than simply return null.

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable; the session simply will not survive a refresh */
  }
}

export function clearToken() {
  setToken(null);
}

function authHeaders(extra) {
  const token = getToken();
  const headers = { ...(extra || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  return Object.keys(headers).length ? headers : undefined;
}

async function request(path, { method = 'GET', body, timeout = DEFAULT_TIMEOUT_MS } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch(`${API_BASE}${path}`, {
      method,
      headers: authHeaders(body ? { 'Content-Type': 'application/json' } : undefined),
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    if (!res.ok) {
      let detail = `${res.status} ${res.statusText}`;
      try {
        const payload = await res.json();
        if (payload && payload.detail) detail = payload.detail;
      } catch {
        /* non-JSON error body; keep the status line */
      }
      throw new Error(detail);
    }

    return await res.json();
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error(`Request timed out after ${Math.round(timeout / 1000)}s`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/** Liveness probe used to show the backend status pill. */
export async function checkHealth() {
  return request('/health', { timeout: 4000 });
}

/** Record assessment authorization before any scanning takes place. */
export async function postConsent({ domain, activeScanAllowed = false }) {
  return request('/consent', {
    method: 'POST',
    body: {
      domain,
      consent_version: '1.0',
      active_scan_allowed: activeScanAllowed,
    },
  });
}

/** Passive attack-surface discovery and composite risk scoring. */
export async function runScan(domain) {
  return request(`/scan/${encodeURIComponent(domain)}`);
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

export async function login({ email, password }) {
  const data = await request('/auth/login', {
    method: 'POST',
    body: { email, password },
    timeout: 15000,
  });
  setToken(data.access_token);
  return data.user;
}

export async function register({ email, password, orgName }) {
  const data = await request('/auth/register', {
    method: 'POST',
    body: { email, password, org_name: orgName || null },
    timeout: 15000,
  });
  setToken(data.access_token);
  return data.user;
}

/** Resolve the stored token to an account, or null if it is absent/expired. */
export async function fetchMe() {
  if (!getToken()) return null;
  try {
    return await request('/auth/me', { timeout: 8000 });
  } catch {
    clearToken();
    return null;
  }
}

export function logout() {
  clearToken();
}

// ---------------------------------------------------------------------------
// History, audit log, derived analytics
// ---------------------------------------------------------------------------

/** Real score history for the signed-in account, oldest first. */
export async function fetchHistory(domain) {
  const qs = domain ? `?domain=${encodeURIComponent(domain)}` : '';
  return request(`/history${qs}`, { timeout: 12000 });
}

export async function fetchAudit({ scanId, limit = 12 } = {}) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (scanId) params.set('scan_id', scanId);
  return request(`/audit?${params}`, { timeout: 12000 });
}

/** Recompute the audit hash chain and report whether it is intact. */
export async function verifyAudit() {
  return request('/audit/verify', { timeout: 15000 });
}

/** Compliance coverage, attack paths, and category risk for a scan. */
export async function fetchAnalytics(scanId) {
  return request(`/analytics/${encodeURIComponent(scanId)}`, { timeout: 20000 });
}

// ---------------------------------------------------------------------------
// WhatsApp passport delivery
// ---------------------------------------------------------------------------

/**
 * Whether Twilio credentials are present on the backend.
 *
 * Lets the UI say "this will really send" vs "this shows a preview" before
 * the user clicks, instead of finding out afterwards.
 */
export async function fetchWhatsAppStatus() {
  return request('/whatsapp/status', { timeout: 8000 });
}

/** Render the exact message body without sending anything. */
export async function previewPassportMessage(snapshot) {
  return request('/whatsapp/preview', {
    method: 'POST',
    body: { snapshot },
    timeout: 10000,
  });
}

/**
 * Send the full current posture to a WhatsApp number.
 *
 * Resolves even when delivery fails: the response carries `delivered`,
 * a plain-language `message`, and the composed `body`. A failed send is
 * something the UI has to show, not an exception to swallow.
 */
export async function sendPassportWhatsApp({ phone, snapshot, scanId }) {
  return request('/whatsapp/send-passport', {
    method: 'POST',
    body: { phone, snapshot, scan_id: scanId || null },
    timeout: 25000,
  });
}

// ---------------------------------------------------------------------------
// Connectors
// ---------------------------------------------------------------------------

/**
 * Ingest an administrator's export from an internal data source.
 *
 * The six sources map to exports every vendor console can produce. The API
 * form of each connector runs this same parser behind an OAuth token, so the
 * analysis is identical either way.
 */
export async function uploadConnector({ sourceId, file, scanId, modelledEalLakhs = 0 }) {
  const params = new URLSearchParams();
  if (scanId) params.set('scan_id', scanId);
  if (modelledEalLakhs) params.set('modelled_eal_lakhs', String(modelledEalLakhs));
  const qs = params.toString();

  const form = new FormData();
  form.append('file', file);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  try {
    const res = await fetch(`${API_BASE}/connectors/${sourceId}${qs ? `?${qs}` : ''}`, {
      method: 'POST',
      // No Content-Type: the browser sets the multipart boundary itself.
      headers: authHeaders(),
      body: form,
      signal: controller.signal,
    });
    if (!res.ok) {
      let detail = `${res.status} ${res.statusText}`;
      try {
        const payload = await res.json();
        if (payload && payload.detail) detail = payload.detail;
      } catch {
        /* keep the status line */
      }
      throw new Error(detail);
    }
    return await res.json();
  } catch (err) {
    if (err.name === 'AbortError') throw new Error('Upload timed out after 30s');
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/** Remove a source's contribution and recompute the score. */
export async function disconnectConnector({ sourceId, scanId }) {
  const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
  return request(`/connectors/${sourceId}${qs}`, { method: 'DELETE', timeout: 15000 });
}

/** URL of a sample export, in the same shape as the real vendor file. */
export function connectorTemplateUrl(sourceId) {
  return `${API_BASE}/connectors/${sourceId}/template`;
}

/** Greedy-ratio knapsack budget optimizer for a completed scan. */
export async function optimize({ scanId, budget }) {
  return request('/optimize', {
    method: 'POST',
    body: { scan_id: scanId, budget },
    timeout: 15000,
  });
}

// ---------------------------------------------------------------------------
// Adapters: backend payloads -> the shapes the dashboard components render.
// Kept here so the view layer never has to know about API field names.
// ---------------------------------------------------------------------------

const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];

/** Title-case the backend's lowercase asset status for display. */
function toDisplayStatus(status) {
  if (!status) return 'Unverified';
  const s = String(status).toLowerCase();
  if (s === 'monitored') return 'Monitored';
  if (s === 'unmonitored') return 'Unmonitored';
  return 'Unverified';
}

export function adaptFindings(findings) {
  return (findings || []).map((f, i) => ({
    id: f.id != null ? f.id : i + 1,
    asset: f.asset || '—',
    issue: f.issue || 'Unclassified finding',
    short: f.short || (f.issue || 'Finding').slice(0, 14),
    cveId: f.cve_id || undefined,
    cvss: f.cvss_score != null ? f.cvss_score : 0,
    epss: f.epss_score != null ? f.epss_score : 0,
    kev: Boolean(f.is_kev),
    confidence: f.confidence != null ? Math.round(f.confidence) : 50,
    cost: f.cost != null ? f.cost : 0,
    reduction: f.reduction != null ? f.reduction : 0,
    severity: SEVERITY_ORDER.indexOf(f.severity) !== -1 ? f.severity : 'Unknown',
    category: f.category || 'Network',
    eal: f.eal != null ? f.eal : 0,
    impact: f.impact != null ? f.impact : 3,
    likelihood: f.likelihood != null ? f.likelihood : 2,
    dataUnavailable: Boolean(f.data_unavailable),
  }));
}

export function adaptAssets(assets) {
  return (assets || []).map((a) => ({
    name: a.asset_name,
    type: a.asset_type || 'Unknown',
    method: a.discovery_method || 'DNS Enum',
    status: toDisplayStatus(a.status),
    risk: a.risk || 'Unknown',
  }));
}

/** Flatten a full /scan response into everything the dashboard needs. */
export function adaptScan(scan) {
  return {
    scanId: scan.scan_id,
    domain: scan.domain,
    scannedAt: scan.scanned_at,
    score: scan.org_score,
    confidence: scan.data_confidence || 'high',
    notes: scan.notes || [],
    cached: Boolean(scan.cached),
    findings: adaptFindings(scan.findings),
    assets: adaptAssets(scan.assets),
  };
}
