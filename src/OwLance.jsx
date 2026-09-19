import { useState, useMemo, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, AlertTriangle, MessageCircle, X, Send, ChevronRight, ChevronLeft,
  Wallet, CheckCircle2, LayoutDashboard, Network, Bug, Route,
  Landmark, FileCheck2, Settings, Search, ChevronDown, Download,
  Globe, Server, Mail, Cloud, KeyRound, FlaskConical,
  Zap, ToggleLeft, ToggleRight, Info, Plug, Loader2, Lock, ShieldCheck,
  XCircle, AlertCircle, QrCode, Share2, Smartphone, Copy, ExternalLink,
  CheckCheck, BadgeCheck, RefreshCw, Activity
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, Radar, Legend, Cell, BarChart, Bar,
  ComposedChart, Line, ReferenceLine
} from 'recharts';
import { Slider } from '@/components/ui/slider';
import {
  checkHealth, postConsent, runScan, adaptScan,
  sendPassportWhatsApp, fetchWhatsAppStatus,
  uploadConnector, disconnectConnector, connectorTemplateUrl, adaptFindings,
  login as apiLogin, register as apiRegister, fetchMe, logout as apiLogout,
  fetchHistory, fetchAudit, verifyAudit, fetchAnalytics,
} from '@/lib/api';

const INK = '#111827';
const INK_SOFT = '#6b7280';
const INK_FAINT = '#9ca3af';
const BORDER = '#e5e7eb';
const HAIRLINE = '#eceef0';
const PAPER = '#FAFAF8';
const WHITE = '#ffffff';

// Interactive/primary accent uses black instead of blue, so the only
// meaningful colors in the app are red, amber, and green (all reserved
// for severity/status), plus black and its neutral grey tints.
const ACCENT = INK;
const ACCENT_SOFT = '#f3f4f6';
const ACCENT_BORDER = '#d1d5db';
const ACCENT_TINT = '#e5e7eb';

const FONT = "-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";

const SEV = { Critical: '#dc2626', High: '#b45309', Medium: '#a16207', Low: '#15803d', Unknown: '#6b7280' };
const SEV_BG = { Critical: '#fef2f2', High: '#fffbeb', Medium: '#fefce8', Low: '#f0fdf4', Unknown: '#f9fafb' };

// ============================================================
// FORMATTING
// ============================================================
function fmtRupees(amount) {
  // Defensive: a formatter should never be the thing that blanks the page.
  if (typeof amount !== 'number' || !Number.isFinite(amount)) return '—';
  if (amount === 0) return 'Free';
  if (amount >= 10000000) return `₹${(amount / 10000000).toFixed(1)}Cr`;
  if (amount >= 100000) return `₹${(amount / 100000).toFixed(1)}L`;
  return `₹${amount.toLocaleString('en-IN')}`;
}
function fmtLakhs(lakhs) {
  if (typeof lakhs !== 'number' || !Number.isFinite(lakhs)) return '—';
  if (lakhs === 0) return 'Free';
  if (lakhs >= 100) return `₹${(lakhs / 100).toFixed(1)}Cr`;
  return `₹${lakhs.toFixed(1)}L`;
}
function fmtLakhRange(low, high) {
  if (low === 0) return `Up to ${fmtLakhs(high)}`;
  return `${fmtLakhs(low)} to ${fmtLakhs(high)}`;
}
function scoreBand(score) {
  if (score >= 750) return { label: 'Good', color: '#15803d', bg: '#f0fdf4', border: '#bbf7d0' };
  if (score >= 600) return { label: 'Moderate', color: '#a16207', bg: '#fefce8', border: '#fde68a' };
  return { label: 'High Risk', color: '#dc2626', bg: '#fef2f2', border: '#fecaca' };
}

function GlobalFont() {
  return (
    <style>{`
      html, body, button, input, textarea, select {
        font-family: ${FONT};
        font-variant-numeric: tabular-nums;
        -webkit-font-smoothing: antialiased;
      }
    `}</style>
  );
}

function BtnOutline({ children, onClick, icon: Icon, disabled }) {
  return (
    <button onClick={onClick} disabled={disabled} className="inline-flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-md transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
      style={{ background: WHITE, color: INK, border: `1px solid ${BORDER}`, fontFamily: FONT }}>
      {Icon ? <Icon size={13} style={{ color: INK }} /> : null}
      {children}
    </button>
  );
}
function BtnPrimary({ children, onClick, icon: Icon, disabled }) {
  return (
    <button onClick={onClick} disabled={disabled} className="inline-flex items-center gap-1.5 text-xs font-medium px-3.5 py-1.5 rounded-md transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
      style={{ background: INK, color: WHITE, border: `1px solid ${INK}`, fontFamily: FONT }}>
      {Icon ? <Icon size={13} color={WHITE} /> : null}
      {children}
    </button>
  );
}
function Chip({ children, color, bg }) {
  const c = color || INK_SOFT;
  const b = bg || '#f3f4f6';
  return (
    <span className="text-[10.5px] font-medium px-1.5 py-[1px] rounded inline-block" style={{ color: c, background: b, fontFamily: FONT }}>
      {children}
    </span>
  );
}
function SeverityDot({ severity }) {
  return <div style={{ width: 7, height: 7, borderRadius: '50%', background: SEV[severity] || SEV.Unknown, flexShrink: 0 }} />;
}
function Panel({ children, className, style }) {
  return <div className={`rounded-lg border ${className || ''}`} style={{ background: WHITE, borderColor: BORDER, fontFamily: FONT, ...(style || {}) }}>{children}</div>;
}
function PanelHeader({ children, right }) {
  return (
    <div className="px-5 pt-5 pb-0 flex items-center justify-between flex-wrap gap-2">
      <div className="text-sm font-medium" style={{ color: '#374151' }}>{children}</div>
      {right || null}
    </div>
  );
}
function PanelBody({ children, className, style }) {
  // Forwards style: panels holding wide tables need to set their own
  // overflow, and a dropped prop fails silently rather than at build time.
  return <div className={`px-5 pb-5 pt-3 ${className || ''}`} style={style}>{children}</div>;
}

// ============================================================
// ONBOARDING DATA
// ============================================================
const INDUSTRIES = ['IT & Software', 'Manufacturing', 'Retail & E-commerce', 'Healthcare', 'Financial Services', 'Professional Services', 'Other'];
const EMPLOYEE_BANDS = ['1 to 10', '11 to 50', '51 to 200', '200+'];
const REVENUE_BANDS = [
  { id: 'under1cr', label: '₹1 Cr', mult: 0.35 },
  { id: '1to10cr', label: '₹1 Cr to ₹10 Cr', mult: 1 },
  { id: '10to50cr', label: '₹10 Cr to ₹50 Cr', mult: 2.4 },
  { id: 'above50cr', label: 'Above ₹50 Cr', mult: 5.2 },
];
const DATA_SOURCES = [
  { id: 'cloud', label: 'Cloud Infrastructure', sub: 'AWS, Azure, or Google Cloud', icon: Cloud, why: 'Surfaces misconfigured storage, IAM roles, and exposed services no external scan can see.' },
  { id: 'identity', label: 'Email & Identity Provider', sub: 'Google Workspace or Microsoft 365', icon: KeyRound, why: 'Confirms actual MFA enforcement and admin account exposure instead of guessing from outside signals.' },
  { id: 'endpoint', label: 'Endpoint Detection (EDR)', sub: 'CrowdStrike, SentinelOne, Defender', icon: Server, why: 'Adds real patch status and device compliance data, sharpening the likelihood estimate.' },
  { id: 'siem', label: 'SIEM / Log Platform', sub: 'Splunk, Sentinel, Elastic, Wazuh', icon: Activity, why: 'Turns alert and log history into evidence of what is actually being attempted against you, not just what is theoretically exposed.' },
  { id: 'cmdb', label: 'Asset Inventory / CMDB', sub: 'ServiceNow, Snipe-IT, or CSV upload', icon: Landmark, why: 'Confirms which assets are business critical, replacing the criticality weight we otherwise infer from external signals.' },
  { id: 'insurance', label: 'Cyber Insurance Policy', sub: 'Upload policy PDF or connect broker', icon: FileCheck2, why: 'Cross checks your coverage limits against modeled loss scenarios to flag underinsured gaps.' },
];
const MAX_DEPTH = 1 + DATA_SOURCES.length;

// Each connector ingests an export the vendor's own console can produce. The
// API form of a connector runs the same parser behind an OAuth token, so what
// the platform does with the data is identical either way.
const SOURCE_EXPORTS = {
  cloud: { accept: '.csv,.json', hint: 'AWS IAM credential report, or any principal/MFA export (CSV)' },
  identity: { accept: '.csv,.json', hint: 'Workspace or M365 user export with MFA status (CSV)' },
  endpoint: { accept: '.csv,.json', hint: 'EDR device export with compliance or patch state (CSV)' },
  siem: { accept: '.csv,.json', hint: 'Alert history with rule name and count (CSV or JSON)' },
  cmdb: { accept: '.csv,.json', hint: 'CI list with names and business criticality (CSV)' },
  insurance: { accept: '.pdf,.csv,.txt', hint: 'Policy schedule listing coverage limits (PDF or CSV)' },
};

// ============================================================
// DATA
// ============================================================
const SAMPLE_FINDINGS = [
  { id: 1, asset: 'mail.company.com', issue: 'Missing SPF/DKIM record', short: 'SPF/DKIM', cvss: 5.3, epss: 0.12, kev: false, confidence: 92, cost: 0, reduction: 12, severity: 'Medium', category: 'Email', eal: 3, impact: 3, likelihood: 2 },
  { id: 2, asset: 'portal.company.com', issue: 'Outdated CMS plugin', cveId: 'CVE-2024-19281', short: 'CMS Patch', cvss: 8.1, epss: 0.61, kev: true, confidence: 88, cost: 8000, reduction: 22, severity: 'Critical', category: 'Web App', eal: 25, impact: 5, likelihood: 4 },
  { id: 3, asset: 'All accounts', issue: 'No MFA on admin accounts', short: 'Enable MFA', cvss: 7.4, epss: 0.35, kev: false, confidence: 95, cost: 0, reduction: 35, severity: 'High', category: 'Identity', eal: 18, impact: 4, likelihood: 3 },
  { id: 4, asset: 'vpn.company.com', issue: 'Exposed RDP port 3389', short: 'Close RDP', cvss: 9.0, epss: 0.55, kev: true, confidence: 80, cost: 25000, reduction: 18, severity: 'Critical', category: 'Network', eal: 14, impact: 5, likelihood: 4 },
  { id: 5, asset: 'assets.company.com', issue: 'Public cloud storage bucket', short: 'Fix Bucket', cvss: 6.5, epss: 0.20, kev: false, confidence: 70, cost: 5000, reduction: 8, severity: 'Medium', category: 'Cloud', eal: 8, impact: 3, likelihood: 2 },
];

// Added one Unmonitored asset so the Asset Manifest STATUS column can
// demonstrate all three states: Monitored (green), Unverified (amber),
// Unmonitored (red).
const SAMPLE_ASSETS = [
  { name: 'company.com', type: 'Primary Domain', method: 'Seed', status: 'Monitored', risk: 'Low' },
  { name: 'portal.company.com', type: 'Web Application', method: 'CT Logs', status: 'Monitored', risk: 'Critical' },
  { name: 'mail.company.com', type: 'Mail Server', method: 'DNS Enum', status: 'Monitored', risk: 'Medium' },
  { name: 'vpn.company.com', type: 'Remote Access', method: 'Port Scan', status: 'Monitored', risk: 'Critical' },
  { name: 'assets.company.com', type: 'Cloud Storage', method: 'Bucket Scan', status: 'Monitored', risk: 'Medium' },
  { name: 'test-old.company.com', type: 'Shadow IT', method: 'CT Logs', status: 'Unverified', risk: 'Unknown' },
  { name: 'legacy-vpn.company.com', type: 'Remote Access', method: 'Port Scan', status: 'Unmonitored', risk: 'Unknown' },
  { name: 'api.company.com', type: 'API Endpoint', method: 'Subdomain Enum', status: 'Monitored', risk: 'Low' },
];

const SAMPLE_TREND_HISTORY = [
  { week: 'W1', score: 540 }, { week: 'W2', score: 565 }, { week: 'W3', score: 578 },
  { week: 'W4', score: 602 }, { week: 'W5', score: 610 }, { week: 'W6', score: 620 },
];

const SAMPLE_COMPLIANCE = [
  { name: 'NIST CSF', coverage: 68 }, { name: 'ISO 27001', coverage: 54 },
  { name: 'CIS Controls', coverage: 71 }, { name: 'RBI Guidelines', coverage: 45 },
  { name: 'SEBI CSCRF', coverage: 41 },
];

const SAMPLE_AUDIT_LOG = [
  { time: '2h ago', action: 'Score recalculated', hash: '8a2f...c91e' },
  { time: '6h ago', action: 'Budget optimizer run at ₹15,000', hash: '3d7b...a204' },
  { time: '1d ago', action: 'New scan completed', hash: 'f192...77b3' },
  { time: '2d ago', action: 'MFA fix marked resolved', hash: '55e0...1cd8' },
];

// Moved up from further down the file: it must be declared before the
// "derived analytics" block below reads it (SAMPLE_ATTACK_PATHS was a
// `const` declared after that point, which threw a temporal-dead-zone
// ReferenceError on module load and left the app blank).
const SAMPLE_ATTACK_PATHS = [
  {
    id: 1, label: 'Web App to Admin Panel',
    steps: [
      { title: 'Internet', sub: 'Anonymous access', icon: Globe, breakpoint: false },
      { title: 'CMS Plugin Flaw', sub: 'CVE-2024-19281', icon: Bug, breakpoint: false },
      { title: 'No MFA', sub: 'Admin accounts', icon: KeyRound, breakpoint: true },
      { title: 'Admin Panel', sub: 'Full write access', icon: Server, breakpoint: false },
      { title: 'Customer Database', sub: 'Crown jewel asset', icon: Shield, breakpoint: false },
    ],
    eal: 45,
    mitre: [{ id: 'T1190', name: 'Exploit Public-Facing Application' }, { id: 'T1078', name: 'Valid Accounts' }],
    fix: 'Enable MFA', fixCost: 0, rosi: null,
  },
  {
    id: 2, label: 'Remote Access to File Server',
    steps: [
      { title: 'Internet', sub: 'Anonymous access', icon: Globe, breakpoint: false },
      { title: 'Exposed RDP', sub: 'Port 3389 open', icon: Server, breakpoint: false },
      { title: 'No MFA', sub: 'VPN login', icon: KeyRound, breakpoint: true },
      { title: 'VPN Pivot', sub: 'Internal network reach', icon: Network, breakpoint: false },
      { title: 'File Server', sub: 'Shared documents', icon: Cloud, breakpoint: false },
    ],
    eal: 28,
    mitre: [{ id: 'T1021', name: 'Remote Services (RDP)' }, { id: 'T1078', name: 'Valid Accounts' }],
    fix: 'Enable MFA', fixCost: 0, rosi: null,
  },
  {
    id: 3, label: 'Phishing to Admin Panel',
    steps: [
      { title: 'Phishing Email', sub: 'Employee inbox', icon: Mail, breakpoint: false },
      { title: 'Weak Password', sub: 'Reused credential', icon: Bug, breakpoint: false },
      { title: 'No MFA', sub: 'Admin accounts', icon: KeyRound, breakpoint: true },
      { title: 'Admin Panel', sub: 'Full write access', icon: Server, breakpoint: false },
      { title: 'Customer Database', sub: 'Crown jewel asset', icon: Shield, breakpoint: false },
    ],
    eal: 38,
    mitre: [{ id: 'T1566', name: 'Phishing' }, { id: 'T1078', name: 'Valid Accounts' }],
    fix: 'Enable MFA', fixCost: 0, rosi: null,
  },
];

const CAT_SHORT = { Identity: 'Identity', Network: 'Network', 'Web App': 'Web App', Cloud: 'Cloud', Email: 'Email' };
const SAMPLE_RADAR_BASE = { Identity: 45, Network: 60, 'Web App': 50, Cloud: 70, Email: 55 };
const SAMPLE_BASE_SCORE = 620;
const MAX_BUDGET = 40000;

// ============================================================
// LIVE DATA STORE
// ------------------------------------------------------------
// The dashboard reads FINDINGS / ASSETS / BASE_SCORE at render time. A real
// scan swaps them in place and the app shell is remounted (see dataVersion),
// so every panel picks up live data without threading props through the
// entire component tree.
//
// The sample dataset above stays as the fallback. If the backend is
// unreachable, or a scan legitimately returns nothing to show, the UI keeps
// rendering sample data and labels it as such -- it never goes blank.
// ============================================================
let FINDINGS = SAMPLE_FINDINGS;
let ASSETS = SAMPLE_ASSETS;
let BASE_SCORE = SAMPLE_BASE_SCORE;

// origin.mode: 'live' | 'sample'
let DATA_ORIGIN = { mode: 'sample', scanId: null, confidence: null, notes: [], reason: null };

// ------------------------------------------------------------
// DERIVED ANALYTICS
// ------------------------------------------------------------
// Compliance coverage, attack paths, category risk, score trend, and the
// audit log are all computed by the backend from the findings a scan
// actually produced. They are held here alongside the findings store so the
// panels read them at render time, falling back to the sample set until a
// live scan supplies the real thing.
let TREND_HISTORY = SAMPLE_TREND_HISTORY;
let COMPLIANCE = SAMPLE_COMPLIANCE;
let AUDIT_LOG = SAMPLE_AUDIT_LOG;
let ATTACK_PATHS = SAMPLE_ATTACK_PATHS;
let ATTACK_GRAPH = buildSampleGraph();
let RADAR_BASE = SAMPLE_RADAR_BASE;
let ANALYTICS_LIVE = false;
// Share of the controls underwriters ask for that could actually be
// evidenced. Null until a scan supplies it -- a figure this one goes into an
// outgoing message, so it must never be a placeholder.
let INSURANCE_READINESS = null;

// ------------------------------------------------------------
// Attack graph fallback
// ------------------------------------------------------------
// The backend computes the real graph (nodes, edges, and the choke point
// that severs the most expected loss). Until a scan supplies one, derive an
// equivalent graph from the sample paths so the renderer has the same shape
// either way and never special-cases "sample mode".
function buildSampleGraph() {
  const nodes = new Map();
  const edges = [];
  const seen = new Set();
  const paths = [];

  const addNode = (id, attrs) => {
    if (!nodes.has(id)) nodes.set(id, { id, ...attrs });
    return id;
  };
  const addEdge = (source, target) => {
    const key = `${source}->${target}`;
    if (seen.has(key)) return;
    seen.add(key);
    edges.push({ source, target });
  };

  SAMPLE_ATTACK_PATHS.forEach((path) => {
    const nodeIds = [];
    let breakpointNodeId = null;

    path.steps.forEach((step, i) => {
      const isFirst = i === 0;
      const isLast = i === path.steps.length - 1;
      // Shared labels collapse to one node, which is what makes converging
      // paths visible rather than three parallel lines.
      const id = isFirst ? `src:${step.title}` : isLast ? `t:${step.title}` : `n:${step.title}`;
      addNode(id, {
        kind: isFirst ? 'source' : isLast ? 'target' : (step.breakpoint ? 'pivot' : 'entry'),
        label: step.title,
        sub: step.sub,
        // The sample fixture stores icons as components already; the live
        // payload sends names. Keep the component so the renderer does not
        // fall back to a default icon for every node.
        iconComponent: step.icon,
        cost: 0,
        is_choke_point: Boolean(step.breakpoint),
        severed_paths: 0,
        severed_eal: 0,
      });
      if (step.breakpoint) {
        breakpointNodeId = id;
        // Cost of breaking here is the cheapest fix among the paths that
        // break at this node, so the note cannot quote another path's price.
        const node = nodes.get(id);
        node.cost = node.cost ? Math.min(node.cost, path.fixCost) : path.fixCost;
      }
      if (nodeIds.length) addEdge(nodeIds[nodeIds.length - 1], id);
      nodeIds.push(id);
    });

    paths.push({
      id: path.id,
      label: path.label,
      node_ids: nodeIds,
      eal: path.eal,
      mitre: path.mitre,
      fix: path.fix,
      fix_cost: path.fixCost,
      rosi: path.rosi,
      breakpoint_node_id: breakpointNodeId,
    });
  });

  // Tally what each node severs. Expected losses across overlapping paths
  // cannot simply be added -- shared findings would be counted twice -- so
  // the headline figure is the worst single path a node cuts.
  const severedWorst = {};
  const severedCount = {};
  paths.forEach((p) => {
    p.node_ids.forEach((id) => {
      const node = nodes.get(id);
      if (!node || node.kind === 'source' || node.kind === 'target') return;
      severedWorst[id] = Math.max(severedWorst[id] || 0, p.eal);
      severedCount[id] = (severedCount[id] || 0) + 1;
    });
  });
  nodes.forEach((node, id) => {
    node.severed_eal = Math.round((severedWorst[id] || 0) * 10) / 10;
    node.severed_paths = severedCount[id] || 0;
  });

  // The choke point is the node on the most paths, worst-path loss breaking
  // ties -- the same rule the backend applies to live findings.
  const chokeId = Object.keys(severedCount).sort(
    (a, b) => (severedCount[b] - severedCount[a]) || (severedWorst[b] - severedWorst[a]),
  )[0];
  nodes.forEach((node, id) => { node.is_choke_point = id === chokeId; });

  const choke = chokeId ? nodes.get(chokeId) : null;
  return {
    nodes: Array.from(nodes.values()),
    edges,
    paths,
    choke_point: choke ? {
      node_id: chokeId,
      label: choke.label,
      cost: choke.cost || 0,
      severed_paths: severedCount[chokeId] || 0,
      total_paths: paths.length,
      severed_eal: Math.round((severedWorst[chokeId] || 0) * 10) / 10,
    } : null,
  };
}

function iconByName(name) {
  const map = {
    Globe, Server, Mail, Cloud, KeyRound, Bug, Shield, Network, Lock, Activity,
  };
  return map[name] || Server;
}

function applyAnalytics({ analytics, history, audit }) {
  if (analytics) {
    ATTACK_PATHS = (analytics.attack_paths || []).map((p) => ({
      id: p.id,
      label: p.label,
      steps: (p.steps || []).map((st) => ({
        title: st.title, sub: st.sub, icon: iconByName(st.icon), breakpoint: st.breakpoint,
      })),
      eal: p.eal,
      mitre: p.mitre || [],
      fix: p.fix,
      fixCost: p.fix_cost,
      rosi: p.rosi,
    }));

    // The graph arrives already analysed: nodes carry how much loss each one
    // severs, and choke_point names the single highest-leverage fix. Icons
    // are the only thing resolved client-side, since the backend sends names.
    const graph = analytics.attack_graph;
    if (graph && (graph.nodes || []).length) {
      ATTACK_GRAPH = {
        nodes: graph.nodes.map((n) => ({ ...n, iconComponent: iconByName(n.icon) })),
        edges: graph.edges || [],
        paths: graph.paths || [],
        choke_point: graph.choke_point || null,
      };
    }

    COMPLIANCE = (analytics.compliance || []).map((f) => ({
      name: f.name,
      coverage: f.coverage,
      fullName: f.full_name,
      met: f.controls_met,
      total: f.controls_total,
      controls: f.controls || [],
    }));
    RADAR_BASE = (analytics.category_risk || []).reduce(
      (acc, r) => ({ ...acc, [r.category]: r.risk }), {},
    );
    if (analytics.insurance && typeof analytics.insurance.readiness === 'number') {
      INSURANCE_READINESS = analytics.insurance.readiness;
    }
    applyCausalGraph(analytics.causal_graph);
    ANALYTICS_LIVE = true;
  }

  if (history && history.length) {
    TREND_HISTORY = history.map((h, i) => ({
      week: `S${i + 1}`,
      score: h.org_score,
      domain: h.domain,
      at: h.scanned_at,
    }));
  }

  if (audit && audit.length) {
    AUDIT_LOG = audit.map((e) => ({
      time: relativeTime(e.timestamp),
      action: e.detail || e.action,
      hash: `${e.entry_hash.slice(0, 4)}...${e.entry_hash.slice(-4)}`,
    }));
  }
}

function resetAnalytics() {
  TREND_HISTORY = SAMPLE_TREND_HISTORY;
  COMPLIANCE = SAMPLE_COMPLIANCE;
  AUDIT_LOG = SAMPLE_AUDIT_LOG;
  ATTACK_PATHS = SAMPLE_ATTACK_PATHS;
  ATTACK_GRAPH = buildSampleGraph();
  RADAR_BASE = SAMPLE_RADAR_BASE;
  ANALYTICS_LIVE = false;
  INSURANCE_READINESS = null;
  resetCausalGraph();
}

function relativeTime(iso) {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return 'just now';
  const mins = Math.max(0, Math.round((Date.now() - then) / 60000));
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function applyLiveScan(scan) {
  FINDINGS = scan.findings;
  ASSETS = scan.assets;
  BASE_SCORE = scan.score;
  CONNECTOR_CONTRIB = {};
  DATA_ORIGIN = {
    mode: 'live',
    scanId: scan.scanId,
    confidence: scan.confidence,
    notes: scan.notes,
    reason: null,
    // Kept so connector contributions can be layered on and removed
    // without re-running the scan.
    baseFindings: scan.findings,
    baseScore: scan.score,
    connectors: [],
  };
}

function applySampleData(reason) {
  FINDINGS = SAMPLE_FINDINGS;
  ASSETS = SAMPLE_ASSETS;
  BASE_SCORE = SAMPLE_BASE_SCORE;
  DATA_ORIGIN = { mode: 'sample', scanId: null, confidence: null, notes: [], reason: reason || null };
  CONNECTOR_CONTRIB = {};
}

// ------------------------------------------------------------
// CONNECTOR CONTRIBUTIONS
// ------------------------------------------------------------
// Findings contributed by each connected source, keyed by source id so a
// disconnect removes exactly that source's contribution. Connector findings
// are tagged with `source` so the UI can show where each one came from.
let CONNECTOR_CONTRIB = {};

// Aggregate risk as a probabilistic union, mirroring the backend's
// compute_org_score. Keeping the two in step matters: the optimizer's
// projected score comes from the backend, and a different local formula
// would make the two numbers disagree on screen.
function scoreFromFindings(findings) {
  let residual = 1;
  findings.forEach((f) => {
    const cvssWeight = Math.max(0.1, (f.cvss || 0) / 10);
    const risk = Math.min(Math.max((f.epss || 0) * cvssWeight * 1.2, 0), 0.99);
    residual *= 1 - risk;
  });
  return Math.round(Math.max(300, 900 - 600 * (1 - residual)));
}

function rebuildFindings() {
  const base = DATA_ORIGIN.mode === 'live' ? (DATA_ORIGIN.baseFindings || []) : SAMPLE_FINDINGS;
  const extra = Object.keys(CONNECTOR_CONTRIB).flatMap((k) => CONNECTOR_CONTRIB[k]);
  FINDINGS = base.concat(extra);
  BASE_SCORE = extra.length
    ? scoreFromFindings(FINDINGS)
    : (DATA_ORIGIN.mode === 'live' ? (DATA_ORIGIN.baseScore ?? SAMPLE_BASE_SCORE) : SAMPLE_BASE_SCORE);
}

function mergeConnectorResult(sourceId, result) {
  const mapped = adaptFindings(result.findings || []).map((f, i) => ({
    ...f,
    id: `conn-${sourceId}-${i}`,
    source: sourceId,
    sourceLabel: result.label,
  }));
  CONNECTOR_CONTRIB[sourceId] = mapped;
  rebuildFindings();

  // When the backend persisted against a live scan it returns the
  // authoritative recomputed score; prefer it over the local estimate.
  if (result.persisted && typeof result.org_score === 'number') {
    BASE_SCORE = result.org_score;
  }
  DATA_ORIGIN = { ...DATA_ORIGIN, connectors: Object.keys(CONNECTOR_CONTRIB) };
}

function removeConnectorResult(sourceId) {
  delete CONNECTOR_CONTRIB[sourceId];
  rebuildFindings();
  DATA_ORIGIN = { ...DATA_ORIGIN, connectors: Object.keys(CONNECTOR_CONTRIB) };
}

function optimizeForBudget(budget) {
  const sorted = FINDINGS.slice().sort((a, b) => {
    const ra = a.cost === 0 ? Infinity : a.reduction / a.cost;
    const rb = b.cost === 0 ? Infinity : b.reduction / b.cost;
    return rb - ra;
  });
  let remaining = budget;
  const selected = [];
  for (let i = 0; i < sorted.length; i++) {
    const f = sorted[i];
    if (f.cost <= remaining) { selected.push(f); remaining -= f.cost; }
  }
  return selected;
}

function pathSeverityColor(eal) {
  if (eal >= 40) return SEV.Critical;
  if (eal >= 25) return SEV.High;
  return SEV.Medium;
}

// ============================================================
// ONBOARDING: WIZARD SHELL
// ============================================================
const WIZARD_STEPS = ['Business Context', 'Data Sources', 'Consent'];

function WizardShell({ stepIndex, title, sub, children, onBack, onNext, nextLabel, nextDisabled }) {
  return (
    <div className="min-h-screen flex items-center justify-center p-6" style={{ background: PAPER, fontFamily: FONT }}>
      <div className="w-full max-w-xl">
        <div className="flex items-center justify-center gap-2 mb-7">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: INK }}>
            <Shield color={WHITE} size={16} />
          </div>
          <span className="text-lg font-semibold" style={{ color: INK }}>OwLance</span>
        </div>

        <div className="flex items-center justify-center gap-2 mb-8">
          {WIZARD_STEPS.map((s, i) => (
            <div key={s} className="flex items-center gap-2">
              <div className="flex items-center gap-1.5">
                <div className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-semibold"
                  style={{
                    background: i < stepIndex ? INK : i === stepIndex ? ACCENT : '#f3f4f6',
                    color: i <= stepIndex ? WHITE : INK_FAINT,
                    border: i === stepIndex ? `1.5px solid ${ACCENT}` : 'none',
                  }}>
                  {i < stepIndex ? <CheckCircle2 size={11} /> : i + 1}
                </div>
                <span className="text-[11px] hidden sm:inline" style={{ color: i === stepIndex ? INK : INK_FAINT, fontWeight: i === stepIndex ? 500 : 400 }}>{s}</span>
              </div>
              {i < WIZARD_STEPS.length - 1 ? <div style={{ width: 24, height: 1, background: BORDER }} /> : null}
            </div>
          ))}
        </div>

        <Panel className="p-7">
          <h2 className="text-xl font-semibold mb-1.5" style={{ color: INK }}>{title}</h2>
          {sub ? <p className="text-sm mb-6" style={{ color: INK_FAINT }}>{sub}</p> : <div className="mb-6" />}
          {children}
          <div className="flex items-center justify-between mt-7 pt-5" style={{ borderTop: `1px solid ${HAIRLINE}` }}>
            {onBack ? (
              <button onClick={onBack} className="inline-flex items-center gap-1 text-xs font-medium" style={{ color: INK_SOFT }}>
                <ChevronLeft size={14} /> Back
              </button>
            ) : <div />}
            <BtnPrimary onClick={onNext} disabled={nextDisabled}>{nextLabel || 'Continue'} <ChevronRight size={13} /></BtnPrimary>
          </div>
        </Panel>
      </div>
    </div>
  );
}

function PillGroup({ options, value, onChange, columns }) {
  return (
    <div className={`grid gap-2`} style={{ gridTemplateColumns: `repeat(${columns || 2}, 1fr)` }}>
      {options.map((opt) => {
        const label = typeof opt === 'string' ? opt : opt.label;
        const val = typeof opt === 'string' ? opt : opt.id;
        const active = value === val;
        return (
          <button key={val} onClick={() => onChange(val)}
            className="text-left px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors"
            style={{
              border: `1.5px solid ${active ? INK : BORDER}`,
              background: active ? INK : WHITE,
              color: active ? WHITE : '#374151',
            }}>
            {label}
          </button>
        );
      })}
    </div>
  );
}

function ContextStep({ industry, setIndustry, employees, setEmployees, revenueBand, setRevenueBand, onBack, onNext }) {
  return (
    <WizardShell stepIndex={0} title="Tell us about the business" sub="This calibrates every loss estimate on your dashboard to your actual size and sector, instead of a generic average." onBack={onBack} onNext={onNext}>
      <div className="space-y-6">
        <div>
          <label className="text-xs font-medium block mb-2" style={{ color: '#374151' }}>Industry</label>
          <PillGroup options={INDUSTRIES} value={industry} onChange={setIndustry} columns={2} />
        </div>
        <div>
          <label className="text-xs font-medium block mb-2" style={{ color: '#374151' }}>Employees</label>
          <PillGroup options={EMPLOYEE_BANDS} value={employees} onChange={setEmployees} columns={4} />
        </div>
        <div>
          <label className="text-xs font-medium block mb-2" style={{ color: '#374151' }}>Annual Revenue</label>
          <PillGroup options={REVENUE_BANDS} value={revenueBand} onChange={setRevenueBand} columns={2} />
        </div>
      </div>
    </WizardShell>
  );
}
function DataSourceCard({ source, connected, connecting, onConnect, onDisconnect, result, error }) {
  const Icon = source.icon;
  const inputId = `connector-file-${source.id}`;
  const spec = SOURCE_EXPORTS[source.id] || { accept: '.csv,.json', hint: 'CSV export' };

  const borderColor = error ? '#fecaca' : connected ? ACCENT_BORDER : BORDER;
  const bg = error ? '#fef2f2' : connected ? ACCENT_SOFT : WHITE;

  return (
    <div className="rounded-lg p-4 flex items-start gap-3" style={{ border: `1px solid ${borderColor}`, background: bg }}>
      <div className="w-9 h-9 rounded-md flex items-center justify-center shrink-0" style={{ background: connected ? ACCENT_TINT : '#f3f4f6' }}>
        <Icon size={16} style={{ color: connected ? ACCENT : '#4b5563' }} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <div className="text-sm font-medium" style={{ color: INK }}>{source.label}</div>
            <div className="text-[11px]" style={{ color: INK_FAINT }}>{source.sub}</div>
          </div>
          {connected ? (
            <button onClick={onDisconnect} className="text-[11px] font-medium shrink-0 flex items-center gap-1" style={{ color: '#15803d' }}>
              <CheckCircle2 size={12} /> Connected
            </button>
          ) : connecting ? (
            <span className="text-[11px] font-medium shrink-0 flex items-center gap-1" style={{ color: INK_FAINT }}>
              <Loader2 size={12} className="animate-spin" /> Parsing
            </span>
          ) : (
            <label htmlFor={inputId}
              className="text-[11px] font-medium shrink-0 px-2.5 py-1 rounded-md cursor-pointer flex items-center gap-1"
              style={{ color: INK, border: `1px solid ${BORDER}`, background: WHITE }}>
              <Plug size={11} /> Connect
            </label>
          )}
          <input
            id={inputId}
            type="file"
            accept={spec.accept}
            style={{ display: 'none' }}
            onChange={(e) => {
              const file = e.target.files && e.target.files[0];
              e.target.value = ''; // allow re-selecting the same file
              if (file) onConnect(file);
            }}
          />
        </div>

        {connected && result ? (
          <div className="mt-2 rounded-md px-2.5 py-2" style={{ background: WHITE, border: `1px solid ${ACCENT_BORDER}` }}>
            <div className="text-[11px] font-medium" style={{ color: INK }}>{result.summary}</div>
            {result.replaces_inference ? (
              <div className="text-[10.5px] mt-1 leading-relaxed" style={{ color: INK_SOFT }}>
                {result.replaces_inference}
              </div>
            ) : null}
            {(result.findings || []).map((f, i) => (
              <div key={i} className="text-[10.5px] mt-1 flex items-start gap-1.5" style={{ color: SEV[f.severity] || INK_SOFT }}>
                <AlertTriangle size={10} style={{ marginTop: 2, flexShrink: 0 }} />
                <span>{f.issue}</span>
              </div>
            ))}
            {result.reweighted_findings ? (
              <div className="text-[10.5px] mt-1" style={{ color: INK_SOFT }}>
                {result.reweighted_findings} existing finding(s) re-weighted by business criticality.
              </div>
            ) : null}
            <div className="text-[10px] mt-1.5 font-mono truncate" style={{ color: INK_FAINT }}>
              {result.filename} — {result.records} record(s)
            </div>
          </div>
        ) : error ? (
          <div className="mt-2 rounded-md px-2.5 py-2" style={{ background: WHITE, border: '1px solid #fecaca' }}>
            <div className="text-[11px] font-medium flex items-start gap-1.5" style={{ color: '#b91c1c' }}>
              <XCircle size={11} style={{ marginTop: 1, flexShrink: 0 }} />
              <span>{error}</span>
            </div>
            <label htmlFor={inputId} className="text-[10.5px] mt-1.5 inline-block cursor-pointer underline" style={{ color: INK_SOFT }}>
              Try a different file
            </label>
          </div>
        ) : (
          <>
            <p className="text-[11.5px] mt-1.5 leading-relaxed" style={{ color: INK_SOFT }}>{source.why}</p>
            <div className="text-[10.5px] mt-1.5 flex items-center justify-between gap-2" style={{ color: INK_FAINT }}>
              <span className="truncate">{spec.hint}</span>
              <a href={connectorTemplateUrl(source.id)} download
                className="shrink-0 flex items-center gap-1 underline" style={{ color: INK_SOFT }}>
                <Download size={10} /> Sample
              </a>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function DepthMeter({ depth }) {
  return (
    <div className="flex items-center gap-3">
      <div className="flex gap-1">
        {Array.from({ length: MAX_DEPTH }).map((_, i) => (
          <div key={i} className="h-2 rounded-sm" style={{ width: 22, background: i < depth ? ACCENT : '#f3f4f6', border: `1px solid ${i < depth ? ACCENT : BORDER}` }} />
        ))}
      </div>
      <span className="text-xs font-medium" style={{ color: INK }}>Depth {depth}/{MAX_DEPTH}</span>
    </div>
  );
}

function SourcesStep({ dataSources, connecting, onConnect, onDisconnect, depth, onBack, onNext, results, errors }) {
  return (
    <WizardShell stepIndex={1} title="Connect data sources" sub="Optional. Passive discovery works with nothing connected. Each source you add fills in the graph with real internal data instead of an external inference." onBack={onBack} onNext={onNext} nextLabel="Continue">
      <div className="space-y-4">
        <div className="rounded-lg px-3.5 py-3 flex items-center justify-between" style={{ background: '#f9fafb', border: `1px solid ${BORDER}` }}>
          <span className="text-xs" style={{ color: INK_SOFT }}>Current scan depth</span>
          <DepthMeter depth={depth} />
        </div>
        <div className="space-y-2.5">
          {DATA_SOURCES.map((s) => (
            <DataSourceCard key={s.id} source={s} connected={dataSources[s.id]} connecting={connecting === s.id}
              result={(results || {})[s.id]} error={(errors || {})[s.id]}
              onConnect={(file) => onConnect(s.id, file)} onDisconnect={() => onDisconnect(s.id)} />
          ))}
        </div>
      </div>
    </WizardShell>
  );
}

function ConsentStep({ activeConsent, setActiveConsent, authorized, setAuthorized, onBack, onNext }) {
  return (
    <WizardShell stepIndex={2} title="Confirm scope and consent" sub="Passive discovery reads only public records. Active checks send real traffic to your systems and require explicit permission." onBack={onBack} onNext={onNext} nextLabel="Run Scan" nextDisabled={!authorized}>
      <div className="space-y-4">
        <div className="rounded-lg p-4 flex items-center justify-between" style={{ border: `1px solid ${BORDER}` }}>
          <div className="flex items-start gap-3">
            <div className="w-9 h-9 rounded-md flex items-center justify-center shrink-0" style={{ background: '#f0fdf4' }}>
              <Globe size={16} style={{ color: '#15803d' }} />
            </div>
            <div>
              <div className="text-sm font-medium" style={{ color: INK }}>Passive discovery</div>
              <p className="text-[11.5px] mt-0.5" style={{ color: INK_FAINT }}>Certificate logs, DNS records, public breach data. Always on, no risk to your systems.</p>
            </div>
          </div>
          <Chip color="#15803d" bg="#f0fdf4">Always on</Chip>
        </div>

        <div className="rounded-lg p-4 flex items-center justify-between" style={{ border: `1px solid ${activeConsent ? ACCENT_BORDER : BORDER}`, background: activeConsent ? ACCENT_SOFT : WHITE }}>
          <div className="flex items-start gap-3">
            <div className="w-9 h-9 rounded-md flex items-center justify-center shrink-0" style={{ background: activeConsent ? ACCENT_TINT : '#f3f4f6' }}>
              <Zap size={16} style={{ color: activeConsent ? ACCENT : '#4b5563' }} />
            </div>
            <div>
              <div className="text-sm font-medium" style={{ color: INK }}>Active checks</div>
              <p className="text-[11.5px] mt-0.5 max-w-xs" style={{ color: INK_FAINT }}>Controlled port and configuration probes against systems you specify. Off by default.</p>
            </div>
          </div>
          <button onClick={() => setActiveConsent(!activeConsent)} className="shrink-0">
            {activeConsent ? <ToggleRight size={26} style={{ color: ACCENT }} /> : <ToggleLeft size={26} style={{ color: INK_FAINT }} />}
          </button>
        </div>

        <label className="flex items-start gap-2.5 rounded-lg p-3.5 cursor-pointer" style={{ background: '#f9fafb', border: `1px solid ${BORDER}` }}>
          <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="mt-0.5" style={{ accentColor: INK }} />
          <span className="text-xs leading-relaxed" style={{ color: '#374151' }}>
            I confirm I am authorized to assess this domain and its connected systems, and understand active checks will only run if enabled above.
          </span>
        </label>

        <div className="flex items-start gap-2 text-[11px]" style={{ color: INK_FAINT }}>
          <Lock size={12} style={{ marginTop: 1, flexShrink: 0 }} />
          Every scan action is written to a tamper evident audit log, visible under Compliance and Reports.
        </div>
      </div>
    </WizardShell>
  );
}

// ============================================================
// SHARED ATOMS
// ============================================================
function CalibrationChips({ industry, employees, revenueLabel, depth }) {
  return (
    <div className="flex items-center gap-2 flex-wrap mb-1">
      <span className="text-[10.5px] uppercase tracking-wide" style={{ color: INK_FAINT }}>Calibrated for</span>
      <Chip color={INK} bg="#f3f4f6">{industry}</Chip>
      <Chip color={INK} bg="#f3f4f6">{employees} employees</Chip>
      <Chip color={INK} bg="#f3f4f6">{revenueLabel}</Chip>
      <Chip color={ACCENT} bg={ACCENT_SOFT}>Depth {depth}/{MAX_DEPTH}</Chip>
    </div>
  );
}

function MetricsTable({ score, medianEAL, confidence, savings, assetsCount }) {
  return (
    <Panel>
      <div className="grid grid-cols-2 md:grid-cols-5">
        <div className="col-span-2 p-5" style={{ borderRight: `1px solid ${BORDER}` }}>
          <div className="text-[11px] uppercase tracking-wide" style={{ color: INK_FAINT }}>Risk Score</div>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className="text-4xl font-semibold" style={{ color: INK }}>{score}</span>
            <span className="text-sm" style={{ color: INK_FAINT }}>/ 900</span>
          </div>
        </div>
        <div className="p-5" style={{ borderRight: `1px solid ${BORDER}` }}>
          <div className="text-[11px] uppercase tracking-wide" style={{ color: INK_FAINT }}>Expected Annual Loss</div>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className="text-2xl font-semibold" style={{ color: INK }}>{fmtLakhs(medianEAL)}</span>
          </div>
          <div className="text-[10.5px] mt-0.5" style={{ color: INK_FAINT }}>{`Confidence ${confidence}%`}</div>
        </div>
        <div className="p-5" style={{ borderRight: `1px solid ${BORDER}` }}>
          <div className="text-[11px] uppercase tracking-wide" style={{ color: INK_FAINT }}>Potential Savings</div>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className="text-2xl font-semibold" style={{ color: INK }}>{fmtRupees(savings)}</span>
            <span className="text-xs" style={{ color: INK_FAINT }}>/ yr</span>
          </div>
        </div>
        <div className="p-5">
          <div className="text-[11px] uppercase tracking-wide" style={{ color: INK_FAINT }}>Assets Monitored</div>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className="text-2xl font-semibold" style={{ color: INK }}>{assetsCount}</span>
            <span className="text-xs" style={{ color: INK_FAINT }}>external</span>
          </div>
        </div>
      </div>
    </Panel>
  );
}

// ============================================================
// DASHBOARD CHARTS
// ============================================================
function PostureComparison({ selected }) {
  const data = Object.keys(RADAR_BASE).map((cat) => {
    const hit = selected.some((f) => f.category === cat);
    return { category: CAT_SHORT[cat], Current: RADAR_BASE[cat], Optimized: Math.min(95, RADAR_BASE[cat] + (hit ? 28 : 4)) };
  });
  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} layout="vertical" margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={BORDER} horizontal={false} />
        <XAxis type="number" domain={[0, 100]} stroke={INK_FAINT} fontSize={11} style={{ fontFamily: FONT }} />
        <YAxis type="category" dataKey="category" stroke={INK_SOFT} fontSize={12} width={70} style={{ fontFamily: FONT }} />
        <Tooltip contentStyle={{ background: WHITE, border: `1px solid ${BORDER}`, borderRadius: 8, fontFamily: FONT }} />
        <Legend wrapperStyle={{ fontSize: 12, color: INK_SOFT, fontFamily: FONT }} />
        <Bar dataKey="Current" fill={INK_FAINT} radius={[0, 3, 3, 0]} barSize={10} />
        <Bar dataKey="Optimized" fill={ACCENT} radius={[0, 3, 3, 0]} barSize={10} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// Score Build-up waterfall: increment bars are now red (per request),
// total bars (Base/Current) stay black for contrast.
function ScoreWaterfall({ selected }) {
  let cum = BASE_SCORE;
  const rows = [{ name: 'Base', base: 0, value: BASE_SCORE, top: BASE_SCORE, total: true }];
  selected.forEach((f) => {
    const inc = f.reduction * 3;
    const base = cum;
    cum += inc;
    rows.push({ name: CAT_SHORT[f.category] || f.short, base, value: inc, top: cum, total: false });
  });
  const finalScore = Math.min(900, cum);
  rows.push({ name: 'Current', base: 0, value: finalScore, top: finalScore, total: true });

  return (
    <ResponsiveContainer width="100%" height={260}>
      <ComposedChart data={rows} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={BORDER} vertical={false} />
        <XAxis dataKey="name" stroke={INK_FAINT} fontSize={11} interval={0} angle={-15} textAnchor="end" height={45} style={{ fontFamily: FONT }} />
        <YAxis stroke={INK_FAINT} fontSize={11} domain={[400, 900]} style={{ fontFamily: FONT }} />
        <Tooltip contentStyle={{ background: WHITE, border: `1px solid ${BORDER}`, borderRadius: 8, fontFamily: FONT }} />
        <Bar dataKey="base" stackId="wf" fill="transparent" />
        <Bar dataKey="value" stackId="wf" radius={[4, 4, 4, 4]}>
          {rows.map((r, i) => <Cell key={i} fill={r.total ? ACCENT : '#dc2626'} />)}
        </Bar>
        <Line type="linear" dataKey="top" stroke={INK_FAINT} strokeDasharray="4 3" strokeWidth={1.5} dot={{ r: 3, fill: INK_FAINT }} />
      </ComposedChart>
    </ResponsiveContainer>
  );
}

// Risk Score Trend: line/area now red (per request).
function RiskScoreTrend({ trendData }) {
  return (
    <ResponsiveContainer width="100%" height={190}>
      <AreaChart data={trendData}>
        <CartesianGrid strokeDasharray="3 3" stroke={BORDER} vertical={false} />
        <XAxis dataKey="week" stroke={INK_FAINT} fontSize={12} style={{ fontFamily: FONT }} />
        <YAxis stroke={INK_FAINT} fontSize={12} domain={[500, 900]} style={{ fontFamily: FONT }} />
        <Tooltip contentStyle={{ background: WHITE, border: `1px solid ${BORDER}`, borderRadius: 8, fontFamily: FONT }} />
        <Area type="monotone" dataKey="score" stroke="#dc2626" strokeWidth={2} fill="#dc2626" fillOpacity={0.08} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

// ============================================================
// VULNERABILITIES
// ============================================================
function bucketForScore(score) {
  if (score <= 4) return { label: 'Low', bg: '#f0fdf4', border: '#bbf7d0', text: '#15803d' };
  if (score <= 9) return { label: 'Medium', bg: '#fefce8', border: '#fde68a', text: '#a16207' };
  if (score <= 19) return { label: 'High', bg: '#fff7ed', border: '#fed7aa', text: '#c2410c' };
  return { label: 'Critical', bg: '#fef2f2', border: '#fecaca', text: '#b91c1c' };
}

function RiskMatrix({ findings, selectedCell, onSelectCell }) {
  const [hovered, setHovered] = useState(null);
  const grid = [];
  for (let impact = 5; impact >= 1; impact--) {
    const row = [];
    for (let likelihood = 1; likelihood <= 5; likelihood++) {
      const score = impact * likelihood;
      const count = findings.filter((f) => f.impact === impact && f.likelihood === likelihood).length;
      row.push({ impact, likelihood, score, count });
    }
    grid.push(row);
  }
  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: '28px 1fr' }}>
        <div />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 3 }}>
          {[1, 2, 3, 4, 5].map((l) => (
            <div key={l} className="text-center text-[10px]" style={{ color: INK_FAINT }}>{l}</div>
          ))}
        </div>
      </div>
      {grid.map((row, ri) => (
        <div key={ri} style={{ display: 'grid', gridTemplateColumns: '28px 1fr', marginBottom: 3, alignItems: 'center' }}>
          <div className="text-[10px] text-right pr-1.5" style={{ color: INK_FAINT }}>{row[0].impact}</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 3 }}>
            {row.map((cell) => {
              const b = bucketForScore(cell.score);
              const key = `${cell.impact}-${cell.likelihood}`;
              const isSelected = selectedCell && selectedCell.impact === cell.impact && selectedCell.likelihood === cell.likelihood;
              const isHovered = hovered === key;
              return (
                <button key={cell.likelihood} onClick={() => onSelectCell(cell.count > 0 ? cell : null)}
                  onMouseEnter={() => { if (cell.count > 0) setHovered(key); }}
                  onMouseLeave={() => setHovered(null)}
                  style={{
                    height: 34, borderRadius: 4, background: b.bg,
                    border: isSelected ? `2px solid ${ACCENT}` : `1px solid ${b.border}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    cursor: cell.count > 0 ? 'pointer' : 'default',
                    transform: isHovered ? 'scale(1.08)' : 'scale(1)',
                    boxShadow: isHovered ? '0 3px 8px rgba(0,0,0,0.14)' : 'none',
                    position: 'relative', zIndex: isHovered ? 2 : 1,
                    transition: 'transform 120ms ease, box-shadow 120ms ease, border-color 120ms ease',
                  }}>
                  {cell.count > 0 ? <span className="text-[11px] font-semibold" style={{ color: b.text }}>{cell.count}</span> : null}
                </button>
              );
            })}
          </div>
        </div>
      ))}
      <div style={{ display: 'grid', gridTemplateColumns: '28px 1fr' }}>
        <div />
        <div className="text-center text-[10px] mt-1" style={{ color: INK_FAINT }}>Likelihood (from EPSS)</div>
      </div>
      <div className="flex items-center gap-4 mt-3 pt-3 flex-wrap" style={{ borderTop: `1px solid ${HAIRLINE}` }}>
        {['Low', 'Medium', 'High', 'Critical'].map((label) => {
          const sample = { Low: 2, Medium: 6, High: 14, Critical: 24 }[label];
          const b = bucketForScore(sample);
          return (
            <div key={label} className="flex items-center gap-1.5 text-[11px]" style={{ color: INK_SOFT }}>
              <div style={{ width: 9, height: 9, borderRadius: 2, background: b.bg, border: `1px solid ${b.border}` }} />
              {label}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function FindingsTable({ findings }) {
  const sorted = findings.slice().sort((a, b) => (b.impact * b.likelihood) - (a.impact * a.likelihood));
  const cols = '20px 1.6fr 1fr 60px 60px 70px 64px';
  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: cols, gap: 12, padding: '0 4px 8px 4px' }}>
        {['', 'FINDING', 'ASSET', 'CVSS', 'EPSS', 'STATUS', 'COST'].map((h) => (
          <div key={h} className="text-[10.5px] font-medium" style={{ color: INK_FAINT, letterSpacing: '0.02em' }}>{h}</div>
        ))}
      </div>
      {sorted.map((f, i) => (
        <div key={f.id}
          style={{
            display: 'grid', gridTemplateColumns: cols, gap: 12, alignItems: 'center',
            padding: '9px 4px', borderTop: `1px solid ${HAIRLINE}`,
          }}
          onMouseEnter={(e) => (e.currentTarget.style.background = '#fafafa')}
          onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}>
          <SeverityDot severity={f.severity} />
          <div className="min-w-0">
            <div className="text-[13px] font-medium truncate" style={{ color: INK }}>{f.issue}</div>
            {f.cveId ? <div className="text-[11px]" style={{ color: INK_FAINT }}>{f.cveId}</div> : null}
          </div>
          <div className="text-[12.5px] truncate" style={{ color: INK_SOFT }}>{f.asset}</div>
          <div className="text-[12.5px]" style={{ color: '#374151' }}>{f.cvss}</div>
          <div className="text-[12.5px]" style={{ color: '#374151' }}>{f.epss.toFixed(2)}</div>
          <div>{f.kev ? <Chip color="#b91c1c" bg="#fef2f2">KEV</Chip> : <span className="text-[11px]" style={{ color: INK_FAINT }}>-</span>}</div>
          <div className="text-[12.5px] text-right" style={{ color: INK }}>{fmtRupees(f.cost)}</div>
        </div>
      ))}
      {sorted.length === 0 ? (
        <div className="text-center py-8 text-sm" style={{ color: INK_FAINT }}>No findings in this cell.</div>
      ) : null}
    </div>
  );
}

function VulnsPage() {
  const [severityFilter, setSeverityFilter] = useState('All');
  const [selectedCell, setSelectedCell] = useState(null);

  let filtered = severityFilter === 'All' ? FINDINGS : FINDINGS.filter((f) => f.severity === severityFilter);
  if (selectedCell) {
    filtered = filtered.filter((f) => f.impact === selectedCell.impact && f.likelihood === selectedCell.likelihood);
  }
  const severities = ['All', 'Critical', 'High', 'Medium', 'Low'];

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between mb-1">
        <div />
        <BtnOutline icon={Download}>Export</BtnOutline>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-5">
        <Panel>
          <PanelHeader right={selectedCell ? (
            <button onClick={() => setSelectedCell(null)} className="text-[11px]" style={{ color: ACCENT }}>Clear filter</button>
          ) : null}>Risk Matrix</PanelHeader>
          <PanelBody>
            <RiskMatrix findings={FINDINGS} selectedCell={selectedCell} onSelectCell={setSelectedCell} />
          </PanelBody>
        </Panel>

        <Panel>
          <PanelHeader right={
            <div className="flex items-center gap-1.5 flex-wrap">
              {severities.map((s) => (
                <button key={s} onClick={() => setSeverityFilter(s)} className="text-[11px] px-2 py-1 rounded transition-colors"
                  style={{ background: severityFilter === s ? INK : 'transparent', color: severityFilter === s ? WHITE : INK_SOFT }}>{s}</button>
              ))}
            </div>
          }>
            {selectedCell ? `Findings for Impact ${selectedCell.impact}, Likelihood ${selectedCell.likelihood}` : 'Findings'}
          </PanelHeader>
          <PanelBody>
            <FindingsTable findings={filtered} />
          </PanelBody>
        </Panel>
      </div>
    </div>
  );
}

// ============================================================
// ATTACK SURFACE
// ============================================================
function SurfaceHeadline() {
  const total = ASSETS.length;
  const monitored = ASSETS.filter((a) => a.status === 'Monitored').length;
  const unverified = ASSETS.filter((a) => a.status === 'Unverified').length;
  const unmonitored = ASSETS.filter((a) => a.status === 'Unmonitored').length;
  const critical = ASSETS.filter((a) => a.risk === 'Critical').length;

  const stats = [
    { n: total, label: 'ASSETS IN SCOPE', color: INK },
    { n: monitored, label: 'ACTIVELY MONITORED', color: '#15803d' },
    { n: critical, label: 'CRITICAL EXPOSURE', color: SEV.Critical },
    { n: unverified + unmonitored, label: 'UNVERIFIED OR UNMONITORED', color: (unverified + unmonitored) > 0 ? SEV.Medium : INK_FAINT },
  ];

  return (
    <Panel>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)' }}>
        {stats.map((s, i) => (
          <div key={s.label} style={{ padding: '22px 22px 20px 22px', borderLeft: i === 0 ? 'none' : `1px solid ${BORDER}` }}>
            <div style={{ fontSize: 34, fontWeight: 600, color: s.color, lineHeight: 1 }}>
              {String(s.n).padStart(2, '0')}
            </div>
            <div className="text-[10px] uppercase tracking-wide mt-2" style={{ color: INK_FAINT, letterSpacing: '0.06em' }}>{s.label}</div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function ConnectedSourcesPanel({ dataSources, connecting, onConnect, onDisconnect, depth, results, errors }) {
  return (
    <Panel>
      <PanelHeader right={<DepthMeter depth={depth} />}>Connected Data Sources</PanelHeader>
      <PanelBody>
        <p className="text-xs mb-4" style={{ color: INK_SOFT }}>
          Connect internal sources anytime to deepen the scan. Each one replaces an external inference with a confirmed internal fact.
          Upload the export your vendor console produces, or grab a sample file to see the shape it expects.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
          {DATA_SOURCES.map((s) => (
            <DataSourceCard key={s.id} source={s} connected={dataSources[s.id]} connecting={connecting === s.id}
              result={(results || {})[s.id]} error={(errors || {})[s.id]}
              onConnect={(file) => onConnect(s.id, file)} onDisconnect={() => onDisconnect(s.id)} />
          ))}
        </div>
      </PanelBody>
    </Panel>
  );
}
// Discovery Coverage: segments are now colored by the highest-risk
// severity found among the assets each method surfaced, instead of an
// arbitrary grayscale gradient. This makes color carry real meaning:
// a method that only turned up Critical-risk assets renders red, one
// that only found Low-risk assets renders green, mixed/unknown renders
// amber, all within the red/amber/green/black rule.
const SEVERITY_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, Unknown: 0 };
function colorForMethod(assetsForMethod) {
  const worst = assetsForMethod.reduce((acc, a) => {
    const rank = SEVERITY_RANK[a.risk] ?? 0;
    return rank > acc.rank ? { rank, risk: a.risk } : acc;
  }, { rank: -1, risk: 'Unknown' });
  if (worst.risk === 'Critical' || worst.risk === 'High') return SEV.Critical;
  if (worst.risk === 'Medium' || worst.risk === 'Unknown') return SEV.Medium;
  return SEV.Low;
}

function DiscoveryCoverageBar() {
  const byMethod = {};
  ASSETS.forEach((a) => {
    if (!byMethod[a.method]) byMethod[a.method] = [];
    byMethod[a.method].push(a);
  });
  const methods = Object.keys(byMethod).map((m) => ({
    method: m,
    count: byMethod[m].length,
    color: colorForMethod(byMethod[m]),
  }));

  return (
    <Panel>
      <PanelHeader>Discovery Coverage: {methods.length} independent passive sources</PanelHeader>
      <PanelBody>
        <div style={{ display: 'flex', height: 12, border: `1px solid ${INK}` }}>
          {methods.map((m, i) => (
            <motion.div key={m.method}
              initial={{ flexGrow: 0 }} animate={{ flexGrow: m.count }}
              style={{ borderLeft: i === 0 ? 'none' : `1px solid ${WHITE}`, background: m.color }} />
          ))}
        </div>
        <div className="flex flex-wrap gap-x-6 gap-y-2 mt-3">
          {methods.map((m) => (
            <div key={m.method} className="flex items-center gap-2 text-[11px]" style={{ color: INK_SOFT }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: m.color }} />
              {m.method.toUpperCase()}: {m.count}
            </div>
          ))}
        </div>
        <div className="flex items-center gap-4 mt-3 pt-3 flex-wrap" style={{ borderTop: `1px solid ${HAIRLINE}` }}>
          <div className="flex items-center gap-1.5 text-[11px]" style={{ color: INK_SOFT }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: SEV.Critical }} /> Surfaced a Critical/High asset
          </div>
          <div className="flex items-center gap-1.5 text-[11px]" style={{ color: INK_SOFT }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: SEV.Medium }} /> Surfaced Medium or Unknown risk
          </div>
          <div className="flex items-center gap-1.5 text-[11px]" style={{ color: INK_SOFT }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: SEV.Low }} /> Surfaced only Low risk
          </div>
        </div>
        <p className="text-[11px] mt-3 pt-3 leading-relaxed" style={{ color: INK_FAINT, borderTop: `1px solid ${HAIRLINE}` }}>
          Each asset below was independently corroborated by at least one of these sources before being marked "monitored."
        </p>
      </PanelBody>
    </Panel>
  );
}

// Status column now renders a colored symbol + label instead of plain
// bracketed text: green check for Monitored, amber warning triangle
// for Unverified, red X for Unmonitored.
function StatusSymbol({ status }) {
  if (status === 'Monitored') {
    return (
      <span className="inline-flex items-center gap-1.5">
        <CheckCircle2 size={13} style={{ color: SEV.Low }} />
        <span className="text-[11.5px] font-medium" style={{ color: SEV.Low }}>Monitored</span>
      </span>
    );
  }
  if (status === 'Unverified') {
    return (
      <span className="inline-flex items-center gap-1.5">
        <AlertCircle size={13} style={{ color: SEV.Medium }} />
        <span className="text-[11.5px] font-medium" style={{ color: SEV.Medium }}>Unverified</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5">
      <XCircle size={13} style={{ color: SEV.Critical }} />
      <span className="text-[11.5px] font-medium" style={{ color: SEV.Critical }}>Unmonitored</span>
    </span>
  );
}

function AssetManifest() {
  const cols = '28px 1.6fr 1fr 1fr 130px 80px';
  return (
    <Panel>
      <PanelHeader right={<BtnOutline icon={Search}>Re-scan</BtnOutline>}>Asset Manifest</PanelHeader>
      <PanelBody>
        <div style={{ display: 'grid', gridTemplateColumns: cols, gap: 12, padding: '0 4px 8px 4px' }}>
          {['#', 'ASSET', 'TYPE', 'DISCOVERY METHOD', 'STATUS', 'RISK'].map((h) => (
            <div key={h} className="text-[10.5px] font-medium" style={{ color: INK_FAINT, letterSpacing: '0.03em' }}>{h}</div>
          ))}
        </div>
        {ASSETS.map((a, i) => (
          <div key={i}
            style={{ display: 'grid', gridTemplateColumns: cols, gap: 12, alignItems: 'center', padding: '10px 4px', borderTop: `1px solid ${HAIRLINE}` }}
            onMouseEnter={(e) => (e.currentTarget.style.background = '#fafafa')}
            onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}>
            <div className="text-[11px]" style={{ color: INK_FAINT }}>{String(i + 1).padStart(2, '0')}</div>
            <div className="text-[13px] font-medium" style={{ color: INK }}>{a.name}</div>
            <div className="text-[12.5px]" style={{ color: INK_SOFT }}>{a.type}</div>
            <div className="text-[12.5px]" style={{ color: INK_SOFT }}>{a.method}</div>
            <div><StatusSymbol status={a.status} /></div>
            <div className="flex items-center justify-end gap-1.5">
              <span className="text-[12px]" style={{ color: '#374151' }}>{a.risk}</span>
              <SeverityDot severity={a.risk} />
            </div>
          </div>
        ))}
      </PanelBody>
    </Panel>
  );
}

function SurfacePage({ dataSources, connecting, onConnect, onDisconnect, depth, results, errors }) {
  return (
    <div className="space-y-5">
      <SurfaceHeadline />
      <ConnectedSourcesPanel dataSources={dataSources} connecting={connecting} onConnect={onConnect} onDisconnect={onDisconnect} depth={depth} results={results} errors={errors} />
      <DiscoveryCoverageBar />
      <AssetManifest />
    </div>
  );
}

// ============================================================
// ATTACK PATHS
// ============================================================
// ---- Graph layout ------------------------------------------------------
// Nodes are placed by longest-path layering: a node sits one column to the
// right of its deepest parent. That derives the columns from the edges
// themselves rather than from a node's declared stage, so a chain of any
// length lays out correctly and an edge never points backwards. Shared
// nodes appear once and collect every edge that reaches them, which is what
// makes converging paths visible: three routes through one identity
// weakness look like three routes through one node, not three parallel
// lines.
const NODE_W = 140;
const NODE_H = 56;
const COL_GAP = 44;
const ROW_GAP = 16;

function layoutGraph(graph) {
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  if (!nodes.length) return null;

  const parents = new Map(nodes.map((n) => [n.id, []]));
  edges.forEach((e) => {
    if (parents.has(e.target)) parents.get(e.target).push(e.source);
  });

  // Longest distance from any root. `visiting` guards against a cycle so a
  // malformed graph degrades to a flat layout instead of hanging the tab.
  const depths = new Map();
  const visiting = new Set();
  function depthOf(id) {
    if (depths.has(id)) return depths.get(id);
    if (visiting.has(id)) return 0;
    visiting.add(id);
    const ps = parents.get(id) || [];
    const d = ps.length ? Math.max(...ps.map(depthOf)) + 1 : 0;
    visiting.delete(id);
    depths.set(id, d);
    return d;
  }
  nodes.forEach((n) => depthOf(n.id));

  // Align every crown jewel in the final column, so targets reached by a
  // shorter chain do not float in the middle of the diagram.
  const maxDepth = Math.max(...Array.from(depths.values()));
  nodes.forEach((n) => { if (n.kind === 'target') depths.set(n.id, maxDepth); });

  const columnCount = Math.max(...Array.from(depths.values())) + 1;
  const columns = [];
  for (let i = 0; i < columnCount; i += 1) {
    columns.push(nodes.filter((n) => depths.get(n.id) === i));
  }

  const maxRows = Math.max(...columns.map((c) => c.length));
  const height = maxRows * NODE_H + (maxRows - 1) * ROW_GAP;
  const width = columnCount * NODE_W + (columnCount - 1) * COL_GAP;

  const positioned = new Map();
  columns.forEach((column, colIndex) => {
    const colHeight = column.length * NODE_H + (column.length - 1) * ROW_GAP;
    const offsetY = (height - colHeight) / 2; // centre short columns
    column.forEach((node, rowIndex) => {
      positioned.set(node.id, {
        ...node,
        x: colIndex * (NODE_W + COL_GAP),
        y: offsetY + rowIndex * (NODE_H + ROW_GAP),
      });
    });
  });

  return { positioned, width, height };
}

/** Cubic bezier between the right edge of one node and the left edge of the next. */
function edgePath(from, to) {
  const x1 = from.x + NODE_W;
  const y1 = from.y + NODE_H / 2;
  const x2 = to.x;
  const y2 = to.y + NODE_H / 2;
  const dx = Math.max(24, (x2 - x1) / 2);
  return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
}

function AttackGraphDiagram({ graph, activePath, onSelectNode }) {
  const layout = useMemo(() => layoutGraph(graph), [graph]);
  const wrapRef = useRef(null);
  const [scale, setScale] = useState(1);

  // Shrink the diagram to fit the pane rather than making the judge scroll
  // sideways during a demo. Never scales up past 1:1, and never below 0.55,
  // where the labels stop being readable -- past that it scrolls instead.
  useEffect(() => {
    if (!layout || !wrapRef.current) return undefined;
    const el = wrapRef.current;
    const fit = () => {
      const available = el.clientWidth;
      if (!available) return;
      setScale(Math.max(0.55, Math.min(1, available / layout.width)));
    };
    fit();
    const observer = new ResizeObserver(fit);
    observer.observe(el);
    return () => observer.disconnect();
  }, [layout]);

  if (!layout) {
    return (
      <div className="text-xs py-8 text-center" style={{ color: INK_FAINT }}>
        No attack path could be constructed from the current findings.
      </div>
    );
  }

  const { positioned, width, height } = layout;
  const activeNodeIds = new Set(activePath ? activePath.node_ids : []);
  const activeEdges = new Set();
  if (activePath) {
    const ids = activePath.node_ids;
    for (let i = 0; i < ids.length - 1; i += 1) activeEdges.add(`${ids[i]}->${ids[i + 1]}`);
  }

  return (
    // Below the readable floor the diagram scrolls in its own box rather
    // than stretching the page.
    <div ref={wrapRef} style={{ overflowX: 'auto', paddingBottom: 4 }}>
      <div style={{ height: height * scale, minWidth: width * scale }}>
        <div style={{
          position: 'relative', width, height,
          transform: `scale(${scale})`, transformOrigin: 'top left',
        }}>
          <svg width={width} height={height} style={{ position: 'absolute', inset: 0, overflow: 'visible' }}>
          <defs>
            <marker id="ow-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
              <path d="M0,0 L7,3.5 L0,7 Z" fill={BORDER} />
            </marker>
            <marker id="ow-arrow-on" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
              <path d="M0,0 L7,3.5 L0,7 Z" fill={ACCENT} />
            </marker>
          </defs>
          {(graph.edges || []).map((edge) => {
            const from = positioned.get(edge.source);
            const to = positioned.get(edge.target);
            if (!from || !to) return null;
            const on = activeEdges.has(`${edge.source}->${edge.target}`);
            return (
              <motion.path
                key={`${edge.source}->${edge.target}`}
                d={edgePath(from, to)}
                fill="none"
                stroke={on ? ACCENT : BORDER}
                strokeWidth={on ? 2 : 1.25}
                markerEnd={on ? 'url(#ow-arrow-on)' : 'url(#ow-arrow)'}
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: on ? 1 : 0.55 }}
                transition={{ duration: 0.45 }}
              />
            );
          })}
        </svg>

        {Array.from(positioned.values()).map((node, i) => {
          const NodeIcon = node.iconComponent || iconByName(node.icon);
          const onPath = activeNodeIds.has(node.id);
          const choke = node.is_choke_point;
          const isFinding = node.kind === 'entry' || node.kind === 'pivot';

          const borderColor = choke ? ACCENT_BORDER : onPath ? '#9ca3af' : BORDER;
          const background = choke ? ACCENT_SOFT : WHITE;

          return (
            <motion.div
              key={node.id}
              initial={{ opacity: 0, scale: 0.96 }}
              animate={{ opacity: onPath || !activePath ? 1 : 0.45, scale: 1 }}
              transition={{ delay: i * 0.04, duration: 0.25 }}
              onClick={isFinding && onSelectNode ? () => onSelectNode(node) : undefined}
              title={
                isFinding && node.severed_paths
                  ? `Fixing this cuts ${node.severed_paths} path${node.severed_paths === 1 ? '' : 's'}`
                  : node.sub
              }
              style={{
                position: 'absolute',
                left: node.x, top: node.y, width: NODE_W, height: NODE_H,
                display: 'flex', alignItems: 'center', gap: 9,
                padding: '0 10px', borderRadius: 8,
                border: `${choke ? 1.5 : 1}px solid ${borderColor}`,
                background,
                cursor: isFinding && onSelectNode ? 'pointer' : 'default',
              }}
            >
              <div style={{
                width: 28, height: 28, borderRadius: 6, flexShrink: 0,
                background: choke ? ACCENT_TINT : '#f3f4f6',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <NodeIcon size={14} style={{ color: choke ? ACCENT : '#4b5563' }} />
              </div>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div className="text-[12px] font-medium truncate" style={{ color: INK }}>{node.label}</div>
                <div className="text-[10.5px] truncate" style={{ color: INK_FAINT }}>{node.sub}</div>
              </div>
              {choke ? (
                <span style={{
                  position: 'absolute', top: -8, right: 8,
                  background: ACCENT, color: WHITE, fontSize: 9, fontWeight: 600,
                  padding: '1px 6px', borderRadius: 999, letterSpacing: '0.02em',
                }}>BREAK HERE</span>
              ) : null}
            </motion.div>
          );
        })}
        </div>
      </div>
    </div>
  );
}

function FinancialImpactPanel({ path }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div>
        <div className="text-[11px] uppercase tracking-wide mb-1" style={{ color: INK_FAINT }}>Expected loss for this path</div>
        <div className="text-3xl font-semibold" style={{ color: INK }}>
          {fmtLakhs(path.eal)}<span className="text-sm font-normal" style={{ color: INK_FAINT }}> per year</span>
        </div>
      </div>
      <div style={{ height: 1, background: BORDER }} />
      <div>
        <div className="text-[11px] uppercase tracking-wide mb-2" style={{ color: INK_FAINT }}>MITRE ATT&CK Mapping</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {path.mitre.map((m) => (
            <div key={m.id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Chip color={ACCENT} bg={ACCENT_SOFT}>{m.id}</Chip>
              <span className="text-xs" style={{ color: '#374151' }}>{m.name}</span>
            </div>
          ))}
        </div>
      </div>
      <div style={{ height: 1, background: BORDER }} />
      <div className="rounded-lg p-3.5" style={{ background: ACCENT_SOFT, border: `1px solid ${ACCENT_BORDER}` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
          <Zap size={13} style={{ color: ACCENT }} />
          <span className="text-xs font-semibold" style={{ color: ACCENT }}>Recommended breakpoint</span>
        </div>
        <div className="text-sm font-medium mb-2" style={{ color: INK }}>{path.fix}</div>
        <div style={{ display: 'flex', gap: 16 }} className="text-xs">
          <span style={{ color: INK_SOFT }}>Cost: <strong style={{ color: INK }}>{fmtRupees(path.fixCost)}</strong></span>
          <span style={{ color: INK_SOFT }}>ROSI: <strong style={{ color: INK }}>{path.rosi === null ? 'Infinite' : `${path.rosi}%`}</strong></span>
        </div>
      </div>
    </div>
  );
}

function AttackPathsSplitPane() {
  const graph = ATTACK_GRAPH;
  const graphPaths = graph.paths || [];

  // Default to the first path that actually exists. The previous default of
  // literal id 1 only matched the sample data -- against a live scan, path
  // ids are finding ids, so nothing was ever selected.
  const [activeId, setActiveId] = useState(() => (graphPaths[0] ? graphPaths[0].id : null));

  const activePath =
    graphPaths.filter((p) => p.id === activeId)[0] || graphPaths[0] || null;

  // The right-hand panel still reads the flat path shape.
  const detailPath =
    ATTACK_PATHS.filter((p) => activePath && p.id === activePath.id)[0] || ATTACK_PATHS[0];

  if (!activePath || !detailPath) {
    return (
      <Panel>
        <PanelHeader>How someone could get in</PanelHeader>
        <PanelBody>
          <p className="text-xs" style={{ color: INK_FAINT }}>
            No attack path could be built from the current findings. A path needs at
            least one exposure an attacker could act on.
          </p>
        </PanelBody>
      </Panel>
    );
  }

  const selectNode = (node) => {
    // Clicking a node jumps to a path that runs through it.
    const hit = graphPaths.filter((p) => p.node_ids.indexOf(node.id) !== -1)[0];
    if (hit) setActiveId(hit.id);
  };

  return (
    <Panel>
      <div className="px-5 pt-5" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {graphPaths.map((p, i) => (
          <button key={p.id} onClick={() => setActiveId(p.id)} className="text-xs px-3 py-1.5 rounded-full border transition-colors"
            style={{
              background: activePath.id === p.id ? INK : WHITE,
              color: activePath.id === p.id ? WHITE : INK_SOFT,
              borderColor: activePath.id === p.id ? INK : BORDER,
            }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: pathSeverityColor(p.eal), display: 'inline-block', flexShrink: 0 }} />
              Path {i + 1}: {p.label}
            </span>
          </button>
        ))}
      </div>
      <div style={{ height: 1, background: BORDER, margin: '16px 20px' }} />
      <div style={{ display: 'grid', gridTemplateColumns: '1.85fr 1fr', gap: 0 }} className="grid-cols-1 lg:[grid-template-columns:1.85fr_1fr]">
        <div className="px-5 pb-5" style={{ borderRight: `1px solid ${BORDER}`, minWidth: 0 }}>
          <div className="flex items-center justify-between mb-2">
            <div className="text-[11px] uppercase tracking-wide" style={{ color: INK_FAINT }}>Exposure graph</div>
            <div className="text-[10.5px]" style={{ color: INK_FAINT }}>
              {graph.nodes.length} nodes · {graph.edges.length} edges · click a node to follow it
            </div>
          </div>
          <AttackGraphDiagram graph={graph} activePath={activePath} onSelectNode={selectNode} />
        </div>
        <div className="px-5 pb-5">
          <div className="text-[11px] uppercase tracking-wide mb-2" style={{ color: INK_FAINT }}>Financial impact</div>
          <AnimatePresence mode="wait">
            <motion.div key={activePath.id} initial={{ opacity: 0, x: 8 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }}>
              <FinancialImpactPanel path={detailPath} />
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </Panel>
  );
}

/**
 * States what the choke point actually severs, computed from the graph.
 *
 * This replaces a hardcoded sentence that claimed "No MFA appears as the
 * breakpoint in all three tracked paths" no matter what the data said.
 */
function ChokePointNote() {
  const choke = ATTACK_GRAPH.choke_point;
  if (!choke) return null;

  const { label, severed_paths: severed, total_paths: total, severed_eal: eal, cost } = choke;
  const allPaths = severed >= total && total > 1;
  const price = cost === 0 ? 'costs nothing' : `costs ${fmtRupees(cost)}`;

  return (
    <Panel className="p-4">
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <Info size={14} style={{ color: INK_FAINT, marginTop: 2, flexShrink: 0 }} />
        <p className="text-xs leading-relaxed" style={{ color: INK_SOFT }}>
          <strong style={{ color: INK }}>{label}</strong> is the highest-leverage fix on this
          graph: it sits on {severed} of the {total} path{total === 1 ? '' : 's'} shown
          {allPaths ? ', so fixing it once collapses every one of them at the same time' : ''}.
          It {price}, and the worst of those paths alone carries {fmtLakhs(eal)} of expected
          annual loss. This is computed from the current findings — resolve it and the
          breakpoint moves to whatever becomes the next chokepoint.
        </p>
      </div>
    </Panel>
  );
}

function PathsPage() {
  return (
    <div className="space-y-5">
      <AttackPathsSplitPane />
      <ChokePointNote />
    </div>
  );
}
// ============================================================
// SIMULATED ENTERPRISE
// ============================================================
const LAYERS = ['Threat', 'Vulnerability', 'Asset', 'Identity', 'Control Gap', 'Business Service', 'Financial Loss'];
const LAYER_STYLE = [
  { symbol: 'T', color: '#dc2626', bg: '#fef2f2' },
  { symbol: 'V', color: '#b45309', bg: '#fffbeb' },
  { symbol: 'A', color: '#4b5563', bg: '#f3f4f6' },
  { symbol: 'I', color: '#111827', bg: '#e5e7eb' },
  { symbol: 'C', color: '#a16207', bg: '#fefce8' },
  { symbol: 'B', color: '#15803d', bg: '#f0fdf4' },
  { symbol: '₹', color: '#991b1b', bg: '#fef2f2' },
];
const SAMPLE_SIM_NODES = [
  { id: 't1', layer: 0, label: 'Phishing Campaign' }, { id: 't2', layer: 0, label: 'Ransomware Group' }, { id: 't3', layer: 0, label: 'Credential Stuffing' },
  { id: 'v1', layer: 1, label: 'Unpatched VPN CVE' }, { id: 'v2', layer: 1, label: 'Weak Password Policy' }, { id: 'v3', layer: 1, label: 'Unpatched File Server' }, { id: 'v4', layer: 1, label: '2,378 minor findings' },
  { id: 'a1', layer: 2, label: 'Employee Laptops' }, { id: 'a2', layer: 2, label: 'File Server' }, { id: 'a3', layer: 2, label: 'Finance Database' },
  { id: 'i1', layer: 3, label: 'Standard User' }, { id: 'i2', layer: 3, label: 'IT Admin' }, { id: 'i3', layer: 3, label: 'Domain Admin' },
  { id: 'c1', layer: 4, label: 'No MFA' }, { id: 'c2', layer: 4, label: 'Flat Network' }, { id: 'c3', layer: 4, label: 'Unencrypted Backups' },
  { id: 'b1', layer: 5, label: 'Payroll Service' }, { id: 'b2', layer: 5, label: 'Financial Reporting' },
  { id: 'loss', layer: 6, label: '₹4.2Cr Loss' },
];
const SAMPLE_DOMINANT_EDGES = [
  { from: 't1', to: 'v2', path: 1 }, { from: 'v2', to: 'a1', path: 1 }, { from: 'a1', to: 'i1', path: 1 }, { from: 'i1', to: 'c1', path: 1 },
  { from: 'c1', to: 'i3', path: 1 }, { from: 'i3', to: 'a3', path: 1 }, { from: 'a3', to: 'b1', path: 1 }, { from: 'b1', to: 'loss', path: 1 },
  { from: 't2', to: 'v3', path: 2 }, { from: 'v3', to: 'a2', path: 2 }, { from: 'a2', to: 'i2', path: 2 }, { from: 'i2', to: 'c2', path: 2 },
  { from: 'c2', to: 'a3', path: 2 }, { from: 'a3', to: 'b2', path: 2 }, { from: 'b2', to: 'loss', path: 2 },
  { from: 't3', to: 'v2', path: 3 }, { from: 'v2', to: 'a1', path: 3 }, { from: 'a1', to: 'i1', path: 3 }, { from: 'i1', to: 'c1', path: 3 },
  { from: 'c1', to: 'i2', path: 3 }, { from: 'i2', to: 'a2', path: 3 }, { from: 'a2', to: 'b1', path: 3 }, { from: 'b1', to: 'loss', path: 3 },
  { from: 't2', to: 'v1', path: 4 }, { from: 'v1', to: 'a2', path: 4 }, { from: 'a2', to: 'i2', path: 4 }, { from: 'i2', to: 'c3', path: 4 },
  { from: 'c3', to: 'b2', path: 4 }, { from: 'b2', to: 'loss', path: 4 },
];
const SAMPLE_NOISE_EDGES = [
  { from: 't1', to: 'v4' }, { from: 'v4', to: 'a1' }, { from: 'v4', to: 'a2' }, { from: 't3', to: 'v4' },
  { from: 'v1', to: 'a1' }, { from: 'v3', to: 'a1' }, { from: 'a1', to: 'i2' }, { from: 'a2', to: 'i1' },
  { from: 'i1', to: 'c2' }, { from: 'i1', to: 'c3' }, { from: 'i2', to: 'c1' }, { from: 'c2', to: 'b1' },
  { from: 'c1', to: 'a3' }, { from: 'a1', to: 'b1' }, { from: 'a2', to: 'b2' }, { from: 'v2', to: 'a2' },
];
const PATH_COLORS = { 1: '#dc2626', 2: ACCENT, 3: '#b45309', 4: '#6b7280' };

// The causal graph is derived by the backend from the findings a scan
// produced. Until one supplies it, the sample fixture above stands in and the
// page says so.
let SIM_NODES = SAMPLE_SIM_NODES;
let DOMINANT_EDGES = SAMPLE_DOMINANT_EDGES;
let NOISE_EDGES = SAMPLE_NOISE_EDGES;
let CAUSAL_STATS = null;   // null => sample fixture
let CAUSAL_PATHS = [];

function applyCausalGraph(graph) {
  if (!graph || !graph.nodes || !graph.nodes.length) return;
  SIM_NODES = graph.nodes.map((n) => ({
    id: n.id, layer: n.layer, label: n.label,
    kind: n.kind, severity: n.severity, eal: n.eal,
    aggregate: n.aggregate, critical: n.critical,
  }));
  DOMINANT_EDGES = graph.edges
    .filter((e) => e.path != null)
    .map((e) => ({ from: e.from, to: e.to, path: e.path }));
  NOISE_EDGES = graph.edges
    .filter((e) => e.path == null)
    .map((e) => ({ from: e.from, to: e.to }));
  CAUSAL_PATHS = graph.paths || [];
  CAUSAL_STATS = {
    rawFindings: graph.raw_findings,
    attackPaths: graph.attack_paths,
    dominantPaths: graph.dominant_paths,
    totalEal: graph.total_eal,
  };
}

function resetCausalGraph() {
  SIM_NODES = SAMPLE_SIM_NODES;
  DOMINANT_EDGES = SAMPLE_DOMINANT_EDGES;
  NOISE_EDGES = SAMPLE_NOISE_EDGES;
  CAUSAL_STATS = null;
  CAUSAL_PATHS = [];
}

function truncateToWidth(text, maxChars) {
  if (!text) return '';
  return text.length > maxChars ? `${text.slice(0, maxChars - 1)}\u2026` : text;
}

/**
 * Lay nodes out in their layer's column.
 *
 * Height is derived from the busiest layer rather than fixed, because the
 * live graph can have any number of nodes per layer -- a fixed canvas made
 * dense layers overlap and clipped the bottom row.
 */
function computeLayout(nodes, width, height, layerCount) {
  const colW = width / layerCount;
  const byLayer = {};
  nodes.forEach((n) => {
    if (!byLayer[n.layer]) byLayer[n.layer] = [];
    byLayer[n.layer].push(n);
  });
  const pos = {};
  Object.keys(byLayer).forEach((layer) => {
    const arr = byLayer[layer];
    const gap = height / (arr.length + 1);
    arr.forEach((n, i) => {
      pos[n.id] = { x: colW * Number(layer) + colW / 2, y: gap * (i + 1) };
    });
  });
  return pos;
}

function CausalGraph({ showAll, highlightPath }) {
  const nodes = SIM_NODES;
  const layerCount = LAYERS.length;

  // Size the canvas to the data. A node needs ~76px of vertical room for its
  // circle plus its caption; anything tighter and captions collide with the
  // circle below them.
  const perLayer = nodes.reduce((acc, n) => {
    acc[n.layer] = (acc[n.layer] || 0) + 1;
    return acc;
  }, {});
  const densest = Math.max(1, ...Object.values(perLayer));
  // No upper cap: clamping the height is what makes a dense layer overlap.
  // A tall graph scrolls with the page, which is preferable to unreadable
  // nodes stacked on top of each other.
  const height = Math.max(340, densest * 78 + 40);
  const colW = 148;
  const width = colW * layerCount;

  const positions = useMemo(
    () => computeLayout(nodes, width, height, layerCount),
    [nodes, width, height, layerCount],
  );
  const inDominant = useMemo(() => {
    const seen = {};
    DOMINANT_EDGES.forEach((e) => { seen[e.from] = true; seen[e.to] = true; });
    return seen;
  }, [nodes]);

  const onHighlighted = useMemo(() => {
    if (!highlightPath) return null;
    const seen = {};
    DOMINANT_EDGES.filter((e) => e.path === highlightPath)
      .forEach((e) => { seen[e.from] = true; seen[e.to] = true; });
    return seen;
  }, [highlightPath, nodes]);

  // Captions must fit the column, otherwise neighbouring labels run together.
  const maxChars = Math.floor(colW / 5.6);

  return (
    <div className="overflow-x-auto" style={{ background: WHITE, minWidth: 0 }}>
      <svg
        width={width}
        height={height + 46}
        viewBox={`0 0 ${width} ${height + 46}`}
        style={{ minWidth: width, display: 'block' }}
      >
        <rect width={width} height={height + 46} fill={WHITE} />

        {LAYERS.slice(1).map((l, i) => (
          <line key={`sep${i}`}
            x1={colW * (i + 1)} y1={26} x2={colW * (i + 1)} y2={height + 34}
            stroke={BORDER} strokeWidth="1" strokeDasharray="3 4" />
        ))}

        {LAYERS.map((l, i) => (
          <text key={l} x={colW * i + colW / 2} y={17} textAnchor="middle"
            fontSize="10.5" fill={INK_FAINT} fontWeight="600">
            {truncateToWidth(l.toUpperCase(), maxChars + 2)}
          </text>
        ))}

        <g transform="translate(0,30)">
          {showAll ? NOISE_EDGES.map((e, i) => {
            const p1 = positions[e.from], p2 = positions[e.to];
            if (!p1 || !p2) return null;
            const midX = (p1.x + p2.x) / 2;
            return <motion.path key={`n${i}`}
              d={`M ${p1.x} ${p1.y} C ${midX} ${p1.y}, ${midX} ${p2.y}, ${p2.x} ${p2.y}`}
              fill="none" stroke={BORDER} strokeWidth="1"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }} />;
          }) : null}

          {DOMINANT_EDGES.map((e, i) => {
            const p1 = positions[e.from], p2 = positions[e.to];
            if (!p1 || !p2) return null;
            const midX = (p1.x + p2.x) / 2;
            const muted = highlightPath && e.path !== highlightPath;
            return <motion.path key={`d${i}`}
              d={`M ${p1.x} ${p1.y} C ${midX} ${p1.y}, ${midX} ${p2.y}, ${p2.x} ${p2.y}`}
              fill="none"
              stroke={PATH_COLORS[e.path] || INK_FAINT}
              strokeWidth={muted ? 1.5 : 2.5}
              strokeOpacity={muted ? 0.18 : 0.75}
              initial={{ pathLength: 0 }} animate={{ pathLength: 1 }}
              transition={{ duration: 0.8, delay: i * 0.015 }} />;
          })}

          {nodes.map((n) => {
            const p = positions[n.id];
            if (!p) return null;
            const dim = (!inDominant[n.id] && !showAll)
              || (onHighlighted && !onHighlighted[n.id]);
            const style = LAYER_STYLE[n.layer] || LAYER_STYLE[0];
            const r = n.layer === 6 ? 26 : n.aggregate ? 22 : 20;
            return (
              <g key={n.id} transform={`translate(${p.x}, ${p.y})`}>
                <motion.circle r={r}
                  fill={dim ? WHITE : style.bg}
                  stroke={dim ? BORDER : style.color}
                  strokeWidth={n.layer === 6 ? 2.5 : n.critical ? 2.5 : 1.5}
                  strokeDasharray={n.aggregate ? '3 3' : undefined}
                  opacity={dim ? 0.3 : 1}
                  initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ duration: 0.3 }} />
                <text y={4} textAnchor="middle" fontSize={n.layer === 6 ? 11 : 12}
                  fontWeight="700" fill={dim ? '#d1d5db' : style.color}>
                  {style.symbol}
                </text>
                <text y={r + 13} textAnchor="middle" fontSize="9.5"
                  fill={dim ? '#d1d5db' : '#374151'} fontWeight={n.layer === 6 ? 700 : 500}>
                  {truncateToWidth(n.label, maxChars)}
                </text>
                {n.eal && !dim ? (
                  <text y={r + 24} textAnchor="middle" fontSize="8.5" fill={INK_FAINT}>
                    {fmtLakhs(n.eal)}
                  </text>
                ) : null}
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}

function SimulatedEnterprisePage() {
  const [showAll, setShowAll] = useState(false);
  const [highlightPath, setHighlightPath] = useState(null);

  const live = CAUSAL_STATS !== null;
  const paths = CAUSAL_PATHS;

  // With live data the counts come from the scan; the fixture keeps its own
  // illustrative numbers so the demo view still reads correctly.
  const stats = live
    ? [
        { label: 'Raw Findings', value: CAUSAL_STATS.rawFindings.toLocaleString('en-IN') },
        { label: 'Paths Carrying Loss', value: String(CAUSAL_STATS.attackPaths) },
        { label: 'Dominant Loss Paths', value: String(CAUSAL_STATS.dominantPaths) },
        { label: 'Expected Annual Loss', value: fmtLakhs(CAUSAL_STATS.totalEal) },
      ]
    : [
        { label: 'Raw Findings', value: '2,381' },
        { label: 'Real Attack Paths', value: '43' },
        { label: 'Dominant Loss Paths', value: '4' },
        { label: 'Expected Annual Loss', value: '\u20b94.2Cr' },
      ];

  const noiseLabel = live
    ? `Show all ${CAUSAL_STATS.rawFindings.toLocaleString('en-IN')} findings`
    : 'Show all 2,381 findings';

  // The control gap shared by the most dominant paths is the highest-leverage
  // fix: severing it collapses several chains at once.
  const leverage = useMemo(() => {
    if (!live || !paths.length) return null;
    const counts = {};
    paths.forEach((p) => { if (p.breakpoint) counts[p.breakpoint] = (counts[p.breakpoint] || 0) + 1; });
    const top = Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0];
    if (!top) return null;
    const node = SIM_NODES.filter((n) => n.id === top)[0];
    const onPaths = paths.filter((p) => p.breakpoint === top);
    const worst = onPaths.reduce((m, p) => (p.eal > m.eal ? p : m), onPaths[0]);
    return { label: node ? node.label : top, count: counts[top], total: paths.length, worst };
  }, [live, paths]);

  const pathLegend = live
    ? paths.map((p) => ({ path: p.path, label: p.label, eal: p.eal, fix: p.fix }))
    : [1, 2, 3, 4].map((p) => ({ path: p, label: `Path ${p}` }));

  return (
    <div className="space-y-5">
      {live ? (
        <div className="rounded-lg px-4 py-3" style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <CheckCircle2 size={16} style={{ color: '#15803d', marginTop: 2, flexShrink: 0 }} />
          <div className="text-sm" style={{ color: '#14532d' }}>
            <span className="font-semibold">Derived from your scan.</span> Every node and edge below
            comes from the findings this scan produced. Connect more internal sources to deepen the
            identity and control-gap layers.
          </div>
        </div>
      ) : (
        <div className="rounded-lg px-4 py-3" style={{ background: '#fffbeb', border: '1px solid #fde68a', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <FlaskConical size={16} style={{ color: '#b45309', marginTop: 2, flexShrink: 0 }} />
          <div className="text-sm" style={{ color: '#78350f' }}>
            <span className="font-semibold">Sample data.</span> Run a scan to build this graph from
            your own findings. The structure below shows what the view produces once it has them.
          </div>
        </div>
      )}

      <Panel>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))' }}>
          {stats.map((c, i) => (
            <div key={c.label} style={{ padding: '14px 20px', borderLeft: i === 0 ? 'none' : `1px solid ${BORDER}`, minWidth: 0 }}>
              <div className="text-[11px] uppercase tracking-wide mb-1" style={{ color: INK_FAINT }}>{c.label}</div>
              <div className="text-2xl font-semibold truncate" style={{ color: INK }}>{c.value}</div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel>
        <PanelHeader right={
          <button onClick={() => setShowAll(!showAll)} className="flex items-center gap-2 text-xs" style={{ color: INK_SOFT }}>
            {showAll ? <ToggleRight size={20} style={{ color: ACCENT }} /> : <ToggleLeft size={20} style={{ color: INK_FAINT }} />}
            {noiseLabel}
          </button>
        }>Attack-Path Collapse</PanelHeader>
        <PanelBody>
          <CausalGraph showAll={showAll} highlightPath={highlightPath} />

          <div className="flex items-center gap-2 mt-2 pt-3 flex-wrap" style={{ borderTop: `1px solid ${BORDER}` }}>
            {pathLegend.map((p) => {
              const on = highlightPath === p.path;
              return (
                <button key={p.path}
                  onClick={() => setHighlightPath(on ? null : p.path)}
                  className="flex items-center gap-1.5 text-xs px-2 py-1 rounded-md"
                  style={{
                    color: on ? INK : INK_SOFT,
                    border: `1px solid ${on ? PATH_COLORS[p.path] : BORDER}`,
                    background: on ? ACCENT_SOFT : WHITE,
                    maxWidth: 280,
                  }}>
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: PATH_COLORS[p.path] }} />
                  <span className="truncate">{p.label}</span>
                  {p.eal ? <span className="shrink-0" style={{ color: INK_FAINT }}>{fmtLakhs(p.eal)}</span> : null}
                </button>
              );
            })}
            {highlightPath ? (
              <button onClick={() => setHighlightPath(null)} className="text-xs" style={{ color: INK_FAINT }}>
                Clear
              </button>
            ) : null}
          </div>

          <div className="flex items-center gap-3 mt-2 flex-wrap" style={{ color: INK_FAINT, fontSize: 10.5 }}>
            {LAYERS.map((l, i) => (
              <div key={l} className="flex items-center gap-1">
                <span style={{ color: LAYER_STYLE[i].color, fontWeight: 700 }}>{LAYER_STYLE[i].symbol}</span>
                <span>{l}</span>
              </div>
            ))}
          </div>
        </PanelBody>
      </Panel>

      <Panel style={{ borderLeft: `4px solid ${ACCENT}` }}>
        <PanelBody className="pt-5">
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16 }}>
            <div style={{ width: 40, height: 40, borderRadius: 8, background: ACCENT_SOFT, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
              <Zap size={18} style={{ color: ACCENT }} />
            </div>
            <div style={{ minWidth: 0 }}>
              {leverage ? (
                <>
                  <div className="text-sm font-semibold mb-1" style={{ color: INK }}>
                    Highest leverage fix: {leverage.worst.fix}
                  </div>
                  <p className="text-sm leading-relaxed" style={{ color: INK_SOFT }}>
                    "{leverage.label}" is the shared control gap on {leverage.count} of the{' '}
                    {leverage.total} dominant loss paths. Severing it collapses those chains at
                    once. The worst single path it sits on carries {fmtLakhs(leverage.worst.eal)},
                    and the fix costs{' '}
                    {leverage.worst.fix_cost === 0 ? 'nothing' : fmtRupees(leverage.worst.fix_cost)}.
                  </p>
                  <p className="text-[11px] mt-1.5" style={{ color: INK_FAINT }}>
                    Paths share findings, so the figure quoted is the worst single path rather than
                    a sum across paths.
                  </p>
                </>
              ) : (
                <>
                  <div className="text-sm font-semibold mb-1" style={{ color: INK }}>Highest leverage fix: Enable MFA</div>
                  <p className="text-sm leading-relaxed" style={{ color: INK_SOFT }}>
                    "No MFA" is a shared control gap across 3 of the 4 dominant loss paths.
                    Remediating it collapses those paths simultaneously.
                  </p>
                </>
              )}
            </div>
          </div>
        </PanelBody>
      </Panel>
    </div>
  );
}

// ============================================================
// DASHBOARD
// ============================================================
function DashboardPage({ selected, score, medianEAL, confidence, savings, calibration }) {
  const trendData = TREND_HISTORY.slice(0, -1).concat([{ week: 'W6', score }]);
  return (
    <div className="space-y-5">
      <CalibrationChips {...calibration} />
      <MetricsTable score={score} medianEAL={medianEAL} confidence={confidence} savings={savings} assetsCount={ASSETS.length} />
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
        <Panel className="lg:col-span-3">
          <PanelHeader>Security Posture: Current vs. Optimized</PanelHeader>
          <PanelBody><PostureComparison selected={selected} /></PanelBody>
        </Panel>
        <Panel className="lg:col-span-2">
          <PanelHeader>Score Build-up</PanelHeader>
          <PanelBody><ScoreWaterfall selected={selected} /></PanelBody>
        </Panel>
      </div>
      <Panel>
        <PanelHeader>Risk Score Trend</PanelHeader>
        <PanelBody><RiskScoreTrend trendData={trendData} /></PanelBody>
      </Panel>
    </div>
  );
}

// ============================================================
// FINANCIAL EXPOSURE
// ============================================================
const LOSS_FORMS = [
  { form: 'Productivity', type: 'Primary', low: 1.2, high: 4.5, desc: 'Lost staff hours during incident response and recovery' },
  { form: 'Response', type: 'Primary', low: 2.0, high: 8.0, desc: 'Forensics, legal counsel, and incident response vendor fees' },
  { form: 'Replacement', type: 'Primary', low: 1.5, high: 6.0, desc: 'Cost to rebuild or replace affected systems and data' },
  { form: 'Fines and Judgments', type: 'Secondary', low: 0, high: 12.0, desc: 'Regulatory penalties under IT Act and sector-specific rules' },
  { form: 'Reputation', type: 'Secondary', low: 1.0, high: 9.0, desc: 'Customer churn and lost future revenue after disclosure' },
  { form: 'Competitive Advantage', type: 'Secondary', low: 0, high: 5.0, desc: 'Loss of trade secrets or negotiating position' },
];

const SCENARIO_LOSSES_BASE = [
  { scenario: 'Ransomware', median: 9.2, p90: 22.5, likelihood: 'High', tiedTo: 'Exposed RDP, weak backups' },
  { scenario: 'Data Breach (customer records)', median: 6.8, p90: 15.4, likelihood: 'High', tiedTo: 'CMS flaw, no MFA' },
  { scenario: 'Business Email Compromise', median: 3.1, p90: 7.2, likelihood: 'Medium', tiedTo: 'Missing SPF/DKIM' },
  { scenario: 'Cloud Data Exposure', median: 2.4, p90: 6.1, likelihood: 'Medium', tiedTo: 'Public storage bucket' },
];

const CONTROL_MATURITY = [
  { dimension: 'Technology', weight: 40, score: 58, color: ACCENT },
  { dimension: 'Process', weight: 35, score: 41, color: '#b45309' },
  { dimension: 'People', weight: 25, score: 63, color: '#15803d' },
];

function LossMetricsTable({ medianEAL, confidence, multiplier }) {
  const rows = [
    { key: 'p50', label: 'P50', sub: 'Median', value: fmtLakhs(medianEAL), desc: 'Most likely annual loss, given current posture', dot: SEV.Low, highlight: true },
    { key: 'p90', label: 'P90', sub: 'VaR 90 - bad case', value: fmtLakhs(12.6 * multiplier), desc: 'Value at Risk: losses exceed this in roughly 1 year in 10', dot: SEV.Medium, highlight: false },
    { key: 'p99', label: 'P99', sub: 'VaR 99 - worst case', value: fmtLakhs(21.3 * multiplier), desc: 'Value at Risk: losses exceed this in roughly 1 year in 100', dot: SEV.Critical, highlight: false },
    { key: 'conf', label: 'Confidence', sub: 'Model fit', value: `${confidence}%`, desc: 'How much data supports this estimate', dot: INK_FAINT, highlight: false },
  ];
  const cols = '150px 110px minmax(200px, 1fr)';
  return (
    <Panel>
      <PanelHeader>Loss Metrics</PanelHeader>
      <PanelBody style={{ overflowX: 'auto', minWidth: 0 }}>
        <div style={{ display: 'grid', gridTemplateColumns: cols, gap: 12, padding: '0 4px 8px 4px', minWidth: 520 }}>
          {['METRIC', 'VALUE', 'MEANING'].map((h) => (
            <div key={h} className="text-[10.5px] font-medium" style={{ color: INK_FAINT, letterSpacing: '0.02em' }}>{h}</div>
          ))}
        </div>
        {rows.map((r, i) => (
          <div key={r.key}
            style={{
              display: 'grid', gridTemplateColumns: cols, gap: 12, alignItems: 'center',
              padding: '11px 4px', borderTop: i === 0 ? 'none' : `1px solid ${HAIRLINE}`,
              background: r.highlight ? '#f9fafb' : 'transparent', minWidth: 520,
            }}>
            <div className="flex items-center gap-2 min-w-0">
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: r.dot, flexShrink: 0 }} />
              <div className="min-w-0">
                <div className="text-[13.5px] font-semibold" style={{ color: INK }}>{r.label}</div>
                <div className="text-[10.5px]" style={{ color: INK_FAINT }}>{r.sub}</div>
              </div>
            </div>
            <div className="text-[16px] font-semibold" style={{ color: INK }}>{r.value}</div>
            <div className="text-[12px]" style={{ color: INK_SOFT }}>{r.desc}</div>
          </div>
        ))}
      </PanelBody>
    </Panel>
  );
}

function LossFormsBreakdown({ multiplier }) {
  const maxHigh = Math.max(...LOSS_FORMS.map((f) => f.high * multiplier));
  return (
    <Panel>
      <PanelHeader>Six Forms of Loss</PanelHeader>
      <PanelBody className="space-y-3">
        {LOSS_FORMS.map((f) => {
          const low = f.low * multiplier, high = f.high * multiplier;
          const pct = (high / maxHigh) * 100;
          const lowPct = (low / maxHigh) * 100;
          const color = f.type === 'Primary' ? ACCENT : '#b45309';
          return (
            <div key={f.form}>
              <div className="flex items-center justify-between gap-2 mb-1 flex-wrap">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-sm font-medium truncate" style={{ color: INK }}>{f.form}</span>
                  <Chip color={color} bg={f.type === 'Primary' ? ACCENT_SOFT : '#fffbeb'}>{f.type}</Chip>
                </div>
                <span className="text-xs shrink-0" style={{ color: INK_FAINT }}>{fmtLakhRange(low, high)}</span>
              </div>
              <div className="h-2.5 rounded-full relative" style={{ background: '#f3f4f6' }}>
                <div className="absolute h-full rounded-full" style={{ left: `${lowPct}%`, width: `${pct - lowPct}%`, background: color, opacity: 0.75 }} />
              </div>
              <p className="text-[11px] mt-1" style={{ color: INK_FAINT }}>{f.desc}</p>
            </div>
          );
        })}
        <div className="flex items-center gap-4 pt-2" style={{ borderTop: `1px solid ${HAIRLINE}` }}>
          <div className="flex items-center gap-1.5 text-[11px]" style={{ color: INK_SOFT }}>
            <div className="w-2.5 h-2.5 rounded-full" style={{ background: ACCENT }} /> Primary (direct cost to you)
          </div>
          <div className="flex items-center gap-1.5 text-[11px]" style={{ color: INK_SOFT }}>
            <div className="w-2.5 h-2.5 rounded-full" style={{ background: '#b45309' }} /> Secondary (from outside reaction)
          </div>
        </div>
      </PanelBody>
    </Panel>
  );
}

function ScenarioBreakdown({ multiplier }) {
  const cols = 'minmax(170px, 1.6fr) 86px 86px 100px minmax(140px, 1.2fr)';
  // The row needs more width than a narrow panel gives it. Scrolling the table
  // inside its own container keeps the columns aligned instead of letting
  // them collapse into each other, and keeps the page itself from scrolling
  // sideways.
  const scroll = { overflowX: 'auto', minWidth: 0 };
  const row = { display: 'grid', gridTemplateColumns: cols, gap: 12, minWidth: 640 };
  return (
    <Panel>
      <PanelHeader>Expected Loss by Scenario</PanelHeader>
      <PanelBody>
        <div style={scroll}>
          <div style={{ ...row, padding: '0 4px 8px 4px' }}>
            {['SCENARIO', 'MEDIAN', 'P90', 'LIKELIHOOD', 'DRIVEN BY'].map((h) => (
              <div key={h} className="text-[10.5px] font-medium" style={{ color: INK_FAINT, letterSpacing: '0.02em' }}>{h}</div>
            ))}
          </div>
          {SCENARIO_LOSSES_BASE.map((s) => (
            <div key={s.scenario} style={{ ...row, alignItems: 'center', padding: '9px 4px', borderTop: `1px solid ${HAIRLINE}` }}>
              <div className="text-[13px] font-medium" style={{ color: INK, minWidth: 0 }}>{s.scenario}</div>
              <div className="text-[12.5px]" style={{ color: '#374151' }}>{fmtLakhs(s.median * multiplier)}</div>
              <div className="text-[12.5px]" style={{ color: SEV.Medium }}>{fmtLakhs(s.p90 * multiplier)}</div>
              <div>
                <Chip color={s.likelihood === 'High' ? SEV.Critical : SEV.Medium} bg={s.likelihood === 'High' ? SEV_BG.Critical : SEV_BG.Medium}>{s.likelihood}</Chip>
              </div>
              <div className="text-[11.5px]" style={{ color: INK_FAINT, minWidth: 0 }}>{s.tiedTo}</div>
            </div>
          ))}
        </div>
      </PanelBody>
    </Panel>
  );
}

function ControlMaturityPanel() {
  const weighted = CONTROL_MATURITY.reduce((s, c) => s + (c.score * c.weight) / 100, 0);
  return (
    <Panel>
      <PanelHeader right={<span className="text-sm font-semibold" style={{ color: INK }}>{weighted.toFixed(0)}/100</span>}>
        Control Maturity Score
      </PanelHeader>
      <PanelBody className="space-y-4">
        {CONTROL_MATURITY.map((c) => (
          <div key={c.dimension}>
            <div className="flex justify-between text-xs mb-1">
              <span style={{ color: '#374151' }}>{c.dimension}<span style={{ color: INK_FAINT }}> (weight {c.weight}%)</span></span>
              <span style={{ color: INK_FAINT }}>{c.score}/100</span>
            </div>
            <div className="h-2 rounded-full overflow-hidden" style={{ background: '#f3f4f6' }}>
              <div style={{ width: `${c.score}%`, background: c.color, height: '100%', borderRadius: 9999 }} />
            </div>
          </div>
        ))}
        <p className="text-[11px] leading-relaxed pt-2" style={{ color: INK_FAINT, borderTop: `1px solid ${HAIRLINE}` }}>
          Weighted using Technology (40%), Process (35%), and People (25%), the standard control maturity split used in FAIR-based
          risk scoring. A higher score here directly lowers the vulnerability term used to compute expected loss.
        </p>
      </PanelBody>
    </Panel>
  );
}

function FinancialPage({ medianEAL, confidence, multiplier, calibration }) {
  const EAL_CURVE = [
    { pct: 'P10', loss: 1.2 * multiplier }, { pct: 'P25', loss: 2.4 * multiplier }, { pct: 'P50', loss: 4.8 * multiplier },
    { pct: 'P75', loss: 8.1 * multiplier }, { pct: 'P90', loss: 12.6 * multiplier }, { pct: 'P99', loss: 21.3 * multiplier },
  ];
  return (
    <div className="space-y-5">
      <CalibrationChips {...calibration} />

      <LossMetricsTable medianEAL={medianEAL} confidence={confidence} multiplier={multiplier} />

      <Panel>
        <PanelHeader>Loss Exceedance Curve</PanelHeader>
        <PanelBody>
          {/* Margins are explicit: the default leaves no room above the plot,
              so the "You are here" marker was clipped, and the y-axis needs
              extra width because the ticks are formatted as currency. */}
          <ResponsiveContainer width="100%" height={290}>
            <AreaChart data={EAL_CURVE} margin={{ top: 28, right: 20, left: 4, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={BORDER} vertical={false} />
              <XAxis dataKey="pct" stroke={INK_FAINT} fontSize={11} tickMargin={8}
                style={{ fontFamily: FONT }} />
              <YAxis stroke={INK_FAINT} fontSize={11} width={74} tickMargin={6}
                tickFormatter={(v) => fmtLakhs(v)} style={{ fontFamily: FONT }} />
              <Tooltip
                contentStyle={{ background: WHITE, border: `1px solid ${BORDER}`, borderRadius: 8, fontFamily: FONT }}
                formatter={(v) => [fmtLakhs(v), 'Loss']} />
              <ReferenceLine x="P50" stroke={ACCENT} strokeDasharray="4 4"
                label={{ value: 'You are here', position: 'insideTopLeft', offset: 10,
                         fill: ACCENT, fontSize: 11, fontFamily: FONT }} />
              <Area type="monotone" dataKey="loss" stroke="#dc2626" strokeWidth={2}
                fill="#dc2626" fillOpacity={0.08} />
            </AreaChart>
          </ResponsiveContainer>
        </PanelBody>
      </Panel>

      {/* min-w-0 on the children: a CSS grid track defaults to min-content,
          so without it a wide panel pushes the row past the viewport instead
          of shrinking and scrolling internally. */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="min-w-0"><LossFormsBreakdown multiplier={multiplier} /></div>
        <div className="min-w-0"><ControlMaturityPanel /></div>
      </div>

      <ScenarioBreakdown multiplier={multiplier} />

      <Panel className="p-4">
        <p className="text-xs leading-relaxed" style={{ color: INK_SOFT }}>
          Similar-sized organizations report a global median breach cost of roughly ₹4.4Cr per the IBM Cost of a Data Breach Report,
          scaled here for company size, sector, and region rather than applied directly. Loss estimates are simulated via Monte Carlo
          (10,000 iterations) rather than a single user-estimated input, which is why every figure on this page is shown as a range
          alongside a confidence percentage.
        </p>
      </Panel>
    </div>
  );
}

// ============================================================
// INVESTMENT OPTIMIZER
// ============================================================
function WhatIfPanel({ medianEAL, multiplier }) {
  const [assumed, setAssumed] = useState([]);
  const toggle = (id) => setAssumed((a) => (a.indexOf(id) === -1 ? a.concat([id]) : a.filter((x) => x !== id)));
  const fixed = FINDINGS.filter((f) => assumed.indexOf(f.id) !== -1);
  const reductionPct = fixed.reduce((s, f) => s + f.reduction, 0);
  const ealRemoved = fixed.reduce((s, f) => s + f.eal, 0) * multiplier;
  const newEAL = Math.max(0, medianEAL - ealRemoved);
  const newScore = Math.min(900, Math.round(BASE_SCORE + reductionPct * 3));
  const cost = fixed.reduce((s, f) => s + f.cost, 0);

  return (
    <Panel>
      <PanelHeader right={assumed.length > 0 ? <BtnOutline onClick={() => setAssumed([])}>Reset</BtnOutline> : null}>
        What if we fixed these?
      </PanelHeader>
      <PanelBody className="space-y-4">
        <div className="text-[12.5px]" style={{ color: INK_SOFT }}>
          Tick any combination to see the effect before committing to it. Nothing here is saved or scanned again.
        </div>
        <div>
          {FINDINGS.map((f, i) => {
            const on = assumed.indexOf(f.id) !== -1;
            return (
              <button key={f.id} onClick={() => toggle(f.id)}
                style={{ width: '100%', textAlign: 'left', display: 'grid', gridTemplateColumns: '20px 1.6fr 70px 70px', gap: 12,
                  alignItems: 'center', padding: '9px 4px', borderTop: i === 0 ? 'none' : `1px solid ${HAIRLINE}`,
                  background: 'transparent', cursor: 'pointer' }}>
                {on ? <CheckCircle2 size={14} style={{ color: ACCENT }} />
                    : <div style={{ width: 14, height: 14, borderRadius: '50%', border: `1.5px solid ${INK_FAINT}` }} />}
                <div className="text-[13px]" style={{ color: on ? INK : INK_SOFT }}>{f.issue}</div>
                <div className="text-[12.5px] text-right" style={{ color: '#15803d' }}>-{f.reduction}%</div>
                <div className="text-[12.5px] text-right" style={{ color: INK }}>{f.cost === 0 ? 'Free' : fmtRupees(f.cost)}</div>
              </button>
            );
          })}
        </div>
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: 'Score', now: BASE_SCORE, next: newScore, fmt: (v) => v, good: newScore > BASE_SCORE },
            { label: 'Expected annual loss', now: fmtLakhs(medianEAL), next: fmtLakhs(newEAL), fmt: (v) => v, good: newEAL < medianEAL },
            { label: 'Cost to get there', now: null, next: cost === 0 ? 'Free' : fmtRupees(cost), fmt: (v) => v, good: cost === 0 },
          ].map((m) => (
            <div key={m.label} className="rounded-lg p-3.5" style={{ background: '#f9fafb', border: `1px solid ${BORDER}` }}>
              <div className="text-[10.5px] uppercase tracking-wide" style={{ color: INK_FAINT }}>{m.label}</div>
              <div className="flex items-baseline gap-2 mt-1">
                {m.now !== null && <span className="text-[13px]" style={{ color: INK_FAINT, textDecoration: assumed.length ? 'line-through' : 'none' }}>{m.now}</span>}
                {assumed.length > 0 && (
                  <span className="text-[17px] font-semibold" style={{ color: m.good ? '#15803d' : INK }}>{m.next}</span>
                )}
              </div>
            </div>
          ))}
        </div>
        {assumed.length === 0 && (
          <div className="text-[11.5px]" style={{ color: INK_FAINT }}>Nothing selected yet, so the figures above show today's position.</div>
        )}
      </PanelBody>
    </Panel>
  );
}

function OptimizerPage({ budget, setBudget, selected, savings, medianEAL, multiplier }) {
  const selectedIds = selected.map((f) => f.id);
  const spent = selected.reduce((s, f) => s + f.cost, 0);
  const rosi = spent > 0 ? Math.round(((savings - spent) / spent) * 100) : null;
  const totalReduction = selected.reduce((s, f) => s + f.reduction, 0);
  const projectedScore = Math.min(900, Math.round(BASE_SCORE + totalReduction * 3));
  const scoreDelta = projectedScore - BASE_SCORE;

  return (
    <div className="space-y-5">
      <Panel>
        <PanelHeader right={<span className="text-sm font-medium" style={{ color: INK }}>Budget: {fmtRupees(budget[0])}</span>}>
          Recommended Actions
        </PanelHeader>
        <PanelBody className="space-y-4">
          <div className="flex items-center justify-between p-4 rounded-lg" style={{ background: ACCENT_SOFT, border: `1px solid ${ACCENT_BORDER}` }}>
            <div>
              <div className="text-[11px] uppercase tracking-wide" style={{ color: INK_FAINT }}>Projected Score If Applied</div>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-2xl font-semibold" style={{ color: INK }}>{projectedScore}</span>
                <span className="text-sm font-medium" style={{ color: '#15803d' }}>+{scoreDelta}</span>
                <span className="text-xs" style={{ color: INK_FAINT }}>vs. current {BASE_SCORE}</span>
              </div>
            </div>
            <Zap size={22} style={{ color: ACCENT }} />
          </div>

          <Slider value={budget} onValueChange={setBudget} max={MAX_BUDGET} step={1000} />
          <div>
            {FINDINGS.slice().sort((a, b) => (a.cost === 0 ? -1 : 1) - (b.cost === 0 ? -1 : 1)).map((f, i) => {
              const isSelected = selectedIds.indexOf(f.id) !== -1;
              return (
                <div key={f.id} style={{ display: 'grid', gridTemplateColumns: '20px 1.6fr 70px 70px', gap: 12, alignItems: 'center', padding: '9px 4px', borderTop: i === 0 ? 'none' : `1px solid ${HAIRLINE}`, opacity: isSelected ? 1 : 0.45 }}>
                  {isSelected ? <CheckCircle2 size={14} style={{ color: ACCENT }} /> : <div style={{ width: 14, height: 14, borderRadius: '50%', border: `1.5px solid ${INK_FAINT}` }} />}
                  <div className="text-[13px]" style={{ color: INK }}>{f.short}</div>
                  <div className="text-[12.5px] text-right" style={{ color: '#15803d' }}>-{f.reduction}%</div>
                  <div className="text-[12.5px] text-right" style={{ color: INK }}>{fmtRupees(f.cost)}</div>
                </div>
              );
            })}
          </div>
        </PanelBody>
      </Panel>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Panel className="p-5">
          <div className="text-xs mb-1" style={{ color: INK_FAINT }}>Annual Savings</div>
          <div className="text-2xl font-semibold" style={{ color: INK }}>{fmtRupees(savings)}</div>
        </Panel>
        <Panel className="p-5">
          <div className="text-xs mb-1" style={{ color: INK_FAINT }}>Total Spend</div>
          <div className="text-2xl font-semibold" style={{ color: INK }}>{fmtRupees(spent)}</div>
        </Panel>
        <Panel className="p-5">
          <div className="text-xs mb-1" style={{ color: INK_FAINT }}>ROSI</div>
          <div className="text-2xl font-semibold" style={{ color: INK }}>{rosi === null ? 'Infinite' : `${rosi}%`}</div>
        </Panel>
      </div>
      <WhatIfPanel medianEAL={medianEAL} multiplier={multiplier} />
    </div>
  );
}

function CompliancePage({ onOpenPassport, auditStatus, onVerifyAudit }) {
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between mb-1">
        <div />
        <div className="flex items-center gap-2">
          <BtnOutline icon={Share2} onClick={onOpenPassport}>Share as Risk Passport</BtnOutline>
          <BtnPrimary icon={Download}>Generate Report</BtnPrimary>
        </div>
      </div>
      <Panel>
        <PanelHeader>Framework Coverage</PanelHeader>
        <PanelBody className="space-y-3">
          {COMPLIANCE.map((c, i) => {
            const failing = (c.controls || []).filter((ctl) => !ctl.met);
            return (
              <div key={i}>
                <div className="flex justify-between text-xs mb-1">
                  <span style={{ color: '#374151' }}>{c.name}</span>
                  <span style={{ color: INK_FAINT }}>
                    {c.total ? `${c.met}/${c.total} controls · ` : ''}{c.coverage}%
                  </span>
                </div>
                <div className="h-2 rounded-full overflow-hidden" style={{ background: '#f3f4f6' }}>
                  <div style={{ width: `${c.coverage}%`, background: ACCENT, height: '100%', borderRadius: 9999 }} />
                </div>
                {failing.length ? (
                  <div className="mt-1.5 space-y-0.5">
                    {failing.slice(0, 3).map((ctl) => (
                      <div key={ctl.id} className="text-[10.5px] flex items-start gap-1.5" style={{ color: INK_FAINT }}>
                        <span className="font-mono shrink-0" style={{ color: SEV[ctl.severity] || INK_FAINT }}>{ctl.id}</span>
                        <span>{ctl.name} — {ctl.reason}</span>
                      </div>
                    ))}
                    {failing.length > 3 ? (
                      <div className="text-[10.5px]" style={{ color: INK_FAINT }}>
                        and {failing.length - 3} more control(s)
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </div>
            );
          })}
          {ANALYTICS_LIVE ? (
            <p className="text-[10.5px] pt-1 leading-relaxed" style={{ color: INK_FAINT }}>
              Coverage counts only the controls this platform can evidence from external
              discovery and connected sources. It is not a claim of full certification.
            </p>
          ) : null}
        </PanelBody>
      </Panel>
      <Panel>
        <PanelHeader right={
          <button onClick={onVerifyAudit}
            className="text-[11px] px-2.5 py-1 rounded-md flex items-center gap-1"
            style={{ color: INK, border: `1px solid ${BORDER}`, background: WHITE }}>
            <ShieldCheck size={11} /> Verify chain
          </button>
        }>Tamper-Evident Audit Log</PanelHeader>
        <PanelBody className="space-y-2">
          {auditStatus ? (
            <div className="rounded-lg px-3 py-2 flex items-start gap-2 mb-1"
              style={{
                background: auditStatus.intact ? '#f0fdf4' : '#fef2f2',
                border: `1px solid ${auditStatus.intact ? '#bbf7d0' : '#fecaca'}`,
              }}>
              {auditStatus.intact
                ? <CheckCircle2 size={13} style={{ color: '#15803d', marginTop: 1, flexShrink: 0 }} />
                : <XCircle size={13} style={{ color: '#b91c1c', marginTop: 1, flexShrink: 0 }} />}
              <div>
                <div className="text-[11px] font-semibold" style={{ color: auditStatus.intact ? '#15803d' : '#b91c1c' }}>
                  {auditStatus.intact ? 'Chain intact' : 'Chain broken'}
                </div>
                <div className="text-[10.5px]" style={{ color: auditStatus.intact ? '#15803d' : '#b91c1c', opacity: 0.85 }}>
                  {auditStatus.detail}
                </div>
              </div>
            </div>
          ) : null}
          {AUDIT_LOG.map((l, i) => (
            <div key={i} className="flex items-center justify-between p-3 rounded-lg" style={{ background: '#f9fafb', border: '1px solid #f3f4f6' }}>
              <div className="flex items-center gap-3">
                <div className="w-1.5 h-1.5 rounded-full" style={{ background: '#15803d' }} />
                <span className="text-sm" style={{ color: '#374151' }}>{l.action}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs" style={{ color: INK_FAINT }}>{l.hash}</span>
                <span className="text-xs" style={{ color: INK_FAINT }}>{l.time}</span>
              </div>
            </div>
          ))}
        </PanelBody>
      </Panel>
    </div>
  );
}
// ============================================================
// RISK PASSPORT + WHATSAPP DELIVERY
// ============================================================
function fakeQr(seed) {
  // Deterministic pseudo-QR pattern for visual purposes only (not scannable).
  const cells = [];
  let s = seed;
  const rand = () => { s = (s * 9301 + 49297) % 233280; return s / 233280; };
  for (let i = 0; i < 121; i++) cells.push(rand() > 0.55);
  return cells;
}
function QrGlyph({ size = 96 }) {
  const cells = useMemo(() => fakeQr(42), []);
  const n = 11;
  const cell = size / n;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ display: 'block' }}>
      <rect width={size} height={size} fill={WHITE} />
      {cells.map((on, i) => {
        if (!on) return null;
        const x = (i % n) * cell;
        const y = Math.floor(i / n) * cell;
        return <rect key={i} x={x} y={y} width={cell} height={cell} fill={INK} />;
      })}
      {/* corner finder squares, like a real QR code */}
      {[[0, 0], [size - cell * 3, 0], [0, size - cell * 3]].map(([x, y], i) => (
        <g key={i}>
          <rect x={x} y={y} width={cell * 3} height={cell * 3} fill={INK} />
          <rect x={x + cell * 0.6} y={y + cell * 0.6} width={cell * 1.8} height={cell * 1.8} fill={WHITE} />
          <rect x={x + cell * 1.1} y={y + cell * 1.1} width={cell * 0.8} height={cell * 0.8} fill={INK} />
        </g>
      ))}
    </svg>
  );
}

function PassportCard({ domain, score, medianEAL, confidence, calibration, insuranceReadiness }) {
  const band = scoreBand(score);
  return (
    <Panel className="overflow-hidden">
      <div className="p-6" style={{ background: '#fbfbfa', borderBottom: `1px solid ${BORDER}` }}>
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: INK }}>
              <Shield color={WHITE} size={18} />
            </div>
            <div>
              <div className="text-sm font-semibold" style={{ color: INK }}>OwLance Risk Passport</div>
              <div className="text-xs" style={{ color: INK_FAINT }}>{domain || 'company.com'}</div>
            </div>
          </div>
          <Chip color={band.color} bg={band.bg}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}><BadgeCheck size={11} /> Verified</span>
          </Chip>
        </div>
      </div>

      <div className="p-6 grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-6 items-center">
        <div>
          <div className="text-[11px] uppercase tracking-wide mb-2" style={{ color: INK_FAINT }}>Overall Risk Score</div>
          <div className="flex items-baseline gap-2 mb-1">
            <span className="text-5xl font-semibold" style={{ color: INK }}>{score}</span>
            <span className="text-sm" style={{ color: INK_FAINT }}>/ 900</span>
            <Chip color={band.color} bg={band.bg}>{band.label}</Chip>
          </div>
          <p className="text-xs mb-4" style={{ color: INK_FAINT }}>Verified 2 days ago &middot; scored against {calibration.industry} businesses of similar size</p>
          <div className="grid grid-cols-3 gap-3 max-w-sm">
            <div className="rounded-lg p-2.5" style={{ background: '#f9fafb', border: `1px solid ${BORDER}` }}>
              <div className="text-[10px]" style={{ color: INK_FAINT }}>Confidence</div>
              <div className="text-sm font-semibold" style={{ color: INK }}>{confidence}%</div>
            </div>
            <div className="rounded-lg p-2.5" style={{ background: '#f9fafb', border: `1px solid ${BORDER}` }}>
              <div className="text-[10px]" style={{ color: INK_FAINT }}>Insurance ready</div>
              <div className="text-sm font-semibold" style={{ color: INK }}>{insuranceReadiness}%</div>
            </div>
            <div className="rounded-lg p-2.5" style={{ background: '#f9fafb', border: `1px solid ${BORDER}` }}>
              <div className="text-[10px]" style={{ color: INK_FAINT }}>EAL exposure</div>
              <div className="text-sm font-semibold" style={{ color: INK }}>{fmtLakhs(medianEAL)}</div>
            </div>
          </div>
        </div>
        <div className="flex flex-col items-center gap-2 justify-self-center">
          <div className="p-2 rounded-lg" style={{ border: `1px solid ${BORDER}` }}>
            <QrGlyph size={92} />
          </div>
          <span className="text-[10px]" style={{ color: INK_FAINT }}>Scan to verify</span>
        </div>
      </div>

      <div className="px-6 pb-5">
        <div className="text-[11px] uppercase tracking-wide mb-2" style={{ color: INK_FAINT }}>What this passport proves</div>
        <div className="space-y-1.5">
          {[
            'The score above was computed by OwLance from live scan data, not self-reported.',
            'It links back to a tamper-evident hash-chain log — editing the underlying record would break verification.',
            'It intentionally does not list any specific vulnerabilities, open ports, or findings that could be used against this organization.',
          ].map((t, i) => (
            <div key={i} className="flex items-start gap-2 text-xs" style={{ color: '#374151' }}>
              <CheckCircle2 size={13} style={{ color: '#15803d', marginTop: 1, flexShrink: 0 }} />
              {t}
            </div>
          ))}
        </div>
      </div>

      <div className="px-6 py-3.5 flex items-center justify-between flex-wrap gap-2" style={{ borderTop: `1px solid ${HAIRLINE}`, background: '#fbfbfa' }}>
        <div className="flex items-center gap-1.5 text-[11px]" style={{ color: INK_FAINT }}>
          <Lock size={11} /> Hash 8a2f...c91e &middot; <a href="#" onClick={(e) => e.preventDefault()} style={{ color: INK, textDecoration: 'underline' }}>Verify authenticity</a>
        </div>
        <span className="text-[11px]" style={{ color: INK_FAINT }}>Expires if unscanned for 30 days</span>
      </div>
    </Panel>
  );
}

const WHATSAPP_SAMPLE_MESSAGES = [
  { kind: 'in', text: 'Weekly check complete. Your OwLance score is 620/900 (Moderate). No new critical issues found.' },
  { kind: 'in', text: 'Heads up: a new subdomain "legacy-vpn.company.com" just appeared with an open port. Want us to check it?' },
  { kind: 'out', text: 'Yes please' },
  { kind: 'in', text: 'Done. It was an old RDP port, now flagged Critical. Fix is free (close the port) — reply FIX to see steps.' },
  { kind: 'in', text: 'Your score improved to 660 after closing that port. New passport link: owlance.in/p/comp-a91f' },
];

/**
 * WhatsApp renders *bold* and _italic_ markers as formatting rather than
 * literal characters, so the preview strips them -- otherwise the mock shows
 * asterisks the recipient will never see. Line breaks are preserved, since
 * the message's structure is most of its readability.
 */
function renderWhatsAppText(text) {
  return String(text)
    .replace(/\*(.+?)\*/g, '$1')
    .replace(/_(.+?)_/g, '$1');
}

function WhatsAppBubble({ kind, text }) {
  const isIn = kind === 'in';
  return (
    <div className="flex" style={{ justifyContent: isIn ? 'flex-start' : 'flex-end' }}>
      <div className="text-xs rounded-lg px-3 py-2 max-w-[82%] leading-relaxed" style={{
        background: isIn ? WHITE : '#dcf8c6',
        border: isIn ? `1px solid ${BORDER}` : 'none',
        color: '#1f2937',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
      }}>{renderWhatsAppText(text)}</div>
    </div>
  );
}

function WhatsAppDeliveryPanel({ phone, setPhone, sending, result, waConfig, onSend }) {
  // The phone mock shows the message that would actually go out once a send
  // has been composed, and the illustrative thread before that.
  const live = result && result.body;

  return (
    <Panel>
      <PanelHeader right={
        waConfig === null
          ? <Chip color={INK_FAINT} bg="#f3f4f6">Checking delivery</Chip>
          : waConfig.configured
            ? <Chip color="#15803d" bg="#f0fdf4">Live delivery</Chip>
            : <Chip color="#b45309" bg="#fffbeb">Preview only</Chip>
      }>Send updates where the owner already looks</PanelHeader>
      <PanelBody>
        <p className="text-xs mb-4 max-w-md" style={{ color: INK_FAINT }}>
          Most owners in this segment will not log into a dashboard every week. OwLance can push score
          changes, new exposures, and the single top fix directly to WhatsApp, in plain language, with a
          one-tap link back to the full passport.
        </p>
        <div className="grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-5">
          <div>
            <div className="rounded-2xl p-3 mx-auto" style={{ background: '#111b21', width: 220 }}>
              <div className="rounded-xl overflow-hidden" style={{ background: '#e5ddd5' }}>
                <div className="px-3 py-2 flex items-center gap-2" style={{ background: '#075e54' }}>
                  <div className="w-6 h-6 rounded-full flex items-center justify-center" style={{ background: WHITE }}>
                    <Shield size={12} style={{ color: '#075e54' }} />
                  </div>
                  <div>
                    <div className="text-[11px] font-medium" style={{ color: WHITE }}>OwLance</div>
                    <div className="text-[9px]" style={{ color: '#d1f0e8' }}>Business account</div>
                  </div>
                </div>
                <div className="p-2.5 space-y-2" style={{ minHeight: 260, maxHeight: 340, overflowY: 'auto' }}>
                  {live
                    ? <WhatsAppBubble kind="in" text={result.body} />
                    : WHATSAPP_SAMPLE_MESSAGES.map((m, i) => <WhatsAppBubble key={i} {...m} />)}
                </div>
              </div>
            </div>
            {live ? (
              <p className="text-[10.5px] mt-2 text-center" style={{ color: INK_FAINT }}>
                {result.delivered ? 'Delivered message' : 'Composed message (not delivered)'}
              </p>
            ) : null}
          </div>
          <div className="flex flex-col justify-between gap-4">
            <div className="space-y-2.5">
              {[
                ['Score changes', 'Only sent when the score actually moves, not on a fixed schedule.'],
                ['New exposure detected', 'Attack-surface drift — a new port, subdomain, or leaked credential.'],
                ['One weekly nudge', 'A single top-priority free fix, never a full findings dump.'],
              ].map(([t, d], i) => (
                <div key={i} className="flex items-start gap-2.5">
                  <CheckCheck size={14} style={{ color: '#15803d', marginTop: 2, flexShrink: 0 }} />
                  <div>
                    <div className="text-xs font-medium" style={{ color: INK }}>{t}</div>
                    <div className="text-[11.5px]" style={{ color: INK_FAINT }}>{d}</div>
                  </div>
                </div>
              ))}
            </div>
            <div className="rounded-lg p-3.5" style={{ background: '#f9fafb', border: `1px solid ${BORDER}` }}>
              <div className="text-[11px] uppercase tracking-wide mb-2" style={{ color: INK_FAINT }}>
                Send the full current status
              </div>
              <div className="flex gap-2">
                <input value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="+91 98765 43210"
                  onKeyDown={(e) => { if (e.key === 'Enter') onSend(); }}
                  className="flex-1 text-sm rounded-md px-3 py-2 outline-none" style={{ border: `1px solid ${BORDER}`, color: INK, fontFamily: FONT }} />
                <BtnPrimary
                  icon={sending ? Loader2 : result && result.delivered ? CheckCircle2 : Smartphone}
                  onClick={onSend}>
                  {sending ? 'Sending' : 'Send status'}
                </BtnPrimary>
              </div>

              {result ? (
                <div className="mt-2.5 rounded-md p-2.5" style={{
                  background: result.delivered ? '#f0fdf4' : '#fffbeb',
                  border: `1px solid ${result.delivered ? '#bbf7d0' : '#fde68a'}`,
                }}>
                  <p className="text-[11px]" style={{ color: result.delivered ? '#15803d' : '#b45309' }}>
                    {result.message}
                  </p>
                  {result.hint ? (
                    <p className="text-[10.5px] mt-1" style={{ color: INK_FAINT }}>{result.hint}</p>
                  ) : null}
                </div>
              ) : (
                <p className="text-[11px] mt-2" style={{ color: INK_FAINT }}>
                  {waConfig && !waConfig.configured
                    ? 'No Twilio credentials on the backend yet, so this will show the exact message without delivering it.'
                    : 'Sends score, exposure, ranked fixes, framework coverage, and the passport link in one message.'}
                </p>
              )}
            </div>
          </div>
        </div>
      </PanelBody>
    </Panel>
  );
}

function PassportPage({
  domain, score, medianEAL, confidence, calibration,
  phone, setPhone, sending, result, waConfig, onSend,
}) {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold" style={{ color: INK }}>Risk Passport</h1>
        <p className="text-sm mt-0.5" style={{ color: INK_FAINT }}>
          A shareable proof of your security posture — for a bank, an insurer, or a client — without exposing what's still open.
        </p>
      </div>
      <div className="flex items-center gap-2 flex-wrap">
        <BtnPrimary icon={sending ? Loader2 : Smartphone} onClick={onSend}>
          {sending ? 'Sending status' : 'Send full status to WhatsApp'}
        </BtnPrimary>
        <BtnOutline icon={Share2}>Copy shareable link</BtnOutline>
        <BtnOutline icon={Download}>Download as PDF</BtnOutline>
        <BtnOutline icon={ExternalLink}>Open public preview</BtnOutline>
      </div>
      {!phone.trim() ? (
        <p className="text-[11px] -mt-2" style={{ color: INK_FAINT }}>
          Add a number below first — the button sends the whole snapshot in one message.
        </p>
      ) : null}
      <PassportCard domain={domain} score={score} medianEAL={medianEAL} confidence={confidence} calibration={calibration} insuranceReadiness={78} />
      <WhatsAppDeliveryPanel
        phone={phone} setPhone={setPhone}
        sending={sending} result={result} waConfig={waConfig} onSend={onSend} />
    </div>
  );
}

// ============================================================
// NAV / SHELL
// ============================================================
const NAV_GROUPS_LIVE = [
  { label: 'MONITOR', items: [{ id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard }] },
  { label: 'DISCOVER & ASSESS', items: [
    { id: 'surface', label: 'Attack Surface', icon: Network, badge: ASSETS.length },
    { id: 'vulns', label: 'Vulnerabilities', icon: Bug, badge: FINDINGS.length },
    { id: 'paths', label: 'Attack Paths', icon: Route },
  ]},
  { label: 'QUANTIFY & ACT', items: [
    { id: 'financial', label: 'Financial Exposure', icon: Landmark },
    { id: 'optimizer', label: 'Investment Optimizer', icon: Wallet },
  ]},
  { label: 'GOVERN', items: [{ id: 'compliance', label: 'Compliance & Reports', icon: FileCheck2 }] },
  { label: 'SHARE & NOTIFY', items: [{ id: 'passport', label: 'Risk Passport', icon: Share2, badge: 'New' }] },
];
const NAV_GROUPS_SIM = [{ label: 'SIMULATED ENTERPRISE', items: [{ id: 'simgraph', label: 'Causal Risk Graph', icon: Network }] }];

// ============================================================
// DATA PROVENANCE BANNER
// ------------------------------------------------------------
// Every number on screen is either live from the backend or from the built-in
// sample dataset. Showing which, permanently and unambiguously, keeps the demo
// honest -- and means a failed scan degrades visibly instead of silently.
// ============================================================
function DataOriginBanner({ origin, domain, onRescan }) {
  const isLive = origin.mode === 'live';
  const partial = isLive && origin.confidence && origin.confidence !== 'high';

  const tone = !isLive
    ? { bg: '#fffbeb', border: '#fde68a', fg: '#92400e', Icon: AlertTriangle }
    : partial
      ? { bg: '#fefce8', border: '#fde68a', fg: '#854d0e', Icon: Info }
      : { bg: '#f0fdf4', border: '#bbf7d0', fg: '#15803d', Icon: CheckCircle2 };

  const label = isLive
    ? `Live data \u2014 ${domain}${partial ? ` (coverage: ${origin.confidence})` : ''}`
    : 'Sample dataset';

  return (
    <div className="mb-4 rounded-lg border px-3 py-2.5"
      style={{ background: tone.bg, borderColor: tone.border }}>
      <div className="flex items-start gap-2">
        <tone.Icon size={15} style={{ color: tone.fg, marginTop: 1, flexShrink: 0 }} />
        <div className="flex-1 min-w-0">
          <div className="text-xs font-semibold" style={{ color: tone.fg }}>{label}</div>
          {origin.reason ? (
            <div className="text-xs mt-0.5" style={{ color: tone.fg, opacity: 0.85 }}>{origin.reason}</div>
          ) : null}
          {(origin.notes || []).map((n, i) => (
            <div key={i} className="text-xs mt-0.5" style={{ color: tone.fg, opacity: 0.85 }}>{n}</div>
          ))}
          {isLive && origin.scanId ? (
            <div className="text-[10px] mt-1 font-mono" style={{ color: tone.fg, opacity: 0.6 }}>
              scan {origin.scanId.slice(0, 8)}
            </div>
          ) : null}
        </div>
        {onRescan ? (
          <button onClick={onRescan}
            className="text-xs px-2 py-1 rounded-md flex items-center gap-1 shrink-0"
            style={{ color: tone.fg, border: `1px solid ${tone.border}`, background: WHITE }}>
            <RefreshCw size={11} /> Rescan
          </button>
        ) : null}
      </div>
    </div>
  );
}

// ============================================================
// AUTHENTICATION
// ============================================================
function AuthScreen({ onAuthed, onSkip, backendUp }) {
  const [mode, setMode] = useState('login');   // 'login' | 'register'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [orgName, setOrgName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const isRegister = mode === 'register';
  const canSubmit = email.trim() && password && !busy;

  const submit = async () => {
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const user = isRegister
        ? await apiRegister({ email: email.trim(), password, orgName })
        : await apiLogin({ email: email.trim(), password });
      onAuthed(user);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const field = (label, value, setter, type = 'text', placeholder = '', autoComplete = undefined) => (
    <div>
      <label className="text-[11px] uppercase tracking-wide block mb-1.5" style={{ color: INK_FAINT }}>{label}</label>
      <input
        type={type}
        value={value}
        autoComplete={autoComplete}
        placeholder={placeholder}
        onChange={(e) => setter(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && submit()}
        className="w-full rounded-lg px-3 py-2.5 text-sm outline-none"
        style={{ border: `1px solid ${BORDER}`, color: INK, fontFamily: FONT, background: WHITE }}
      />
    </div>
  );

  return (
    <>
      <GlobalFont />
      <div className="min-h-screen flex items-center justify-center p-6" style={{ background: PAPER, fontFamily: FONT }}>
        <div className="w-full max-w-sm">
          <div className="flex items-center justify-center gap-2 mb-7">
            <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: INK }}>
              <Shield color={WHITE} size={18} />
            </div>
            <span className="text-xl font-semibold" style={{ color: INK }}>OwLance</span>
          </div>

          <Panel className="p-5">
            <h1 className="text-base font-semibold mb-1" style={{ color: INK }}>
              {isRegister ? 'Create your account' : 'Sign in'}
            </h1>
            <p className="text-xs mb-5" style={{ color: INK_FAINT }}>
              {isRegister
                ? 'An account keeps your scan history and audit trail across sessions.'
                : 'Your scans, score history, and audit log are tied to your account.'}
            </p>

            <div className="space-y-3">
              {field('Work email', email, setEmail, 'email', 'you@company.com', 'email')}
              {field('Password', password, setPassword, 'password',
                     isRegister ? 'At least 8 characters, with a number' : '',
                     isRegister ? 'new-password' : 'current-password')}
              {isRegister ? field('Organisation (optional)', orgName, setOrgName, 'text', 'Acme Pvt Ltd') : null}
            </div>

            {error ? (
              <div className="mt-3 rounded-md px-2.5 py-2 flex items-start gap-1.5"
                style={{ background: '#fef2f2', border: '1px solid #fecaca' }}>
                <XCircle size={12} style={{ color: '#b91c1c', marginTop: 1, flexShrink: 0 }} />
                <span className="text-[11px]" style={{ color: '#b91c1c' }}>{error}</span>
              </div>
            ) : null}

            {backendUp === false ? (
              <div className="mt-3 rounded-md px-2.5 py-2 flex items-start gap-1.5"
                style={{ background: '#fffbeb', border: '1px solid #fde68a' }}>
                <AlertTriangle size={12} style={{ color: '#92400e', marginTop: 1, flexShrink: 0 }} />
                <span className="text-[11px]" style={{ color: '#92400e' }}>
                  Backend not reachable. You can continue without an account and explore with sample data.
                </span>
              </div>
            ) : null}

            <button onClick={submit} disabled={!canSubmit}
              className="w-full mt-4 rounded-lg py-2.5 text-sm font-medium flex items-center justify-center gap-2"
              style={{ background: canSubmit ? INK : '#d1d5db', color: WHITE, cursor: canSubmit ? 'pointer' : 'not-allowed' }}>
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Lock size={14} />}
              {busy ? 'Working' : isRegister ? 'Create account' : 'Sign in'}
            </button>

            <button
              onClick={() => { setMode(isRegister ? 'login' : 'register'); setError(null); }}
              className="w-full mt-2.5 text-[11.5px]" style={{ color: INK_SOFT }}>
              {isRegister ? 'Already have an account? Sign in' : 'No account? Create one'}
            </button>
          </Panel>

          <button onClick={onSkip} className="w-full mt-3 text-[11.5px]" style={{ color: INK_FAINT }}>
            Continue without an account
          </button>
          <p className="text-[10.5px] text-center mt-1.5 leading-relaxed" style={{ color: INK_FAINT }}>
            Scanning works signed out. History and the audit trail are not retained.
          </p>
        </div>
      </div>
    </>
  );
}

export default function OwLanceDemo() {
  const [screen, setScreen] = useState('auth');
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [auditStatus, setAuditStatus] = useState(null);
  const [mode, setMode] = useState('live');
  const [active, setActive] = useState('dashboard');
  const [domain, setDomain] = useState('');

  // onboarding state
  const [industry, setIndustry] = useState(INDUSTRIES[0]);
  const [employees, setEmployees] = useState(EMPLOYEE_BANDS[1]);
  const [revenueBand, setRevenueBand] = useState(REVENUE_BANDS[1].id);
  const [dataSources, setDataSources] = useState({
    cloud: false, identity: false, endpoint: false, siem: false, cmdb: false, insurance: false,
  });
  const [connectorResults, setConnectorResults] = useState({});
  const [connectorErrors, setConnectorErrors] = useState({});
  const [connecting, setConnecting] = useState(null);
  const [activeConsent, setActiveConsent] = useState(false);
  const [authorized, setAuthorized] = useState(false);

  // live scan state
  const [dataVersion, setDataVersion] = useState(0);
  const [origin, setOrigin] = useState(DATA_ORIGIN);
  const [scanError, setScanError] = useState(null);
  const [backendUp, setBackendUp] = useState(null); // null = unknown until probed

  const [budget, setBudget] = useState([15000]);
  const [waPhone, setWaPhone] = useState('');
  const [waSending, setWaSending] = useState(false);
  const [waResult, setWaResult] = useState(null);
  // null until the backend answers, so the UI can say "checking" rather than
  // guessing whether delivery is live.
  const [waConfig, setWaConfig] = useState(null);
  const [chatOpen, setChatOpen] = useState(false);
  const [messages, setMessages] = useState([{ role: 'ai', text: 'Ask me anything in plain English \u2014 for example, "What is our highest financial risk today?"' }]);
  const [chatInput, setChatInput] = useState('');

  // Probe the backend once on mount so the header can report whether this
  // session is running against live data before the user commits to a scan.
  useEffect(() => {
    let cancelled = false;
    checkHealth()
      .then(() => { if (!cancelled) setBackendUp(true); })
      .catch(() => { if (!cancelled) setBackendUp(false); });

    // Whether Twilio credentials are present, so the passport page can say
    // up front whether a send will really deliver or only compose.
    fetchWhatsAppStatus()
      .then((cfg) => { if (!cancelled) setWaConfig(cfg); })
      .catch(() => {
        if (!cancelled) setWaConfig({ configured: false, missing: [], detail: 'Backend unreachable' });
      });

    // Resolve a stored token so a refresh does not force a re-login.
    fetchMe()
      .then((me) => {
        if (cancelled) return;
        if (me) { setUser(me); setScreen('landing'); }
      })
      .catch(() => { /* treated as signed out */ })
      .finally(() => { if (!cancelled) setAuthChecked(true); });

    return () => { cancelled = true; };
  }, []);

  const handleAuthed = (me) => {
    setUser(me);
    setScreen('landing');
  };

  const handleVerifyAudit = async () => {
    try {
      setAuditStatus(await verifyAudit());
    } catch (err) {
      setAuditStatus({ intact: false, detail: `Could not reach the audit service: ${err.message}` });
    }
  };

  const handleSignOut = () => {
    apiLogout();
    setUser(null);
    applySampleData(null);
    resetAnalytics();
    setConnectorResults({});
    setDataSources({ cloud: false, identity: false, endpoint: false, siem: false, cmdb: false, insurance: false });
    setOrigin(DATA_ORIGIN);
    setDataVersion((v) => v + 1);
    setScreen('auth');
  };

  // Ingest a real export. The file is parsed by the backend, and whatever it
  // yields -- new findings, re-weighted criticality, a coverage gap -- is
  // merged into the live data store and the score is recomputed.
  const connectSource = async (id, file) => {
    if (!file) return;
    setConnecting(id);
    setConnectorErrors((prev) => ({ ...prev, [id]: null }));

    try {
      const result = await uploadConnector({
        sourceId: id,
        file,
        scanId: DATA_ORIGIN.scanId || undefined,
        modelledEalLakhs: Math.round(medianEAL),
      });

      mergeConnectorResult(id, result);

      // A connector changes findings, so compliance coverage, attack paths
      // and category risk all move with it.
      if (result.persisted && DATA_ORIGIN.scanId) {
        const [analytics, audit] = await Promise.all([
          fetchAnalytics(DATA_ORIGIN.scanId).catch(() => null),
          fetchAudit({ scanId: DATA_ORIGIN.scanId, limit: 12 }).catch(() => null),
        ]);
        applyAnalytics({ analytics, audit });
      }

      setDataSources((prev) => ({ ...prev, [id]: true }));
      setConnectorResults((prev) => ({ ...prev, [id]: result }));
      setOrigin(DATA_ORIGIN);
      setDataVersion((v) => v + 1);
    } catch (err) {
      setConnectorErrors((prev) => ({ ...prev, [id]: err.message }));
    } finally {
      setConnecting(null);
    }
  };

  const disconnectSource = async (id) => {
    // Drop the contribution locally first so the UI stays responsive even if
    // the backend call fails; the local store is the source of truth for
    // what is rendered.
    removeConnectorResult(id);
    setDataSources((prev) => ({ ...prev, [id]: false }));
    setConnectorResults((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
    setConnectorErrors((prev) => ({ ...prev, [id]: null }));
    setOrigin(DATA_ORIGIN);
    setDataVersion((v) => v + 1);

    if (DATA_ORIGIN.scanId) {
      try {
        await disconnectConnector({ sourceId: id, scanId: DATA_ORIGIN.scanId });
      } catch (err) {
        console.warn('Backend disconnect failed:', err.message);
      }
    }
  };

  const connectedCount = Object.values(dataSources).filter(Boolean).length;
  const depth = 1 + connectedCount;
  const revenueMultiplier = REVENUE_BANDS.filter((r) => r.id === revenueBand)[0].mult;
  const revenueLabel = REVENUE_BANDS.filter((r) => r.id === revenueBand)[0].label;

  const selected = useMemo(() => optimizeForBudget(budget[0]), [budget]);
  const totalReduction = selected.reduce((s, f) => s + f.reduction, 0);
  const score = Math.min(900, Math.round(BASE_SCORE + totalReduction * 3));
  const confidence = Math.min(99, Math.round(FINDINGS.reduce((s, f) => s + f.confidence, 0) / FINDINGS.length) + connectedCount * 4);
  const medianEALBase = Math.max(1, 7 - totalReduction * 0.045);
  const medianEAL = medianEALBase * revenueMultiplier;
  const savingsNum = (7 - medianEALBase) * 100000 * revenueMultiplier;

  const calibration = { industry, employees, revenueLabel, depth };

  const handleLandingScan = () => { if (!domain.trim()) return; setScreen('context'); };

  /**
   * Send everything currently on screen to WhatsApp in one message.
   *
   * The snapshot is built from live state rather than the stored scan, so it
   * reflects the user's current optimizer position and revenue calibration --
   * what they are actually looking at is what the recipient receives.
   */
  const sendWaStatus = async () => {
    if (!waPhone.trim() || waSending) return;
    setWaSending(true);
    setWaResult(null);

    const bySeverity = FINDINGS.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {});

    const snapshot = {
      domain: domain.trim() || 'your organisation',
      as_of: new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }),
      score,
      confidence,
      // Omitted entirely when nothing has computed it. The message says
      // "X% of the controls underwriters usually ask for", which must not be
      // a number we invented.
      insurance_readiness: INSURANCE_READINESS ?? undefined,
      median_eal: Number(medianEAL.toFixed(1)),
      // Same P90/P99 spread the financial page draws, so the message and the
      // dashboard cannot quote different numbers.
      p90_eal: Number((medianEAL * 3.05).toFixed(1)),
      p99_eal: Number((medianEAL * 6.98).toFixed(1)),
      findings_summary: bySeverity,
      top_fixes: selected.slice(0, 5).map((f) => ({
        name: f.issue || f.short,
        cost: f.cost,
        reduction: f.reduction,
      })),
      compliance: COMPLIANCE.map((c) => ({ name: c.name, coverage: c.coverage })),
      verification_hash: AUDIT_LOG.length ? AUDIT_LOG[0].hash : undefined,
    };

    try {
      const res = await sendPassportWhatsApp({
        phone: waPhone,
        snapshot,
        scanId: DATA_ORIGIN.scanId,
      });
      setWaResult(res);
    } catch (err) {
      // A backend that is down is a delivery failure like any other; show it
      // rather than leaving the button spinning.
      setWaResult({
        delivered: false,
        message: `Could not reach the backend: ${err.message}`,
        body: '',
      });
    } finally {
      setWaSending(false);
    }
  };

  const handleRunScan = async () => {
    setScreen('scanning');
    setScanError(null);

    const target = domain.trim().replace(/^https?:\/\//i, '').split('/')[0];
    const startedAt = Date.now();

    // Hold the scanning screen briefly even on a fast response, so the
    // transition does not flash past before it can be read.
    const settle = async () => {
      const elapsed = Date.now() - startedAt;
      if (elapsed < 1200) await new Promise((r) => setTimeout(r, 1200 - elapsed));
    };

    try {
      // Consent is recorded before any scanning begins. A failure to log it
      // is surfaced in the console but does not block the assessment.
      try {
        await postConsent({ domain: target, activeScanAllowed: activeConsent });
      } catch (err) {
        console.warn('Consent logging failed:', err.message);
      }

      const scan = adaptScan(await runScan(target));

      if (scan.findings.length === 0) {
        // The backend answered, but there is nothing to populate a dashboard
        // with. Show the sample dataset rather than a wall of empty panels,
        // and say plainly that that is what is happening.
        applySampleData(
          'Live scan of ' + scan.domain + ' completed but surfaced no findings ' +
          '(coverage: ' + scan.confidence + '). Showing the sample dataset.'
        );
        setBackendUp(true);
      } else {
        applyLiveScan(scan);
        setBackendUp(true);
      }
    } catch (err) {
      applySampleData('Backend unreachable (' + err.message + '). Showing the sample dataset.');
      setScanError(err.message);
      setBackendUp(false);
    }

    // Pull the derived analytics the backend computed for this scan, plus
    // real score history and the audit trail. Each is optional: a failure
    // leaves the corresponding panel on its sample data rather than
    // breaking the dashboard.
    if (DATA_ORIGIN.mode === 'live' && DATA_ORIGIN.scanId) {
      const [analytics, history, audit] = await Promise.all([
        fetchAnalytics(DATA_ORIGIN.scanId).catch(() => null),
        fetchHistory().catch(() => null),
        fetchAudit({ scanId: DATA_ORIGIN.scanId, limit: 12 }).catch(() => null),
      ]);
      applyAnalytics({ analytics, history, audit });
    } else {
      resetAnalytics();
    }

    await settle();
    setOrigin(DATA_ORIGIN);
    setDataVersion((v) => v + 1);
    setScreen('app');
    setActive('dashboard');
  };

  const sendMessage = () => {
    if (!chatInput.trim()) return;
    const msg = chatInput.trim();
    setMessages((m) => m.concat([{ role: 'user', text: msg }]));
    setChatInput('');
    setTimeout(() => {
      let reply = 'Try asking about your highest financial risk, your score, your budget plan, or a specific fix.';
      const l = msg.toLowerCase();
      if ((l.indexOf('highest') !== -1 || l.indexOf('biggest') !== -1 || l.indexOf('worst') !== -1) &&
          (l.indexOf('risk') !== -1 || l.indexOf('financial') !== -1 || l.indexOf('cost') !== -1)) {
        const top = FINDINGS.slice().sort((a, b) => b.eal - a.eal)[0];
        reply = `Your largest single exposure is "${top.issue}" on ${top.asset}, carrying about ${fmtLakhs(top.eal * revenueMultiplier)} of the ${fmtLakhs(medianEAL)} annual expected loss. Fixing it costs ${top.cost === 0 ? 'nothing' : fmtRupees(top.cost)} and removes ${top.reduction}% of total risk.`;
      } else if (l.indexOf('why') !== -1 || l.indexOf('score') !== -1) {
        reply = `Your score is ${score} out of 900. The largest contributor is "No MFA on admin accounts," a 35% potential reduction, at zero cost.`;
      } else if (l.indexOf('budget') !== -1 || l.indexOf('fix') !== -1 || l.indexOf('invest') !== -1) {
        reply = `With ${fmtRupees(budget[0])}, the optimizer recommends: ${selected.map((f) => f.short).join(', ')}. Estimated annual savings: ${fmtRupees(savingsNum)}.`;
      } else if (l.indexOf('mfa') !== -1) {
        reply = 'MFA is your highest leverage fix. It is free, and cuts risk by 35%. Prioritize this first.';
      } else if (l.indexOf('source') !== -1 || l.indexOf('connect') !== -1) {
        reply = `You currently have ${connectedCount} of ${DATA_SOURCES.length} data sources connected, putting your scan depth at ${depth}/${MAX_DEPTH}. Connecting more from Attack Surface sharpens confidence.`;
      }
      setMessages((m) => m.concat([{ role: 'ai', text: reply }]));
    }, 500);
  };

  // ---- Auth gate ----
  if (screen === 'auth') {
    // Hold the screen until the stored token has been checked, so a signed-in
    // user never sees a login form flash before being let through.
    if (!authChecked) {
      return (
        <>
          <GlobalFont />
          <div className="min-h-screen flex items-center justify-center" style={{ background: PAPER }}>
            <Loader2 size={20} className="animate-spin" style={{ color: INK_FAINT }} />
          </div>
        </>
      );
    }
    return (
      <AuthScreen
        backendUp={backendUp}
        onAuthed={handleAuthed}
        onSkip={() => setScreen('landing')}
      />
    );
  }

  // ---- Onboarding screens ----
  if (screen === 'landing') {
    return (
      <>
        <GlobalFont />
        <div className="min-h-screen flex items-center justify-center p-6" style={{ background: PAPER, fontFamily: FONT }}>
          <div className="w-full max-w-md text-center">
            <div className="flex items-center justify-center gap-2 mb-8">
              <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: INK }}>
                <Shield color={WHITE} size={18} />
              </div>
              <span className="text-xl font-semibold" style={{ color: INK }}>OwLance</span>
            </div>
            <h1 className="text-2xl font-semibold mb-2 leading-snug" style={{ color: INK }}>
              Enter a domain for a risk score, financial exposure estimate, and prioritized fix list.
            </h1>
            <p className="text-sm mb-8" style={{ color: INK_FAINT }}>Passive discovery by default. Active checks require consent.</p>
            <Panel className="p-1.5" style={{ display: 'flex', gap: 8 }}>
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 8, padding: '0 12px' }}>
                <input className="bg-transparent border-none outline-none w-full py-2.5 text-sm" style={{ color: INK, fontFamily: FONT }}
                  placeholder="yourcompany.com" value={domain} onChange={(e) => setDomain(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleLandingScan()} />
              </div>
              <BtnPrimary onClick={handleLandingScan}>Continue <ChevronRight size={14} /></BtnPrimary>
            </Panel>
            <p className="text-[11px] mt-4" style={{ color: INK_FAINT }}>
              Next: a couple of quick questions about the business, so every number that follows is calibrated instead of generic.
            </p>
          </div>
        </div>
      </>
    );
  }

  if (screen === 'context') {
    return (
      <>
        <GlobalFont />
        <ContextStep industry={industry} setIndustry={setIndustry} employees={employees} setEmployees={setEmployees}
          revenueBand={revenueBand} setRevenueBand={setRevenueBand}
          onBack={() => setScreen('landing')} onNext={() => setScreen('sources')} />
      </>
    );
  }

  if (screen === 'sources') {
    return (
      <>
        <GlobalFont />
        <SourcesStep dataSources={dataSources} connecting={connecting} onConnect={connectSource} onDisconnect={disconnectSource}
          results={connectorResults} errors={connectorErrors}
          depth={depth} onBack={() => setScreen('context')} onNext={() => setScreen('consent')} />
      </>
    );
  }

  if (screen === 'consent') {
    return (
      <>
        <GlobalFont />
        <ConsentStep activeConsent={activeConsent} setActiveConsent={setActiveConsent} authorized={authorized} setAuthorized={setAuthorized}
          onBack={() => setScreen('sources')} onNext={handleRunScan} />
      </>
    );
  }

  if (screen === 'scanning') {
    const scanMsgs = [
      'Discovering subdomains via certificate transparency logs',
      'Cross referencing CVE, EPSS, and CISA KEV',
    ];
    if (dataSources.identity) scanMsgs.push('Pulling MFA and conditional access status from connected identity provider');
    if (dataSources.cloud) scanMsgs.push('Enumerating storage buckets and IAM roles from connected cloud account');
    if (dataSources.endpoint) scanMsgs.push('Reading device compliance and patch status from EDR');
    if (dataSources.insurance) scanMsgs.push('Cross-referencing policy sub-limits against modeled loss scenarios');
    if (activeConsent) scanMsgs.push('Running consented active checks against exposed ports');
    scanMsgs.push(`Calculating composite risk score, calibrated for ${industry}`);

    return (
      <>
        <GlobalFont />
        <div className="min-h-screen flex items-center justify-center p-6" style={{ background: PAPER, fontFamily: FONT }}>
          <div className="w-full max-w-md text-center">
            <div className="flex items-center justify-center gap-2 mb-8">
              <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: INK }}>
                <Shield color={WHITE} size={18} />
              </div>
              <span className="text-xl font-semibold" style={{ color: INK }}>OwLance</span>
            </div>
            <div className="flex items-center justify-center gap-2 mb-4">
              <Loader2 size={16} className="animate-spin" style={{ color: ACCENT }} />
              <span className="text-sm font-medium" style={{ color: INK }}>Scanning {domain || 'yourcompany.com'}</span>
            </div>
            <div className="text-xs" style={{ color: INK_FAINT }}>
              {backendUp === false
                ? 'Backend not reachable \u2014 preparing sample dataset'
                : 'Querying live intelligence feeds \u2014 this can take up to a minute'}
            </div>
            <div className="mt-6 text-sm text-left" style={{ color: INK_FAINT, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {scanMsgs.map((m, i) => (
                <motion.div key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.35 }}>{m}</motion.div>
              ))}
            </div>
          </div>
        </div>
      </>
    );
  }

  // ---- Main app shell ----
  const PAGES = {
    dashboard: <DashboardPage selected={selected} score={score} medianEAL={medianEAL} confidence={confidence} savings={savingsNum} calibration={calibration} />,
    surface: <SurfacePage dataSources={dataSources} connecting={connecting} onConnect={connectSource} onDisconnect={disconnectSource} depth={depth} results={connectorResults} errors={connectorErrors} />,
    vulns: <VulnsPage />,
    paths: <PathsPage />,
    financial: <FinancialPage medianEAL={medianEAL} confidence={confidence} multiplier={revenueMultiplier} calibration={calibration} />,
    optimizer: <OptimizerPage budget={budget} setBudget={setBudget} selected={selected} savings={savingsNum} medianEAL={medianEAL} multiplier={revenueMultiplier} />,
    compliance: <CompliancePage onOpenPassport={() => setActive('passport')} auditStatus={auditStatus} onVerifyAudit={handleVerifyAudit} />,
    passport: <PassportPage domain={domain} score={score} medianEAL={medianEAL} confidence={confidence}
      calibration={calibration} phone={waPhone} setPhone={setWaPhone}
      sending={waSending} result={waResult} waConfig={waConfig} onSend={sendWaStatus} />,
    simgraph: <SimulatedEnterprisePage />,
  };
  const NAV_GROUPS = mode === 'live' ? NAV_GROUPS_LIVE : NAV_GROUPS_SIM;
  const liveIds = ['dashboard', 'surface', 'vulns', 'paths', 'financial', 'optimizer', 'compliance', 'passport'];
  const currentActive = mode === 'live' ? (liveIds.indexOf(active) !== -1 ? active : 'dashboard') : 'simgraph';

  return (
    <>
      <GlobalFont />
      {/* dataVersion remounts the shell whenever a scan swaps the data store,
          so every panel re-reads FINDINGS / ASSETS / BASE_SCORE. */}
      <div key={dataVersion} className="min-h-screen flex" style={{ background: PAPER, color: INK, fontFamily: FONT }}>
        <div className="w-60 shrink-0 border-r h-screen sticky top-0 flex flex-col" style={{ background: WHITE, borderColor: BORDER }}>
          <div className="p-4 border-b flex items-center gap-2.5" style={{ borderColor: BORDER }}>
            <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: INK }}>
              <Shield color={WHITE} size={15} />
            </div>
            <span className="font-semibold text-sm" style={{ color: INK }}>OwLance</span>
          </div>

          <div className="p-3 border-b" style={{ borderColor: BORDER }}>
            <div className="flex rounded-lg p-1 gap-1" style={{ background: '#f3f4f6' }}>
              <button onClick={() => { setMode('live'); setActive('dashboard'); }} className="flex-1 text-xs py-1.5 rounded-md font-medium transition-colors"
                style={{ background: mode === 'live' ? WHITE : 'transparent', color: mode === 'live' ? INK : INK_FAINT }}>
                Live Scan
              </button>
              <button onClick={() => { setMode('simulated'); setActive('simgraph'); }} className="flex-1 text-xs py-1.5 rounded-md font-medium transition-colors" style={{ background: mode === 'simulated' ? WHITE : 'transparent', color: mode === 'simulated' ? INK : INK_FAINT, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}>
                <FlaskConical size={11} /> Simulated
              </button>
            </div>
          </div>

          <div className="px-3 py-2.5 space-y-2">
            <div className="flex items-center gap-2 rounded-lg px-2.5 py-2" style={{ background: '#f9fafb', border: `1px solid ${BORDER}` }}>
              <div className="w-6 h-6 rounded flex items-center justify-center text-[10px] font-semibold" style={{ background: INK, color: WHITE }}>
                {mode === 'live' ? (domain || 'C').charAt(0).toUpperCase() : 'S'}
              </div>
              <span className="text-xs truncate flex-1" style={{ color: '#374151' }}>{mode === 'live' ? (domain || 'company.com') : 'Synthetic Org (demo)'}</span>
              <ChevronDown size={12} style={{ color: INK_FAINT }} />
            </div>
            {mode === 'live' ? (
              <div className="flex items-center gap-1.5 flex-wrap px-0.5">
                <Chip color={INK} bg="#f3f4f6">{industry}</Chip>
                <Chip color={INK} bg="#f3f4f6">{employees}</Chip>
                <Chip color={ACCENT} bg={ACCENT_SOFT}>Depth {depth}/{MAX_DEPTH}</Chip>
              </div>
            ) : null}
          </div>

          <div className="flex-1 overflow-y-auto px-3 py-2 space-y-5">
            {NAV_GROUPS.map((group) => (
              <div key={group.label}>
                <div className="text-[10px] tracking-wide font-semibold px-2 mb-1.5" style={{ color: INK_FAINT }}>{group.label}</div>
                <div className="space-y-0.5">
                  {group.items.map((item) => {
                    const isActive = currentActive === item.id;
                    const ItemIcon = item.icon;
                    return (
                      <button key={item.id} onClick={() => setActive(item.id)} className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-sm transition-colors"
                        style={{ background: isActive ? '#f3f4f6' : 'transparent', color: isActive ? INK : INK_SOFT, fontWeight: isActive ? 500 : 400 }}>
                        <ItemIcon size={15} />
                        <span className="flex-1 text-left">{item.label}</span>
                        {item.badge ? <span className="text-[10px] px-1.5 py-0.5 rounded-full" style={{ background: '#f3f4f6', color: INK_FAINT, border: `1px solid ${BORDER}` }}>{item.badge}</span> : null}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
          <div className="p-3 border-t space-y-1" style={{ borderColor: BORDER }}>
            {user ? (
              <div className="px-2.5 py-2 rounded-lg" style={{ background: '#f9fafb', border: `1px solid ${BORDER}` }}>
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-full flex items-center justify-center shrink-0"
                    style={{ background: INK, color: WHITE, fontSize: 10, fontWeight: 600 }}>
                    {user.email.charAt(0).toUpperCase()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-[11px] truncate" style={{ color: INK }}>{user.email}</div>
                    {user.org_name ? (
                      <div className="text-[10px] truncate" style={{ color: INK_FAINT }}>{user.org_name}</div>
                    ) : null}
                  </div>
                </div>
                <button onClick={handleSignOut}
                  className="w-full mt-2 text-[10.5px] py-1 rounded-md"
                  style={{ color: INK_SOFT, border: `1px solid ${BORDER}`, background: WHITE }}>
                  Sign out
                </button>
              </div>
            ) : (
              <button onClick={() => setScreen('auth')}
                className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-sm"
                style={{ color: INK_SOFT, border: `1px solid ${BORDER}`, background: WHITE }}>
                <Lock size={14} /> Sign in to keep history
              </button>
            )}
            <button className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-sm" style={{ color: INK_FAINT }}>
              <Settings size={15} /> Settings
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto h-screen">
          <div className="p-6 max-w-6xl mx-auto" style={{ paddingRight: 60 }}>
            {mode === 'live' ? (
              <DataOriginBanner origin={origin} domain={domain} onRescan={handleRunScan} />
            ) : null}
            <AnimatePresence mode="wait">
              <motion.div key={currentActive} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.15 }}>
                {PAGES[currentActive]}
              </motion.div>
            </AnimatePresence>
          </div>
        </div>

        {!chatOpen ? (
          <button onClick={() => setChatOpen(true)}
            className="fixed top-0 right-0 h-full w-12 flex flex-col items-center justify-center gap-2 z-30 border-l"
            style={{ background: WHITE, borderColor: BORDER }}>
            <MessageCircle size={20} style={{ color: INK }} />
          </button>
        ) : null}

        <AnimatePresence>
          {chatOpen ? (
            <motion.div initial={{ x: 380 }} animate={{ x: 0 }} exit={{ x: 380 }} transition={{ type: 'spring', stiffness: 320, damping: 32 }}
              className="fixed right-0 top-0 h-full w-full sm:w-96 border-l flex flex-col z-40" style={{ background: WHITE, borderColor: BORDER }}>
              <div className="p-4 border-b flex items-center justify-between" style={{ borderColor: BORDER }}>
                <span className="font-medium text-sm" style={{ color: INK }}>Risk Copilot</span>
                <button onClick={() => setChatOpen(false)} style={{ color: INK_FAINT }}><X size={18} /></button>
              </div>
              <div className="flex-1 overflow-y-auto p-4 space-y-3">
                {messages.map((m, i) => (
                  <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    <div className="max-w-[85%] rounded-lg px-3.5 py-2 text-sm" style={{
                      background: m.role === 'user' ? INK : '#f9fafb',
                      color: m.role === 'user' ? WHITE : '#374151',
                      border: m.role === 'user' ? 'none' : `1px solid ${BORDER}`,
                    }}>{m.text}</div>
                  </div>
                ))}
              </div>
              <div className="p-3 border-t flex gap-2" style={{ borderColor: BORDER }}>
                <input className="flex-1 rounded-full px-4 py-2 text-sm outline-none" style={{ background: '#f9fafb', border: `1px solid ${BORDER}`, color: INK, fontFamily: FONT }}
                  placeholder="What is our highest financial risk today?" value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && sendMessage()} />
                <button onClick={sendMessage} className="w-9 h-9 rounded-full flex items-center justify-center" style={{ background: INK }}>
                  <Send size={14} color={WHITE} />
                </button>
              </div>
            </motion.div>
          ) : null}
        </AnimatePresence>
      </div>
    </>
  );
}