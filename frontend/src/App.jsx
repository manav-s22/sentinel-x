import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, Bell, CheckCircle2, ChevronRight, ClipboardList, Clock3,
  Database, Download, ExternalLink, FileJson, FileSearch, FileSpreadsheet, Fingerprint,
  Globe, History, LayoutDashboard, LoaderCircle, LockKeyhole, Microscope, Network,
  Printer, RefreshCw, RotateCw, Search, Settings as SettingsIcon, Shield, ShieldAlert,
  ShieldCheck, Trash2, X, XCircle, Zap,
} from "lucide-react";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";

const DEFAULT_API = "http://127.0.0.1:8001";
const API_BASE = (() => {
  try { return localStorage.getItem("sentinelx.apiBase") || DEFAULT_API; }
  catch { return DEFAULT_API; }
})();

const DEFAULT_SETTINGS = { timezone: "Asia/Kolkata", refreshSeconds: 30, queueView: "open" };

const navItems = [
  { id: "command", label: "Command Center", icon: LayoutDashboard },
  { id: "analyzer", label: "URL Analyzer", icon: Search },
  { id: "history", label: "Scan History", icon: History },
  { id: "alerts", label: "Security Alerts", icon: Bell },
  { id: "intelligence", label: "Threat Intelligence", icon: Microscope },
  { id: "reports", label: "Reports & Export", icon: FileSpreadsheet },
];
const settingsItem = { id: "settings", label: "Settings", icon: SettingsIcon };
const allNav = [...navItems, settingsItem];

/* ---------- Style constants ---------- */
const panel =
  "rounded-xl border border-white/[0.07] bg-[linear-gradient(180deg,#111a2a,#0d1420)] shadow-[0_8px_24px_rgba(0,0,0,0.35),inset_0_0_0_1px_rgba(255,255,255,0.02)]";
const inputClass =
  "w-full rounded-lg border border-white/10 bg-[#070b12] px-4 py-3 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-400/10";
const primary =
  "inline-flex items-center justify-center gap-2 rounded-lg bg-violet-600 px-4 py-3 text-sm font-semibold text-white shadow-[0_0_22px_rgba(124,92,255,0.35)] transition hover:bg-violet-500 disabled:cursor-not-allowed disabled:opacity-40 disabled:shadow-none";
const secondary =
  "inline-flex items-center justify-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-4 py-3 text-sm font-medium text-slate-300 transition hover:border-cyan-400/30 hover:bg-white/[0.06] disabled:cursor-not-allowed disabled:opacity-40";
const small = "!px-3 !py-2 text-xs";
const tooltipStyle = { background: "#0d1420", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 10, color: "#e6edf6", fontSize: 12 };

const tones = {
  cyan: { chip: "border-cyan-400/20 bg-cyan-400/10 text-cyan-300", value: "text-cyan-300" },
  red: { chip: "border-rose-400/20 bg-rose-400/10 text-rose-400", value: "text-rose-400" },
  amber: { chip: "border-amber-400/20 bg-amber-400/10 text-amber-400", value: "text-amber-400" },
  green: { chip: "border-emerald-400/20 bg-emerald-400/10 text-emerald-400", value: "text-emerald-400" },
};

const severityMeta = {
  critical: { label: "Critical", badge: "border-rose-500/40 bg-rose-500/15 text-rose-300", dot: "bg-rose-400", text: "text-rose-300" },
  high: { label: "High", badge: "border-orange-400/30 bg-orange-400/10 text-orange-300", dot: "bg-orange-400", text: "text-orange-300" },
  medium: { label: "Medium", badge: "border-amber-400/30 bg-amber-400/10 text-amber-300", dot: "bg-amber-400", text: "text-amber-300" },
  informational: { label: "Informational", badge: "border-sky-400/30 bg-sky-400/10 text-sky-300", dot: "bg-sky-400", text: "text-sky-300" },
};
const severityOrder = ["critical", "high", "medium", "informational"];

const statusMeta = {
  new: { label: "New", cls: "border-cyan-400/30 bg-cyan-400/10 text-cyan-300" },
  acknowledged: { label: "Acknowledged", cls: "border-violet-400/30 bg-violet-400/10 text-violet-300" },
  investigating: { label: "Investigating", cls: "border-violet-400/30 bg-violet-400/10 text-violet-300" },
  resolved: { label: "Resolved", cls: "border-emerald-400/30 bg-emerald-400/10 text-emerald-300" },
  dismissed: { label: "Dismissed", cls: "border-white/10 bg-white/[0.05] text-slate-400" },
};

const categoryLabel = {
  intel_match: "Intelligence match",
  heuristic_risk: "Heuristic risk",
  risk_change: "Risk change",
};

// Mirrors the backend lifecycle: New -> Acknowledged -> Resolved / Dismissed.
const alertActions = {
  new: [["acknowledged", "Acknowledge", true], ["dismissed", "Dismiss", false]],
  acknowledged: [["resolved", "Resolve", true], ["dismissed", "Dismiss", false]],
  resolved: [["new", "Reopen", false]],
  dismissed: [["new", "Reopen", false]],
};

const investigationStatuses = ["new", "investigating", "resolved", "dismissed"];

const barColor = (level) =>
  ({ high: "bg-rose-400", medium: "bg-amber-400" }[(level || "").toLowerCase()] || "bg-emerald-400");

/* ---------- Helpers ---------- */
function hostname(value) {
  try { return new URL(value).hostname; }
  catch { return value || "Unknown host"; }
}

let displayTz = "Asia/Kolkata";

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(/(?:Z|[+-]\d{2}:\d{2})$/i.test(value) ? value : `${value}Z`);
  if (Number.isNaN(date.getTime())) return "Invalid date";
  return new Intl.DateTimeFormat("en-IN", {
    timeZone: displayTz, day: "2-digit", month: "short",
    year: "numeric", hour: "2-digit", minute: "2-digit",
  }).format(date);
}

function riskStyle(level) {
  switch ((level || "").toLowerCase()) {
    case "high": return "border-rose-500/30 bg-rose-500/10 text-rose-400";
    case "medium": return "border-amber-500/30 bg-amber-500/10 text-amber-400";
    case "low": return "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
    default: return "border-white/10 bg-white/[0.05] text-slate-300";
  }
}

function threatLevel(open = {}) {
  const n = (key) => Number(open[key] || 0);
  const plural = (count, word) => `${count} ${word} alert${count === 1 ? "" : "s"} open`;
  if (n("critical")) return { label: "Critical", cls: "text-rose-400", tone: "red", sub: plural(n("critical"), "critical") };
  if (n("high")) return { label: "Elevated", cls: "text-orange-300", tone: "amber", sub: plural(n("high"), "high-severity") };
  if (n("medium")) return { label: "Guarded", cls: "text-amber-300", tone: "amber", sub: plural(n("medium"), "medium-severity") };
  return { label: "Normal", cls: "text-emerald-400", tone: "green", sub: "No critical, high or medium alerts open" };
}

function urlhausCard(intel) {
  switch (intel?.urlhaus_availability) {
    case "reachable": return { value: "Reachable", cls: "text-emerald-400", tone: "green", sub: `Last lookup ${formatDate(intel.urlhaus_last_checked)}` };
    case "degraded": return { value: "Unavailable", cls: "text-rose-400", tone: "red", sub: `Last lookup failed (${intel.urlhaus_last_status}) · ${formatDate(intel.urlhaus_last_checked)}` };
    case "untested": return { value: "Configured", cls: "text-cyan-300", tone: "cyan", sub: "No lookup has run since the backend started" };
    case "not_configured": return { value: "Not configured", cls: "text-amber-400", tone: "amber", sub: "Set URLHAUS_AUTH_KEY in the backend .env" };
    default: return { value: "Unknown", cls: "text-slate-400", tone: "cyan", sub: "Backend status unavailable" };
  }
}

/* ---------- Small components ---------- */
function RiskBadge({ level }) {
  const Icon = (level || "").toLowerCase() === "high"
    ? ShieldAlert
    : (level || "").toLowerCase() === "medium" ? AlertTriangle : ShieldCheck;
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-semibold ${riskStyle(level)}`}>
      <Icon size={13} />{level || "Unknown"}
    </span>
  );
}

function SeverityBadge({ severity }) {
  const meta = severityMeta[(severity || "").toLowerCase()] || severityMeta.informational;
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-semibold ${meta.badge}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />{meta.label}
    </span>
  );
}

function StatusPill({ status }) {
  const meta = statusMeta[status] || statusMeta.new;
  return <span className={`inline-flex whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-semibold ${meta.cls}`}>{meta.label}</span>;
}

function Heading({ eyebrow, title, description, action }) {
  return (
    <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
      <div>
        <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.14em] text-cyan-400/70">{eyebrow}</p>
        <h2 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">{title}</h2>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">{description}</p>
      </div>
      {action}
    </div>
  );
}

function StatCard({ title, value, subtitle, icon: Icon, tone = "cyan", colored = false, meta }) {
  const t = tones[tone];
  return (
    <div className={`${panel} group p-4 transition hover:border-cyan-400/25`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs text-slate-500">{title}</p>
          <p className={`mt-3 text-3xl font-semibold tabular-nums tracking-tight ${colored ? t.value : "text-white"}`}>{value}</p>
        </div>
        <div className={`rounded-lg border p-2.5 ${t.chip}`}><Icon size={18} /></div>
      </div>
      <div className="mt-4 flex items-center justify-between gap-2 border-t border-white/[0.07] pt-3 text-[11px] text-slate-600">
        <span>{subtitle}</span>
        {meta && <span className={`rounded-full border px-2 py-0.5 ${t.chip}`}>{meta}</span>}
      </div>
    </div>
  );
}

function OpsCard({ title, value, valueClass = "text-white", sub, icon: Icon, tone = "cyan", children }) {
  const t = tones[tone];
  return (
    <div className={`${panel} p-4`}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs text-slate-500">{title}</p>
          <p className={`mt-3 truncate text-2xl font-semibold tracking-tight ${valueClass}`}>{value}</p>
        </div>
        <div className={`rounded-lg border p-2.5 ${t.chip}`}><Icon size={18} /></div>
      </div>
      {children}
      <p className="mt-3 border-t border-white/[0.07] pt-3 text-[11px] leading-4 text-slate-600">{sub}</p>
    </div>
  );
}

function Sparkline({ data, dataKey, color = "#22d3ee" }) {
  const id = `spark-${dataKey}`;
  return (
    <div className="mt-2 h-10 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
          <defs><linearGradient id={id} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={color} stopOpacity={0.4} /><stop offset="100%" stopColor={color} stopOpacity={0} /></linearGradient></defs>
          <Area type="monotone" dataKey={dataKey} stroke={color} strokeWidth={1.5} fill={`url(#${id})`} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function Gauge({ value, label, color }) {
  const circumference = Math.PI * 70;
  const pct = Math.max(0, Math.min(100, Number(value) || 0));
  return (
    <div className="relative mx-auto w-48">
      <svg viewBox="0 0 180 100" className="w-full">
        <path d="M20 90 A70 70 0 0 1 160 90" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="12" strokeLinecap="round" />
        <path d="M20 90 A70 70 0 0 1 160 90" fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={`${(pct / 100) * circumference} ${circumference}`}
          style={{ filter: `drop-shadow(0 0 6px ${color}99)` }} />
      </svg>
      <div className="absolute inset-x-0 bottom-0 text-center">
        <p className="text-3xl font-semibold tabular-nums text-white">{Math.round(pct)}</p>
        <p className="text-[11px] text-slate-500">{label}</p>
      </div>
    </div>
  );
}

function EmptyState({ icon: Icon, title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center px-5 py-12 text-center">
      <div className="mb-4 rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-4 text-cyan-300"><Icon size={27} /></div>
      <h3 className="font-semibold text-white">{title}</h3>
      <p className="mt-2 max-w-sm text-sm leading-6 text-slate-500">{description}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

function DetailRow({ label, value }) {
  const display = value === undefined || value === null || value === ""
    ? "Not available"
    : typeof value === "boolean" ? (value ? "Yes" : "No") : String(value);
  return (
    <div className="flex flex-col gap-1 border-b border-white/[0.05] py-3 last:border-0 sm:flex-row sm:items-start sm:justify-between sm:gap-5">
      <span className="shrink-0 text-xs text-slate-500">{label}</span>
      <span className="break-all text-sm text-slate-200 sm:max-w-[70%] sm:text-right">{display}</span>
    </div>
  );
}

function SignalList({ signals }) {
  if (!Array.isArray(signals) || !signals.length) {
    return <p className="text-sm text-slate-500">No individual signal details were returned.</p>;
  }
  return (
    <div className="space-y-2">
      {signals.map((signal, index) => (
        <div key={`${signal.signal || "signal"}-${index}`} className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4">
          <div className="flex items-start gap-3">
            {Number(signal.points) > 0
              ? <AlertTriangle size={17} className="mt-0.5 shrink-0 text-amber-400" />
              : <CheckCircle2 size={17} className="mt-0.5 shrink-0 text-emerald-400" />}
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-slate-200">{signal.signal || "Analysis signal"}</p>
              <p className="mt-1 text-xs leading-5 text-slate-500">{signal.detail || "No additional details."}</p>
            </div>
            {Number(signal.points) > 0 && <span className="text-xs text-amber-400">+{signal.points}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ---------- Modals ---------- */
function ModalShell({ labelId, eyebrow, title, onClose, children }) {
  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/85 p-0 backdrop-blur-md sm:items-center sm:p-5" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <section role="dialog" aria-modal="true" aria-labelledby={labelId} className="max-h-[92vh] w-full max-w-2xl overflow-y-auto rounded-t-2xl border border-white/10 bg-[#0d1420] shadow-2xl sm:rounded-2xl">
        <div className="sticky top-0 z-10 flex items-center justify-between gap-4 border-b border-white/[0.07] bg-[#0d1420]/95 p-5 backdrop-blur">
          <div className="min-w-0">
            <p className="text-[10px] uppercase tracking-[0.14em] text-cyan-400/70">{eyebrow}</p>
            <h2 id={labelId} className="mt-2 truncate text-2xl font-semibold text-white">{title}</h2>
          </div>
          <button type="button" onClick={onClose} aria-label="Close details" className={secondary}><X size={17} /></button>
        </div>
        <div className="space-y-5 p-5 sm:p-6">{children}</div>
      </section>
    </div>
  );
}

function ScanModal({ scan, onClose }) {
  if (!scan) return null;
  return (
    <ModalShell labelId="scan-modal-title" eyebrow="Investigation record" title={`Scan #${scan.id}`} onClose={onClose}>
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4"><p className="text-xs text-slate-500">Risk score</p><p className="mt-3 text-2xl font-semibold text-white">{scan.risk_score ?? "—"}<span className="text-sm text-slate-600">/100</span></p></div>
        <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4"><p className="mb-3 text-xs text-slate-500">Classification</p><RiskBadge level={scan.risk_level} /></div>
        <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4"><p className="text-xs text-slate-500">Signals</p><p className="mt-3 text-2xl font-semibold text-white">{scan.signal_count ?? scan.signals?.length ?? 0}</p></div>
      </div>
      <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4"><p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Submitted URL</p><p className="mt-2 break-all text-sm leading-6 text-slate-200">{scan.submitted_url || scan.normalized_url || "Not available"}</p></div>
      <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4"><div className="flex items-center gap-2 text-slate-300"><Clock3 size={15} /><p className="text-xs font-semibold uppercase tracking-wider">Scan timestamp</p></div><p className="mt-2 text-sm text-slate-200">{formatDate(scan.created_at)}</p><p className="mt-2 text-xs text-slate-500">Method: {scan.analysis_method || "heuristic"}</p></div>
      <div><h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-white"><FileSearch size={17} className="text-cyan-300" />Analysis signals</h3><SignalList signals={scan.signals} /></div>
      {scan.recommendation && <div className="rounded-xl border border-violet-400/20 bg-violet-500/[0.07] p-4"><p className="text-xs font-bold uppercase tracking-wider text-violet-300">Recommendation</p><p className="mt-2 text-sm leading-6 text-slate-300">{scan.recommendation}</p></div>}
      <p className="text-xs leading-5 text-slate-600">Heuristic scores are indicators, not proof that a URL is safe or malicious.</p>
      <button type="button" onClick={onClose} className={`${secondary} w-full`}>Close details</button>
    </ModalShell>
  );
}

function AlertModal({ alert, onClose, onStatus, onInvestigate, onRescan }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  if (!alert) return null;

  const actions = alertActions[alert.status] || [];
  const timeline = [...(alert.timeline || [])].reverse();

  const act = async (status) => {
    setBusy(true);
    setErr("");
    try {
      await onStatus(alert.id, status, note.trim());
      setNote("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Update failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell labelId="alert-modal-title" eyebrow="Security alert" title={`Alert #${alert.id}`} onClose={onClose}>
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={alert.severity} />
          <StatusPill status={alert.status} />
          <span className="rounded-full border border-white/10 px-2.5 py-1 text-xs text-slate-400">{categoryLabel[alert.category] || alert.category}</span>
        </div>
        <p className="mt-3 text-lg font-semibold text-white">{alert.title}</p>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4"><p className="text-xs text-slate-500">Risk score</p><p className="mt-3 text-2xl font-semibold tabular-nums text-white">{alert.risk_score ?? "—"}{alert.risk_score != null && <span className="text-sm text-slate-600">/100</span>}</p></div>
        <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4"><p className="text-xs text-slate-500">Source</p><p className="mt-3 text-sm font-semibold text-cyan-300">{alert.source || "—"}</p></div>
        <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4"><p className="text-xs text-slate-500">Times observed</p><p className="mt-3 text-2xl font-semibold tabular-nums text-white">{alert.occurrences}</p></div>
      </div>

      <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4">
        <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Affected URL</p>
        <p className="mt-2 break-all text-sm leading-6 text-slate-200">{alert.normalized_url}</p>
        <p className="mt-2 text-xs text-slate-600">Raised {formatDate(alert.created_at)} · Updated {formatDate(alert.updated_at)}{alert.scan_id ? ` · Scan #${alert.scan_id}` : ""}</p>
      </div>

      <div>
        <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-white"><FileSearch size={17} className="text-cyan-300" />Evidence</h3>
        {alert.evidence?.length ? (
          <div className="space-y-2">
            {alert.evidence.map((item, i) => (
              <div key={`${item.label}-${i}`} className="flex items-start gap-3 rounded-xl border border-white/[0.07] bg-white/[0.03] p-3">
                {Number(item.points) > 0 ? <AlertTriangle size={16} className="mt-0.5 shrink-0 text-amber-400" /> : <FileSearch size={16} className="mt-0.5 shrink-0 text-cyan-300" />}
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-slate-200">{item.label}</p>
                  <p className="mt-0.5 break-words text-xs leading-5 text-slate-500">{item.detail}</p>
                </div>
                {Number(item.points) > 0 && <span className="text-xs text-amber-400">+{item.points}</span>}
              </div>
            ))}
          </div>
        ) : <p className="text-sm text-slate-500">No evidence was recorded.</p>}
      </div>

      {alert.recommendation && <div className="rounded-xl border border-violet-400/20 bg-violet-500/[0.07] p-4"><p className="text-xs font-bold uppercase tracking-wider text-violet-300">Recommended next action</p><p className="mt-2 text-sm leading-6 text-slate-300">{alert.recommendation}</p></div>}

      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={() => onInvestigate(alert.normalized_url)} className={`${secondary} ${small}`}><Microscope size={14} /> Investigate</button>
        <button type="button" onClick={() => onRescan(alert.normalized_url)} className={`${secondary} ${small}`}><RotateCw size={14} /> Rescan</button>
      </div>

      <div>
        <h3 className="mb-3 text-sm font-semibold text-white">Lifecycle</h3>
        <ol className="space-y-2.5">
          {timeline.map((ev, i) => {
            const oldest = i === timeline.length - 1;
            const label = ev.status === "new" ? (oldest ? "Raised" : "Reopened") : statusMeta[ev.status]?.label || ev.status;
            return (
              <li key={`${ev.at}-${i}`} className="flex items-start gap-3 text-xs">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
                <div className="min-w-0 flex-1"><span className="font-semibold text-slate-200">{label}</span>{ev.note && <p className="mt-0.5 break-words text-slate-500">{ev.note}</p>}</div>
                <span className="shrink-0 text-slate-600">{formatDate(ev.at)}</span>
              </li>
            );
          })}
        </ol>
      </div>

      <div className="space-y-3 border-t border-white/[0.07] pt-5">
        <label htmlFor="alert-note" className="block text-xs font-medium text-slate-400">Note (optional, saved with the status change)</label>
        <textarea id="alert-note" rows={2} maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} className={`${inputClass} resize-none`} placeholder="e.g. Confirmed with the sender, link is legitimate." />
        {err && <p role="alert" className="text-xs text-rose-400">{err}</p>}
        <div className="flex flex-wrap gap-2">
          {actions.map(([status, label, isPrimary]) => (
            <button key={status} type="button" disabled={busy} onClick={() => act(status)} className={isPrimary ? `${primary} ${small}` : `${secondary} ${small}`}>
              {busy && <LoaderCircle size={13} className="animate-spin" />}{label}
            </button>
          ))}
        </div>
      </div>
    </ModalShell>
  );
}

function InvestigationModal({ item, onClose, onUpdate, onRescan, onInvestigate }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  if (!item) return null;

  const timeline = [...(item.investigation?.timeline || [])].reverse();

  const run = async (payload) => {
    setBusy(true);
    setErr("");
    try {
      await onUpdate(item.normalized_url, payload);
      if (payload.note) setNote("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Update failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell labelId="inv-modal-title" eyebrow="Investigation" title={item.hostname || hostname(item.normalized_url)} onClose={onClose}>
      <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4">
        <p className="break-all text-sm leading-6 text-slate-200">{item.normalized_url}</p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <RiskBadge level={item.risk_level} />
          <span className="text-sm font-semibold tabular-nums text-white">{item.risk_score}/100</span>
          <span className="text-xs text-slate-600">· scanned {item.scan_count}× · last {formatDate(item.last_scanned)}</span>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={() => onInvestigate(item.normalized_url)} className={`${secondary} ${small}`}><Microscope size={14} /> Investigate</button>
        <button type="button" onClick={() => onRescan(item.normalized_url)} className={`${secondary} ${small}`}><RotateCw size={14} /> Rescan</button>
      </div>

      <div>
        <p className="mb-2 text-xs font-medium text-slate-400">Status</p>
        <div className="flex flex-wrap gap-2" role="group" aria-label="Investigation status">
          {investigationStatuses.map((s) => (
            <button key={s} type="button" disabled={busy} aria-pressed={item.status === s} onClick={() => run({ status: s })}
              className={`rounded-lg border px-3 py-2 text-xs font-medium transition ${item.status === s ? "border-cyan-400/40 bg-cyan-400/10 text-cyan-300" : "border-white/10 bg-[#070b12] text-slate-500 hover:text-white"}`}>
              {statusMeta[s].label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-3">
        <label htmlFor="inv-note" className="block text-xs font-medium text-slate-400">Add a note</label>
        <textarea id="inv-note" rows={3} maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} className={`${inputClass} resize-none`} placeholder="What did you check, and what did you find?" />
        {err && <p role="alert" className="text-xs text-rose-400">{err}</p>}
        <button type="button" disabled={busy || !note.trim()} onClick={() => run({ note: note.trim() })} className={`${primary} ${small}`}>
          {busy && <LoaderCircle size={13} className="animate-spin" />}Save note
        </button>
      </div>

      <div>
        <h3 className="mb-3 text-sm font-semibold text-white">Activity</h3>
        {!timeline.length ? <p className="text-sm text-slate-500">No workflow activity yet. Set a status or add a note to start tracking this URL.</p> : (
          <ol className="space-y-2.5">
            {timeline.map((ev, i) => (
              <li key={`${ev.at}-${i}`} className="flex items-start gap-3 text-xs">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
                <div className="min-w-0 flex-1">
                  {ev.type === "note"
                    ? <p className="whitespace-pre-wrap break-words text-slate-300">{ev.text}</p>
                    : <span className="font-semibold text-slate-200">{ev.type === "created" ? "Tracking started" : `Status set to ${statusMeta[ev.status]?.label || ev.status}`}</span>}
                </div>
                <span className="shrink-0 text-slate-600">{formatDate(ev.at)}</span>
              </li>
            ))}
          </ol>
        )}
      </div>
    </ModalShell>
  );
}

/* ---------- Command Center ---------- */
function CommandCenter({
  command, health, apiOnline, history, loading, error, defaultQueueView,
  onAnalyze, onInvestigate, onRescan, onOpenReport, onOpenAlerts,
  onOpenAlert, onOpenScan, onOpenInvestigation, onSetStatus,
}) {
  const [quickUrl, setQuickUrl] = useState("");
  const [quickError, setQuickError] = useState("");
  const [queueView, setQueueView] = useState(defaultQueueView === "all" ? "all" : "open");

  const totals = command?.totals || { scans: 0, unique_urls: 0, high: 0, medium: 0, low: 0, avg_score: 0, last_24h: 0, last_scan: null };
  const alertInfo = command?.alerts || { open: 0, new: 0, open_by_severity: {}, priority: [] };
  const queue = command?.queue || [];
  const trend = command?.trend || [];
  const detections = command?.latest_detections || [];
  const distribution = command?.score_distribution || [];
  const topSignals = command?.top_signals || [];

  const level = threatLevel(alertInfo.open_by_severity);
  const intel = urlhausCard(health?.threat_intelligence);
  const backendValue = !apiOnline ? "Offline" : health?.status === "ok" ? "Operational" : "Degraded";
  const backendTone = !apiOnline ? "red" : health?.status === "ok" ? "green" : "amber";
  const visibleQueue = queueView === "open" ? queue.filter((q) => ["new", "investigating"].includes(q.status)) : queue;
  const hasTrend = trend.some((d) => d.scans > 0);
  const gaugeColor = totals.avg_score >= 60 ? "#fb7185" : totals.avg_score >= 30 ? "#fbbf24" : "#2dd4a0";

  const mix = [
    { name: "High", value: totals.high, color: "#fb7185" },
    { name: "Medium", value: totals.medium, color: "#fbbf24" },
    { name: "Low", value: totals.low, color: "#34d399" },
  ];
  const bandColors = ["#34d399", "#a3e635", "#fbbf24", "#fb923c", "#fb7185"];
  const maxSignal = Math.max(1, ...topSignals.map((s) => s.count));
  const pipelineColors = { new: "bg-cyan-400", investigating: "bg-violet-400", resolved: "bg-emerald-400", dismissed: "bg-slate-500" };
  const pipeline = investigationStatuses.map((s) => ({ status: s, count: queue.filter((q) => q.status === s).length }));
  const openSev = alertInfo.open_by_severity || {};
  const maxSev = Math.max(1, ...severityOrder.map((k) => openSev[k] || 0));

  const needUrl = () => {
    const value = quickUrl.trim();
    if (!value) { setQuickError("Enter a URL first."); return null; }
    setQuickError("");
    return value;
  };

  return (
    <>
      <Heading eyebrow="Security operations / 01" title="Command center" description="Operational status, the investigation queue and threat overview, built from your recorded scans and alerts."
        action={
          <div className="flex flex-wrap items-center gap-3">
            {command?.generated_at && <span className="inline-flex items-center gap-2 rounded-full border border-white/10 px-3 py-2 text-xs text-slate-400"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-400" />Updated {formatDate(command.generated_at)}</span>}
            <button type="button" onClick={() => onAnalyze("")} className={primary}><Search size={16} /> Analyze URL <ChevronRight size={15} /></button>
          </div>
        } />

      {error && <div role="alert" className="mb-5 rounded-xl border border-amber-500/20 bg-amber-500/[0.05] p-4 text-sm text-amber-300"><AlertTriangle size={17} className="mr-2 inline" />{error}</div>}

      {/* Operational status */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <OpsCard title="Threat level" value={level.label} valueClass={level.cls} sub={`${level.sub}. Derived from open alerts.`} icon={ShieldAlert} tone={level.tone} />
        <OpsCard title="Backend" value={backendValue} valueClass={backendTone === "green" ? "text-emerald-400" : backendTone === "red" ? "text-rose-400" : "text-amber-400"} sub={apiOnline ? `API v${health?.version || "?"} · Database ${health?.database || "unknown"}` : "Backend unavailable"} icon={Activity} tone={backendTone} />
        <OpsCard title="URLhaus" value={intel.value} valueClass={intel.cls} sub={intel.sub} icon={ExternalLink} tone={intel.tone} />
        <OpsCard title="Scan activity" value={`${totals.last_24h} in 24h`} sub={totals.last_scan ? `Last scan ${formatDate(totals.last_scan)} · ${totals.scans} total` : "No scans recorded yet"} icon={FileSearch} tone="cyan">
          {hasTrend && <Sparkline data={trend} dataKey="scans" />}
        </OpsCard>
      </div>

      {/* Quick actions */}
      <section className={`${panel} mt-4 p-5`}>
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white"><Zap size={16} className="text-cyan-300" />Quick actions</div>
        <form onSubmit={(e) => { e.preventDefault(); const v = needUrl(); if (v) onAnalyze(v); }} className="flex flex-col gap-3 lg:flex-row">
          <div className="relative flex-1">
            <Globe size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600" />
            <input value={quickUrl} onChange={(e) => setQuickUrl(e.target.value)} maxLength={2048} aria-label="URL for quick actions" placeholder="Paste a URL to analyze, rescan or investigate" className={`${inputClass} pl-11`} />
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="submit" disabled={!apiOnline} className={primary}><ShieldCheck size={16} /> Analyze / rescan</button>
            <button type="button" onClick={() => { const v = needUrl(); if (v) onInvestigate(v); }} className={secondary}><Microscope size={16} /> Investigate</button>
            <button type="button" onClick={onOpenReport} className={secondary}><FileSpreadsheet size={16} /> Open report</button>
          </div>
        </form>
        {quickError && <p role="alert" className="mt-2 text-xs text-rose-400">{quickError}</p>}
      </section>

      {/* Queue + priority alerts */}
      <div className="mt-4 grid gap-4 xl:grid-cols-[1.7fr_1fr]">
        <section className={`${panel} overflow-hidden`}>
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] px-5 py-4">
            <div>
              <h3 className="flex items-center gap-2 text-sm font-semibold text-white"><ClipboardList size={16} className="text-cyan-300" />Investigation queue</h3>
              <p className="mt-1 text-[11px] text-slate-600">Latest high and medium-risk scan per URL, with workflow status.</p>
            </div>
            <div className="flex gap-1 rounded-lg border border-white/10 bg-[#070b12] p-1" role="group" aria-label="Queue view">
              {[["open", "Open"], ["all", "All"]].map(([id, label]) => (
                <button key={id} type="button" aria-pressed={queueView === id} onClick={() => setQueueView(id)}
                  className={`rounded-md px-3 py-1.5 text-xs font-medium ${queueView === id ? "bg-cyan-400/10 text-cyan-300" : "text-slate-500 hover:text-white"}`}>{label}</button>
              ))}
            </div>
          </div>
          {loading && !command ? <div className="p-12 text-center text-sm text-slate-500"><LoaderCircle className="mr-2 inline animate-spin" size={18} />Loading...</div>
            : !visibleQueue.length ? <EmptyState icon={CheckCircle2} title="Nothing needs attention" description={queue.length ? "Every flagged URL is resolved or dismissed." : "No high or medium-risk URLs have been scanned yet."} />
            : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[760px] text-left text-sm">
                  <thead className="text-[11px] text-slate-600"><tr>{["Target", "Risk", "Alerts", "Last scanned", "Status", ""].map((h) => <th key={h} className="px-5 py-3 font-medium">{h}</th>)}</tr></thead>
                  <tbody className="divide-y divide-white/[0.05]">
                    {visibleQueue.map((item) => (
                      <tr key={item.normalized_url} className="hover:bg-cyan-400/[0.04]">
                        <td className="max-w-[240px] px-5 py-3">
                          <p className="truncate font-medium text-slate-200">{item.hostname || hostname(item.normalized_url)}</p>
                          <p className="mt-0.5 truncate text-xs text-slate-600">{item.normalized_url}</p>
                        </td>
                        <td className="px-5 py-3"><div className="flex items-center gap-2"><RiskBadge level={item.risk_level} /><span className="text-xs tabular-nums text-slate-400">{item.risk_score}</span></div></td>
                        <td className="px-5 py-3">{item.open_alerts > 0 ? <span className="rounded-full border border-rose-400/20 bg-rose-400/10 px-2 py-0.5 text-xs font-semibold text-rose-300">{item.open_alerts} open</span> : <span className="text-xs text-slate-600">—</span>}</td>
                        <td className="whitespace-nowrap px-5 py-3 text-xs text-slate-500">{formatDate(item.last_scanned)}</td>
                        <td className="px-5 py-3">
                          <select value={item.status} aria-label={`Status for ${item.hostname}`} onChange={(e) => onSetStatus(item.normalized_url, e.target.value)} className="rounded-md border border-white/10 bg-[#070b12] px-2 py-1.5 text-xs text-slate-200 outline-none focus:border-cyan-400/60">
                            {investigationStatuses.map((s) => <option key={s} value={s}>{statusMeta[s].label}</option>)}
                          </select>
                        </td>
                        <td className="px-5 py-3">
                          <div className="flex justify-end gap-1.5">
                            <button type="button" onClick={() => onRescan(item.normalized_url)} aria-label="Rescan" title="Rescan" className={`${secondary} !px-2.5 !py-2`}><RotateCw size={14} /></button>
                            <button type="button" onClick={() => onInvestigate(item.normalized_url)} aria-label="Investigate" title="Investigate" className={`${secondary} !px-2.5 !py-2`}><Microscope size={14} /></button>
                            <button type="button" onClick={() => onOpenInvestigation(item)} className={`${secondary} ${small}`}>Notes</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
        </section>

        <section className={`${panel} flex flex-col overflow-hidden`}>
          <div className="flex items-center justify-between gap-3 border-b border-white/[0.07] px-5 py-4">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-white"><Bell size={16} className="text-cyan-300" />Priority alerts<span className="rounded-full bg-white/[0.06] px-2 py-0.5 text-[11px] text-slate-400">{alertInfo.open} open</span></h3>
            <button type="button" onClick={onOpenAlerts} className="text-xs font-semibold text-cyan-300 hover:text-cyan-200">View all →</button>
          </div>
          {!alertInfo.priority.length ? <EmptyState icon={ShieldCheck} title="No open alerts" description="Alerts appear here when a scan or intelligence lookup trips a rule." /> : (
            <ul className="divide-y divide-white/[0.05]">
              {alertInfo.priority.map((a) => (
                <li key={a.id}>
                  <button type="button" onClick={() => onOpenAlert(a)} className="w-full px-5 py-3.5 text-left transition hover:bg-cyan-400/[0.04]">
                    <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={a.severity} /><StatusPill status={a.status} /></div>
                    <p className="mt-2 text-sm font-medium text-slate-200">{a.title}</p>
                    <p className="mt-0.5 truncate text-xs text-slate-600">{a.hostname || hostname(a.normalized_url)} · {formatDate(a.created_at)}</p>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      {/* Trend + average score */}
      <div className="mt-4 grid gap-4 xl:grid-cols-[1.7fr_1fr]">
        <section className={`${panel} p-5`}>
          <div className="mb-4 flex items-start justify-between gap-3">
            <div><h3 className="text-sm font-semibold text-white">Risk-score trend</h3><p className="mt-1 text-[11px] text-slate-600">Last 14 days. Days without scans are skipped.</p></div>
            <span className="rounded-md border border-white/10 bg-white/[0.03] px-2.5 py-1 text-[10px] uppercase tracking-wider text-slate-400">Live data</span>
          </div>
          {!hasTrend ? <EmptyState icon={Activity} title="No scans in the last 14 days" description="The trend appears once you analyze some URLs." /> : (
            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trend} margin={{ top: 10, right: 8, left: -18, bottom: 0 }}>
                  <defs><linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} /><stop offset="100%" stopColor="#22d3ee" stopOpacity={0} /></linearGradient></defs>
                  <CartesianGrid stroke="rgba(255,255,255,0.06)" strokeDasharray="3 5" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} interval="preserveStartEnd" />
                  <YAxis domain={[0, 100]} tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip cursor={{ stroke: "rgba(34,211,238,0.3)" }} contentStyle={tooltipStyle} />
                  <Area type="monotone" dataKey="max_score" name="Peak score" stroke="#a78bfa" strokeWidth={1.5} strokeDasharray="4 4" fill="none" connectNulls />
                  <Area type="monotone" dataKey="avg_score" name="Average score" stroke="#22d3ee" strokeWidth={2} fill="url(#trendGradient)" dot={{ r: 2.5, fill: "#22d3ee" }} connectNulls />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        <section className={`${panel} flex flex-col p-5`}>
          <h3 className="text-sm font-semibold text-white">Average risk score</h3>
          <p className="mt-1 text-[11px] text-slate-600">{totals.scans} scans across {totals.unique_urls} unique URLs</p>
          <div className="flex flex-1 items-center py-6"><Gauge value={totals.avg_score} label="out of 100" color={gaugeColor} /></div>
          <p className="text-center text-[11px] text-slate-600">0-29 Low · 30-59 Medium · 60+ High</p>
        </section>
      </div>

      {/* Volume by risk + risk mix */}
      <div className="mt-4 grid gap-4 xl:grid-cols-[1.7fr_1fr]">
        <section className={`${panel} p-5`}>
          <h3 className="text-sm font-semibold text-white">Daily scan volume</h3>
          <p className="mb-4 mt-1 text-[11px] text-slate-600">Scans per day, split by risk level (last 14 days)</p>
          {!hasTrend ? <EmptyState icon={FileSearch} title="No scan volume yet" description="Daily volume appears once scans are recorded." /> : (
            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={trend} margin={{ top: 10, right: 8, left: -18, bottom: 0 }}>
                  <CartesianGrid stroke="rgba(255,255,255,0.06)" strokeDasharray="3 5" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} interval="preserveStartEnd" />
                  <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} contentStyle={tooltipStyle} />
                  <Bar dataKey="low" name="Low" stackId="risk" fill="#34d399" />
                  <Bar dataKey="medium" name="Medium" stackId="risk" fill="#fbbf24" />
                  <Bar dataKey="high" name="High" stackId="risk" fill="#fb7185" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        <section className={`${panel} flex flex-col p-5`}>
          <h3 className="text-sm font-semibold text-white">Risk mix</h3>
          <p className="mt-1 text-[11px] text-slate-600">All recorded scans by classification</p>
          {!totals.scans ? <EmptyState icon={ShieldCheck} title="No data yet" description="Analyze a URL to see the mix." /> : (
            <>
              <div className="relative mx-auto my-3 h-44 w-44">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={mix.filter((d) => d.value > 0)} dataKey="value" nameKey="name" innerRadius={55} outerRadius={80} paddingAngle={3} stroke="none">
                      {mix.filter((d) => d.value > 0).map((d) => <Cell key={d.name} fill={d.color} />)}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                  <p className="text-3xl font-semibold tabular-nums text-white">{totals.scans}</p>
                  <p className="text-[11px] text-slate-500">scans</p>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-2 text-center text-[11px]">
                {mix.map((d) => (
                  <div key={d.name} className="rounded-lg bg-white/[0.03] py-2">
                    <p className="font-semibold tabular-nums text-white">{d.value}</p>
                    <p className="flex items-center justify-center gap-1.5 text-slate-500"><span className="h-1.5 w-1.5 rounded-full" style={{ background: d.color }} />{d.name} · {Math.round((d.value / totals.scans) * 100)}%</p>
                  </div>
                ))}
              </div>
            </>
          )}
        </section>
      </div>

      {/* Distribution, top signals, workflow */}
      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <section className={`${panel} p-5`}>
          <h3 className="text-sm font-semibold text-white">Score distribution</h3>
          <p className="mb-4 mt-1 text-[11px] text-slate-600">Number of scans in each score band</p>
          {!totals.scans ? <EmptyState icon={Activity} title="No data yet" description="Scores will be grouped here." /> : (
            <div className="h-48 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={distribution} margin={{ top: 8, right: 4, left: -22, bottom: 0 }}>
                  <CartesianGrid stroke="rgba(255,255,255,0.06)" strokeDasharray="3 5" vertical={false} />
                  <XAxis dataKey="band" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} contentStyle={tooltipStyle} />
                  <Bar dataKey="count" name="Scans" radius={[4, 4, 0, 0]}>
                    {distribution.map((_, i) => <Cell key={i} fill={bandColors[i % bandColors.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        <section className={`${panel} p-5`}>
          <h3 className="text-sm font-semibold text-white">Top triggered signals</h3>
          <p className="mb-4 mt-1 text-[11px] text-slate-600">Rules that add risk most often (latest 500 scans)</p>
          {!topSignals.length ? <EmptyState icon={FileSearch} title="No signals yet" description="Signals that add risk will be ranked here." /> : (
            <ul className="space-y-3.5">
              {topSignals.map((s) => (
                <li key={s.signal}>
                  <div className="flex items-center justify-between gap-3 text-xs"><span className="truncate text-slate-300">{s.signal}</span><span className="tabular-nums text-slate-500">{s.count}</span></div>
                  <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-white/10"><div className="h-full rounded-full bg-cyan-400" style={{ width: `${(s.count / maxSignal) * 100}%` }} /></div>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className={`${panel} p-5`}>
          <h3 className="text-sm font-semibold text-white">Workflow</h3>
          <p className="mb-4 mt-1 text-[11px] text-slate-600">Investigation status and open alerts</p>
          <p className="mb-2 text-[11px] font-medium text-slate-500">Flagged URLs by status ({queue.length})</p>
          {queue.length ? (
            <>
              <div className="flex h-2.5 overflow-hidden rounded-full bg-white/10">
                {pipeline.map((p) => p.count > 0 && <div key={p.status} className={pipelineColors[p.status]} style={{ width: `${(p.count / queue.length) * 100}%` }} />)}
              </div>
              <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
                {pipeline.map((p) => <div key={p.status} className="flex items-center justify-between text-slate-400"><span className="flex items-center gap-2"><span className={`h-2 w-2 rounded-full ${pipelineColors[p.status]}`} />{statusMeta[p.status].label}</span><span className="tabular-nums text-slate-300">{p.count}</span></div>)}
              </div>
            </>
          ) : <p className="text-xs text-slate-600">No flagged URLs yet.</p>}

          <p className="mb-2 mt-6 text-[11px] font-medium text-slate-500">Open alerts by severity ({alertInfo.open})</p>
          <ul className="space-y-2.5">
            {severityOrder.map((key) => {
              const n = openSev[key] || 0;
              return (
                <li key={key} className="flex items-center gap-3 text-xs">
                  <span className="w-24 shrink-0 text-slate-400">{severityMeta[key].label}</span>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/10"><div className={`h-full rounded-full ${severityMeta[key].dot}`} style={{ width: `${(n / maxSev) * 100}%` }} /></div>
                  <span className="w-5 text-right tabular-nums text-slate-300">{n}</span>
                </li>
              );
            })}
          </ul>
        </section>
      </div>

      {/* Latest detections + recent activity */}
      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <section className={`${panel} overflow-hidden`}>
          <div className="border-b border-white/[0.07] px-5 py-4"><h3 className="text-sm font-semibold text-white">Latest detections</h3><p className="mt-1 text-[11px] text-slate-600">Most recent high and medium-risk scans</p></div>
          {!detections.length ? <EmptyState icon={ShieldCheck} title="No detections yet" description="High and medium-risk scans will be listed here." /> : (
            <ul className="divide-y divide-white/[0.05]">
              {detections.map((scan) => (
                <li key={scan.id}><button type="button" onClick={() => onOpenScan(scan)} className="flex w-full items-center justify-between gap-3 px-5 py-3.5 text-left hover:bg-cyan-400/[0.04]">
                  <div className="min-w-0"><p className="truncate text-sm font-medium text-slate-200">{scan.hostname || hostname(scan.normalized_url)}</p><p className="mt-0.5 text-xs text-slate-600">{formatDate(scan.created_at)}</p></div>
                  <div className="flex items-center gap-2"><span className="text-xs tabular-nums text-slate-400">{scan.risk_score}</span><RiskBadge level={scan.risk_level} /></div>
                </button></li>
              ))}
            </ul>
          )}
        </section>

        <section className={`${panel} overflow-hidden`}>
          <div className="border-b border-white/[0.07] px-5 py-4"><h3 className="text-sm font-semibold text-white">Recent scan activity</h3><p className="mt-1 text-[11px] text-slate-600">Latest scans of any risk level</p></div>
          {!history.length ? <EmptyState icon={Search} title="No scans yet" description="Analyze a URL to start building activity." /> : (
            <ul className="divide-y divide-white/[0.05]">
              {history.slice(0, 5).map((scan) => (
                <li key={scan.id}><button type="button" onClick={() => onOpenScan(scan)} className="flex w-full items-center justify-between gap-3 px-5 py-3.5 text-left hover:bg-cyan-400/[0.04]">
                  <div className="flex min-w-0 items-center gap-2.5"><Globe size={15} className="shrink-0 text-slate-600" /><div className="min-w-0"><p className="truncate text-sm font-medium text-slate-200">{scan.hostname || hostname(scan.normalized_url || scan.submitted_url)}</p><p className="mt-0.5 text-xs text-slate-600">{formatDate(scan.created_at)}</p></div></div>
                  <RiskBadge level={scan.risk_level} />
                </button></li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </>
  );
}

/* ---------- Security Alerts page ---------- */
const selectClass = `${inputClass} !py-2.5`;

function AlertsPage({ alerts, loading, error, filters, setFilters, onOpenAlert, onRefresh }) {
  const counts = alerts.counts || { by_status: {}, open_by_severity: {} };
  const totalAll = Object.values(counts.by_status || {}).reduce((a, b) => a + b, 0);
  const filtered = Object.values(filters).some((v) => v !== "all");
  const setFilter = (key) => (e) => setFilters((f) => ({ ...f, [key]: e.target.value }));

  return (
    <>
      <Heading eyebrow="Alert management / 06" title="Security alerts" description="Rule-based alerts from heuristic scans, URLhaus matches and rescans. Triage them through New, Acknowledged and Resolved or Dismissed."
        action={<button type="button" onClick={onRefresh} disabled={loading} className={secondary}><RefreshCw size={15} className={loading ? "animate-spin" : ""} /> Refresh</button>} />

      {error && <div role="alert" className="mb-5 rounded-xl border border-rose-500/20 bg-rose-500/[0.05] p-4 text-sm text-rose-300">{error}</div>}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {severityOrder.map((key) => {
          const meta = severityMeta[key];
          const n = counts.open_by_severity?.[key] || 0;
          return (
            <div key={key} className={`${panel} p-4`}>
              <div className="flex items-center gap-2 text-xs text-slate-500"><span className={`h-2 w-2 rounded-full ${meta.dot}`} />Open · {meta.label}</div>
              <p className={`mt-3 text-3xl font-semibold tabular-nums ${n ? meta.text : "text-white"}`}>{n}</p>
            </div>
          );
        })}
      </div>

      <section className={`${panel} mt-4 overflow-hidden`}>
        <div className="border-b border-white/[0.07] p-5">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              ["severity", "Severity", [["all", "All severities"], ...severityOrder.map((s) => [s, severityMeta[s].label])]],
              ["status", "Status", [["all", "All statuses"], ["new", "New"], ["acknowledged", "Acknowledged"], ["resolved", "Resolved"], ["dismissed", "Dismissed"]]],
              ["category", "Category", [["all", "All categories"], ...Object.entries(categoryLabel)]],
              ["days", "Raised", [["all", "Any time"], ["1", "Last 24 hours"], ["7", "Last 7 days"], ["30", "Last 30 days"]]],
            ].map(([key, label, options]) => (
              <label key={key} className="block text-xs text-slate-500">{label}
                <select value={filters[key]} onChange={setFilter(key)} className={`${selectClass} mt-1.5`}>
                  {options.map(([value, text]) => <option key={value} value={value}>{text}</option>)}
                </select>
              </label>
            ))}
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
            <span>{alerts.total_matching ?? alerts.items.length} matching of {totalAll} alerts</span>
            {filtered && <button type="button" onClick={() => setFilters({ severity: "all", status: "all", category: "all", days: "all" })} className="text-cyan-300">Clear filters</button>}
          </div>
        </div>

        {loading && !alerts.items.length ? <div className="p-12 text-center text-sm text-slate-500"><LoaderCircle className="mr-2 inline animate-spin" size={18} />Loading alerts...</div>
          : !totalAll ? <EmptyState icon={Bell} title="No alerts yet" description="Alerts are raised when a scan scores Medium or High, or when an intelligence lookup matches URLhaus." />
          : !alerts.items.length ? <EmptyState icon={Search} title="No matching alerts" description="Try different filters." />
          : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[820px] text-left text-sm">
                <thead className="bg-white/[0.02] text-[11px] text-slate-600"><tr>{["Severity", "Alert", "Category", "Status", "Score", "Raised"].map((h) => <th key={h} className="px-5 py-4 font-medium">{h}</th>)}</tr></thead>
                <tbody className="divide-y divide-white/[0.05]">
                  {alerts.items.map((a) => (
                    <tr key={a.id} tabIndex={0} role="button" aria-label={`Open alert ${a.id}`} onClick={() => onOpenAlert(a)}
                      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onOpenAlert(a); } }}
                      className="cursor-pointer hover:bg-cyan-400/[0.04] focus:bg-white/[0.05] focus:outline-none">
                      <td className="px-5 py-4"><SeverityBadge severity={a.severity} /></td>
                      <td className="max-w-xs px-5 py-4"><p className="truncate font-medium text-slate-200">{a.title}</p><p className="mt-1 truncate text-xs text-slate-600">{a.normalized_url}</p></td>
                      <td className="whitespace-nowrap px-5 py-4 text-xs text-slate-400">{categoryLabel[a.category] || a.category}</td>
                      <td className="px-5 py-4"><StatusPill status={a.status} /></td>
                      <td className="px-5 py-4 tabular-nums text-slate-300">{a.risk_score ?? "—"}</td>
                      <td className="whitespace-nowrap px-5 py-4 text-xs text-slate-500">{formatDate(a.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </section>

      <details className={`${panel} mt-4 group`}>
        <summary className="flex cursor-pointer list-none items-center gap-2 px-5 py-4 text-sm font-semibold text-white [&::-webkit-details-marker]:hidden">
          <ShieldCheck size={16} className="text-cyan-300" />How alerts are raised
          <ChevronRight size={15} className="ml-auto text-slate-600 transition group-open:rotate-90" />
        </summary>
        <div className="space-y-4 border-t border-white/[0.07] p-5">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-left text-sm">
              <thead className="text-[11px] text-slate-600"><tr><th className="py-2 pr-4 font-medium">Category</th><th className="py-2 pr-4 font-medium">Condition</th><th className="py-2 font-medium">Severity</th></tr></thead>
              <tbody className="divide-y divide-white/[0.05] text-slate-300">
                {[
                  ["Intelligence match", "URLhaus exact match, listing not reported offline", "critical"],
                  ["Intelligence match", "URLhaus exact match, listing reported offline", "high"],
                  ["Heuristic risk", "Scan classified High (score 60 or more)", "high"],
                  ["Heuristic risk", "Scan classified Medium (score 30 to 59)", "medium"],
                  ["Risk change", "Rescan score up 20+ points and now High", "high"],
                  ["Risk change", "Rescan score up 20+ points, below High", "medium"],
                  ["Risk change", "Rescan score down 20+ points", "informational"],
                ].map(([cat, cond, sev], i) => <tr key={i}><td className="py-2.5 pr-4">{cat}</td><td className="py-2.5 pr-4 text-slate-400">{cond}</td><td className="py-2.5"><SeverityBadge severity={sev} /></td></tr>)}
              </tbody>
            </table>
          </div>
          <p className="text-xs leading-5 text-slate-500">While an alert for the same URL and rule is New or Acknowledged, repeat scans update it instead of creating a duplicate. A severity escalation moves an acknowledged alert back to New. Risk-change alerts only fire when the same URL scores differently between two scans.</p>
        </div>
      </details>
    </>
  );
}

/* ---------- Settings page ---------- */
function SettingRow({ label, hint, children }) {
  return (
    <div className="flex flex-col gap-3 border-b border-white/[0.05] py-4 last:border-0 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <p className="text-sm font-medium text-slate-200">{label}</p>
        {hint && <p className="mt-0.5 text-xs leading-5 text-slate-500">{hint}</p>}
      </div>
      <div className="shrink-0 sm:w-60">{children}</div>
    </div>
  );
}

function SettingsPage({ settings, setSettings, health, apiOnline, onRecheck, onReset }) {
  const [apiInput, setApiInput] = useState(API_BASE);
  const [apiErr, setApiErr] = useState("");
  const [confirmText, setConfirmText] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const intel = urlhausCard(health?.threat_intelligence);

  const set = (key) => (e) =>
    setSettings((s) => ({ ...s, [key]: key === "refreshSeconds" ? Number(e.target.value) : e.target.value }));

  const saveApi = () => {
    try {
      const parsed = new URL(apiInput.trim());
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("protocol");
      localStorage.setItem("sentinelx.apiBase", parsed.origin);
      window.location.reload();
    } catch {
      setApiErr("Enter a full URL such as http://127.0.0.1:8001");
    }
  };

  const resetApi = () => {
    try { localStorage.removeItem("sentinelx.apiBase"); } catch { /* ignore */ }
    window.location.reload();
  };

  const doReset = async () => {
    setBusy(true);
    setMsg("");
    try {
      const d = await onReset();
      setMsg(`Deleted ${d.scans} scans, ${d.alerts} alerts and ${d.investigations} investigations.`);
      setConfirmText("");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Reset failed.");
    } finally {
      setBusy(false);
    }
  };

  const statusRows = [
    ["API", apiOnline ? "Online" : "Offline", apiOnline ? "text-emerald-400" : "text-rose-400"],
    ["Version", health?.version || "—", "text-slate-200"],
    ["Database", health?.database || "—", health?.database === "ok" ? "text-emerald-400" : "text-slate-200"],
    ["URLhaus", intel.value, intel.cls],
  ];

  return (
    <>
      <Heading eyebrow="Workspace / 07" title="Settings" description="Preferences are stored in this browser. Connection and data options act on your backend." />

      <div className="grid gap-4 xl:grid-cols-2">
        <section className={`${panel} p-5 sm:p-6`}>
          <h3 className="text-sm font-semibold text-white">Preferences</h3>
          <SettingRow label="Display time zone" hint="Used for every timestamp in the app.">
            <select value={settings.timezone} onChange={set("timezone")} className={selectClass}>
              <option value="Asia/Kolkata">India (IST)</option>
              <option value="UTC">UTC</option>
              <option value="local">Browser local time</option>
            </select>
          </SettingRow>
          <SettingRow label="Auto-refresh" hint="How often the Command Center reloads in the background.">
            <select value={settings.refreshSeconds} onChange={set("refreshSeconds")} className={selectClass}>
              <option value={0}>Off (manual only)</option>
              <option value={15}>Every 15 seconds</option>
              <option value={30}>Every 30 seconds</option>
              <option value={60}>Every minute</option>
              <option value={120}>Every 2 minutes</option>
            </select>
          </SettingRow>
          <SettingRow label="Default queue view" hint="Which investigation queue tab opens first.">
            <select value={settings.queueView} onChange={set("queueView")} className={selectClass}>
              <option value="open">Open items only</option>
              <option value="all">All flagged URLs</option>
            </select>
          </SettingRow>
          <button type="button" onClick={() => setSettings(DEFAULT_SETTINGS)} className={`${secondary} ${small} mt-2`}>Restore defaults</button>
        </section>

        <section className={`${panel} p-5 sm:p-6`}>
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-sm font-semibold text-white">Connection</h3>
            <button type="button" onClick={onRecheck} className={`${secondary} ${small}`}><RefreshCw size={13} /> Re-check</button>
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2">
            {statusRows.map(([label, value, cls]) => (
              <div key={label} className="rounded-lg bg-white/[0.03] px-3 py-2.5">
                <p className="text-[11px] text-slate-500">{label}</p>
                <p className={`mt-1 truncate text-sm font-semibold ${cls}`}>{value}</p>
              </div>
            ))}
          </div>
          <div className="mt-5">
            <label htmlFor="api-url" className="block text-xs font-medium text-slate-400">Backend URL</label>
            <input id="api-url" value={apiInput} onChange={(e) => { setApiInput(e.target.value); setApiErr(""); }} className={`${inputClass} mt-1.5`} />
            {apiErr && <p role="alert" className="mt-2 text-xs text-rose-400">{apiErr}</p>}
            <div className="mt-3 flex flex-wrap gap-2">
              <button type="button" onClick={saveApi} disabled={apiInput.trim() === API_BASE} className={`${primary} ${small}`}>Save and reload</button>
              <button type="button" onClick={resetApi} disabled={API_BASE === DEFAULT_API} className={`${secondary} ${small}`}>Use default</button>
            </div>
            <p className="mt-3 text-xs leading-5 text-slate-600">The backend only accepts requests from the dev server origins listed in its CORS settings. API keys such as <span className="font-mono">URLHAUS_AUTH_KEY</span> stay in the backend <span className="font-mono">.env</span>.</p>
          </div>
        </section>

        <section className={`${panel} p-5 sm:p-6`}>
          <h3 className="text-sm font-semibold text-white">About this workspace</h3>
          <div className="mt-3">
            <DetailRow label="Analysis method" value="Rule-based heuristics" />
            <DetailRow label="Risk bands" value="Low 0-29 · Medium 30-59 · High 60-100" />
            <DetailRow label="Alert rules" value="Fixed (see Security Alerts)" />
            <DetailRow label="Reputation source" value="URLhaus (optional)" />
          </div>
          <p className="mt-3 text-xs leading-5 text-slate-600">Scores are indicators, not verdicts. A URLhaus "no match" does not prove a URL is safe.</p>
        </section>

        <section className="rounded-xl border border-rose-500/25 bg-rose-500/[0.04] p-5 sm:p-6">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-rose-300"><Trash2 size={16} />Danger zone</h3>
          <p className="mt-2 text-sm leading-6 text-slate-400">Permanently deletes every saved scan, alert and investigation from the backend database. This cannot be undone. Export your history first if you need it.</p>
          <label htmlFor="reset-confirm" className="mt-4 block text-xs font-medium text-slate-400">Type DELETE to enable the button</label>
          <input id="reset-confirm" value={confirmText} onChange={(e) => setConfirmText(e.target.value)} autoComplete="off" className={`${inputClass} mt-1.5`} placeholder="DELETE" />
          <button type="button" disabled={confirmText !== "DELETE" || busy || !apiOnline} onClick={doReset}
            className="mt-3 inline-flex items-center gap-2 rounded-lg bg-rose-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-rose-500 disabled:cursor-not-allowed disabled:opacity-40">
            {busy ? <LoaderCircle size={15} className="animate-spin" /> : <Trash2 size={15} />}Delete all data
          </button>
          {msg && <p role="status" className="mt-3 text-xs text-slate-300">{msg}</p>}
        </section>
      </div>
    </>
  );
}

/* ---------- App ---------- */
function App() {
  const [page, setPage] = useState("command");
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [apiOnline, setApiOnline] = useState(false);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(false);
  const [intelLoading, setIntelLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [error, setError] = useState("");
  const [intelError, setIntelError] = useState("");
  const [historyError, setHistoryError] = useState("");
  const [query, setQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState("All");
  const [selectedScan, setSelectedScan] = useState(null);
  const [intelResult, setIntelResult] = useState(null);
  const [intelUrl, setIntelUrl] = useState("");

  const [command, setCommand] = useState(null);
  const [commandLoading, setCommandLoading] = useState(false);
  const [commandError, setCommandError] = useState("");
  const [alerts, setAlerts] = useState({ items: [], total_matching: 0, counts: { by_status: {}, open_by_severity: {} } });
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [alertsError, setAlertsError] = useState("");
  const [alertFilters, setAlertFilters] = useState({ severity: "all", status: "all", category: "all", days: "all" });
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedInvestigation, setSelectedInvestigation] = useState(null);

  const [settings, setSettings] = useState(() => {
    try { return { ...DEFAULT_SETTINGS, ...JSON.parse(localStorage.getItem("sentinelx.settings") || "{}") }; }
    catch { return DEFAULT_SETTINGS; }
  });

  useEffect(() => {
    try { localStorage.setItem("sentinelx.settings", JSON.stringify(settings)); } catch { /* ignore */ }
  }, [settings]);

  const checkApi = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/health`);
      setApiOnline(response.ok);
      setHealth(response.ok ? await response.json().catch(() => null) : null);
    } catch {
      setApiOnline(false);
      setHealth(null);
    }
  }, []);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError("");
    try {
      const response = await fetch(`${API_BASE}/api/history`);
      if (!response.ok) throw new Error(`History request failed (${response.status}).`);
      const data = await response.json();
      if (!Array.isArray(data)) throw new Error("Unexpected history response.");
      setHistory(data);
      setSelectedScan((current) => current ? data.find((item) => item.id === current.id) || current : null);
    } catch (err) {
      setHistoryError(err instanceof Error ? err.message : "Could not load history.");
    } finally { setHistoryLoading(false); }
  }, []);

  const loadCommand = useCallback(async (silent = false) => {
    if (!silent) setCommandLoading(true);
    try {
      const offset = -new Date().getTimezoneOffset();
      const response = await fetch(`${API_BASE}/api/command-center?tz=${offset}`);
      if (!response.ok) throw new Error(`Command center request failed (${response.status}).`);
      setCommand(await response.json());
      setCommandError("");
    } catch (err) {
      setCommandError(err instanceof Error ? err.message : "Could not load the command center.");
    } finally { if (!silent) setCommandLoading(false); }
  }, []);

  const loadAlerts = useCallback(async () => {
    setAlertsLoading(true);
    setAlertsError("");
    try {
      const params = new URLSearchParams();
      Object.entries(alertFilters).forEach(([key, value]) => { if (value !== "all") params.set(key, value); });
      const response = await fetch(`${API_BASE}/api/alerts?${params}`);
      if (!response.ok) throw new Error(`Alerts request failed (${response.status}).`);
      setAlerts(await response.json());
    } catch (err) {
      setAlertsError(err instanceof Error ? err.message : "Could not load alerts.");
    } finally { setAlertsLoading(false); }
  }, [alertFilters]);

  useEffect(() => {
    checkApi();
    loadHistory();
    loadCommand();
    const timer = setInterval(checkApi, 15000);
    return () => clearInterval(timer);
  }, [checkApi, loadHistory, loadCommand]);

  useEffect(() => {
    if (!settings.refreshSeconds) return undefined;
    const timer = setInterval(() => loadCommand(true), settings.refreshSeconds * 1000);
    return () => clearInterval(timer);
  }, [loadCommand, settings.refreshSeconds]);

  useEffect(() => { loadAlerts(); }, [loadAlerts]);

  useEffect(() => {
    const onKey = (event) => {
      if (event.key === "Escape") { setSelectedScan(null); setSelectedAlert(null); setSelectedInvestigation(null); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const refreshAll = () => { checkApi(); loadHistory(); loadCommand(); loadAlerts(); };

  async function parseResponse(response) {
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = Array.isArray(data.detail) ? data.detail.map((item) => item.msg).join(", ") : data.detail;
      throw new Error(detail || `Request failed (${response.status}).`);
    }
    return data;
  }

  async function runAnalysis(submitted) {
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const response = await fetch(`${API_BASE}/api/analyze-url`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: submitted }),
      });
      setResult(await parseResponse(response));
      await Promise.all([loadHistory(), loadCommand(true), loadAlerts()]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed.");
    } finally { setLoading(false); checkApi(); }
  }

  async function analyze(event) {
    event.preventDefault();
    const submitted = url.trim();
    if (!submitted) { setError("Enter a URL to analyze."); return; }
    await runAnalysis(submitted);
  }

  // Analyze or rescan a URL from anywhere: show the analyzer page and run it.
  function rescan(target) {
    setSelectedAlert(null);
    setSelectedInvestigation(null);
    setPage("analyzer");
    setError("");
    if (!target) return;
    setUrl(target);
    runAnalysis(target);
  }

  // Prefill the intelligence page. The lookup itself stays an explicit click.
  function investigate(target) {
    setSelectedAlert(null);
    setSelectedInvestigation(null);
    setIntelUrl(target);
    setIntelResult(null);
    setIntelError("");
    setPage("intelligence");
  }

  async function analyzeIntelligence(event) {
    event.preventDefault();
    const submitted = intelUrl.trim();
    if (!submitted) { setIntelError("Enter a URL to investigate."); return; }
    setIntelLoading(true);
    setIntelError("");
    setIntelResult(null);
    try {
      const response = await fetch(`${API_BASE}/api/threat-intelligence`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: submitted }),
      });
      setIntelResult(await parseResponse(response));
      loadAlerts();       // a URLhaus match raises an alert
      loadCommand(true);
    } catch (err) {
      setIntelError(err instanceof Error ? err.message : "Threat intelligence request failed.");
    } finally { setIntelLoading(false); checkApi(); }
  }

  async function updateAlertStatus(alertId, status, note) {
    const response = await fetch(`${API_BASE}/api/alerts/${alertId}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, note: note || null }),
    });
    const updated = await parseResponse(response);
    setSelectedAlert((current) => (current && current.id === updated.id ? updated : current));
    await Promise.all([loadAlerts(), loadCommand(true)]);
    return updated;
  }

  async function updateInvestigation(target, payload) {
    const response = await fetch(`${API_BASE}/api/investigations`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: target, ...payload }),
    });
    const updated = await parseResponse(response);
    setSelectedInvestigation((current) =>
      current && current.normalized_url === target ? { ...current, status: updated.status, investigation: updated } : current);
    await loadCommand(true);
    return updated;
  }

  async function resetData() {
    const response = await fetch(`${API_BASE}/api/data?confirm=DELETE`, { method: "DELETE" });
    const data = await parseResponse(response);
    setResult(null);
    setIntelResult(null);
    setSelectedScan(null);
    setSelectedAlert(null);
    setSelectedInvestigation(null);
    await Promise.all([loadHistory(), loadCommand(true), loadAlerts()]);
    return data.deleted;
  }

  const high = history.filter((item) => (item.risk_level || "").toLowerCase() === "high").length;

  const filteredHistory = useMemo(() => {
    const search = query.trim().toLowerCase();
    return history.filter((item) => {
      const level = (item.risk_level || "").toLowerCase();
      const matchesRisk = riskFilter === "All" || level === riskFilter.toLowerCase();
      const text = [item.hostname, item.submitted_url, item.normalized_url, item.recommendation, item.id].filter(Boolean).join(" ").toLowerCase();
      return matchesRisk && (!search || text.includes(search));
    });
  }, [history, query, riskFilter]);

  const goAnalyze = () => { setPage("analyzer"); setError(""); };
  const openAlerts = command?.alerts?.open ?? 0;

  const StatusDot = () => (
    <span className="relative flex h-2 w-2">
      {apiOnline && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />}
      <span className={`relative inline-flex h-2 w-2 rounded-full ${apiOnline ? "bg-emerald-400" : "bg-rose-400"}`} />
    </span>
  );

  function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
  }

  function exportJsonReport() {
    const report = {
      product: "Sentinel X",
      report_type: "URL security analysis",
      exported_at: new Date().toISOString(),
      intelligence: intelResult,
      latest_heuristic_scan: result,
      latest_saved_scan: history[0] || null,
      disclaimer: "Heuristic and reputation results are indicators, not proof that a URL is safe or malicious. A URLhaus no-match result does not guarantee safety."
    };
    downloadFile(JSON.stringify(report, null, 2), `sentinel-x-report-${new Date().toISOString().slice(0, 10)}.json`, "application/json;charset=utf-8");
  }

  function exportHistoryCsv() {
    const columns = ["id", "submitted_url", "normalized_url", "hostname", "risk_level", "risk_score", "signal_count", "analysis_method", "created_at", "recommendation"];
    const quote = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
    const rows = history.map((scan) => columns.map((key) => quote(key === "signal_count" ? (scan.signal_count ?? scan.signals?.length ?? 0) : scan[key])).join(","));
    const csv = [columns.join(","), ...rows].join("\r\n");
    downloadFile("\uFEFF" + csv, `sentinel-x-scan-history-${new Date().toISOString().slice(0, 10)}.csv`, "text/csv;charset=utf-8");
  }

  const forensics = intelResult?.forensics || {};
  const urlhaus =
    intelResult?.intelligence?.urlhaus ||
    intelResult?.urlhaus ||
    intelResult?.urlhaus_lookup ||
    intelResult?.threat_intelligence?.urlhaus ||
    intelResult?.threat_intelligence ||
    null;
  const urlhausStatus = urlhaus?.status || urlhaus?.query_status || "Not returned";
  const intelSignals = intelResult?.signals || intelResult?.analysis?.signals || [];

  const navButton = (item, mobile = false) => {
    const Icon = item.icon;
    const active = page === item.id;
    const badge = item.id === "alerts" && openAlerts > 0
      ? <span className="rounded-full bg-rose-500/20 px-2 py-0.5 text-[10px] font-semibold text-rose-300">{openAlerts}</span> : null;
    if (mobile) {
      return <button key={item.id} type="button" onClick={() => setPage(item.id)} className={`flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-xs ${active ? "bg-cyan-400/10 text-cyan-300" : "bg-white/[0.03] text-slate-500"}`}><Icon size={15} />{item.label}{badge}</button>;
    }
    return (
      <button key={item.id} type="button" onClick={() => setPage(item.id)}
        className={`flex w-full items-center gap-3 rounded-lg px-3 py-3 text-sm transition ${active ? "bg-cyan-400/10 text-cyan-300 shadow-[inset_2px_0_0_#22d3ee]" : "text-slate-500 hover:bg-white/[0.04] hover:text-white"}`}>
        <Icon size={18} />{item.label}
        <span className="ml-auto flex items-center gap-2">{badge}{active && <ChevronRight size={16} className="text-cyan-400/70" />}</span>
      </button>
    );
  };

  displayTz = settings.timezone === "local" ? undefined : settings.timezone;

  return (
    <div className="min-h-screen bg-transparent text-slate-200">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -left-40 -top-40 h-96 w-96 rounded-full bg-cyan-400/[0.05] blur-[130px]" />
        <div className="absolute -right-40 top-40 h-96 w-96 rounded-full bg-violet-500/[0.05] blur-[130px]" />
      </div>

      <div className="relative flex min-h-screen">
        <aside className="hidden w-64 shrink-0 border-r border-white/[0.07] bg-[#070b12]/80 p-5 backdrop-blur md:flex md:flex-col">
          <button type="button" onClick={() => setPage("command")} className="mb-10 flex items-center gap-3 text-left">
            <div className="rounded-lg border border-cyan-400/30 bg-cyan-400/10 p-2.5 text-cyan-300"><Shield size={24} /></div>
            <div><p className="text-lg font-bold tracking-[0.12em] text-white">SENTINEL <span className="text-cyan-400">X</span></p><p className="mt-1 text-[9px] uppercase tracking-[0.2em] text-slate-600">Security intelligence</p></div>
          </button>
          <p className="mb-3 px-3 text-[10px] font-bold uppercase tracking-[0.18em] text-slate-600">Workspace</p>
          <nav className="space-y-1.5">{navItems.map((item) => navButton(item))}</nav>
          <div className="mt-auto">
            <div className="mb-4 border-t border-white/[0.07] pt-4">{navButton(settingsItem)}</div>
            <div className="rounded-lg border border-white/[0.07] bg-white/[0.03] p-4">
              <div className="mb-3 flex items-center gap-2"><Activity size={16} className="text-cyan-300" /><span className="text-xs font-semibold text-white">Analysis service</span></div>
              <div className="flex items-center gap-2"><StatusDot /><span className={`text-xs ${apiOnline ? "text-emerald-400" : "text-rose-400"}`}>{apiOnline ? "API Online" : "API Offline"}</span></div>
              <p className="mt-2 text-[11px] text-slate-600">FastAPI · Port 8001</p>
            </div>
            <div className="mt-4 flex items-center gap-2 px-2 text-[11px] text-slate-600"><LockKeyhole size={13} /> Local environment</div>
          </div>
        </aside>

        <main className="min-w-0 flex-1">
          <header className="sticky top-0 z-20 border-b border-white/[0.07] bg-[#070b12]/80 px-4 py-4 backdrop-blur-xl sm:px-6 lg:px-10">
            <div className="mx-auto flex max-w-7xl items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg border border-cyan-400/30 bg-cyan-400/10 p-2 text-cyan-300 md:hidden"><Shield size={19} /></div>
                <div><p className="text-sm font-semibold text-white">{allNav.find((item) => item.id === page)?.label}</p><p className="mt-1 text-xs text-slate-600">Sentinel X / Security workspace</p></div>
              </div>
              <div className="flex items-center gap-3">
                <div className={`hidden items-center gap-2 rounded-full border px-3 py-2 text-xs sm:flex ${apiOnline ? "border-emerald-500/20 text-emerald-400" : "border-rose-500/20 text-rose-400"}`}><StatusDot />{apiOnline ? "System operational" : "Service unavailable"}</div>
                <button type="button" onClick={refreshAll} aria-label="Refresh dashboard" className={secondary}><RefreshCw size={16} className={historyLoading || commandLoading ? "animate-spin" : ""} /></button>
              </div>
            </div>
            <nav className="mt-4 flex gap-2 overflow-x-auto md:hidden">{allNav.map((item) => navButton(item, true))}</nav>
          </header>

          <div className="mx-auto max-w-7xl px-4 py-7 sm:px-6 lg:px-10 lg:py-10">
            {page === "command" && (
              <CommandCenter
                command={command} health={health} apiOnline={apiOnline} history={history}
                loading={commandLoading} error={commandError} defaultQueueView={settings.queueView}
                onAnalyze={rescan} onInvestigate={investigate} onRescan={rescan}
                onOpenReport={() => setPage("reports")} onOpenAlerts={() => setPage("alerts")}
                onOpenAlert={setSelectedAlert} onOpenScan={setSelectedScan}
                onOpenInvestigation={setSelectedInvestigation}
                onSetStatus={(target, status) => updateInvestigation(target, { status }).catch((err) => setCommandError(err instanceof Error ? err.message : "Could not update status."))}
              />
            )}

            {page === "alerts" && (
              <AlertsPage alerts={alerts} loading={alertsLoading} error={alertsError} filters={alertFilters} setFilters={setAlertFilters} onOpenAlert={setSelectedAlert} onRefresh={() => { loadAlerts(); loadCommand(true); }} />
            )}

            {page === "settings" && (
              <SettingsPage settings={settings} setSettings={setSettings} health={health} apiOnline={apiOnline} onRecheck={checkApi} onReset={resetData} />
            )}

            {page === "analyzer" && (
              <>
                <Heading eyebrow="Threat investigation / 02" title="URL Analyzer" description="Inspect a URL using Sentinel X's explainable heuristic rules." />
                <div className="grid items-start gap-5 xl:grid-cols-[1.05fr_0.95fr]">
                  <section className={`${panel} p-5 sm:p-7`}>
                    <div className="mb-7 flex items-center gap-3"><div className="rounded-lg border border-cyan-400/20 bg-cyan-400/10 p-3 text-cyan-300"><Search size={22} /></div><div><h3 className="font-semibold text-white">Inspect a destination</h3><p className="mt-1 text-xs text-slate-500">Enter a URL or hostname</p></div></div>
                    <form onSubmit={analyze} className="space-y-4">
                      <label htmlFor="url-input" className="block text-sm font-medium text-slate-300">URL to analyze</label>
                      <div className="relative"><Globe size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600" /><input id="url-input" type="text" inputMode="url" autoComplete="url" maxLength={2048} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" className={`${inputClass} py-4 pl-11`} /></div>
                      <p className="text-xs leading-5 text-slate-600">The analyzer evaluates URL text without opening the destination.</p>
                      {error && <div role="alert" className="rounded-xl border border-rose-500/20 bg-rose-500/[0.05] p-3 text-sm text-rose-300"><XCircle size={16} className="mr-2 inline" />{error}</div>}
                      <button type="submit" disabled={loading || !apiOnline} className={`${primary} w-full py-4`}>{loading ? <><LoaderCircle size={17} className="animate-spin" /> Analyzing...</> : <><ShieldCheck size={17} /> Analyze URL <ChevronRight size={16} /></>}</button>
                      {!apiOnline && <p className="text-center text-xs text-rose-400">Backend unavailable.</p>}
                      <button type="button" onClick={() => { setUrl("https://example.com"); setError(""); }} className={`${secondary} w-full`}>Use example.com</button>
                    </form>
                  </section>

                  <section className={`${panel} p-5 sm:p-7`}>
                    <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-cyan-400/70">Analysis output</p><h3 className="mt-2 text-xl font-semibold text-white">Analysis results</h3><p className="mt-1 text-xs text-slate-600">Evidence returned by the API</p>
                    {!result ? <EmptyState icon={FileSearch} title="Awaiting analysis" description="Your risk score, signals, and recommendation appear here after a successful analysis." /> : <div className="mt-5 space-y-5">
                      <div className="rounded-xl border border-white/10 bg-[#070b12] p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-xs text-slate-500">Heuristic risk score</p><div className="mt-2 flex items-baseline gap-2"><span className="text-5xl font-semibold text-white">{result.risk_score}</span><span className="text-sm text-slate-600">/100</span></div></div><RiskBadge level={result.risk_level} /></div><div className="mt-5 h-2 overflow-hidden rounded-full bg-white/10"><div className={`h-full rounded-full ${barColor(result.risk_level)}`} style={{ width: `${Math.max(0, Math.min(100, Number(result.risk_score) || 0))}%` }} /></div><p className="mt-3 text-xs text-slate-600">Rule-based score, not a calibrated probability.</p></div>

                      {result.alerts?.length > 0 && (
                        <div className="rounded-xl border border-amber-400/20 bg-amber-400/[0.05] p-4">
                          <p className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-amber-300"><Bell size={14} />{result.alerts.length} alert{result.alerts.length === 1 ? "" : "s"} raised or updated</p>
                          <ul className="mt-3 space-y-2">{result.alerts.map((a) => <li key={a.id} className="flex flex-wrap items-center gap-2 text-sm text-slate-300"><SeverityBadge severity={a.severity} />{a.title}</li>)}</ul>
                          <button type="button" onClick={() => setPage("alerts")} className={`${secondary} mt-3 w-full`}>Open security alerts →</button>
                        </div>
                      )}

                      <div><div className="mb-3 flex items-center justify-between"><h4 className="text-sm font-semibold text-white">Detected signals</h4><span className="text-xs text-slate-600">{result.signals?.length || 0} observations</span></div><SignalList signals={result.signals} /></div>
                      {result.recommendation && <div className="rounded-xl border border-violet-400/20 bg-violet-500/[0.07] p-4"><p className="text-xs font-bold uppercase tracking-wider text-violet-300">Recommendation</p><p className="mt-2 text-sm leading-6 text-slate-300">{result.recommendation}</p></div>}
                      <p className="text-xs leading-5 text-slate-600">{result.disclaimer || "This heuristic assessment is not proof that a URL is safe or malicious."}</p><p className="text-xs text-slate-600">Scan record: #{result.scan_id ?? "saved"}</p>
                      <button type="button" onClick={() => investigate(url)} className={`${primary} w-full`}><Microscope size={16} /> Investigate further <ChevronRight size={15} /></button>
                      <button type="button" onClick={() => setPage("history")} className={`${secondary} w-full`}>View scan history →</button>
                    </div>}
                  </section>
                </div>
              </>
            )}

            {page === "history" && (
              <>
                <Heading eyebrow="Investigation records / 03" title="Scan History" description="Search, filter, and inspect persisted URL analysis records." action={<button type="button" onClick={loadHistory} disabled={historyLoading} className={secondary}><RefreshCw size={15} className={historyLoading ? "animate-spin" : ""} /> Refresh</button>} />
                {historyError && <div role="alert" className="mb-5 rounded-xl border border-rose-500/20 bg-rose-500/[0.05] p-4 text-sm text-rose-300">{historyError}</div>}
                <div className="mb-5 grid gap-4 sm:grid-cols-3"><StatCard title="Total records" value={history.length} subtitle="Loaded from backend" icon={Database} /><StatCard title="High risk" value={high} subtitle="High-risk classifications" icon={ShieldAlert} tone={high ? "red" : "green"} colored /><StatCard title="Latest record" value={history.length ? `#${history[0].id}` : "—"} subtitle={history.length ? formatDate(history[0].created_at) : "No records"} icon={Clock3} /></div>
                <section className={`${panel} overflow-hidden`}>
                  <div className="border-b border-white/[0.07] p-5 sm:p-6"><div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-lg font-semibold text-white">Searchable scan records</h3><p className="mt-1 text-xs text-slate-600">Select a record to inspect the saved analysis.</p></div><span className="rounded-md border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-slate-400">{filteredHistory.length} of {history.length}</span></div>
                    <div className="mt-5 grid gap-3 md:grid-cols-[minmax(0,1fr)_auto]"><div className="relative"><Search size={17} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-600" /><input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search hostname, URL, recommendation, ID..." aria-label="Search scan history" className={`${inputClass} pl-10`} /></div><div className="flex flex-wrap gap-2" role="group" aria-label="Filter by risk">{["All", "Low", "Medium", "High"].map((filter) => <button key={filter} type="button" onClick={() => setRiskFilter(filter)} aria-pressed={riskFilter === filter} className={`rounded-lg border px-3.5 py-2.5 text-xs font-medium ${riskFilter === filter ? "border-cyan-400/40 bg-cyan-400/10 text-cyan-300" : "border-white/10 bg-[#070b12] text-slate-500 hover:text-white"}`}>{filter}</button>)}</div></div>
                    {(query || riskFilter !== "All") && <div className="mt-3 flex justify-between text-xs text-slate-500"><span>{filteredHistory.length} matching records</span><button type="button" onClick={() => { setQuery(""); setRiskFilter("All"); }} className="text-cyan-300">Clear filters</button></div>}
                  </div>
                  {historyLoading && !history.length ? <div className="p-12 text-center text-sm text-slate-500"><LoaderCircle className="mr-2 inline animate-spin" size={18} />Loading history...</div> : !history.length ? <EmptyState icon={History} title="Your history is empty" description="Successful analyses will be stored by the backend." action={<button type="button" onClick={goAnalyze} className={primary}>Analyze a URL</button>} /> : !filteredHistory.length ? <EmptyState icon={Search} title="No matching scans" description="Try a different search or risk filter." action={<button type="button" onClick={() => { setQuery(""); setRiskFilter("All"); }} className={secondary}>Clear filters</button>} /> : <div className="overflow-x-auto"><table className="w-full min-w-[740px] text-left text-sm"><thead className="bg-white/[0.02] text-[11px] text-slate-600"><tr>{["Target", "Risk", "Score", "Signals", "Date", "Details"].map((h) => <th key={h} className="px-5 py-4 font-medium">{h}</th>)}</tr></thead><tbody className="divide-y divide-white/[0.05]">{filteredHistory.map((scan) => <tr key={scan.id} tabIndex={0} role="button" aria-label={`Open scan ${scan.id}`} onClick={() => setSelectedScan(scan)} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSelectedScan(scan); } }} className="cursor-pointer hover:bg-cyan-400/[0.04] focus:outline-none"><td className="max-w-xs px-5 py-4"><div className="flex items-center gap-3"><div className="rounded-lg border border-white/10 bg-white/[0.05] p-2 text-slate-400"><Globe size={16} /></div><div className="min-w-0"><p className="truncate font-medium text-slate-200">{scan.hostname || hostname(scan.normalized_url || scan.submitted_url)}</p><p className="mt-1 truncate text-xs text-slate-600">{scan.submitted_url || scan.normalized_url}</p></div></div></td><td className="px-5 py-4"><RiskBadge level={scan.risk_level} /></td><td className="px-5 py-4"><span className="font-semibold text-white">{scan.risk_score}</span></td><td className="px-5 py-4 text-slate-400">{scan.signal_count ?? scan.signals?.length ?? 0}</td><td className="whitespace-nowrap px-5 py-4 text-xs text-slate-500">{formatDate(scan.created_at)}</td><td className="px-5 py-4"><span className="inline-flex items-center gap-1 text-xs font-semibold text-cyan-300">Inspect <ChevronRight size={14} /></span></td></tr>)}</tbody></table></div>}
                  {history.length > 0 && <div className="border-t border-white/[0.07] px-5 py-3 text-xs text-slate-600 sm:px-6">Filters apply to records returned by the backend.</div>}
                </section>
              </>
            )}

            {page === "reports" && (
              <>
                <Heading eyebrow="Security operations / 05" title="Reports & export" description="Export your analysis evidence and scan history for review, documentation, or incident handoff." />
                <div className="grid gap-4 lg:grid-cols-2">
                  <section className={`${panel} p-5 sm:p-6`}>
                    <div className="flex items-start gap-3">
                      <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-3 text-cyan-300"><FileJson size={22} /></div>
                      <div><h3 className="font-semibold text-white">Full analysis report</h3><p className="mt-1 text-sm leading-6 text-slate-500">JSON includes the latest threat-intelligence response, heuristic result, latest saved scan, export timestamp, and safety disclaimer.</p></div>
                    </div>
                    <button type="button" onClick={exportJsonReport} className={`${primary} mt-5 w-full`}><Download size={16} /> Export JSON report</button>
                    <p className="mt-3 text-xs text-slate-600">{intelResult ? "Includes the latest threat-intelligence lookup." : result ? "Includes the latest URL analyzer result." : history.length ? "No live lookup yet; includes the latest saved scan." : "No scans recorded yet; exports a report shell."}</p>
                  </section>
                  <section className={`${panel} p-5 sm:p-6`}>
                    <div className="flex items-start gap-3">
                      <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/10 p-3 text-emerald-300"><FileSpreadsheet size={22} /></div>
                      <div><h3 className="font-semibold text-white">Scan history (CSV)</h3><p className="mt-1 text-sm leading-6 text-slate-500">Spreadsheet-friendly records with URL, risk classification, score, signal count, method, and timestamp.</p></div>
                    </div>
                    <button type="button" onClick={exportHistoryCsv} disabled={!history.length} className={`${primary} mt-5 w-full disabled:cursor-not-allowed disabled:opacity-40`}><Download size={16} /> Export {history.length} scan{history.length === 1 ? "" : "s"} to CSV</button>
                    {!history.length && <p className="mt-3 text-xs text-slate-600">Run a URL analysis to create scan history before exporting CSV.</p>}
                  </section>
                  <section className={`${panel} p-5 sm:p-6 lg:col-span-2`}>
                    <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                      <div className="flex items-start gap-3"><div className="rounded-xl border border-violet-400/20 bg-violet-400/10 p-3 text-violet-300"><Printer size={22} /></div><div><h3 className="font-semibold text-white">Print / Save as PDF</h3><p className="mt-1 text-sm leading-6 text-slate-500">Open the browser print dialog to print this report page or choose “Save as PDF”.</p></div></div>
                      <button type="button" onClick={() => window.print()} className={secondary}><Printer size={16} /> Print report page</button>
                    </div>
                    <div className="mt-5 grid gap-3 sm:grid-cols-3">
                      <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-4"><p className="text-xs text-slate-500">Recorded scans</p><p className="mt-2 text-2xl font-semibold text-white">{history.length}</p></div>
                      <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-4"><p className="text-xs text-slate-500">High-risk records</p><p className="mt-2 text-2xl font-semibold text-rose-300">{high}</p></div>
                      <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-4"><p className="text-xs text-slate-500">Latest scan</p><p className="mt-2 text-sm font-medium text-white">{history[0] ? formatDate(history[0].created_at) : "No scans yet"}</p></div>
                    </div>
                    <p className="mt-4 text-xs leading-5 text-slate-600">Security note: these reports summarize available analysis data. “No match” from a reputation provider is not proof that a URL is safe.</p>
                  </section>
                </div>
              </>
            )}

            {page === "intelligence" && (
              <>
                <Heading eyebrow="Threat investigation / 04" title="Threat Intelligence" description="Combine Sentinel X heuristic analysis with URL forensic metadata and the URLhaus lookup result." action={<button type="button" onClick={() => { setIntelResult(null); setIntelError(""); }} className={secondary}><RefreshCw size={15} /> Clear results</button>} />
                <div className="grid items-start gap-5 xl:grid-cols-[0.85fr_1.15fr]">
                  <section className={`${panel} p-5 sm:p-7`}>
                    <div className="mb-6 flex items-center gap-3"><div className="rounded-lg border border-cyan-400/20 bg-cyan-400/10 p-3 text-cyan-300"><Microscope size={22} /></div><div><h3 className="font-semibold text-white">Investigate a URL</h3><p className="mt-1 text-xs text-slate-500">Forensics and external reputation lookup</p></div></div>
                    <form onSubmit={analyzeIntelligence} className="space-y-4">
                      <label htmlFor="intel-url" className="block text-sm font-medium text-slate-300">Target URL</label>
                      <div className="relative"><Globe size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600" /><input id="intel-url" type="text" inputMode="url" autoComplete="url" maxLength={2048} value={intelUrl} onChange={(e) => setIntelUrl(e.target.value)} placeholder="https://example.com/login" className={`${inputClass} py-4 pl-11`} /></div>
                      <p className="text-xs leading-5 text-slate-600">This endpoint inspects the URL string. It should not require opening the target website.</p>
                      {intelError && <div role="alert" className="rounded-xl border border-rose-500/20 bg-rose-500/[0.05] p-3 text-sm text-rose-300"><XCircle size={16} className="mr-2 inline" />{intelError}</div>}
                      <button type="submit" disabled={intelLoading || !apiOnline} className={`${primary} w-full py-4`}>{intelLoading ? <><LoaderCircle size={17} className="animate-spin" /> Investigating...</> : <><Fingerprint size={17} /> Run intelligence lookup <ChevronRight size={16} /></>}</button>
                      {!apiOnline && <p className="text-center text-xs text-rose-400">Backend unavailable.</p>}
                      <button type="button" onClick={() => { setIntelUrl(url || "https://example.com/login"); setIntelError(""); }} className={`${secondary} w-full`}>Use current analyzer URL / example</button>
                    </form>
                    <div className="mt-6 rounded-xl border border-violet-400/20 bg-violet-500/[0.07] p-4"><p className="flex items-center gap-2 text-xs font-semibold text-violet-300"><LockKeyhole size={14} /> Safe investigation note</p><p className="mt-2 text-xs leading-5 text-slate-400">A URL's appearance alone cannot prove whether it is malicious. Treat scores and reputation lookups as triage evidence, not a definitive verdict.</p></div>
                  </section>

                  <div className="space-y-4">
                    {!intelResult ? <section className={panel}><EmptyState icon={Network} title="Awaiting intelligence lookup" description="Submit a URL to view its risk assessment, forensic URL structure, and URLhaus lookup status." /></section> : <>
                      <section className={`${panel} p-5 sm:p-6`}>
                        <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="text-[10px] font-bold uppercase tracking-[0.14em] text-cyan-400/70">Combined assessment</p><h3 className="mt-2 break-all text-lg font-semibold text-white">{intelResult.hostname || forensics.hostname || hostname(intelResult.normalized_url || intelResult.submitted_url || intelUrl)}</h3><p className="mt-1 break-all text-xs text-slate-500">{intelResult.normalized_url || intelResult.submitted_url || intelUrl}</p></div><RiskBadge level={intelResult.risk_level || intelResult.analysis?.risk_level} /></div>
                        <div className="mt-5 grid gap-3 sm:grid-cols-3"><div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4"><p className="text-xs text-slate-500">Risk score</p><p className="mt-2 text-3xl font-semibold text-white">{intelResult.risk_score ?? intelResult.analysis?.risk_score ?? "—"}<span className="text-sm text-slate-600">/100</span></p></div><div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4"><p className="text-xs text-slate-500">Signals</p><p className="mt-2 text-3xl font-semibold text-white">{intelSignals.length || intelResult.signal_count || 0}</p></div><div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4"><p className="text-xs text-slate-500">Analysis method</p><p className="mt-2 text-sm font-semibold text-cyan-300">{intelResult.analysis_method || intelResult.analysis?.analysis_method || "Heuristic"}</p></div></div>
                        {(intelResult.recommendation || intelResult.analysis?.recommendation) && <div className="mt-4 rounded-xl border border-violet-400/20 bg-violet-500/[0.07] p-4"><p className="text-xs font-bold uppercase tracking-wider text-violet-300">Recommendation</p><p className="mt-2 text-sm leading-6 text-slate-300">{intelResult.recommendation || intelResult.analysis?.recommendation}</p></div>}
                      </section>

                      <section className={`${panel} p-5 sm:p-6`}>
                        <div className="mb-4 flex items-center gap-2"><Network size={17} className="text-cyan-300" /><h3 className="text-sm font-semibold text-white">URL forensics</h3></div>
                        {Object.keys(forensics).length ? <div>
                          <DetailRow label="Scheme / protocol" value={forensics.scheme} />
                          <DetailRow label="Hostname" value={forensics.hostname} />
                          <DetailRow label="Port" value={forensics.port} />
                          <DetailRow label="Path" value={forensics.path} />
                          <DetailRow label="Query parameter count" value={forensics.query_parameter_count ?? forensics.query_params_count} />
                          <DetailRow label="Query parameter names" value={Array.isArray(forensics.query_parameter_names) ? forensics.query_parameter_names.join(", ") || "None" : forensics.query_parameter_names} />
                          <DetailRow label="Fragment present" value={forensics.fragment_present ?? forensics.fragment} />
                          <DetailRow label="URL length" value={forensics.url_length ?? forensics.length} />
                          <DetailRow label="Hostname label count" value={forensics.hostname_label_count ?? forensics.hostname_labels ?? forensics.host_labels} />
                          <DetailRow label="Subdomain count" value={forensics.subdomain_count} />
                          <DetailRow label="Contains user information" value={forensics.userinfo_present ?? forensics.has_userinfo} />
                          <DetailRow label="Hostname is an IP address" value={forensics.hostname_is_ip ?? forensics.is_ip_address} />
                          <DetailRow label="IP version" value={forensics.ip_version} />
                          <DetailRow label="Globally routable IP" value={forensics.ip_is_global ?? forensics.ip_global} />
                          <DetailRow label="Punycode detected" value={forensics.punycode_present ?? forensics.has_punycode} />
                          <DetailRow label="HTTPS enabled" value={forensics.https_used ?? forensics.uses_https ?? forensics.is_https} />
                        </div> : <p className="text-sm leading-6 text-amber-300">The API returned no `forensics` object. Check the backend response schema for this endpoint.</p>}
                      </section>

                      <section className={`${panel} p-5 sm:p-6`}>
                        <div className="mb-4 flex items-center gap-2"><ExternalLink size={17} className="text-cyan-300" /><h3 className="text-sm font-semibold text-white">URLhaus reputation lookup</h3></div>
                        <div className="flex flex-wrap items-center gap-2"><span className="text-xs text-slate-500">Lookup status</span><span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${/match|malicious|found/i.test(urlhausStatus) && !/no_match|not_found|no match/i.test(urlhausStatus) ? "border-rose-400/20 bg-rose-400/10 text-rose-300" : /no_match|not_found|no match/i.test(urlhausStatus) ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300" : "border-amber-400/20 bg-amber-400/10 text-amber-300"}`}>{urlhausStatus}</span></div>
                        {urlhaus && typeof urlhaus === "object" ? <div className="mt-4">
                          <DetailRow label="Threat / query status" value={urlhaus.query_status || urlhaus.status} />
                          <DetailRow label="URLhaus ID" value={urlhaus.id || urlhaus.url_id} />
                          <DetailRow label="Threat type" value={urlhaus.threat || urlhaus.threat_type} />
                          <DetailRow label="Tags" value={Array.isArray(urlhaus.tags) ? urlhaus.tags.join(", ") : urlhaus.tags} />
                          <DetailRow label="Date added" value={urlhaus.date_added} />
                          <DetailRow label="Reference" value={urlhaus.url || urlhaus.reference} />
                          {urlhaus.message && <p className="mt-3 text-xs leading-5 text-slate-500">{urlhaus.message}</p>}
                          <details className="mt-4"><summary className="cursor-pointer text-xs text-cyan-300">View raw lookup response</summary><pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-[#070b12] p-3 text-xs text-slate-400">{JSON.stringify(urlhaus, null, 2)}</pre></details>
                        </div> : <p className="mt-3 text-sm leading-6 text-slate-500">No separate URLhaus object was found in the response. Inspect the raw API result below to confirm the backend's field names and lookup status.</p>}
                        <p className="mt-4 text-xs leading-5 text-slate-600">“No match” means the provider did not return a known listing; it does not guarantee safety. An unavailable or unconfigured lookup is not a clean result.</p>
                      </section>

                      <section className={`${panel} p-5 sm:p-6`}>
                        <div className="mb-4 flex items-center gap-2"><FileSearch size={17} className="text-cyan-300" /><h3 className="text-sm font-semibold text-white">Heuristic evidence</h3></div>
                        <SignalList signals={intelSignals} />
                        <details className="mt-5"><summary className="cursor-pointer text-xs text-cyan-300">View complete API response</summary><pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-[#070b12] p-3 text-xs text-slate-400">{JSON.stringify(intelResult, null, 2)}</pre></details>
                      </section>
                    </>}
                  </div>
                </div>
              </>
            )}

            <footer className="mt-10 border-t border-white/[0.07] pt-5"><div className="flex flex-col justify-between gap-3 text-xs text-slate-600 sm:flex-row"><p>Sentinel X · Academic security analysis project</p><p className="flex items-center gap-2"><LockKeyhole size={13} /> Heuristic triage only · Not a security verdict</p></div></footer>
          </div>
        </main>
      </div>

      {selectedScan && <ScanModal scan={selectedScan} onClose={() => setSelectedScan(null)} />}
      {selectedAlert && <AlertModal key={selectedAlert.id} alert={selectedAlert} onClose={() => setSelectedAlert(null)} onStatus={updateAlertStatus} onInvestigate={investigate} onRescan={rescan} />}
      {selectedInvestigation && <InvestigationModal key={selectedInvestigation.normalized_url} item={selectedInvestigation} onClose={() => setSelectedInvestigation(null)} onUpdate={updateInvestigation} onInvestigate={investigate} onRescan={rescan} />}
    </div>
  );
}

export default App;