"use client";

import { useEffect, useState } from "react";
import { useWebSocket } from "@/lib/useWebSocket";
import { AlertTriangle, Filter, CheckCircle, XCircle } from "lucide-react";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";
const API = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";

interface Alert {
  id: string;
  severity: string;
  attack_type: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  port: number;
  confidence_score: number;
  rule_triggered: string;
  status: string;
  timestamp: string;
  created_at?: string;
}

const SEV_ORDER: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };

function SeverityBadge({ severity }: { severity: string }) {
  const cls: Record<string, string> = {
    Critical: "severity-critical", High: "severity-high",
    Medium: "severity-medium", Low: "severity-low",
  };
  return <span className={`badge ${cls[severity] || cls.Low}`}>{severity}</span>;
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    open: "bg-red-500/10 text-red-400 border-red-500/20",
    acknowledged: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    resolved: "bg-green-500/10 text-green-400 border-green-500/20",
  };
  return (
    <span className={`badge border ${styles[status] || styles.open}`}>
      {status}
    </span>
  );
}

export default function AlertsPage() {
  const { data: liveAlerts } = useWebSocket<Alert>({ url: `${WS_URL}/ws/alerts`, maxBuffer: 300 });
  const [dbAlerts, setDbAlerts] = useState<Alert[]>([]);
  const [filterSev, setFilterSev] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/alerts?limit=100`)
      .then((r) => r.json())
      .then((d) => { setDbAlerts(d.data || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  // Merge live + db alerts, deduplicate by ID
  const allAlerts = [...liveAlerts, ...dbAlerts];
  const seen = new Set<string>();
  const unique = allAlerts.filter((a) => {
    if (seen.has(a.id)) return false;
    seen.add(a.id);
    return true;
  });

  const filtered = unique
    .filter((a) => filterSev === "all" || a.severity === filterSev)
    .filter((a) => filterStatus === "all" || a.status === filterStatus)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4));

  // Summary stats
  const stats = {
    total: unique.length,
    critical: unique.filter((a) => a.severity === "Critical").length,
    high: unique.filter((a) => a.severity === "High").length,
    open: unique.filter((a) => a.status === "open" || !a.status).length,
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-[var(--text-primary)] flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-red-400" />
          Alert Management
        </h1>
      </div>

      {/* Stats Strip */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: "Total Alerts", value: stats.total, color: "#00f5ff" },
          { label: "Critical", value: stats.critical, color: "#ff073a" },
          { label: "High", value: stats.high, color: "#ff6b35" },
          { label: "Open", value: stats.open, color: "#ffb700" },
        ].map((s) => (
          <div key={s.label} className="glass-panel-sm px-4 py-3 flex items-center justify-between">
            <span className="text-xs text-[var(--text-muted)] uppercase">{s.label}</span>
            <span className="text-lg font-bold mono" style={{ color: s.color }}>{s.value}</span>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Filter className="w-4 h-4 text-[var(--text-muted)]" />
        <select value={filterSev} onChange={(e) => setFilterSev(e.target.value)}
          className="px-3 py-1.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-xs text-[var(--text-primary)]">
          <option value="all">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}
          className="px-3 py-1.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-xs text-[var(--text-primary)]">
          <option value="all">All Statuses</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
        </select>
        <span className="text-xs text-[var(--text-muted)] ml-auto">{filtered.length} results</span>
      </div>

      {/* Alerts Table */}
      <div className="glass-panel overflow-hidden">
        <div className="overflow-auto max-h-[60vh]">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-[var(--bg-secondary)]">
              <tr className="text-[var(--text-muted)] uppercase tracking-wider border-b border-[var(--border-glow)]">
                <th className="px-4 py-3 text-left font-medium">Severity</th>
                <th className="px-4 py-3 text-left font-medium">Attack Type</th>
                <th className="px-4 py-3 text-left font-medium">Source</th>
                <th className="px-4 py-3 text-left font-medium">Destination</th>
                <th className="px-4 py-3 text-left font-medium">Protocol</th>
                <th className="px-4 py-3 text-left font-medium">Port</th>
                <th className="px-4 py-3 text-left font-medium">Confidence</th>
                <th className="px-4 py-3 text-left font-medium">Status</th>
                <th className="px-4 py-3 text-left font-medium">Time</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((a, i) => (
                <tr key={i} className={`border-b border-white/5 hover:bg-white/[0.02] transition-colors ${a.severity === "Critical" ? "bg-red-500/[0.03]" : ""}`}>
                  <td className="px-4 py-2.5"><SeverityBadge severity={a.severity} /></td>
                  <td className="px-4 py-2.5 text-[var(--text-primary)] font-medium">{a.attack_type}</td>
                  <td className="px-4 py-2.5 mono text-cyan-400/80">{a.src_ip}</td>
                  <td className="px-4 py-2.5 mono text-[var(--text-muted)]">{a.dst_ip}</td>
                  <td className="px-4 py-2.5 text-[var(--text-muted)]">{a.protocol}</td>
                  <td className="px-4 py-2.5 mono text-[var(--text-muted)]">{a.port}</td>
                  <td className="px-4 py-2.5 mono">{Math.round(a.confidence_score * 100)}%</td>
                  <td className="px-4 py-2.5"><StatusBadge status={a.status || "open"} /></td>
                  <td className="px-4 py-2.5 text-[var(--text-muted)]">
                    {new Date(a.timestamp || a.created_at || "").toLocaleTimeString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {loading && <div className="text-center py-12 text-[var(--text-muted)]">Loading...</div>}
          {!loading && filtered.length === 0 && (
            <div className="text-center py-12 text-[var(--text-muted)]">No alerts match filters</div>
          )}
        </div>
      </div>
    </div>
  );
}
