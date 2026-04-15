"use client";

import { useEffect, useState } from "react";
import { FileText, Filter, Download } from "lucide-react";

const API = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";

interface LogEntry {
  id: string;
  created_at: string;
  level: string;
  message: string;
  source: string;
  metadata: Record<string, unknown>;
}

function LevelBadge({ level }: { level: string }) {
  const styles: Record<string, string> = {
    error: "bg-red-500/10 text-red-400 border-red-500/20",
    warning: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    info: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
    debug: "bg-white/5 text-[var(--text-muted)] border-white/10",
  };
  return <span className={`badge border ${styles[level] || styles.info}`}>{level}</span>;
}

export default function LogsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterLevel, setFilterLevel] = useState("all");

  useEffect(() => {
    const params = filterLevel !== "all" ? `?level=${filterLevel}` : "";
    fetch(`${API}/api/logs${params}`)
      .then((r) => r.json())
      .then((d) => { setLogs(d.data || []); setLoading(false); })
      .catch(() => { setLogs([]); setLoading(false); });
  }, [filterLevel]);

  function exportCSV() {
    const csv = [
      "Time,Level,Source,Message",
      ...logs.map((l) => `"${l.created_at}","${l.level}","${l.source}","${l.message}"`),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "system_logs.csv"; a.click();
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-[var(--text-primary)] flex items-center gap-2">
          <FileText className="w-5 h-5 text-cyan-400" />
          System Logs
        </h1>
        <button onClick={exportCSV} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-medium hover:bg-cyan-500/20 transition-all">
          <Download className="w-3.5 h-3.5" /> Export CSV
        </button>
      </div>

      <div className="flex items-center gap-3">
        <Filter className="w-4 h-4 text-[var(--text-muted)]" />
        {["all", "error", "warning", "info", "debug"].map((l) => (
          <button key={l} onClick={() => setFilterLevel(l)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${filterLevel === l ? "bg-cyan-500/10 border border-cyan-500/20 text-cyan-400" : "text-[var(--text-muted)] hover:bg-white/5"}`}>
            {l.toUpperCase()}
          </button>
        ))}
      </div>

      <div className="glass-panel overflow-hidden">
        <div className="overflow-auto max-h-[70vh]">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-[var(--bg-secondary)]">
              <tr className="text-[var(--text-muted)] uppercase tracking-wider border-b border-[var(--border-glow)]">
                <th className="px-4 py-3 text-left">Time</th>
                <th className="px-4 py-3 text-left">Level</th>
                <th className="px-4 py-3 text-left">Source</th>
                <th className="px-4 py-3 text-left">Message</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id} className="border-b border-white/5 hover:bg-white/[0.02]">
                  <td className="px-4 py-2.5 mono text-[var(--text-muted)] whitespace-nowrap">
                    {new Date(log.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2.5"><LevelBadge level={log.level} /></td>
                  <td className="px-4 py-2.5 text-[var(--text-primary)]">{log.source || "system"}</td>
                  <td className="px-4 py-2.5 text-[var(--text-muted)] max-w-md truncate">{log.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {loading && <div className="text-center py-12 text-[var(--text-muted)]">Loading...</div>}
          {!loading && logs.length === 0 && (
            <div className="text-center py-12 text-[var(--text-muted)]">No logs to display</div>
          )}
        </div>
      </div>
    </div>
  );
}
