"use client";

import { useMemo } from "react";
import { useWebSocket } from "@/lib/useWebSocket";
import { Brain, Shield, Crosshair, TrendingUp } from "lucide-react";
import { BarChart, Bar, ResponsiveContainer, XAxis, YAxis, Tooltip, CartesianGrid } from "recharts";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";

interface Alert {
  severity: string; attack_type: string; src_ip: string;
  confidence_score: number; rule_triggered: string;
}

export default function IntelligencePage() {
  const { data: alerts } = useWebSocket<Alert>({ url: `${WS_URL}/ws/alerts`, maxBuffer: 300 });

  const attackPatterns = useMemo(() => {
    const c: Record<string, { count: number; avgConf: number; totalConf: number }> = {};
    alerts.forEach((a) => {
      if (!c[a.attack_type]) c[a.attack_type] = { count: 0, avgConf: 0, totalConf: 0 };
      c[a.attack_type].count++;
      c[a.attack_type].totalConf += a.confidence_score;
      c[a.attack_type].avgConf = c[a.attack_type].totalConf / c[a.attack_type].count;
    });
    return Object.entries(c).map(([type, d]) => ({
      type, count: d.count, avgConf: Math.round(d.avgConf * 100),
    })).sort((a, b) => b.count - a.count);
  }, [alerts]);

  const ruleHits = useMemo(() => {
    const c: Record<string, number> = {};
    alerts.forEach((a) => { c[a.rule_triggered] = (c[a.rule_triggered] || 0) + 1; });
    return Object.entries(c).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  }, [alerts]);

  const suspiciousIPs = useMemo(() => {
    const c: Record<string, { count: number; types: Set<string>; maxSev: string }> = {};
    const sevOrder: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    alerts.forEach((a) => {
      if (!c[a.src_ip]) c[a.src_ip] = { count: 0, types: new Set(), maxSev: "Low" };
      c[a.src_ip].count++;
      c[a.src_ip].types.add(a.attack_type);
      if ((sevOrder[a.severity] ?? 4) < (sevOrder[c[a.src_ip].maxSev] ?? 4)) {
        c[a.src_ip].maxSev = a.severity;
      }
    });
    return Object.entries(c)
      .map(([ip, d]) => ({ ip, count: d.count, types: Array.from(d.types), maxSev: d.maxSev }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [alerts]);

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-[var(--text-primary)] flex items-center gap-2">
        <Brain className="w-5 h-5 text-purple-400" />
        Threat Intelligence
      </h1>

      <div className="grid grid-cols-3 gap-4">
        {/* Attack Patterns */}
        <div className="col-span-2 glass-panel p-5">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-amber-400" /> Attack Pattern Analysis
          </h3>
          <div className="space-y-3">
            {attackPatterns.map((p) => (
              <div key={p.type} className="flex items-center gap-4">
                <span className="w-36 text-xs text-[var(--text-primary)] font-medium truncate">{p.type}</span>
                <div className="flex-1 h-6 bg-white/5 rounded-lg overflow-hidden relative">
                  <div
                    className="h-full rounded-lg bg-gradient-to-r from-purple-500/40 to-cyan-500/40"
                    style={{ width: `${Math.min(100, (p.count / (attackPatterns[0]?.count || 1)) * 100)}%` }}
                  />
                  <span className="absolute inset-y-0 right-2 flex items-center text-[10px] mono text-[var(--text-muted)]">
                    {p.count} hits • {p.avgConf}% conf
                  </span>
                </div>
              </div>
            ))}
            {attackPatterns.length === 0 && (
              <p className="text-sm text-[var(--text-muted)] text-center py-8">Collecting intelligence...</p>
            )}
          </div>
        </div>

        {/* Rule Effectiveness */}
        <div className="glass-panel p-5">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-green-400" /> Rule Triggers
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={ruleHits} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,245,255,0.07)" />
              <XAxis type="number" tick={{ fontSize: 10, fill: "#6b7b8d" }} />
              <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: "#6b7b8d" }} width={80} />
              <Tooltip contentStyle={{ background: "#0d1b2a", border: "1px solid rgba(0,245,255,0.2)", borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="value" fill="#39ff14" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Suspicious IPs */}
      <div className="glass-panel p-5">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-red-400" /> Suspicious IP Addresses
        </h3>
        <div className="overflow-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-[var(--text-muted)] uppercase tracking-wider border-b border-[var(--border-glow)]">
                <th className="px-4 py-2 text-left">IP Address</th>
                <th className="px-4 py-2 text-left">Alerts</th>
                <th className="px-4 py-2 text-left">Max Severity</th>
                <th className="px-4 py-2 text-left">Attack Types</th>
                <th className="px-4 py-2 text-left">Risk Level</th>
              </tr>
            </thead>
            <tbody>
              {suspiciousIPs.map((ip) => (
                <tr key={ip.ip} className="border-b border-white/5 hover:bg-white/[0.02]">
                  <td className="px-4 py-2.5 mono text-cyan-400">{ip.ip}</td>
                  <td className="px-4 py-2.5 mono font-bold text-[var(--text-primary)]">{ip.count}</td>
                  <td className="px-4 py-2.5">
                    <span className={`badge severity-${ip.maxSev.toLowerCase()}`}>{ip.maxSev}</span>
                  </td>
                  <td className="px-4 py-2.5 text-[var(--text-muted)]">{ip.types.join(", ")}</td>
                  <td className="px-4 py-2.5">
                    <div className="w-20 h-2 rounded-full bg-white/10">
                      <div className="h-full rounded-full bg-gradient-to-r from-amber-500 to-red-500"
                        style={{ width: `${Math.min(100, (ip.count / (suspiciousIPs[0]?.count || 1)) * 100)}%` }} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {suspiciousIPs.length === 0 && (
            <div className="text-center py-8 text-[var(--text-muted)]">No suspicious IPs detected yet</div>
          )}
        </div>
      </div>
    </div>
  );
}
