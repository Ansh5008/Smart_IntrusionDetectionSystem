"use client";

import { useMemo } from "react";
import { useWebSocket } from "@/lib/useWebSocket";
import {
  AreaChart, Area, PieChart, Pie, Cell, ResponsiveContainer,
  XAxis, YAxis, Tooltip, CartesianGrid
} from "recharts";
import {
  ShieldAlert, Activity, Zap, Globe, AlertTriangle, Wifi,
  ArrowUpRight, ArrowDownRight
} from "lucide-react";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";

interface Packet {
  id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  size_bytes: number;
  is_flagged: boolean;
  timestamp: string;
  geo_country: string;
  flags: string[];
}

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
  timestamp: string;
}

const COLORS = {
  cyan: "#00f5ff",
  red: "#ff073a",
  green: "#39ff14",
  amber: "#ffb700",
  purple: "#a855f7",
  orange: "#ff6b35",
};

const PIE_COLORS = [COLORS.red, COLORS.amber, COLORS.purple, COLORS.orange, COLORS.cyan];

function SeverityBadge({ severity }: { severity: string }) {
  const cls: Record<string, string> = {
    Critical: "severity-critical",
    High: "severity-high",
    Medium: "severity-medium",
    Low: "severity-low",
  };
  return <span className={`badge ${cls[severity] || cls.Low}`}>{severity}</span>;
}

function KPICard({
  label, value, delta, deltaUp, icon: Icon, color,
}: {
  label: string;
  value: string | number;
  delta: string;
  deltaUp: boolean;
  icon: React.ElementType;
  color: string;
}) {
  return (
    <div className="glass-panel p-5 animate-fade-in">
      <div className="flex items-start justify-between mb-3">
        <div className="p-2 rounded-lg" style={{ background: `${color}15`, border: `1px solid ${color}30` }}>
          <Icon className="w-5 h-5" style={{ color }} />
        </div>
        <div className={`flex items-center gap-1 text-xs font-semibold ${deltaUp ? "text-red-400" : "text-green-400"}`}>
          {deltaUp ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
          {delta}
        </div>
      </div>
      <p className="text-2xl font-bold mono" style={{ color }}>{value}</p>
      <p className="text-xs text-[var(--text-muted)] mt-1 uppercase tracking-wider">{label}</p>
    </div>
  );
}

export default function DashboardPage() {
  const { data: packets, connected: trafficUp } = useWebSocket<Packet>({
    url: `${WS_URL}/ws/traffic`,
    maxBuffer: 500,
  });
  const { data: alerts } = useWebSocket<Alert>({
    url: `${WS_URL}/ws/alerts`,
    maxBuffer: 200,
  });

  // KPI calculations
  const totalPackets = packets.length;
  const flaggedPackets = packets.filter((p) => p.is_flagged).length;
  const totalAlerts = alerts.length;
  const criticalAlerts = alerts.filter((a) => a.severity === "Critical").length;

  // Time-series chart data (last 30 data points)
  const chartData = useMemo(() => {
    const buckets: { time: string; total: number; flagged: number }[] = [];
    const chunkSize = Math.max(1, Math.floor(packets.length / 30));
    for (let i = 0; i < 30; i++) {
      const slice = packets.slice(i * chunkSize, (i + 1) * chunkSize);
      buckets.push({
        time: `${30 - i}s`,
        total: slice.length,
        flagged: slice.filter((p) => p.is_flagged).length,
      });
    }
    return buckets.reverse();
  }, [packets]);

  // Attack type pie data
  const pieData = useMemo(() => {
    const counts: Record<string, number> = {};
    alerts.forEach((a) => {
      counts[a.attack_type] = (counts[a.attack_type] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 5);
  }, [alerts]);

  // Top source IPs
  const topIPs = useMemo(() => {
    const counts: Record<string, number> = {};
    alerts.forEach((a) => {
      counts[a.src_ip] = (counts[a.src_ip] || 0) + 1;
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [alerts]);

  // Top severity for banner
  const threatLevel = criticalAlerts > 2 ? "CRITICAL" : totalAlerts > 10 ? "HIGH" : totalAlerts > 3 ? "MODERATE" : "LOW";
  const tlColor: Record<string, string> = { CRITICAL: COLORS.red, HIGH: COLORS.orange, MODERATE: COLORS.amber, LOW: COLORS.green };

  return (
    <div className="space-y-6">
      {/* Threat Level Banner */}
      <div
        className="glass-panel-sm px-5 py-3 flex items-center gap-4"
        style={{ borderLeftColor: tlColor[threatLevel], borderLeftWidth: 3 }}
      >
        <span className="text-lg font-bold" style={{ color: tlColor[threatLevel] }}>
          ⚠ THREAT LEVEL: {threatLevel}
        </span>
        <span className="text-sm text-[var(--text-muted)]">
          Network monitoring active • {trafficUp ? "connected" : "reconnecting..."} • {totalPackets.toLocaleString()} packets analyzed
        </span>
        <div className="ml-auto flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${trafficUp ? "bg-green-400 animate-pulse" : "bg-red-400"}`} />
          <span className={`text-xs font-medium ${trafficUp ? "text-green-400" : "text-red-400"}`}>
            {trafficUp ? "LIVE" : "OFFLINE"}
          </span>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        <KPICard label="Total Alerts" value={totalAlerts} delta={`+${Math.min(totalAlerts, 99)}`} deltaUp={true} icon={ShieldAlert} color={COLORS.red} />
        <KPICard label="Packets Analyzed" value={totalPackets.toLocaleString()} delta={`${Math.round(totalPackets / Math.max(1, Math.floor(Date.now() / 1000) % 60))}/s`} deltaUp={false} icon={Activity} color={COLORS.cyan} />
        <KPICard label="Critical Events" value={criticalAlerts} delta={criticalAlerts > 0 ? "active" : "none"} deltaUp={criticalAlerts > 0} icon={Zap} color={COLORS.amber} />
        <KPICard label="Flagged Traffic" value={`${totalPackets > 0 ? Math.round((flaggedPackets / totalPackets) * 100) : 0}%`} delta={`${flaggedPackets} pkts`} deltaUp={flaggedPackets > 10} icon={AlertTriangle} color={COLORS.purple} />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-3 gap-4">
        {/* Traffic Timeline */}
        <div className="col-span-2 glass-panel p-5">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            Network Activity Timeline
          </h3>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={COLORS.cyan} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={COLORS.cyan} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gFlagged" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={COLORS.red} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={COLORS.red} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,245,255,0.07)" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#6b7b8d" }} />
              <YAxis tick={{ fontSize: 10, fill: "#6b7b8d" }} />
              <Tooltip
                contentStyle={{ background: "#0d1b2a", border: "1px solid rgba(0,245,255,0.2)", borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: "#6b7b8d" }}
              />
              <Area type="monotone" dataKey="total" stroke={COLORS.cyan} fill="url(#gTotal)" strokeWidth={2} name="Total" />
              <Area type="monotone" dataKey="flagged" stroke={COLORS.red} fill="url(#gFlagged)" strokeWidth={2} name="Flagged" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Attack Distribution Pie */}
        <div className="glass-panel p-5">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
            <Globe className="w-4 h-4 text-purple-400" />
            Attack Distribution
          </h3>
          {pieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" stroke="none">
                    {pieData.map((_, i) => (
                      <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#0d1b2a", border: "1px solid rgba(0,245,255,0.2)", borderRadius: 8, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1.5 mt-2">
                {pieData.map((d, i) => (
                  <div key={d.name} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <div className="w-2.5 h-2.5 rounded-full" style={{ background: PIE_COLORS[i % PIE_COLORS.length] }} />
                      <span className="text-[var(--text-muted)]">{d.name}</span>
                    </div>
                    <span className="mono font-semibold text-[var(--text-primary)]">{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-48 text-[var(--text-muted)] text-sm">
              Waiting for data...
            </div>
          )}
        </div>
      </div>

      {/* Bottom Row: Alerts Table + Activity Feed */}
      <div className="grid grid-cols-3 gap-4">
        {/* Recent Alerts Table */}
        <div className="col-span-2 glass-panel p-5">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            Recent Alerts
            <span className="ml-auto text-xs text-[var(--text-muted)]">{alerts.length} total</span>
          </h3>
          <div className="overflow-auto max-h-[320px]">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-[var(--text-muted)] uppercase tracking-wider border-b border-[var(--border-glow)]">
                  <th className="pb-2 text-left font-medium">Severity</th>
                  <th className="pb-2 text-left font-medium">Attack Type</th>
                  <th className="pb-2 text-left font-medium">Source IP</th>
                  <th className="pb-2 text-left font-medium">Port</th>
                  <th className="pb-2 text-left font-medium">Confidence</th>
                  <th className="pb-2 text-left font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {alerts.slice(0, 20).map((alert, i) => (
                  <tr key={i} className="border-b border-white/5 hover:bg-white/[0.02] transition-colors">
                    <td className="py-2"><SeverityBadge severity={alert.severity} /></td>
                    <td className="py-2 text-[var(--text-primary)]">{alert.attack_type}</td>
                    <td className="py-2 mono text-cyan-400/80">{alert.src_ip}</td>
                    <td className="py-2 mono text-[var(--text-muted)]">{alert.port}</td>
                    <td className="py-2">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-white/10">
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${Math.round(alert.confidence_score * 100)}%`,
                              background: alert.confidence_score > 0.8 ? COLORS.red : alert.confidence_score > 0.6 ? COLORS.amber : COLORS.green,
                            }}
                          />
                        </div>
                        <span className="text-[var(--text-muted)]">{Math.round(alert.confidence_score * 100)}%</span>
                      </div>
                    </td>
                    <td className="py-2 text-[var(--text-muted)]">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {alerts.length === 0 && (
              <div className="text-center py-12 text-[var(--text-muted)] text-sm">Monitoring for threats...</div>
            )}
          </div>
        </div>

        {/* Live Activity Feed + Top IPs */}
        <div className="space-y-4">
          {/* Top Source IPs */}
          <div className="glass-panel p-5">
            <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-2">
              <Wifi className="w-4 h-4 text-amber-400" />
              Top Threat Sources
            </h3>
            <div className="space-y-2">
              {topIPs.length > 0 ? topIPs.map(([ip, count], i) => (
                <div key={ip} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-[var(--text-muted)] w-4">{i + 1}.</span>
                    <span className="mono text-xs text-cyan-400/80">{ip}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-20 h-1.5 rounded-full bg-white/10">
                      <div className="h-full rounded-full bg-red-500/60" style={{ width: `${Math.min(100, (count / (topIPs[0]?.[1] || 1)) * 100)}%` }} />
                    </div>
                    <span className="mono text-xs text-[var(--text-muted)] w-6 text-right">{count}</span>
                  </div>
                </div>
              )) : (
                <p className="text-xs text-[var(--text-muted)]">No threats detected yet</p>
              )}
            </div>
          </div>

          {/* Live Packet Feed */}
          <div className="glass-panel p-5">
            <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-2">
              <Activity className="w-4 h-4 text-green-400" />
              Live Feed
              <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse ml-1" />
            </h3>
            <div className="space-y-1 max-h-[200px] overflow-y-auto">
              {packets.slice(0, 15).map((pkt, i) => (
                <div
                  key={i}
                  className={`text-[10px] mono px-2 py-1 rounded flex items-center gap-2 ${
                    pkt.is_flagged ? "bg-red-500/5 border border-red-500/10" : "bg-white/[0.02]"
                  }`}
                >
                  <span className={pkt.is_flagged ? "text-red-400" : "text-green-400"}>
                    {pkt.is_flagged ? "⚠" : "•"}
                  </span>
                  <span className="text-cyan-400/70">{pkt.src_ip}</span>
                  <span className="text-[var(--text-muted)]">→</span>
                  <span className="text-[var(--text-muted)]">{pkt.dst_ip}:{pkt.dst_port}</span>
                  <span className="ml-auto text-[var(--text-muted)]">{pkt.protocol}</span>
                </div>
              ))}
              {packets.length === 0 && (
                <p className="text-xs text-[var(--text-muted)] text-center py-4">Connecting...</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
