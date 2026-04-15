"use client";

import { useMemo } from "react";
import { useWebSocket } from "@/lib/useWebSocket";
import {
  AreaChart, Area, BarChart, Bar, ResponsiveContainer,
  XAxis, YAxis, Tooltip, CartesianGrid
} from "recharts";
import { Activity, Wifi, Globe, ArrowUpDown } from "lucide-react";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";

interface Packet {
  src_ip: string; dst_ip: string; src_port: number; dst_port: number;
  protocol: string; size_bytes: number; is_flagged: boolean;
  geo_country: string; timestamp: string; flags: string[];
}

export default function TrafficPage() {
  const { data: packets, connected } = useWebSocket<Packet>({
    url: `${WS_URL}/ws/traffic`, maxBuffer: 500,
  });

  const protocolCounts = useMemo(() => {
    const c: Record<string, number> = {};
    packets.forEach((p) => { c[p.protocol] = (c[p.protocol] || 0) + 1; });
    return Object.entries(c).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  }, [packets]);

  const geoCounts = useMemo(() => {
    const c: Record<string, number> = {};
    packets.forEach((p) => { c[p.geo_country] = (c[p.geo_country] || 0) + 1; });
    return Object.entries(c).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value).slice(0, 10);
  }, [packets]);

  const topPorts = useMemo(() => {
    const c: Record<number, number> = {};
    packets.forEach((p) => { c[p.dst_port] = (c[p.dst_port] || 0) + 1; });
    return Object.entries(c).map(([port, count]) => ({ port, count: count as number }))
      .sort((a, b) => b.count - a.count).slice(0, 8);
  }, [packets]);

  const bandwidth = useMemo(() => {
    const total = packets.reduce((s, p) => s + p.size_bytes, 0);
    return (total / 1024).toFixed(1);
  }, [packets]);

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-[var(--text-primary)] flex items-center gap-2">
        <Activity className="w-5 h-5 text-cyan-400" />
        Live Traffic Monitor
        <div className={`w-2 h-2 rounded-full ml-2 ${connected ? "bg-green-400 animate-pulse" : "bg-red-400"}`} />
      </h1>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: "Packets Captured", value: packets.length.toLocaleString(), color: "#00f5ff" },
          { label: "Bandwidth", value: `${bandwidth} KB`, color: "#a855f7" },
          { label: "Flagged", value: packets.filter((p) => p.is_flagged).length, color: "#ff073a" },
          { label: "Unique Sources", value: new Set(packets.map((p) => p.src_ip)).size, color: "#ffb700" },
        ].map((s) => (
          <div key={s.label} className="glass-panel-sm px-4 py-3 flex items-center justify-between">
            <span className="text-xs text-[var(--text-muted)] uppercase">{s.label}</span>
            <span className="text-lg font-bold mono" style={{ color: s.color }}>{s.value}</span>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Protocol Distribution */}
        <div className="glass-panel p-5">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
            <ArrowUpDown className="w-4 h-4 text-purple-400" /> Protocol Distribution
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={protocolCounts}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,245,255,0.07)" />
              <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#6b7b8d" }} />
              <YAxis tick={{ fontSize: 10, fill: "#6b7b8d" }} />
              <Tooltip contentStyle={{ background: "#0d1b2a", border: "1px solid rgba(0,245,255,0.2)", borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="value" fill="#a855f7" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top Destination Ports */}
        <div className="glass-panel p-5">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
            <Wifi className="w-4 h-4 text-cyan-400" /> Top Destination Ports
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={topPorts} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,245,255,0.07)" />
              <XAxis type="number" tick={{ fontSize: 10, fill: "#6b7b8d" }} />
              <YAxis dataKey="port" type="category" tick={{ fontSize: 11, fill: "#6b7b8d" }} width={50} />
              <Tooltip contentStyle={{ background: "#0d1b2a", border: "1px solid rgba(0,245,255,0.2)", borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="count" fill="#00f5ff" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Geo Distribution */}
      <div className="glass-panel p-5">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
          <Globe className="w-4 h-4 text-amber-400" /> Geographic Distribution
        </h3>
        <div className="grid grid-cols-5 gap-3">
          {geoCounts.map((g) => (
            <div key={g.name} className="glass-panel-sm px-3 py-2 text-center">
              <p className="text-lg font-bold mono text-[var(--text-primary)]">{g.name}</p>
              <p className="text-xs text-[var(--text-muted)]">{g.value} packets</p>
            </div>
          ))}
        </div>
      </div>

      {/* Live Packet Table */}
      <div className="glass-panel p-5">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4">Recent Packets</h3>
        <div className="overflow-auto max-h-[300px]">
          <table className="w-full text-[11px]">
            <thead className="sticky top-0 bg-[var(--bg-secondary)]">
              <tr className="text-[var(--text-muted)] uppercase tracking-wider border-b border-[var(--border-glow)]">
                <th className="px-3 py-2 text-left">Source</th>
                <th className="px-3 py-2 text-left">Destination</th>
                <th className="px-3 py-2 text-left">Protocol</th>
                <th className="px-3 py-2 text-left">Size</th>
                <th className="px-3 py-2 text-left">Country</th>
                <th className="px-3 py-2 text-left">Flagged</th>
              </tr>
            </thead>
            <tbody>
              {packets.slice(0, 30).map((p, i) => (
                <tr key={i} className={`border-b border-white/5 ${p.is_flagged ? "bg-red-500/[0.03]" : ""}`}>
                  <td className="px-3 py-1.5 mono text-cyan-400/80">{p.src_ip}:{p.src_port}</td>
                  <td className="px-3 py-1.5 mono text-[var(--text-muted)]">{p.dst_ip}:{p.dst_port}</td>
                  <td className="px-3 py-1.5 text-[var(--text-primary)]">{p.protocol}</td>
                  <td className="px-3 py-1.5 mono text-[var(--text-muted)]">{p.size_bytes}B</td>
                  <td className="px-3 py-1.5">{p.geo_country}</td>
                  <td className="px-3 py-1.5">{p.is_flagged ? <span className="text-red-400">⚠ Yes</span> : <span className="text-green-400">No</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
