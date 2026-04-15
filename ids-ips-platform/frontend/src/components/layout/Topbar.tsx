"use client";

import { Bell, Search, User } from "lucide-react";

export default function Topbar({ alertCount }: { alertCount: number }) {
  return (
    <header className="h-14 border-b border-[var(--border-glow)] bg-[var(--bg-secondary)]/80 backdrop-blur-xl flex items-center justify-between px-6 sticky top-0 z-40">
      {/* Search */}
      <div className="relative w-80">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
        <input
          type="text"
          placeholder="Search threats, IPs, alerts... (Ctrl+K)"
          className="w-full pl-10 pr-4 py-1.5 bg-white/5 border border-[var(--border-glow)] rounded-lg text-sm focus:outline-none focus:border-cyan-500/40 text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 transition-all"
        />
      </div>

      {/* Right side */}
      <div className="flex items-center gap-4">
        {/* Live indicator */}
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-green-500/10 border border-green-500/20">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-xs font-medium text-green-400">LIVE</span>
        </div>

        {/* Notifications */}
        <button className="relative p-2 rounded-lg hover:bg-white/5 transition-all">
          <Bell className="w-5 h-5 text-[var(--text-muted)]" />
          {alertCount > 0 && (
            <span className="absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full bg-red-500 text-[10px] font-bold text-white flex items-center justify-center">
              {alertCount > 9 ? "9+" : alertCount}
            </span>
          )}
        </button>

        {/* User */}
        <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500/30 to-purple-500/30 border border-cyan-500/20 flex items-center justify-center">
          <User className="w-4 h-4 text-cyan-400" />
        </div>
      </div>
    </header>
  );
}
