"use client";

import { useState, useEffect } from "react";
import { createClient } from "@/lib/supabase/client";
import { Settings as SettingsIcon, User, Shield, Bell, LogOut } from "lucide-react";
import { useRouter } from "next/navigation";

export default function SettingsPage() {
  const [user, setUser] = useState<{ email?: string; id?: string } | null>(null);
  const [profile, setProfile] = useState<{ username?: string; full_name?: string; role?: string }>({});
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");
  const supabase = createClient();
  const router = useRouter();

  useEffect(() => {
    supabase.auth.getUser().then(({ data }) => {
      if (data.user) {
        setUser(data.user);
        supabase.from("profiles").select("*").eq("id", data.user.id).single()
          .then(({ data: p }) => { if (p) setProfile(p); });
      }
    });
  }, []);

  async function saveProfile() {
    if (!user?.id) return;
    setSaving(true);
    await supabase.from("profiles").update({
      username: profile.username, full_name: profile.full_name,
    }).eq("id", user.id);
    setMsg("Saved!"); setSaving(false);
    setTimeout(() => setMsg(""), 2000);
  }

  async function handleLogout() {
    await supabase.auth.signOut();
    router.push("/login"); router.refresh();
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <h1 className="text-xl font-bold text-[var(--text-primary)] flex items-center gap-2">
        <SettingsIcon className="w-5 h-5 text-cyan-400" /> Settings
      </h1>

      {/* Profile */}
      <div className="glass-panel p-6">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
          <User className="w-4 h-4 text-purple-400" /> Profile
        </h3>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1.5">Email</label>
              <input type="text" value={user?.email || ""} disabled
                className="w-full px-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-sm text-[var(--text-muted)]" />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1.5">Role</label>
              <input type="text" value={profile.role || "analyst"} disabled
                className="w-full px-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-sm text-[var(--text-muted)]" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1.5">Full Name</label>
              <input type="text" value={profile.full_name || ""} onChange={(e) => setProfile({ ...profile, full_name: e.target.value })}
                className="w-full px-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-sm focus:outline-none focus:border-cyan-500/40 text-[var(--text-primary)]" />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1.5">Username</label>
              <input type="text" value={profile.username || ""} onChange={(e) => setProfile({ ...profile, username: e.target.value })}
                className="w-full px-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-sm focus:outline-none focus:border-cyan-500/40 text-[var(--text-primary)]" />
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={saveProfile} disabled={saving}
              className="px-6 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-sm font-medium hover:bg-cyan-500/20 disabled:opacity-50 transition-all">
              {saving ? "Saving..." : "Save Changes"}
            </button>
            {msg && <span className="text-sm text-green-400">{msg}</span>}
          </div>
        </div>
      </div>

      {/* IDS Config */}
      <div className="glass-panel p-6">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
          <Shield className="w-4 h-4 text-amber-400" /> IDS Configuration
        </h3>
        <div className="space-y-3">
          {[
            { rule: "DDoS Detection", desc: "Threshold: 100 pkts/10s per source IP", enabled: true },
            { rule: "Port Scan Detection", desc: "Threshold: 20 unique ports/30s per source", enabled: true },
            { rule: "Brute Force Detection", desc: "Threshold: 30 SYN/60s per destination port", enabled: true },
            { rule: "Data Exfiltration", desc: "Entropy > 7.0 + Size > 40KB to non-standard port", enabled: true },
          ].map((r) => (
            <div key={r.rule} className="flex items-center justify-between px-4 py-3 bg-white/[0.02] rounded-lg">
              <div>
                <p className="text-sm text-[var(--text-primary)] font-medium">{r.rule}</p>
                <p className="text-xs text-[var(--text-muted)]">{r.desc}</p>
              </div>
              <div className={`w-10 h-5 rounded-full relative cursor-pointer transition-all ${r.enabled ? "bg-green-500/30" : "bg-white/10"}`}>
                <div className={`absolute top-0.5 w-4 h-4 rounded-full transition-all ${r.enabled ? "right-0.5 bg-green-400" : "left-0.5 bg-[var(--text-muted)]"}`} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Danger Zone */}
      <div className="glass-panel p-6 border-red-500/20">
        <h3 className="text-sm font-semibold text-red-400 mb-4">Danger Zone</h3>
        <button onClick={handleLogout}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm hover:bg-red-500/20 transition-all">
          <LogOut className="w-4 h-4" /> Sign Out
        </button>
      </div>
    </div>
  );
}
