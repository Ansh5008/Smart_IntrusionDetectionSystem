"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";
import { Shield, Mail, Lock, User, UserCircle } from "lucide-react";

export default function SignupPage() {
  const [username, setUsername] = useState("");
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [role, setRole] = useState("analyst");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const router = useRouter();
  const supabase = createClient();

  async function handleSignup(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) { setError("Passwords do not match"); return; }
    if (password.length < 6) { setError("Password must be at least 6 characters"); return; }
    setLoading(true); setError("");

    const { data, error: err } = await supabase.auth.signUp({
      email,
      password,
      options: { data: { username, full_name: fullName, role } },
    });

    if (err) { setError(err.message); setLoading(false); return; }

    if (data.user) {
      await supabase.from("profiles").insert({
        id: data.user.id, username, email, full_name: fullName, role,
      });
      setSuccess(true);
      setTimeout(() => router.push("/login"), 2000);
    }
    setLoading(false);
  }

  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden">
      <div className="absolute inset-0 opacity-30">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-[120px] animate-pulse" />
        <div className="absolute bottom-1/3 right-1/3 w-80 h-80 bg-cyan-500/10 rounded-full blur-[100px] animate-pulse delay-700" />
      </div>

      <div className="relative z-10 w-full max-w-lg px-6">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-purple-500/20 to-cyan-600/20 border border-purple-500/30 mb-4">
            <Shield className="w-8 h-8 text-purple-400" />
          </div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">
            Create Account
          </h1>
        </div>

        <div className="glass-panel p-8">
          {success ? (
            <div className="text-center py-8">
              <div className="text-green-400 text-5xl mb-4">✓</div>
              <p className="text-lg font-semibold text-green-400">Account Created!</p>
              <p className="text-sm text-[var(--text-muted)] mt-2">Redirecting to login...</p>
            </div>
          ) : (
            <form onSubmit={handleSignup} className="space-y-4">
              {error && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">{error}</div>
              )}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1.5">Full Name</label>
                  <div className="relative">
                    <UserCircle className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                    <input type="text" value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="John Doe"
                      className="w-full pl-10 pr-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-sm focus:outline-none focus:border-cyan-500/40 text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 transition-all" required />
                  </div>
                </div>
                <div>
                  <label className="block text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1.5">Username</label>
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                    <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="analyst01"
                      className="w-full pl-10 pr-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-sm focus:outline-none focus:border-cyan-500/40 text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 transition-all" required />
                  </div>
                </div>
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1.5">Email</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                  <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com"
                    className="w-full pl-10 pr-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-sm focus:outline-none focus:border-cyan-500/40 text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 transition-all" required />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1.5">Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                    <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Min 6 chars"
                      className="w-full pl-10 pr-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-sm focus:outline-none focus:border-cyan-500/40 text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 transition-all" required />
                  </div>
                </div>
                <div>
                  <label className="block text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1.5">Confirm</label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                    <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="Repeat"
                      className="w-full pl-10 pr-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-sm focus:outline-none focus:border-cyan-500/40 text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 transition-all" required />
                  </div>
                </div>
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1.5">Role</label>
                <select value={role} onChange={(e) => setRole(e.target.value)}
                  className="w-full px-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-sm focus:outline-none focus:border-cyan-500/40 text-[var(--text-primary)] transition-all">
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                  <option value="viewer">Viewer</option>
                </select>
              </div>
              <button type="submit" disabled={loading}
                className="w-full py-2.5 rounded-lg bg-gradient-to-r from-purple-500/20 to-cyan-500/10 border border-purple-500/30 text-purple-400 font-semibold text-sm hover:from-purple-500/30 hover:to-cyan-500/20 disabled:opacity-50 transition-all">
                {loading ? "Creating..." : "🚀 CREATE ACCOUNT"}
              </button>
            </form>
          )}
          <p className="text-center text-xs text-[var(--text-muted)] mt-5">
            Already have an account? <a href="/login" className="text-cyan-400 hover:underline">Login</a>
          </p>
        </div>
      </div>
    </div>
  );
}
