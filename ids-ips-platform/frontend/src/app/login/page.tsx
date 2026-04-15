"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";
import { Shield, Mail, Lock, User, Eye, EyeOff, Globe } from "lucide-react";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();
  const supabase = createClient();

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    const { error: err } = await supabase.auth.signInWithPassword({ email, password });
    if (err) {
      setError(err.message);
      setLoading(false);
    } else {
      router.push("/");
      router.refresh();
    }
  }

  async function handleGoogle() {
    await supabase.auth.signInWithOAuth({
      provider: "google",
      options: { redirectTo: `${window.location.origin}/auth/callback` },
    });
  }

  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0 opacity-30">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-[120px] animate-pulse" />
        <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-purple-500/10 rounded-full blur-[100px] animate-pulse delay-1000" />
        <div className="absolute top-1/2 left-1/2 w-64 h-64 bg-red-500/5 rounded-full blur-[80px] animate-pulse delay-500" />
      </div>

      {/* Grid overlay */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `linear-gradient(rgba(0,245,255,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(0,245,255,0.3) 1px, transparent 1px)`,
          backgroundSize: "60px 60px",
        }}
      />

      <div className="relative z-10 w-full max-w-md px-6">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-purple-600/20 border border-cyan-500/30 mb-4">
            <Shield className="w-8 h-8 text-cyan-400" />
          </div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
            CyberShield IDS
          </h1>
          <p className="text-[var(--text-muted)] text-sm mt-1">
            Security Operations Center
          </p>
        </div>

        {/* Login Card */}
        <div className="glass-panel p-8">
          <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-6">
            Welcome back, Analyst
          </h2>

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
              {error}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1.5">
                Email
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@cybershield.io"
                  className="w-full pl-10 pr-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-sm focus:outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/20 text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 transition-all"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1.5">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                <input
                  type={showPw ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full pl-10 pr-10 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border-glow)] rounded-lg text-sm focus:outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/20 text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 transition-all"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPw(!showPw)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)] hover:text-cyan-400 transition-colors"
                >
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-500/20 to-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-semibold text-sm hover:from-cyan-500/30 hover:to-cyan-500/20 hover:shadow-[0_0_20px_rgba(0,245,255,0.15)] disabled:opacity-50 transition-all"
            >
              {loading ? "Authenticating..." : "⚡ LOGIN"}
            </button>
          </form>

          <div className="my-5 flex items-center gap-3">
            <div className="flex-1 h-px bg-[var(--border-glow)]" />
            <span className="text-xs text-[var(--text-muted)]">OR</span>
            <div className="flex-1 h-px bg-[var(--border-glow)]" />
          </div>

          <button
            onClick={handleGoogle}
            className="w-full py-2.5 rounded-lg bg-white/5 border border-white/10 text-[var(--text-primary)] text-sm font-medium hover:bg-white/10 transition-all flex items-center justify-center gap-2"
          >
            <Globe className="w-4 h-4" />
            Continue with Google
          </button>

          <p className="text-center text-xs text-[var(--text-muted)] mt-5">
            No account?{" "}
            <a href="/signup" className="text-cyan-400 hover:underline">
              Create one
            </a>
          </p>
        </div>

        <p className="text-center text-xs text-[var(--text-muted)] mt-6">
          🔒 Secured by Supabase Authentication
        </p>
      </div>
    </div>
  );
}
