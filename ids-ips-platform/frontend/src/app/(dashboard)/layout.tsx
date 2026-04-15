"use client";

import { useState } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Topbar from "@/components/layout/Topbar";
import { useWebSocket } from "@/lib/useWebSocket";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const { data: alerts } = useWebSocket({ url: `${WS_URL}/ws/alerts`, maxBuffer: 200 });
  const openAlertCount = alerts.length;

  return (
    <div className="min-h-screen">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} alertCount={openAlertCount} />
      <div className={`transition-all duration-300 ${collapsed ? "ml-[64px]" : "ml-[240px]"}`}>
        <Topbar alertCount={openAlertCount} />
        <main className="p-6">{children}</main>
      </div>
    </div>
  );
}
