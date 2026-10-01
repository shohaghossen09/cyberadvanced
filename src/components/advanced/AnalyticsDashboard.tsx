"use client";

import { useMemo } from "react";
import {
  Activity, BarChart3, Brain, PieChart as PieChartIcon, TrendingUp,
} from "lucide-react";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ScanResult } from "./types";

const LEVEL_COLORS: Record<ScanResult["threatLevel"], string> = {
  critical: "#ff3344",
  high: "#ff5566",
  medium: "#ffaa00",
  low: "#00ff88",
  safe: "#334155",
};

const TYPE_COLORS: Record<ScanResult["type"], string> = {
  malware: "#ff3344",
  phishing: "#ffaa00",
  ids: "#00f0ff",
};

const TOOLTIP_STYLE = {
  backgroundColor: "#0d1321",
  border: "1px solid #1a2540",
  borderRadius: "6px",
  fontFamily: "monospace",
  fontSize: "11px",
  color: "#e2e8f0",
};

export default function AnalyticsDashboard({ scans }: { scans: ScanResult[] }) {
  const stats = useMemo(() => {
    const total = scans.length;
    const malicious = scans.filter((s) => s.threatLevel === "critical" || s.threatLevel === "high").length;
    const aiEnhanced = scans.filter((s) => s.aiEnhanced).length;
    const avgScore = total > 0 ? Math.round(scans.reduce((sum, s) => sum + s.score, 0) / total) : 0;

    const byLevel = (["critical", "high", "medium", "low", "safe"] as const)
      .map((level) => ({ name: level, value: scans.filter((s) => s.threatLevel === level).length }))
      .filter((d) => d.value > 0);

    const byType = (["malware", "phishing", "ids"] as const)
      .map((type) => ({ name: type, value: scans.filter((s) => s.type === type).length }))
      .filter((d) => d.value > 0);

    const byHour = new Map<string, number>();
    for (const scan of scans) {
      const t = new Date(scan.timestamp).getTime();
      if (Number.isNaN(t)) continue;
      const key = `${String(new Date(t).getHours()).padStart(2, "0")}:00`;
      byHour.set(key, (byHour.get(key) ?? 0) + 1);
    }
    const timeline = Array.from(byHour.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([hour, count]) => ({ hour, scans: count }));

    return { total, malicious, aiEnhanced, avgScore, byLevel, byType, timeline };
  }, [scans]);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard icon={<Activity className="w-4 h-4" />} label="TOTAL SCANS" value={stats.total} color="text-cyber-cyan" />
        <StatCard icon={<TrendingUp className="w-4 h-4" />} label="THREATS FOUND" value={stats.malicious} color="text-cyber-red" />
        <StatCard icon={<Brain className="w-4 h-4" />} label="AI-ENHANCED" value={stats.aiEnhanced} color="text-cyber-purple" />
        <StatCard icon={<BarChart3 className="w-4 h-4" />} label="AVG SCORE" value={stats.avgScore} color="text-cyber-amber" />
      </div>

      {stats.total === 0 ? (
        <EmptyState />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <ChartCard title="SEVERITY DISTRIBUTION">
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie data={stats.byLevel} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={3} strokeWidth={0}>
                  {stats.byLevel.map((entry) => (
                    <Cell key={entry.name} fill={LEVEL_COLORS[entry.name as ScanResult["threatLevel"]] ?? "#334155"} />
                  ))}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} />
              </PieChart>
            </ResponsiveContainer>
          </ChartCard>

          <ChartCard title="SCANS BY TYPE">
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={stats.byType} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" />
                <XAxis dataKey="name" stroke="#64748b" fontSize={10} fontFamily="monospace" tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} fontFamily="monospace" allowDecimals={false} tickLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "rgba(0,240,255,0.05)" }} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {stats.byType.map((entry) => (
                    <Cell key={entry.name} fill={TYPE_COLORS[entry.name as ScanResult["type"]]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartCard>

          {stats.timeline.length > 0 && (
            <ChartCard title="SCAN TIMELINE (BY HOUR)" className="lg:col-span-2">
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={stats.timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#00f0ff" stopOpacity={0.5} />
                      <stop offset="100%" stopColor="#00f0ff" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1a2540" />
                  <XAxis dataKey="hour" stroke="#64748b" fontSize={10} fontFamily="monospace" tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} fontFamily="monospace" allowDecimals={false} tickLine={false} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Area type="monotone" dataKey="scans" stroke="#00f0ff" strokeWidth={2} fill="url(#scanGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            </ChartCard>
          )}
        </div>
      )}
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  color: string;
}) {
  return (
    <Card className="cyber-card border-cyber-border">
      <CardContent className="p-4 flex items-center gap-3">
        <div className={color}>{icon}</div>
        <div>
          <div className="text-[9px] font-mono text-slate-500 tracking-widest">{label}</div>
          <div className={`text-2xl font-mono font-bold ${color} cyber-glow`}>{value}</div>
        </div>
      </CardContent>
    </Card>
  );
}

function ChartCard({
  title,
  children,
  className,
}: {
  title: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <Card className={`cyber-card border-cyber-border ${className ?? ""}`}>
      <CardHeader className="pb-0">
        <CardTitle className="text-[10px] font-mono tracking-widest text-slate-400">{title}</CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function EmptyState() {
  return (
    <Card className="cyber-card border-cyber-border">
      <CardContent className="py-12 flex flex-col items-center gap-2 text-slate-500">
        <PieChartIcon className="w-8 h-8 opacity-40" />
        <p className="text-xs font-mono">No scan data — analytics will populate as scans are completed.</p>
      </CardContent>
    </Card>
  );
}

