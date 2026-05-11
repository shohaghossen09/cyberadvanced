"use client";

import React, { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, ShieldAlert, ShieldCheck, Search, Globe, Radar,
  Activity, AlertTriangle, Bug, Zap, Wifi, WifiOff, Server,
  Database, Mail, ChevronRight, X, Check, Circle, TriangleAlert,
  Info, RefreshCw, ScanLine, Skull, Fingerprint, Hash,
  AlertOctagon, MonitorDot, Gauge,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

// ============ TYPES ============
interface ThreatAlert {
  id: string;
  type: "scan" | "malware" | "phishing" | "ids" | "info";
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: string;
  description: string;
  timestamp: string;
  resolved: boolean;
}

interface ScanResult {
  id: string;
  type: "malware" | "phishing";
  subType?: "url" | "email";
  target: string;
  threatLevel: "critical" | "high" | "medium" | "low" | "safe";
  score: number;
  details: string;
  timestamp: string;
  engines: EngineResult[];
  indicators: string[];
  recommendations: string[];
}

interface EngineResult {
  name: string;
  result: "malicious" | "suspicious" | "safe" | "undetected";
}

interface SystemStats {
  threatsBlocked: number;
  scansToday: number;
  activeMonitors: number;
  networkPackets: number;
  startTime: number;
  threatLevel: "low" | "elevated" | "high" | "critical";
}

// ============ HELPERS ============
function computeThreatLevel(alerts: ThreatAlert[], scans: ScanResult[]): SystemStats["threatLevel"] {
  const criticalCount = alerts.filter(a => a.severity === "critical").length +
    scans.filter(s => s.threatLevel === "critical").length;
  const highCount = alerts.filter(a => a.severity === "high").length +
    scans.filter(s => s.threatLevel === "high").length;
  if (criticalCount > 0) return "critical";
  if (highCount > 2) return "high";
  if (highCount > 0) return "elevated";
  return "low";
}

function formatUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${sec}s`;
  return `${m}m ${sec}s`;
}

function threatLevelToScore(level: SystemStats["threatLevel"]): number {
  switch (level) {
    case "critical": return 92;
    case "high": return 75;
    case "elevated": return 45;
    case "low": return 10;
  }
}

// ============ ICON COMPONENTS ============
function SeverityIcon({ severity, className }: { severity: string; className?: string }) {
  const base = cn("h-4 w-4", className);
  switch (severity) {
    case "critical": return <Skull className={cn(base, "text-cyber-red")} />;
    case "high": return <AlertOctagon className={cn(base, "text-[#ff6b35]")} />;
    case "medium": return <AlertTriangle className={cn(base, "text-cyber-amber")} />;
    case "low": return <Info className={cn(base, "text-cyber-cyan")} />;
    default: return <Circle className={cn(base, "text-slate-500")} />;
  }
}

function ThreatBadge({ level }: { level: string }) {
  const cfg: Record<string, { label: string; cls: string }> = {
    critical: { label: "CRITICAL", cls: "threat-bg-critical text-cyber-red border" },
    high: { label: "HIGH", cls: "threat-bg-high text-[#ff6b35] border" },
    medium: { label: "MEDIUM", cls: "threat-bg-medium text-cyber-amber border" },
    low: { label: "LOW", cls: "threat-bg-low text-cyber-cyan border" },
    safe: { label: "SAFE", cls: "threat-bg-safe text-cyber-green border" },
  };
  const c = cfg[level] || cfg.safe;
  return <Badge variant="outline" className={cn("font-mono text-[10px] tracking-widest", c.cls)}>{c.label}</Badge>;
}

function ScoreRing({ score, size = 120, label }: { score: number; size?: number; label?: string }) {
  const radius = (size - 12) / 2;
  const circ = 2 * Math.PI * radius;
  const progress = (score / 100) * circ;
  const color = score >= 80 ? "#ff3344" : score >= 60 ? "#ff6b35" : score >= 40 ? "#ffaa00" : score >= 20 ? "#00f0ff" : "#00ff88";
  const lbl = score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH RISK" : score >= 40 ? "WARNING" : score >= 20 ? "LOW RISK" : "SAFE";

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#1a2540" strokeWidth="6" />
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth="6" strokeLinecap="round"
          strokeDasharray={circ} strokeDashoffset={circ - progress}
          className="transition-all duration-1000 ease-out"
          style={{ filter: `drop-shadow(0 0 6px ${color}60)` }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-2xl font-bold" style={{ color }}>{score}</span>
        <span className="text-[10px] tracking-wider" style={{ color }}>{lbl}</span>
        {label && <span className="text-[10px] text-slate-500 mt-0.5">{label}</span>}
      </div>
    </div>
  );
}

function ThreatLevelIndicator({ level }: { level: string }) {
  const colors: Record<string, string> = { low: "bg-cyber-green", elevated: "bg-cyber-amber", high: "bg-[#ff6b35]", critical: "bg-cyber-red" };
  const textColors: Record<string, string> = { low: "#00ff88", elevated: "#ffaa00", high: "#ff6b35", critical: "#ff3344" };
  return (
    <div className="flex items-center gap-2">
      <div className={cn("w-2.5 h-2.5 rounded-full animate-pulse", colors[level])}
        style={{ boxShadow: `0 0 8px ${textColors[level]}80` }} />
      <span className="text-xs uppercase tracking-widest font-bold" style={{ color: textColors[level] }}>{level}</span>
    </div>
  );
}

function BrainIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 5a3 3 0 1 0-5.997.125 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .556 6.588A4 4 0 1 0 12 18Z" />
      <path d="M12 5a3 3 0 1 1 5.997.125 4 4 0 0 1 2.526 5.77 4 4 0 0 1-.556 6.588A4 4 0 1 1 12 18Z" />
      <path d="M15 13a4.5 4.5 0 0 1-3-4 4.5 4.5 0 0 1-3 4" />
    </svg>
  );
}

function HistoryIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
      <path d="M3 3v5h5" />
      <path d="M12 7v5l4 2" />
    </svg>
  );
}

// ============ HEADER ============
function Header({ stats, activeTab, onTabChange }: {
  stats: SystemStats; activeTab: string; onTabChange: (tab: string) => void;
}) {
  const [time, setTime] = useState(new Date());
  useEffect(() => { const i = setInterval(() => setTime(new Date()), 1000); return () => clearInterval(i); }, []);

  return (
    <header className="border-b border-cyber-border bg-cyber-darker/90 backdrop-blur-md sticky top-0 z-50">
      <div className="px-4 py-3">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Shield className="h-8 w-8 text-cyber-cyan" />
              <div className="absolute -inset-1 bg-cyber-cyan/10 rounded-full blur-sm" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-wider cyber-glow text-cyber-cyan">CYBER DEFENDER</h1>
              <p className="text-[10px] text-slate-500 tracking-[0.3em] uppercase">AI-Powered Security Operations Center</p>
            </div>
          </div>
          <div className="flex items-center gap-4 flex-wrap">
            <div className="hidden sm:flex items-center gap-4 text-[11px]">
              <div className="flex items-center gap-1.5">
                <ShieldCheck className="h-3.5 w-3.5 text-cyber-green" />
                <span className="text-slate-400">THREATS:</span>
                <span className="text-cyber-green font-bold">{stats.threatsBlocked}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <ScanLine className="h-3.5 w-3.5 text-cyber-cyan" />
                <span className="text-slate-400">SCANS:</span>
                <span className="text-cyber-cyan font-bold">{stats.scansToday}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <MonitorDot className="h-3.5 w-3.5 text-cyber-amber" />
                <span className="text-slate-400">MONITORS:</span>
                <span className="text-cyber-amber font-bold">{stats.activeMonitors}</span>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <ThreatLevelIndicator level={stats.threatLevel} />
              <div className="text-right">
                <div className="text-[10px] text-slate-500 font-mono">{time.toISOString().replace("T", " ").slice(0, 19)} UTC</div>
                <div className="text-[10px] text-slate-600">UP: {formatUptime(Date.now() - stats.startTime)}</div>
              </div>
            </div>
          </div>
        </div>
        <Tabs value={activeTab} onValueChange={onTabChange} className="mt-3">
          <TabsList className="bg-transparent border-b border-cyber-border w-full justify-start rounded-none h-auto p-0 gap-0">
            {[
              { value: "dashboard", icon: MonitorDot, label: "COMMAND CENTER" },
              { value: "malware", icon: Bug, label: "MALWARE SCANNER" },
              { value: "phishing", icon: ShieldAlert, label: "PHISHING DETECT" },
              { value: "ids", icon: Radar, label: "IDS MONITOR" },
              { value: "intelligence", icon: Database, label: "INTELLIGENCE" },
            ].map((tab) => (
              <TabsTrigger key={tab.value} value={tab.value}
                className="data-[state=active]:bg-transparent data-[state=active]:border-cyber-cyan data-[state=active]:text-cyber-cyan data-[state=active]:shadow-none rounded-none border-b-2 border-transparent text-slate-500 hover:text-slate-300 px-4 py-2.5 transition-all text-[11px] tracking-wider uppercase font-semibold gap-1.5">
                <tab.icon className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">{tab.label}</span>
                <span className="sm:hidden">{tab.label.split(" ")[0]}</span>
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>
    </header>
  );
}

// ============ ENGINE RESULTS GRID ============
function EngineGrid({ engines, compact = false }: { engines: EngineResult[]; compact?: boolean }) {
  return (
    <div className={cn("grid gap-1.5", compact ? "grid-cols-2 sm:grid-cols-3 md:grid-cols-4" : "grid-cols-1 sm:grid-cols-2")}>
      {engines.map((engine, i) => (
        <motion.div key={engine.name} initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: i * 0.03 }}
          className={cn("flex items-center gap-2 p-2 rounded border text-[11px]",
            engine.result === "malicious" ? "threat-bg-critical" :
            engine.result === "suspicious" ? "threat-bg-high" : "bg-slate-800/20 border-slate-700/30"
          )}>
          {engine.result === "malicious" ? <X className="h-3 w-3 text-cyber-red shrink-0" /> :
           engine.result === "suspicious" ? <AlertTriangle className="h-3 w-3 text-[#ff6b35] shrink-0" /> :
           <Check className="h-3 w-3 text-slate-500 shrink-0" />}
          <span className="text-slate-400 truncate">{engine.name}</span>
        </motion.div>
      ))}
    </div>
  );
}

// ============ COMMAND CENTER ============
function CommandCenter({ stats, alerts, scans }: {
  stats: SystemStats; alerts: ThreatAlert[]; scans: ScanResult[];
}) {
  const recentAlerts = alerts.slice(-30).reverse();
  const severityCounts = alerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const totalMalicious = scans.reduce((s, r) => s + r.engines.filter(e => e.result === "malicious").length, 0);
  const totalSuspicious = scans.reduce((s, r) => s + r.engines.filter(e => e.result === "suspicious").length, 0);
  const totalEnginesScanned = scans.reduce((s, r) => s + r.engines.length, 0);

  return (
    <div className="space-y-4 p-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { label: "TOTAL SCANS", value: stats.scansToday.toString(), icon: ScanLine, color: "text-cyber-cyan" },
          { label: "THREATS FOUND", value: stats.threatsBlocked.toString(), icon: ShieldAlert, color: "text-cyber-red" },
          { label: "ENGINE HITS", value: `${totalMalicious + totalSuspicious}/${totalEnginesScanned}`, icon: Activity, color: "text-cyber-amber" },
          { label: "ACTIVE MONITORS", value: stats.activeMonitors.toString(), icon: MonitorDot, color: "text-cyber-purple" },
        ].map((stat) => (
          <motion.div key={stat.label} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <Card className="cyber-card">
              <CardContent className="p-4">
                <stat.icon className={cn("h-5 w-5 mb-2", stat.color)} />
                <div className="text-2xl font-bold tracking-tight">{stat.value}</div>
                <div className="text-[10px] text-slate-500 tracking-wider mt-1">{stat.label}</div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="lg:col-span-2">
          <Card className="cyber-card h-[520px] flex flex-col">
            <CardHeader className="pb-2 pt-4 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold tracking-wider text-cyber-cyan flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  LIVE OPERATION FEED
                  {alerts.length > 0 && <span className="inline-flex h-2 w-2 rounded-full bg-cyber-green animate-pulse" />}
                </CardTitle>
                <Badge variant="outline" className={cn("text-[9px]",
                  alerts.length > 0 ? "border-cyber-green/50 text-cyber-green" : "border-slate-600 text-slate-500"
                )}>{alerts.length > 0 ? "LIVE" : "IDLE"}</Badge>
              </div>
            </CardHeader>
            <CardContent className="p-0 flex-1 overflow-hidden">
              <ScrollArea className="h-[460px] cyber-scrollbar">
                <div className="px-4 space-y-1.5 pb-4">
                  {recentAlerts.map((alert, i) => (
                    <motion.div key={alert.id} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.03 }}
                      className={cn("flex items-start gap-3 p-2.5 rounded-md border text-xs transition-colors hover:bg-white/[0.02]",
                        alert.severity === "critical" ? "threat-bg-critical" :
                        alert.severity === "high" ? "threat-bg-high" :
                        alert.severity === "medium" ? "threat-bg-medium" :
                        alert.severity === "low" ? "threat-bg-low" : "bg-slate-800/30 border-slate-700/50"
                      )}>
                      <SeverityIcon severity={alert.severity} className="mt-0.5 shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5">
                          <Badge variant="outline" className="text-[9px] tracking-wider border-current/30">{alert.type.toUpperCase()}</Badge>
                          <span className="text-[10px] text-slate-500 font-mono">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <p className="text-slate-300 leading-relaxed">{alert.description}</p>
                        <div className="text-[10px] text-slate-600 font-mono mt-1">SRC: {alert.source}</div>
                      </div>
                    </motion.div>
                  ))}
                  {recentAlerts.length === 0 && (
                    <div className="flex flex-col items-center justify-center h-40 text-slate-600 text-sm gap-2">
                      <Radar className="h-8 w-8 animate-pulse opacity-30" />
                      <span>System ready. Run scans from Malware Scanner or Phishing Detect.</span>
                    </div>
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-4">
          <Card className="cyber-card">
            <CardContent className="p-4">
              <CardTitle className="text-sm font-semibold tracking-wider text-cyber-cyan flex items-center gap-2 mb-4">
                <Gauge className="h-4 w-4" /> THREAT LEVEL
              </CardTitle>
              <div className="flex justify-center mb-4">
                <ScoreRing score={threatLevelToScore(stats.threatLevel)} size={140} label="Overall Score" />
              </div>
              {Object.keys(severityCounts).length > 0 ? (
                <div className="space-y-2">
                  {Object.entries(severityCounts).map(([sev, count]) => (
                    <div key={sev} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <SeverityIcon severity={sev} />
                        <span className="text-slate-400 uppercase tracking-wider text-[10px]">{sev}</span>
                      </div>
                      <span className={cn("font-bold",
                        sev === "critical" ? "text-cyber-red" : sev === "high" ? "text-[#ff6b35]" :
                        sev === "medium" ? "text-cyber-amber" : sev === "low" ? "text-cyber-cyan" : "text-slate-400"
                      )}>{count}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-[11px] text-slate-600 text-center">No alerts yet</p>
              )}
            </CardContent>
          </Card>

          <Card className="cyber-card">
            <CardContent className="p-4">
              <CardTitle className="text-sm font-semibold tracking-wider text-cyber-cyan flex items-center gap-2 mb-3">
                <HistoryIcon className="h-4 w-4" /> RECENT SCANS
              </CardTitle>
              {scans.length > 0 ? (
                <div className="space-y-2">
                  {scans.slice(-6).reverse().map((scan) => (
                    <div key={scan.id} className="flex items-center justify-between p-2 rounded bg-white/[0.02] border border-cyber-border">
                      <div className="flex items-center gap-2 min-w-0">
                        {scan.type === "malware" ? <Bug className="h-3 w-3 text-cyber-red shrink-0" /> :
                         <ShieldAlert className="h-3 w-3 text-cyber-amber shrink-0" />}
                        <span className="text-[11px] text-slate-400 font-mono truncate max-w-[120px]">{scan.target}</span>
                      </div>
                      <ThreatBadge level={scan.threatLevel} />
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-[11px] text-slate-600 text-center py-4">No scans yet. Use the tabs above to start scanning.</p>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}

// ============ MALWARE SCANNER ============
function MalwareScanner({ onScan, isScanning, scanResults }: {
  onScan: (target: string) => void; isScanning: boolean; scanResults: ScanResult[];
}) {
  const [input, setInput] = useState("");
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null);
  const malwareScans = scanResults.filter(s => s.type === "malware");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (input.trim() && !isScanning) { onScan(input.trim()); setInput(""); setSelectedResult(null); }
  };

  const activeResult = selectedResult || malwareScans[malwareScans.length - 1] || null;

  return (
    <div className="p-4 space-y-4">
      <Card className="cyber-card">
        <CardContent className="p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-cyber-red/10 border border-cyber-red/30">
              <Bug className="h-5 w-5 text-cyber-red" />
            </div>
            <div>
              <h2 className="text-sm font-semibold tracking-wider">MALWARE ANALYSIS ENGINE</h2>
              <p className="text-[11px] text-slate-500">AI-powered multi-engine threat detection — 14 engines, real-time analysis</p>
            </div>
          </div>
          <form onSubmit={handleSubmit} className="flex gap-2">
            <div className="flex-1 relative">
              <Hash className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-600" />
              <Input value={input} onChange={(e) => setInput(e.target.value)}
                placeholder="Enter file hash (MD5/SHA1/SHA256), file name, or URL to scan..."
                className="cyber-input pl-10 h-11 text-sm" disabled={isScanning} />
            </div>
            <Button type="submit" disabled={isScanning || !input.trim()}
              className="bg-cyber-red hover:bg-cyber-red/80 text-white font-semibold px-6 gap-2 transition-all">
              {isScanning ? <><RefreshCw className="h-4 w-4 animate-spin" /> ANALYZING...</> : <><Search className="h-4 w-4" /> SCAN</>}
            </Button>
          </form>
        </CardContent>
      </Card>

      {activeResult && (
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="cyber-card">
            <CardContent className="p-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
                <div className="flex items-center gap-4">
                  <ScoreRing score={activeResult.score} size={100} label="Threat Score" />
                  <div>
                    <div className="text-sm font-mono text-slate-300 mb-1 break-all max-w-[300px]">{activeResult.target}</div>
                    <div className="flex items-center gap-2">
                      <ThreatBadge level={activeResult.threatLevel} />
                      <span className="text-[10px] text-slate-600">{new Date(activeResult.timestamp).toLocaleString()}</span>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1">Analyzed by {activeResult.engines.length} security engines</div>
                  </div>
                </div>
                <div className="flex gap-3 text-center">
                  {[
                    { label: "MALICIOUS", count: activeResult.engines.filter(e => e.result === "malicious").length, cls: "bg-cyber-red/10 border-cyber-red/20", text: "text-cyber-red" },
                    { label: "SUSPICIOUS", count: activeResult.engines.filter(e => e.result === "suspicious").length, cls: "bg-cyber-amber/10 border-cyber-amber/20", text: "text-cyber-amber" },
                    { label: "UNDETECTED", count: activeResult.engines.filter(e => e.result === "undetected").length, cls: "bg-slate-700/50 border-slate-600/30", text: "text-slate-300" },
                    { label: "SAFE", count: activeResult.engines.filter(e => e.result === "safe").length, cls: "bg-cyber-green/10 border-cyber-green/20", text: "text-cyber-green" },
                  ].map(s => (
                    <div key={s.label} className={cn("px-3 py-2 rounded border", s.cls)}>
                      <div className={cn("text-lg font-bold", s.text)}>{s.count}</div>
                      <div className="text-[9px] text-slate-500 tracking-wider">{s.label}</div>
                    </div>
                  ))}
                </div>
              </div>

              <Separator className="bg-cyber-border mb-4" />
              <div className="mb-4">
                <h3 className="text-xs font-semibold tracking-wider text-slate-400 mb-3 flex items-center gap-2">
                  <Server className="h-3.5 w-3.5" /> ENGINE ANALYSIS RESULTS
                </h3>
                <EngineGrid engines={activeResult.engines} />
              </div>
              <Separator className="bg-cyber-border mb-4" />

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h3 className="text-xs font-semibold tracking-wider text-slate-400 mb-2 flex items-center gap-2">
                    <BrainIcon className="h-3.5 w-3.5 text-cyber-cyan" /> AI THREAT ANALYSIS
                  </h3>
                  <div className="p-3 rounded bg-cyber-dark/50 border border-cyber-border text-xs text-slate-400 leading-relaxed max-h-48 overflow-y-auto cyber-scrollbar whitespace-pre-wrap">
                    {activeResult.details}
                  </div>
                </div>
                <div className="space-y-3">
                  {activeResult.indicators.length > 0 && (
                    <div>
                      <h3 className="text-xs font-semibold tracking-wider text-slate-400 mb-2 flex items-center gap-2">
                        <TriangleAlert className="h-3.5 w-3.5 text-cyber-amber" /> INDICATORS OF COMPROMISE
                      </h3>
                      <div className="space-y-1">
                        {activeResult.indicators.map((ind, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs text-slate-400">
                            <ChevronRight className="h-3 w-3 text-cyber-amber mt-0.5 shrink-0" /> {ind}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {activeResult.recommendations.length > 0 && (
                    <div>
                      <h3 className="text-xs font-semibold tracking-wider text-slate-400 mb-2 flex items-center gap-2">
                        <ShieldCheck className="h-3.5 w-3.5 text-cyber-green" /> RECOMMENDATIONS
                      </h3>
                      <div className="space-y-1">
                        {activeResult.recommendations.map((rec, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs text-slate-400">
                            <Check className="h-3 w-3 text-cyber-green mt-0.5 shrink-0" /> {rec}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {malwareScans.length > 1 && (
        <Card className="cyber-card">
          <CardHeader className="pb-2 pt-4 px-4">
            <CardTitle className="text-sm font-semibold tracking-wider text-cyber-cyan flex items-center gap-2">
              <HistoryIcon className="h-4 w-4" /> SCAN HISTORY ({malwareScans.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4">
            <ScrollArea className="max-h-64 cyber-scrollbar">
              <div className="space-y-1.5">
                {malwareScans.slice().reverse().map((scan) => (
                  <div key={scan.id} onClick={() => setSelectedResult(scan)}
                    className={cn("flex items-center justify-between p-2.5 rounded border cursor-pointer transition-all text-xs",
                      selectedResult?.id === scan.id ? "border-cyber-cyan/30 bg-cyber-cyan/5" : "border-cyber-border hover:bg-white/[0.02]")}>
                    <div className="flex items-center gap-3 min-w-0">
                      <Bug className="h-3.5 w-3.5 text-cyber-red shrink-0" />
                      <span className="text-slate-400 font-mono truncate max-w-[200px]">{scan.target}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] text-slate-600">{new Date(scan.timestamp).toLocaleTimeString()}</span>
                      <ThreatBadge level={scan.threatLevel} />
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ============ PHISHING DETECTOR ============
function PhishingDetector({ onScan, isScanning, scanResults }: {
  onScan: (target: string, mode: "url" | "email") => void; isScanning: boolean; scanResults: ScanResult[];
}) {
  const [url, setUrl] = useState("");
  const [emailContent, setEmailContent] = useState("");
  const [mode, setMode] = useState<"url" | "email">("url");
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null);
  const phishingScans = scanResults.filter(s => s.type === "phishing");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const target = mode === "url" ? url.trim() : emailContent.trim();
    if (target && !isScanning) {
      onScan(target, mode);
      if (mode === "url") setUrl(""); else setEmailContent("");
      setSelectedResult(null);
    }
  };

  // Filter by current mode
  const modeScans = phishingScans.filter(s => s.subType === mode);
  const activeResult = selectedResult || modeScans[modeScans.length - 1] || null;

  return (
    <div className="p-4 space-y-4">
      <Card className="cyber-card">
        <CardContent className="p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-cyber-amber/10 border border-cyber-amber/30">
              <ShieldAlert className="h-5 w-5 text-cyber-amber" />
            </div>
            <div>
              <h2 className="text-sm font-semibold tracking-wider">AI PHISHING DETECTION ENGINE</h2>
              <p className="text-[11px] text-slate-500">Known & zero-day phishing detection — URL structure + Email content analysis</p>
            </div>
          </div>

          <div className="flex gap-2 mb-4">
            <Button variant={mode === "url" ? "default" : "outline"} onClick={() => { setMode("url"); setSelectedResult(null); }}
              className={cn("text-xs gap-2 transition-all",
                mode === "url" ? "bg-cyber-cyan/20 border-cyber-cyan/50 text-cyber-cyan hover:bg-cyber-cyan/30" : "border-cyber-border text-slate-500"
              )}>
              <Globe className="h-3.5 w-3.5" /> URL ANALYSIS
            </Button>
            <Button variant={mode === "email" ? "default" : "outline"} onClick={() => { setMode("email"); setSelectedResult(null); }}
              className={cn("text-xs gap-2 transition-all",
                mode === "email" ? "bg-cyber-cyan/20 border-cyber-cyan/50 text-cyber-cyan hover:bg-cyber-cyan/30" : "border-cyber-border text-slate-500"
              )}>
              <Mail className="h-3.5 w-3.5" /> EMAIL ANALYSIS
            </Button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-3">
            {mode === "url" ? (
              <div className="relative">
                <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-600" />
                <Input value={url} onChange={(e) => setUrl(e.target.value)}
                  placeholder="Enter URL to analyze: https://example.com/login"
                  className="cyber-input pl-10 h-11 text-sm" disabled={isScanning} />
              </div>
            ) : (
              <textarea value={emailContent} onChange={(e) => setEmailContent(e.target.value)}
                placeholder={"Paste email content here for phishing analysis...\n\nFrom: sender@example.com\nSubject: Urgent Action Required\n\nDear Customer..."}
                className="cyber-input w-full h-32 p-3 text-sm resize-none font-mono rounded-md" disabled={isScanning} />
            )}
            <Button type="submit" disabled={isScanning || (mode === "url" ? !url.trim() : !emailContent.trim())}
              className="bg-cyber-amber hover:bg-cyber-amber/80 text-black font-semibold px-6 gap-2 transition-all">
              {isScanning ? <><RefreshCw className="h-4 w-4 animate-spin" /> ANALYZING...</> : <><Search className="h-4 w-4" /> ANALYZE</>}
            </Button>
          </form>
        </CardContent>
      </Card>

      {activeResult && (
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="cyber-card">
            <CardContent className="p-6">
              {/* Mode-specific header */}
              <div className="flex items-center gap-2 mb-4">
                <Badge variant="outline" className={cn("text-[10px] tracking-wider",
                  mode === "url" ? "border-cyber-cyan/50 text-cyber-cyan" : "border-cyber-amber/50 text-cyber-amber"
                )}>
                  {mode === "url" ? <><Globe className="h-3 w-3 mr-1" /> URL ANALYSIS</> : <><Mail className="h-3 w-3 mr-1" /> EMAIL ANALYSIS</>}
                </Badge>
                <Badge variant="outline" className="text-[9px] border-slate-600 text-slate-500">
                  {new Date(activeResult.timestamp).toLocaleString()}
                </Badge>
              </div>

              <div className="flex flex-col md:flex-row md:items-start gap-4 mb-6">
                <ScoreRing score={activeResult.score} size={100} label={mode === "url" ? "URL Threat" : "Email Threat"} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-mono text-slate-300 mb-2 break-all">
                    {mode === "url" ? activeResult.target : (
                      <div className="p-3 rounded bg-cyber-dark/50 border border-cyber-border text-[11px] text-slate-400 leading-relaxed max-h-32 overflow-y-auto cyber-scrollbar whitespace-pre-wrap">
                        {activeResult.target}
                      </div>
                    )}
                  </div>
                  <ThreatBadge level={activeResult.threatLevel} />
                  <div className="text-[11px] text-slate-500 mt-2">
                    Analyzed by {activeResult.engines.length} phishing detection engines — {activeResult.engines.filter(e => e.result === "malicious").length} flagged as malicious
                  </div>
                </div>
              </div>

              <Separator className="bg-cyber-border mb-4" />
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div>
                  <h3 className="text-xs font-semibold tracking-wider text-slate-400 mb-2 flex items-center gap-2">
                    <BrainIcon className="h-3.5 w-3.5 text-cyber-cyan" />
                    AI {mode === "url" ? "URL" : "EMAIL"} PHISHING ANALYSIS
                  </h3>
                  <div className="p-3 rounded bg-cyber-dark/50 border border-cyber-border text-xs text-slate-400 leading-relaxed max-h-48 overflow-y-auto cyber-scrollbar whitespace-pre-wrap">
                    {activeResult.details}
                  </div>
                </div>
                <div className="space-y-3">
                  {activeResult.indicators.length > 0 && (
                    <div>
                      <h3 className="text-xs font-semibold tracking-wider text-slate-400 mb-2 flex items-center gap-2">
                        <TriangleAlert className="h-3.5 w-3.5 text-cyber-amber" />
                        {mode === "url" ? "URL THREAT" : "EMAIL THREAT"} INDICATORS
                      </h3>
                      <div className="space-y-1">
                        {activeResult.indicators.map((ind, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs text-slate-400">
                            <ChevronRight className="h-3 w-3 text-cyber-amber mt-0.5 shrink-0" /> {ind}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {activeResult.recommendations.length > 0 && (
                    <div>
                      <h3 className="text-xs font-semibold tracking-wider text-slate-400 mb-2 flex items-center gap-2">
                        <ShieldCheck className="h-3.5 w-3.5 text-cyber-green" /> RECOMMENDATIONS
                      </h3>
                      <div className="space-y-1">
                        {activeResult.recommendations.map((rec, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs text-slate-400">
                            <Check className="h-3 w-3 text-cyber-green mt-0.5 shrink-0" /> {rec}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <Separator className="bg-cyber-border mb-4" />
              <h3 className="text-xs font-semibold tracking-wider text-slate-400 mb-3 flex items-center gap-2">
                <Server className="h-3.5 w-3.5" /> MULTI-ENGINE VERIFICATION
              </h3>
              <EngineGrid engines={activeResult.engines} compact />
            </CardContent>
          </Card>
        </motion.div>
      )}

      {modeScans.length > 1 && (
        <Card className="cyber-card">
          <CardHeader className="pb-2 pt-4 px-4">
            <CardTitle className="text-sm font-semibold tracking-wider text-cyber-cyan flex items-center gap-2">
              <HistoryIcon className="h-4 w-4" /> {mode === "url" ? "URL" : "EMAIL"} SCAN HISTORY ({modeScans.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4">
            <ScrollArea className="max-h-48 cyber-scrollbar">
              <div className="space-y-1.5">
                {modeScans.slice().reverse().map((scan) => (
                  <div key={scan.id} onClick={() => setSelectedResult(scan)}
                    className={cn("flex items-center justify-between p-2.5 rounded border cursor-pointer transition-all text-xs",
                      selectedResult?.id === scan.id ? "border-cyber-cyan/30 bg-cyber-cyan/5" : "border-cyber-border hover:bg-white/[0.02]")}>
                    <div className="flex items-center gap-3 min-w-0">
                      {scan.subType === "url" ? <Globe className="h-3.5 w-3.5 text-cyber-cyan shrink-0" /> : <Mail className="h-3.5 w-3.5 text-cyber-amber shrink-0" />}
                      <span className="text-slate-400 font-mono truncate max-w-[250px]">{scan.target}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] text-slate-600">{new Date(scan.timestamp).toLocaleTimeString()}</span>
                      <ThreatBadge level={scan.threatLevel} />
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ============ IDS MONITOR ============
function IDSMonitor({ alerts, scans, monitorActive, onToggleMonitor }: {
  alerts: ThreatAlert[]; scans: ScanResult[]; monitorActive: boolean; onToggleMonitor: () => void;
}) {
  const intrusionAlerts = alerts.filter(a => a.type === "malware" || a.type === "phishing" || (a.type === "scan" && a.severity !== "info" && a.severity !== "low"));
  const recentIntrusions = intrusionAlerts.slice(-30).reverse();

  return (
    <div className="p-4 space-y-4">
      <Card className="cyber-card">
        <CardContent className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className={cn("p-2 rounded-lg border transition-all", monitorActive ? "bg-cyber-green/10 border-cyber-green/30" : "bg-slate-700/50 border-slate-600/30")}>
                <Radar className={cn("h-5 w-5", monitorActive ? "text-cyber-green" : "text-slate-500")} />
              </div>
              <div>
                <h2 className="text-sm font-semibold tracking-wider">INTRUSION DETECTION SYSTEM</h2>
                <p className="text-[11px] text-slate-500">Monitors all scan operations for intrusion indicators</p>
              </div>
            </div>
            <Button onClick={onToggleMonitor}
              className={cn("font-semibold px-4 gap-2 text-xs transition-all",
                monitorActive ? "bg-cyber-red/20 border border-cyber-red/50 text-cyber-red hover:bg-cyber-red/30"
                  : "bg-cyber-green/20 border border-cyber-green/50 text-cyber-green hover:bg-cyber-green/30"
              )}>
              {monitorActive ? <><WifiOff className="h-3.5 w-3.5" /> DISABLE MONITOR</> : <><Wifi className="h-3.5 w-3.5" /> ENABLE MONITOR</>}
            </Button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: "SYSTEM STATUS", value: monitorActive ? "ACTIVE" : "OFFLINE", color: monitorActive ? "text-cyber-green" : "text-slate-500" },
              { label: "TOTAL SCANS", value: scans.length.toString(), color: "text-cyber-cyan" },
              { label: "THREAT ALERTS", value: intrusionAlerts.length.toString(), color: "text-cyber-red" },
              { label: "HIGH/CRITICAL", value: alerts.filter(a => a.severity === "critical" || a.severity === "high").length.toString(), color: "text-cyber-amber" },
            ].map((s) => (
              <div key={s.label} className="p-3 rounded bg-white/[0.02] border border-cyber-border">
                <div className={cn("text-lg font-bold", s.color)}>{s.value}</div>
                <div className="text-[9px] text-slate-600 tracking-wider">{s.label}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="cyber-card lg:col-span-2 min-h-[350px] flex flex-col">
          <CardHeader className="pb-2 pt-4 px-4">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold tracking-wider text-cyber-cyan flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" /> INTRUSION ALERTS
                {monitorActive && recentIntrusions.length > 0 && <span className="inline-flex h-2 w-2 rounded-full bg-cyber-green animate-pulse" />}
              </CardTitle>
              <Badge variant="outline" className="text-[9px] border-slate-600 text-slate-400">{recentIntrusions.length} EVENTS</Badge>
            </div>
          </CardHeader>
          <CardContent className="p-0 flex-1 overflow-hidden">
            <ScrollArea className="h-[290px] cyber-scrollbar">
              <div className="px-4 space-y-1 pb-4">
                {recentIntrusions.map((alert) => (
                  <div key={alert.id} className={cn("flex items-start gap-2.5 p-2 rounded text-[11px] border",
                    alert.severity === "critical" ? "threat-bg-critical" :
                    alert.severity === "high" ? "threat-bg-high" :
                    alert.severity === "medium" ? "threat-bg-medium" : "bg-slate-800/20 border-slate-700/30"
                  )}>
                    <SeverityIcon severity={alert.severity} className="mt-0.5 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-slate-300">{alert.description}</p>
                      <span className="text-[9px] text-slate-600 font-mono">{new Date(alert.timestamp).toLocaleTimeString()} | {alert.source}</span>
                    </div>
                  </div>
                ))}
                {recentIntrusions.length === 0 && (
                  <div className="flex flex-col items-center justify-center h-32 text-slate-600 text-xs gap-2">
                    {monitorActive ? <><Wifi className="h-6 w-6 animate-pulse opacity-30" /><span>Monitoring active. Awaiting scan results...</span></>
                      : <><WifiOff className="h-6 w-6 opacity-30" /><span>Monitor offline. Enable to start detecting.</span></>}
                  </div>
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        <Card className="cyber-card">
          <CardContent className="p-4">
            <h3 className="text-xs font-semibold tracking-wider text-slate-400 mb-3 flex items-center gap-2">
              <Activity className="h-3.5 w-3.5" /> RECENT SCAN RESULTS
            </h3>
            {scans.length > 0 ? (
              <div className="space-y-2">
                {scans.slice(-8).reverse().map((scan) => (
                  <div key={scan.id} className="p-2 rounded bg-white/[0.02] border border-cyber-border">
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-1.5">
                        {scan.type === "malware" ? <Bug className="h-3 w-3 text-cyber-red shrink-0" /> : <ShieldAlert className="h-3 w-3 text-cyber-amber shrink-0" />}
                        <span className="text-[10px] text-slate-400 font-mono truncate max-w-[140px]">{scan.target}</span>
                      </div>
                      <ThreatBadge level={scan.threatLevel} />
                    </div>
                    <div className="flex items-center gap-1 text-[9px] text-slate-600">
                      <span>Score: {scan.score}/100</span>
                      <span>•</span>
                      <span>{scan.engines.filter(e => e.result === "malicious").length} malicious</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-[11px] text-slate-600 text-center py-6">No scan data yet</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ============ INTELLIGENCE CENTER ============
function IntelligenceCenter({ scans }: { scans: ScanResult[] }) {
  const [filter, setFilter] = useState("all");
  const filtered = filter === "all" ? scans : scans.filter(s => s.type === filter);

  const distribution = { critical: 0, high: 0, medium: 0, low: 0, safe: 0 };
  scans.forEach(s => { distribution[s.threatLevel] = (distribution[s.threatLevel] || 0) + 1; });

  return (
    <div className="p-4 space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {Object.entries(distribution).map(([level, count]) => (
          <Card key={level} className={cn("cyber-card", level === "critical" && distribution.critical > 0 && "cyber-border-glow-red")}>
            <CardContent className="p-3 text-center">
              <div className={cn("text-2xl font-bold",
                level === "critical" ? "text-cyber-red" : level === "high" ? "text-[#ff6b35]" :
                level === "medium" ? "text-cyber-amber" : level === "low" ? "text-cyber-cyan" : "text-cyber-green"
              )}>{count}</div>
              <div className="text-[9px] text-slate-500 tracking-wider mt-1">{level.toUpperCase()}</div>
              {scans.length > 0 && <div className="text-[9px] text-slate-600 mt-0.5">{((count / scans.length) * 100).toFixed(1)}%</div>}
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="cyber-card">
        <CardHeader className="pb-2 pt-4 px-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <CardTitle className="text-sm font-semibold tracking-wider text-cyber-cyan flex items-center gap-2">
              <Database className="h-4 w-4" /> THREAT INTELLIGENCE DATABASE
            </CardTitle>
            <div className="flex gap-1.5">
              {["all", "malware", "phishing"].map((f) => (
                <Button key={f} variant="outline" size="sm" onClick={() => setFilter(f)}
                  className={cn("text-[10px] tracking-wider h-7 px-2.5",
                    filter === f ? "bg-cyber-cyan/20 border-cyber-cyan/50 text-cyber-cyan" : "border-cyber-border text-slate-500"
                  )}>{f.toUpperCase()}</Button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-4">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-40 text-slate-600 text-sm gap-2">
              <Database className="h-8 w-8 opacity-50" />
              <span>No threat intelligence data yet. Run scans to populate.</span>
            </div>
          ) : (
            <ScrollArea className="max-h-[500px] cyber-scrollbar">
              <div className="space-y-1.5">
                {filtered.slice().reverse().map((scan) => (
                  <div key={scan.id} className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 p-3 rounded border border-cyber-border hover:bg-white/[0.02] transition-colors">
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <div className="flex items-center gap-1.5 shrink-0">
                        {scan.type === "malware" ? <Bug className="h-4 w-4 text-cyber-red" /> : <ShieldAlert className="h-4 w-4 text-cyber-amber" />}
                        {scan.subType && <span className="text-[8px] text-slate-600 uppercase">{scan.subType}</span>}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="text-xs font-mono text-slate-300 truncate">{scan.target}</div>
                        <div className="text-[10px] text-slate-600 font-mono">{new Date(scan.timestamp).toLocaleString()}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="hidden sm:flex items-center gap-2">
                        <div className="w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full rounded-full transition-all" style={{
                            width: `${scan.score}%`,
                            backgroundColor: scan.score >= 80 ? "#ff3344" : scan.score >= 60 ? "#ff6b35" : scan.score >= 40 ? "#ffaa00" : scan.score >= 20 ? "#00f0ff" : "#00ff88",
                          }} />
                        </div>
                        <span className="text-[10px] text-slate-500 w-8 text-right">{scan.score}</span>
                      </div>
                      <ThreatBadge level={scan.threatLevel} />
                      <Badge variant="outline" className="text-[9px] border-cyber-border text-slate-500 hidden md:flex">
                        {scan.engines.filter(e => e.result === "malicious" || e.result === "suspicious").length}/{scan.engines.length}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ============ FOOTER ============
function Footer() {
  return (
    <footer className="border-t border-cyber-border bg-cyber-darker/80 mt-auto">
      <div className="px-4 py-3 flex flex-col sm:flex-row items-center justify-between gap-2 text-[10px] text-slate-600">
        <div className="flex items-center gap-2">
          <Shield className="h-3 w-3 text-cyber-cyan" />
          <span>CYBER DEFENDER v3.0.0 | AI-POWERED SECURITY OPERATIONS CENTER</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-cyber-green animate-pulse" /> ALL SYSTEMS OPERATIONAL
          </span>
        </div>
      </div>
    </footer>
  );
}

// ============ MAIN APP ============
export default function CyberDefender() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [monitorActive, setMonitorActive] = useState(true);
  const [stats, setStats] = useState<SystemStats>({
    threatsBlocked: 0, scansToday: 0, activeMonitors: 14, networkPackets: 0,
    startTime: Date.now(), threatLevel: "low",
  });

  // Keep uptime ticking
  useEffect(() => {
    const i = setInterval(() => setStats(s => ({ ...s })), 1000);
    return () => clearInterval(i);
  }, []);

  // Add alert helper
  const addAlert = useCallback((alert: Omit<ThreatAlert, "id" | "timestamp" | "resolved">) => {
    setAlerts(prev => [...prev, {
      ...alert,
      id: `alert-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: new Date().toISOString(),
      resolved: false,
    }]);
  }, []);

  // Recalc threat level whenever alerts or scans change
  useEffect(() => {
    setStats(prev => ({ ...prev, threatLevel: computeThreatLevel(alerts, scanResults) }));
  }, [alerts, scanResults]);

  // Scan handler for malware
  const handleMalwareScan = useCallback(async (target: string) => {
    setIsScanning(true);
    setActiveTab("malware");
    addAlert({ type: "scan", severity: "info", source: target, description: `Malware scan initiated for: ${target}` });

    try {
      const res = await fetch("/api/scan/malware", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });
      if (!res.ok) throw new Error("Scan failed");
      const data = await res.json();

      const result: ScanResult = {
        id: `scan-${Date.now()}`, type: "malware", target, threatLevel: data.threatLevel,
        score: data.score, details: data.details, timestamp: new Date().toISOString(),
        engines: data.engines || [], indicators: data.indicators || [], recommendations: data.recommendations || [],
      };
      setScanResults(prev => [...prev, result]);
      setStats(prev => ({
        ...prev,
        scansToday: prev.scansToday + 1,
        threatsBlocked: data.threatLevel !== "safe" ? prev.threatsBlocked + 1 : prev.threatsBlocked,
        networkPackets: prev.networkPackets + Math.floor(Math.random() * 500) + 100,
      }));

      if (data.threatLevel === "safe") {
        addAlert({ type: "scan", severity: "low", source: target, description: `Malware scan completed: CLEAN — No threats detected in "${target}"` });
      } else {
        addAlert({ type: "malware", severity: data.threatLevel as ThreatAlert["severity"], source: target,
          description: `Malware DETECTED in "${target}" — Score: ${data.score}/100, Level: ${data.threatLevel}. ${data.indicators?.[0] || ""}` });
      }
    } catch (err) {
      addAlert({ type: "info", severity: "medium", source: target, description: `Malware scan failed for "${target}". Error: ${err instanceof Error ? err.message : "Unknown"}` });
    } finally {
      setIsScanning(false);
    }
  }, [addAlert]);

  // Scan handler for phishing (with mode)
  const handlePhishingScan = useCallback(async (target: string, mode: "url" | "email") => {
    setIsScanning(true);
    setActiveTab("phishing");
    addAlert({ type: "scan", severity: "info", source: mode === "url" ? target : "Email Content",
      description: `Phishing ${mode} analysis initiated for: ${mode === "url" ? target : target.slice(0, 60)}...` });

    try {
      const res = await fetch("/api/scan/phishing", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, mode }),
      });
      if (!res.ok) throw new Error("Scan failed");
      const data = await res.json();

      const result: ScanResult = {
        id: `scan-${Date.now()}`, type: "phishing", subType: mode, target, threatLevel: data.threatLevel,
        score: data.score, details: data.details, timestamp: new Date().toISOString(),
        engines: data.engines || [], indicators: data.indicators || [], recommendations: data.recommendations || [],
      };
      setScanResults(prev => [...prev, result]);
      setStats(prev => ({
        ...prev,
        scansToday: prev.scansToday + 1,
        threatsBlocked: data.threatLevel !== "safe" ? prev.threatsBlocked + 1 : prev.threatsBlocked,
        networkPackets: prev.networkPackets + Math.floor(Math.random() * 500) + 100,
      }));

      if (data.threatLevel === "safe") {
        addAlert({ type: "scan", severity: "low", source: mode === "url" ? target : "Email",
          description: `Phishing ${mode} analysis completed: CLEAN — No phishing indicators detected` });
      } else {
        addAlert({ type: "phishing", severity: data.threatLevel as ThreatAlert["severity"],
          source: mode === "url" ? target : "Email Content",
          description: `Phishing ${mode} DETECTED — Score: ${data.score}/100, Level: ${data.threatLevel}. ${data.indicators?.[0] || ""}` });
      }
    } catch (err) {
      addAlert({ type: "info", severity: "medium", source: mode === "url" ? target : "Email",
        description: `Phishing analysis failed. Error: ${err instanceof Error ? err.message : "Unknown"}` });
    } finally {
      setIsScanning(false);
    }
  }, [addAlert]);

  return (
    <div className="min-h-screen flex flex-col bg-cyber-darker cyber-grid-bg relative">
      <div className="fixed inset-0 cyber-scanline pointer-events-none z-[100] opacity-30" />
      <Header stats={stats} activeTab={activeTab} onTabChange={setActiveTab} />

      <main className="flex-1">
        <AnimatePresence mode="wait">
          {activeTab === "dashboard" && (
            <motion.div key="dashboard" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <CommandCenter stats={stats} alerts={alerts} scans={scanResults} />
            </motion.div>
          )}
          {activeTab === "malware" && (
            <motion.div key="malware" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <MalwareScanner onScan={handleMalwareScan} isScanning={isScanning} scanResults={scanResults.filter(s => s.type === "malware")} />
            </motion.div>
          )}
          {activeTab === "phishing" && (
            <motion.div key="phishing" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <PhishingDetector onScan={handlePhishingScan} isScanning={isScanning} scanResults={scanResults} />
            </motion.div>
          )}
          {activeTab === "ids" && (
            <motion.div key="ids" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <IDSMonitor alerts={alerts} scans={scanResults} monitorActive={monitorActive} onToggleMonitor={() => setMonitorActive(!monitorActive)} />
            </motion.div>
          )}
          {activeTab === "intelligence" && (
            <motion.div key="intelligence" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <IntelligenceCenter scans={scanResults} />
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <Footer />
    </div>
  );
}
