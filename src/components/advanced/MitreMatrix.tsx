"use client";

import { useMemo, useState } from "react";
import { Crosshair, Grid3x3, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import {
  buildObservedTechniques,
  MITRE_TACTICS,
  type ObservedTechnique,
  type ScanResult,
} from "./types";

const LEVEL_STYLES: Record<ScanResult["threatLevel"], { border: string; text: string; bg: string }> = {
  critical: { border: "border-cyber-red", text: "text-cyber-red", bg: "bg-cyber-red/15" },
  high: { border: "border-cyber-red/60", text: "text-cyber-red", bg: "bg-cyber-red/10" },
  medium: { border: "border-cyber-amber", text: "text-cyber-amber", bg: "bg-cyber-amber/15" },
  low: { border: "border-cyber-green/60", text: "text-cyber-green", bg: "bg-cyber-green/10" },
  safe: { border: "border-cyber-border", text: "text-slate-400", bg: "bg-cyber-panel" },
};

export default function MitreMatrix({ scans }: { scans: ScanResult[] }) {
  const [selected, setSelected] = useState<string | null>(null);

  const observed = useMemo(() => buildObservedTechniques(scans), [scans]);
  const detectedCount = observed.size;
  const coveredScans = useMemo(
    () => new Set(Array.from(observed.values()).flatMap((t) => t.scans.map((s) => s.id))).size,
    [observed]
  );

  const selectedTech = selected ? observed.get(selected) : undefined;

  return (
    <div className="space-y-4">
      <Card className="cyber-card border-cyber-border">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <CardTitle className="flex items-center gap-2 text-cyber-cyan text-base font-mono">
              <Grid3x3 className="w-4 h-4" />
              MITRE ATT&amp;CK MATRIX
            </CardTitle>
            <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400">
              <Badge variant="outline" className="border-cyber-cyan/40 text-cyber-cyan">
                {detectedCount} techniques observed
              </Badge>
              <Badge variant="outline" className="border-cyber-border text-slate-400">
                {coveredScans}/{scans.length} scans mapped
              </Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {scans.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-slate-500 gap-2">
              <ShieldAlert className="w-8 h-8 opacity-40" />
              <p className="text-xs font-mono">No scan data — run a scan to map attacker techniques.</p>
            </div>
          ) : (
            <MitreGrid observed={observed} selected={selected} onSelect={setSelected} />
          )}
        </CardContent>
      </Card>

      {selectedTech && <TechniqueDetail technique={selectedTech} />}
    </div>
  );
}

function MitreGrid({
  observed,
  selected,
  onSelect,
}: {
  observed: ReturnType<typeof buildObservedTechniques>;
  selected: string | null;
  onSelect: (id: string | null) => void;
}) {
  return (
    <ScrollArea className="w-full">
      <div className="flex gap-2 pb-2 min-w-max">
        {MITRE_TACTICS.map((tactic) => {
          const tacticObserved = tactic.techniques.filter((t) => observed.has(t.id));
          return (
            <div key={tactic.id} className="w-44 shrink-0 space-y-2">
              <div className="text-center">
                <div className="text-[11px] font-mono font-bold text-cyber-cyan cyber-glow truncate" title={tactic.name}>
                  {tactic.name}
                </div>
                <div className="text-[9px] text-slate-600 font-mono">
                  {tactic.id} · {tacticObserved.length}/{tactic.techniques.length}
                </div>
              </div>
              <div className="space-y-1.5">
                {tactic.techniques.map((technique) => {
                  const obs = observed.get(technique.id);
                  const style = obs ? LEVEL_STYLES[obs.worstLevel] : null;
                  const isSelected = selected === technique.id;
                  return (
                    <button
                      key={technique.id}
                      type="button"
                      disabled={!obs}
                      onClick={() => onSelect(isSelected ? null : technique.id)}
                      className={cn(
                        "w-full text-left rounded border px-2 py-1.5 transition-all",
                        obs
                          ? cn(style?.border, style?.bg, "hover:brightness-125 cursor-pointer")
                          : "border-cyber-border/40 bg-cyber-dark/50 opacity-40 cursor-default"
                      )}
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className={cn("text-[9px] font-mono", obs ? style?.text : "text-slate-600")}>
                          {technique.id}
                        </span>
                        {obs && <span className="text-[9px] font-mono text-slate-500">×{obs.scans.length}</span>}
                      </div>
                      <div className={cn("text-[10px] leading-tight", obs ? "text-slate-200" : "text-slate-600")}>
                        {technique.name}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </ScrollArea>
  );
}

function TechniqueDetail({ technique }: { technique: ObservedTechnique }) {
  return (
    <Card className="cyber-card border-cyber-border cyber-border-glow">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-mono text-cyber-cyan">
          <Crosshair className="w-4 h-4" />
          {technique.id} — {technique.name}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="flex items-center gap-2">
          <Badge className={cn("font-mono text-[10px] border-0", LEVEL_STYLES[technique.worstLevel].bg, LEVEL_STYLES[technique.worstLevel].text)}>
            worst severity: {technique.worstLevel}
          </Badge>
          <Badge variant="outline" className="border-cyber-border text-slate-400 font-mono text-[10px]">
            max score: {technique.maxScore}
          </Badge>
        </div>
        <ScrollArea className="max-h-48">
          <div className="space-y-1.5">
            {technique.scans.map((scan) => (
              <div
                key={scan.id}
                className="flex items-center justify-between gap-2 rounded border border-cyber-border/60 bg-cyber-dark/60 px-2 py-1.5 text-[11px]"
              >
                <div className="min-w-0">
                  <span className="font-mono text-cyber-cyan">{scan.type.toUpperCase()}</span>
                  <span className="ml-2 text-slate-300 truncate">{scan.target}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="font-mono text-slate-500">{scan.score}</span>
                  <span className={cn("font-mono", LEVEL_STYLES[scan.threatLevel].text)}>{scan.threatLevel}</span>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
