"use client";

import { useMemo, useState } from "react";
import { Network, Radar } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import type { ScanResult } from "./types";

const LEVEL_COLORS: Record<ScanResult["threatLevel"], string> = {
  critical: "#ff3344",
  high: "#ff5566",
  medium: "#ffaa00",
  low: "#00ff88",
  safe: "#475569",
};

const MAX_INDICATORS_PER_SCAN = 5;
const WIDTH = 900;
const HEIGHT = 560;
const CENTER = { x: WIDTH / 2, y: HEIGHT / 2 };
const SCAN_RADIUS = 150;
const INDICATOR_RADIUS = 255;

interface GraphNode {
  id: string;
  label: string;
  x: number;
  y: number;
  kind: "scan" | "indicator";
  scan?: ScanResult;
}

interface GraphEdge {
  from: { x: number; y: number };
  to: { x: number; y: number };
  scanId: string;
}

function hashString(input: string): number {
  let h = 0;
  for (let i = 0; i < input.length; i++) {
    h = (Math.imul(31, h) + input.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

function buildGraph(scans: ScanResult[]) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const scanCount = Math.max(scans.length, 1);

  scans.forEach((scan, i) => {
    const h = hashString(scan.id);
    const angle = (i / scanCount) * Math.PI * 2 + (h % 10) * 0.02;
    const sx = CENTER.x + Math.cos(angle) * SCAN_RADIUS;
    const sy = CENTER.y + Math.sin(angle) * SCAN_RADIUS * 0.82;

    nodes.push({ id: `scan:${scan.id}`, label: scan.target, x: sx, y: sy, kind: "scan", scan });

    const indicators = scan.indicators.slice(0, MAX_INDICATORS_PER_SCAN);
    indicators.forEach((ind, j) => {
      let node = nodes.find((n) => n.id === `ind:${ind}`);
      if (!node) {
        const ih = hashString(ind);
        const iAngle = (ih % 360) * (Math.PI / 180) + j * 0.35;
        node = {
          id: `ind:${ind}`,
          label: ind.length > 28 ? `${ind.slice(0, 26)}…` : ind,
          x: CENTER.x + Math.cos(iAngle) * INDICATOR_RADIUS,
          y: CENTER.y + Math.sin(iAngle) * INDICATOR_RADIUS * 0.82,
          kind: "indicator",
        };
        nodes.push(node);
      }
      edges.push({ from: { x: sx, y: sy }, to: { x: node.x, y: node.y }, scanId: scan.id });
    });
  });

  return { nodes, edges };
}

export default function ThreatGraph({ scans }: { scans: ScanResult[] }) {
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);

  const { nodes, edges } = useMemo(() => buildGraph(scans), [scans]);
  const selectedScan = scans.find((s) => s.id === selectedScanId) ?? null;

  return (
    <div className="space-y-4">
      <Card className="cyber-card border-cyber-border">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <CardTitle className="flex items-center gap-2 text-cyber-cyan text-base font-mono">
              <Network className="w-4 h-4" />
              THREAT RELATIONSHIP GRAPH
            </CardTitle>
            <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400">
              <Badge variant="outline" className="border-cyber-border text-slate-400">
                {scans.length} scan nodes
              </Badge>
              <Badge variant="outline" className="border-cyber-border text-slate-400">
                {edges.length} links
              </Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {scans.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-slate-500 gap-2">
              <Radar className="w-8 h-8 opacity-40" />
              <p className="text-xs font-mono">No scan data — run a scan to build the threat graph.</p>
            </div>
          ) : (
            <GraphSvg
              nodes={nodes}
              edges={edges}
              selectedScanId={selectedScanId}
              onSelect={setSelectedScanId}
            />
          )}
          <Legend />
        </CardContent>
      </Card>

      {selectedScan && <ScanSummary scan={selectedScan} />}
    </div>
  );
}

function GraphSvg({
  nodes,
  edges,
  selectedScanId,
  onSelect,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedScanId: string | null;
  onSelect: (id: string | null) => void;
}) {
  const scanNodes = nodes.filter((n) => n.kind === "scan");
  const indicatorNodes = nodes.filter((n) => n.kind === "indicator");

  return (
    <div className="overflow-x-auto cyber-scrollbar">
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full min-w-[640px]">
        {edges.map((edge, i) => {
          const active = selectedScanId === edge.scanId;
          const dim = selectedScanId !== null && !active;
          return (
            <line
              key={`${edge.scanId}-${i}`}
              x1={edge.from.x}
              y1={edge.from.y}
              x2={edge.to.x}
              y2={edge.to.y}
              stroke={active ? "#00f0ff" : "#1a2540"}
              strokeWidth={active ? 1.5 : 1}
              opacity={dim ? 0.25 : 0.9}
            />
          );
        })}

        <g>
          <circle cx={CENTER.x} cy={CENTER.y} r={34} fill="#0d1321" stroke="#00f0ff" strokeWidth={1.5} />
          <circle cx={CENTER.x} cy={CENTER.y} r={44} fill="none" stroke="#00f0ff" strokeWidth={0.5} opacity={0.4} />
          <text x={CENTER.x} y={CENTER.y + 4} textAnchor="middle" fill="#00f0ff" fontSize={11} fontFamily="monospace">
            CORE
          </text>
        </g>

        {scanNodes.map((node) => {
          const scan = node.scan!;
          const color = LEVEL_COLORS[scan.threatLevel];
          const dim = selectedScanId !== null && selectedScanId !== scan.id;
          return (
            <g
              key={node.id}
              onClick={() => onSelect(selectedScanId === scan.id ? null : scan.id)}
              className="cursor-pointer"
              opacity={dim ? 0.3 : 1}
            >
              {selectedScanId === scan.id && (
                <circle cx={node.x} cy={node.y} r={22} fill="none" stroke="#00f0ff" strokeWidth={1} opacity={0.7} />
              )}
              <circle cx={node.x} cy={node.y} r={16} fill="#0a0e1a" stroke={color} strokeWidth={2} />
              <text x={node.x} y={node.y + 3.5} textAnchor="middle" fill={color} fontSize={9} fontFamily="monospace">
                {scan.score}
              </text>
              <text x={node.x} y={node.y + 30} textAnchor="middle" fill="#94a3b8" fontSize={9} fontFamily="monospace">
                {node.label.length > 22 ? `${node.label.slice(0, 20)}…` : node.label}
              </text>
            </g>
          );
        })}

        {indicatorNodes.map((node) => {
          const connected = edges.some((e) => e.to.x === node.x && e.to.y === node.y && e.scanId === selectedScanId);
          const dim = selectedScanId !== null && !connected;
          return (
            <g key={node.id} opacity={dim ? 0.25 : 1}>
              <rect
                x={node.x - 5}
                y={node.y - 5}
                width={10}
                height={10}
                fill="#0a0e1a"
                stroke="#00f0ff"
                strokeWidth={1}
                transform={`rotate(45 ${node.x} ${node.y})`}
              />
              <text x={node.x} y={node.y - 10} textAnchor="middle" fill="#64748b" fontSize={8.5} fontFamily="monospace">
                {node.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function Legend() {
  return (
    <div className="mt-3 flex items-center gap-4 justify-center text-[9px] font-mono text-slate-500">
      {Object.entries(LEVEL_COLORS).map(([level, color]) => (
        <span key={level} className="flex items-center gap-1">
          <span className="inline-block w-2 h-2 rounded-full" style={{ background: color }} />
          {level}
        </span>
      ))}
    </div>
  );
}

function ScanSummary({ scan }: { scan: ScanResult }) {
  return (
    <Card className="cyber-card border-cyber-border cyber-border-glow">
      <CardHeader className="pb-2">
        <CardTitle className={cn("text-sm font-mono")} style={{ color: LEVEL_COLORS[scan.threatLevel] }}>
          {scan.type.toUpperCase()} — {scan.target}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="max-h-40">
          <div className="text-[11px] text-slate-300 font-mono space-y-1">
            <p>{scan.details}</p>
            {scan.indicators.length > 0 && (
              <div className="flex flex-wrap gap-1 pt-2">
                {scan.indicators.map((ind) => (
                  <Badge key={ind} variant="outline" className="border-cyber-border text-slate-400 text-[9px] font-mono">
                    {ind}
                  </Badge>
                ))}
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

