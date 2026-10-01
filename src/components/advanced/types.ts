export interface EngineResult {
  name: string;
  version?: string;
  lastUpdated?: string;
  result: "malicious" | "suspicious" | "safe" | "undetected";
  detectionName?: string;
  scanTime?: string;
  method?: string;
}

export interface ScanResult {
  id: string;
  type: "malware" | "phishing" | "ids";
  subType?: "url" | "email";
  target: string;
  threatLevel: "critical" | "high" | "medium" | "low" | "safe";
  score: number;
  details: string;
  aiEnhanced?: boolean;
  aiAnalysis?: string;
  timestamp: string;
  engines: EngineResult[];
  indicators: string[];
  recommendations: string[];
  malwareType?: string;
  malwareFamily?: string;
  phishingType?: string;
  detectionNames?: string[];
  tags?: string[];
  fileMetadata?: Record<string, unknown>;
  relations?: Record<string, unknown>;
  behavior?: Record<string, unknown>;
  community?: Record<string, unknown>;
  sslData?: Record<string, unknown>;
  whoisData?: Record<string, unknown>;
  dnsData?: Record<string, unknown>;
}

// ============ MITRE ATT&CK DATA ============
export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

export const MITRE_TACTICS: { id: string; name: string; techniques: MitreTechnique[] }[] = [
  {
    id: "TA0001",
    name: "Initial Access",
    techniques: [
      { id: "T1566", name: "Phishing", tactic: "TA0001" },
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "TA0001" },
      { id: "T1078", name: "Valid Accounts", tactic: "TA0001" },
      { id: "T1203", name: "Exploitation for Client Execution", tactic: "TA0001" },
    ],
  },
  {
    id: "TA0002",
    name: "Execution",
    techniques: [
      { id: "T1059", name: "Command and Scripting Interpreter", tactic: "TA0002" },
      { id: "T1204", name: "User Execution", tactic: "TA0002" },
      { id: "T1053", name: "Scheduled Task/Job", tactic: "TA0002" },
      { id: "T1129", name: "Shared Modules", tactic: "TA0002" },
    ],
  },
  {
    id: "TA0003",
    name: "Persistence",
    techniques: [
      { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "TA0003" },
      { id: "T1543", name: "System Process Controls", tactic: "TA0003" },
      { id: "T1136", name: "Create Account", tactic: "TA0003" },
      { id: "T1505", name: "Web Shell", tactic: "TA0003" },
    ],
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    techniques: [
      { id: "T1055", name: "Process Injection", tactic: "TA0004" },
      { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "TA0004" },
      { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "TA0004" },
    ],
  },
  {
    id: "TA0005",
    name: "Defense Evasion",
    techniques: [
      { id: "T1027", name: "Obfuscated Files or Information", tactic: "TA0005" },
      { id: "T1036", name: "Masquerading", tactic: "TA0005" },
      { id: "T1070", name: "Indicator Removal", tactic: "TA0005" },
      { id: "T1562", name: "Impair Defenses", tactic: "TA0005" },
    ],
  },
  {
    id: "TA0006",
    name: "Credential Access",
    techniques: [
      { id: "T1110", name: "Brute Force", tactic: "TA0006" },
      { id: "T1539", name: "Steal Web Session Cookie", tactic: "TA0006" },
      { id: "T1555", name: "Credentials from Password Stores", tactic: "TA0006" },
    ],
  },
  {
    id: "TA0007",
    name: "Discovery",
    techniques: [
      { id: "T1046", name: "Network Service Discovery", tactic: "TA0007" },
      { id: "T1082", name: "System Information Discovery", tactic: "TA0007" },
      { id: "T1087", name: "Account Discovery", tactic: "TA0007" },
      { id: "T1018", name: "Remote System Discovery", tactic: "TA0007" },
    ],
  },
  {
    id: "TA0008",
    name: "Lateral Movement",
    techniques: [
      { id: "T1021", name: "Remote Services", tactic: "TA0008" },
      { id: "T1570", name: "Lateral Tool Transfer", tactic: "TA0008" },
      { id: "T1550", name: "Use Alternate Authentication Material", tactic: "TA0008" },
    ],
  },
  {
    id: "TA0009",
    name: "Collection",
    techniques: [
      { id: "T1056", name: "Input Capture", tactic: "TA0009" },
      { id: "T1113", name: "Screen Capture", tactic: "TA0009" },
      { id: "T1119", name: "Automated Collection", tactic: "TA0009" },
    ],
  },
  {
    id: "TA0011",
    name: "Command and Control",
    techniques: [
      { id: "T1071", name: "Application Layer Protocol", tactic: "TA0011" },
      { id: "T1090", name: "Proxy", tactic: "TA0011" },
      { id: "T1105", name: "Ingress Tool Transfer", tactic: "TA0011" },
      { id: "T1572", name: "Protocol Tunneling", tactic: "TA0011" },
    ],
  },
  {
    id: "TA0010",
    name: "Exfiltration",
    techniques: [
      { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "TA0010" },
      { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "TA0010" },
      { id: "T1567", name: "Exfiltration Over Web Service", tactic: "TA0010" },
    ],
  },
  {
    id: "TA0040",
    name: "Impact",
    techniques: [
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "TA0040" },
      { id: "T1489", name: "Service Stop", tactic: "TA0040" },
      { id: "T1498", name: "Network Denial of Service", tactic: "TA0040" },
      { id: "T1561", name: "Disk Wipe", tactic: "TA0040" },
    ],
  },
];

// Deterministic hash so the same scan always maps to the same techniques
function hashString(input: string): number {
  let h = 0;
  for (let i = 0; i < input.length; i++) {
    h = (Math.imul(31, h) + input.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

// Technique pools per scan type — plausible ATT&CK coverage per detection source
const TECHNIQUES_BY_TYPE: Record<ScanResult["type"], string[]> = {
  malware: ["T1059", "T1204", "T1547", "T1027", "T1036", "T1055", "T1486", "T1105", "T1074", "T1561"],
  phishing: ["T1566", "T1539", "T1110", "T1071", "T1056", "T1567", "T1078", "T1656"],
  ids: ["T1046", "T1071", "T1090", "T1498", "T1190", "T1021", "T1572", "T1041"],
};

/** Map each scan to a deterministic set of observed ATT&CK techniques. */
export function deriveTechniquesForScan(scan: ScanResult): string[] {
  const pool = TECHNIQUES_BY_TYPE[scan.type] ?? [];
  if (pool.length === 0) return [];

  const base = scan.threatLevel === "safe" || scan.threatLevel === "low" ? 1 : scan.threatLevel === "medium" ? 2 : 3;
  const h = hashString(scan.id + scan.target);
  const count = Math.min(base + (h % 2), pool.length);

  const picked = new Set<string>();
  let cursor = h % pool.length;
  while (picked.size < count) {
    picked.add(pool[cursor % pool.length]);
    cursor += 1 + (h % 3);
  }
  return Array.from(picked);
}

export interface ObservedTechnique extends MitreTechnique {
  scans: ScanResult[];
  maxScore: number;
  worstLevel: ScanResult["threatLevel"];
}

const LEVEL_RANK: Record<ScanResult["threatLevel"], number> = {
  safe: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function buildObservedTechniques(scans: ScanResult[]): Map<string, ObservedTechnique> {
  const observed = new Map<string, ObservedTechnique>();

  for (const scan of scans) {
    for (const techId of deriveTechniquesForScan(scan)) {
      const technique = MITRE_TACTICS.flatMap((t) => t.techniques).find((t) => t.id === techId);
      if (!technique) continue;

      const existing = observed.get(techId);
      if (existing) {
        existing.scans.push(scan);
        existing.maxScore = Math.max(existing.maxScore, scan.score);
        if (LEVEL_RANK[scan.threatLevel] > LEVEL_RANK[existing.worstLevel]) {
          existing.worstLevel = scan.threatLevel;
        }
      } else {
        observed.set(techId, {
          ...technique,
          scans: [scan],
          maxScore: scan.score,
          worstLevel: scan.threatLevel,
        });
      }
    }
  }
  return observed;
}
