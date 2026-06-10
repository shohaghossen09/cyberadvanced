// ============================================================================
// Cyber Defender — Comprehensive Heuristic Analysis Engine
// ============================================================================
// Self-contained analysis engine that generates VirusTotal-style multi-engine
// scan results. Completely deterministic — same input always produces the same
// output. No external dependencies.
// ============================================================================

// ======================== TYPE EXPORTS =====================================

export type ThreatLevel = "critical" | "high" | "medium" | "low" | "safe";
export type EngineVerdict = "malicious" | "suspicious" | "safe" | "undetected";
export type EngineMethod = "signature" | "heuristic" | "ml" | "behavior" | "sandbox";

export interface EngineResult {
  name: string;
  version: string;
  lastUpdated: string;
  result: EngineVerdict;
  detectionName: string;
  scanTime: string;
  method: EngineMethod;
}

export interface FileMetadata {
  target: string;
  inputType: "hash" | "url" | "filename";
  fileType: string;
  fileSize: string;
  md5: string;
  sha1: string;
  sha256: string;
  ssdeep: string;
  firstSeen: string;
  lastAnalysis: string;
  submissionCount: number;
  reputationScore: number;
  magic: string;
  trid: string[];
  packers: string[];
}

export interface Relations {
  contactedDomains: string[];
  contactedIPs: string[];
  contactedURLs: string[];
  downloadedFiles: string[];
  executingFiles: string[];
  similarFiles: string[];
}

export interface Behavior {
  network: { action: string; destination: string; port: number; protocol: string }[];
  filesystem: { action: string; target: string; description: string }[];
  registry: { action: string; key: string; description: string }[];
  process: { action: string; process: string; description: string }[];
}

export interface CommunityData {
  votes: { harmless: number; malicious: number };
  comments: { date: string; user: string; text: string; verdict: string }[];
  popularityRank: number;
  totalVotes: number;
  communityScore: number;
}

export interface MalwareAnalysisResult {
  score: number;
  threatLevel: ThreatLevel;
  malwareType: string;
  malwareFamily: string;
  details: string;
  engines: EngineResult[];
  fileMetadata: FileMetadata;
  detectionNames: string[];
  tags: string[];
  indicators: string[];
  recommendations: string[];
  relations: Relations;
  behavior: Behavior;
  community: CommunityData;
}

export interface PhishingFileMetadata {
  target: string;
  targetType: "url" | "email";
  firstSeen: string;
  lastAnalysis: string;
  submissionCount: number;
  reputationScore: number;
  category: string;
  threatClassification: string;
}

export interface SSLData {
  issuer: string;
  validFrom: string;
  validTo: string;
  protocol: string;
  isExpired: boolean;
  isSelfSigned: boolean;
}

export interface WHOISData {
  registrar: string;
  creationDate: string;
  expirationDate: string;
  nameServers: string[];
  registrantOrg: string;
  registrantCountry: string;
}

export interface DNSData {
  aRecords: string[];
  mxRecords: string[];
  nsRecords: string[];
  txtRecords: string[];
  soaRecord: string;
}

export interface PhishingAnalysisResult {
  score: number;
  threatLevel: ThreatLevel;
  phishingType: string;
  details: string;
  engines: EngineResult[];
  fileMetadata: PhishingFileMetadata;
  indicators: string[];
  recommendations: string[];
  relations: Relations;
  behavior: Behavior;
  community: CommunityData;
  sslData?: SSLData;
  whoisData?: WHOISData;
  dnsData?: DNSData;
}

// ======================== SEEDED PRNG ======================================

/**
 * Deterministic PRNG seeded from an input string.
 * Uses a simple mulberry32 algorithm for consistency.
 */
function createRNG(seed: number) {
  let s = seed | 0;
  return () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Hash a string to a 32-bit integer */
function hashString(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    hash = ((hash << 5) - hash + ch) | 0;
  }
  return hash;
}

/** Hash a string to an N-bit integer (max 53 bits for JS safety) */
function hashStringN(str: string, bits: number): number {
  const mask = (1 << Math.min(bits, 53)) - 1;
  let h = hashString(str);
  // Extend by re-hashing with different offsets
  for (let shift = 32; shift < bits; shift += 32) {
    h = ((h << 32) | hashString(str + shift.toString())) & mask;
  }
  return h & mask;
}

// ======================== DATA GENERATORS ==================================

/** Generate a hex string of given length deterministically */
function hexFromRNG(rng: () => number, len: number): string {
  const hex = "0123456789abcdef";
  let result = "";
  for (let i = 0; i < len; i++) {
    result += hex[Math.floor(rng() * 16)];
  }
  return result;
}

/** Generate a realistic-looking file hash */
function generateHash(rng: () => number, bits: 32 | 40 | 64 | 128 | 256): string {
  return hexFromRNG(rng, bits / 4);
}

/** Generate an IPv4 address */
function generateIPv4(rng: () => number): string {
  return `${Math.floor(rng() * 223) + 1}.${Math.floor(rng() * 256)}.${Math.floor(rng() * 256)}.${Math.floor(rng() * 256)}`;
}

/** Generate an IPv6 address */
function generateIPv6(rng: () => number): string {
  const groups = Array.from({ length: 8 }, () => hexFromRNG(rng, 4));
  return groups.join(":");
}

/** Domain name components for realistic generation */
const DOMAIN_PREFIXES = [
  "cdn", "api", "static", "mail", "secure", "login", "account", "update",
  "verify", "cdn2", "img", "assets", "web", "app", "srv", "gateway",
  "proxy", "relay", "node", "edge", "origin", "ns1", "ns2", "mx1",
];
const DOMAIN_MID = [
  "cloud", "data", "sys", "net", "web", "tech", "host", "serv", "core",
  "infra", "ops", "main", "prod", "stage", "dev", "live", "fast",
];
const SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cc", ".top", ".click", ".download", ".win", ".bid", ".stream", ".gq", ".cf", ".pw", ".racing"];
const NORMAL_TLDS = [".com", ".net", ".org", ".io", ".co", ".info", ".biz", ".online", ".site", ".app"];

const BRAND_NAMES = ["google", "paypal", "amazon", "microsoft", "apple", "facebook", "netflix", "dropbox", "linkedin", "twitter", "instagram", "whatsapp", "steam", "spotify", "adobe", "yahoo", "outlook", "office365", "chase", "wellsfargo"];
const BRAND_NAMES_CAP = BRAND_NAMES.map(b => b.charAt(0).toUpperCase() + b.slice(1));

/** Generate a domain name */
function generateDomain(rng: () => number, suspicious = false): string {
  const prefix = DOMAIN_PREFIXES[Math.floor(rng() * DOMAIN_PREFIXES.length)];
  const mid = DOMAIN_MID[Math.floor(rng() * DOMAIN_MID.length)];
  const suffix = hexFromRNG(rng, Math.floor(rng() * 4 + 4));
  const tld = suspicious
    ? SUSPICIOUS_TLDS[Math.floor(rng() * SUSPICIOUS_TLDS.length)]
    : NORMAL_TLDS[Math.floor(rng() * NORMAL_TLDS.length)];
  return `${prefix}-${mid}-${suffix}${tld}`;
}

/** Generate a brand-impersonating domain */
function generateBrandDomain(rng: () => number, brand: string): string {
  const typos = [
    brand + "secure", brand + "login", brand + "-verify",
    brand.replace("o", "0"), brand.replace("l", "1"), brand.replace("e", "3"),
    brand + "update", brand + "-account", brand + "safety",
    brand + "-auth", brand + "confirm", "secure-" + brand,
    brand + "-support", brand + "help", brand + "service",
    brand + "-team", brand + "cdn", brand + "cloud",
  ];
  const typo = typos[Math.floor(rng() * typos.length)];
  const tld = SUSPICIOUS_TLDS[Math.floor(rng() * SUSPICIOUS_TLDS.length)];
  return `${typo}${tld}`;
}

/** Generate a random date in the past (daysAgo range) */
function generateDate(rng: () => number, daysAgo: number): string {
  const now = Date.now();
  const offset = Math.floor(rng() * daysAgo * 86400000);
  return new Date(now - offset).toISOString();
}

/** Format ISO date for display */
function formatDate(iso: string): string {
  return new Date(iso).toISOString().slice(0, 10);
}

/** Generate a username */
function generateUsername(rng: () => number): string {
  const prefixes = ["security", "malware", "threat", "cyber", "analyst", "researcher", "hunting", "dfir", "soc", "admin", "user", "tech", "net", "infosec"];
  const suffixes = ["hunter", "analyst", "expert", "pro", "guru", "master", "ninja", "coder", "geek", "fan", "42", "99", "ops", "dev", "watch"];
  return prefixes[Math.floor(rng() * prefixes.length)] + suffixes[Math.floor(rng() * suffixes.length)] + Math.floor(rng() * 999);
}

/** Generate a file size string */
function generateFileSize(rng: () => number): string {
  const sizes = [0.3, 0.5, 0.8, 1.2, 1.5, 2.0, 2.4, 3.1, 4.5, 5.2, 6.8, 8.3, 10.5, 12.7, 15.0, 18.3, 24.5, 32.1, 48.6, 64.2];
  const units = ["KB", "KB", "KB", "MB", "MB", "MB", "MB", "MB", "MB", "MB"];
  const s = sizes[Math.floor(rng() * sizes.length)];
  const u = units[Math.floor(rng() * units.length)];
  return `${s.toFixed(1)} ${u}`;
}

/** Pick N items from array deterministically */
function pickItems<T>(rng: () => number, arr: T[], count: number): T[] {
  const shuffled = [...arr];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled.slice(0, count);
}

// ======================== ENGINE DEFINITIONS ===============================

const MALWARE_ENGINES: { name: string; version: string; method: EngineMethod }[] = [
  { name: "CyberDefender AI", version: "v3.0", method: "ml" },
  { name: "Microsoft Defender", version: "v4.18.24050", method: "signature" },
  { name: "ClamAV", version: "v1.3.1", method: "signature" },
  { name: "YARA Engine", version: "v4.5.0", method: "signature" },
  { name: "Sigma Rules", version: "v2.2", method: "heuristic" },
  { name: "Snort IDS", version: "v3.1.41", method: "behavior" },
  { name: "Suricata", version: "v7.0.4", method: "behavior" },
  { name: "CrowdStrike Falcon", version: "v6.54", method: "ml" },
  { name: "Kaspersky Engine", version: "2024.05", method: "signature" },
  { name: "BitDefender", version: "v7.9", method: "heuristic" },
  { name: "McAfee", version: "v6.0.6342", method: "signature" },
  { name: "Sophos", version: "v4.98", method: "ml" },
  { name: "Avast Engine", version: "v24.04", method: "heuristic" },
  { name: "ESET NOD32", version: "v22165", method: "signature" },
  { name: "Norton LifeLock", version: "v6.3", method: "heuristic" },
  { name: "Trend Micro", version: "v17.0", method: "ml" },
  { name: "Malwarebytes", version: "v5.1", method: "heuristic" },
  { name: "Cisco AMP", version: "v8.4", method: "sandbox" },
  { name: "FireEye NX", version: "v9.2", method: "sandbox" },
  { name: "Palo Alto Unit42", version: "v11.1", method: "behavior" },
];

const PHISHING_URL_ENGINES: { name: string; version: string; method: EngineMethod }[] = [
  { name: "CyberDefender AI", version: "v3.0", method: "ml" },
  { name: "Google Safe Browsing", version: "v4.2", method: "signature" },
  { name: "PhishTank API", version: "v2.0", method: "signature" },
  { name: "URLhaus", version: "v1.3", method: "signature" },
  { name: "Microsoft Defender SmartScreen", version: "v4.18", method: "heuristic" },
  { name: "Norton Safe Web", version: "v3.2", method: "heuristic" },
  { name: "McAfee SiteAdvisor", version: "v4.5", method: "ml" },
  { name: "Web of Trust", version: "v2.8", method: "ml" },
  { name: "Spamhaus ZEN", version: "v3.1", method: "signature" },
  { name: "OpenPhish", version: "v1.5", method: "ml" },
  { name: "Phishing.Database", version: "v2024.05", method: "signature" },
  { name: "VirusTotal URL", version: "v2.1", method: "heuristic" },
  { name: "ESET URL Advisor", version: "v4.0", method: "heuristic" },
  { name: "BitDefender TrafficLight", version: "v3.7", method: "heuristic" },
  { name: "FortiGuard Web Filter", version: "v5.4", method: "signature" },
  { name: "Sucuri SiteCheck", version: "v2.3", method: "sandbox" },
];

const PHISHING_EMAIL_ENGINES: { name: string; version: string; method: EngineMethod }[] = [
  { name: "CyberDefender AI", version: "v3.0", method: "ml" },
  { name: "Email Header Parser", version: "v2.1", method: "heuristic" },
  { name: "Sender Analyzer", version: "v1.8", method: "heuristic" },
  { name: "NLP Engine", version: "v3.2", method: "ml" },
  { name: "Content Analyzer", version: "v2.5", method: "ml" },
  { name: "Link Inspector", version: "v2.0", method: "heuristic" },
  { name: "Domain Validator", version: "v1.9", method: "heuristic" },
  { name: "DKIM/SPF Checker", version: "v2.3", method: "signature" },
  { name: "ML Classifier", version: "v3.0", method: "ml" },
  { name: "Social Engineering Detector", version: "v1.5", method: "behavior" },
  { name: "Urgency Analyzer", version: "v2.1", method: "ml" },
  { name: "Grammar Checker", version: "v1.7", method: "heuristic" },
  { name: "Attachment Scanner", version: "v2.4", method: "signature" },
  { name: "OAuth Token Detector", version: "v1.3", method: "behavior" },
];

// ======================== DETECTION NAME DATABASES =========================

const MALWARE_TYPES: Record<number, string[]> = {
  high: [
    "Trojan.GenericKD.48525312", "Trojan.Win32.Agent.xwz", "W32.Blaster.Worm",
    "Trojan.Dropper.BCMiner", "Backdoor.Win32.DarkComet", "Trojan.Win64.Crypt.abc",
    "Gen:Variant.Razy.485212", "Ransom.WannaCry.B", "Trojan.Inject.Agent.gen",
    "Trojan.Win32.Patched.jd", "Malware.AI.3847291056", "Trojan.Win32.Cosmu.gen",
    "Adware.BrowseFox.Gen", "PUP.Optional.BundleInstaller", "Riskware.Agent.bn",
    "Trojan.GenericKD.52341879", "HackTool.Win32.KMS.gen", "Riskware.BitCoinMiner",
    "Phishing.Email.Spoof.gen", "Spyware.Keylogger.Gen",
  ],
  medium: [
    "PUP.Optional.Conduit", "Adware.Generic.5234", "Riskware.Tool.CK",
    "Suspicious.Agent.Gen", "PUP.BundleInstaller.Oi", "Adware.BrowseFox.2891",
    "Riskware.GameTool.Gen", "PUP.Optional.SearchBar", "HackTool.Patcher.Gen",
    "Not-a-virus:Riskware.NSIS.Downloader",
  ],
  low: [
    "Heuristic.Behaves.Win32.Ext", "Suspicious.Cloud.7", "ARTEMIS!Troya",
    "ML/PE-A", "Gen:Heur.FKP.1",
  ],
};

const MALWARE_FAMILIES: Record<number, string[]> = {
  high: [
    "Emotet", "TrickBot", "Qakbot", "Cobalt Strike", "Ryuk", "Conti",
    "LockBit", "BlackBasta", "ALPHV/BlackCat", "Cl0p", "Volt Typhoon",
    "Lazarus Group", "APT28", "APT29", "Fancy Bear", "DarkSide",
    "REvil", "Dridex", "Ursnif/Gozi", "IcedID",
  ],
  medium: [
    "RedLine Stealer", "Raccoon Stealer", "Vidar", "FormBook", "Agent Tesla",
    "Snake Keylogger", "Rhysida", "Royal Ransomware", "BlackCat", "Hive",
  ],
  low: [
    "Generic PUA", "Adware family", "Riskware bundle",
  ],
};

const PHISHING_TYPES_URL: Record<number, string[]> = {
  high: [
    "Brand Impersonation", "Credential Harvesting", "Phishing Landing Page",
    "Typosquatting Domain", "Homograph Attack", "Compromised Website",
    "Drive-by Download Portal", "Advance Fee Fraud",
  ],
  medium: [
    "Suspicious Redirect Chain", "Newly Registered Domain", "Low Reputation Domain",
    "Self-Signed SSL", "Obfuscated URL", "URL Shortener Abuse",
  ],
  low: [
    "Minor Suspicious Pattern", "Uncommon TLD", "Generic Risk Indicator",
  ],
};

const PHISHING_TYPES_EMAIL: Record<number, string[]> = {
  high: [
    "Credential Harvesting", "Business Email Compromise (BEC)", "CEO Fraud",
    "Spear Phishing", "Social Engineering Attack", "Account Takeover Attempt",
    "Invoice Fraud", "Tech Support Scam", "Advance Fee Fraud",
  ],
  medium: [
    "Suspicious Email Pattern", "Potential Spoofing", "Urgency Language Detected",
    "Mismatched Sender Domain", "Generic Phishing Template",
  ],
  low: [
    "Bulk/Spam Pattern", "Unverified Sender", "Minor Anomaly",
  ],
};

// ======================== HELPER: SCORE → THREAT LEVEL ====================

function scoreToThreatLevel(score: number): ThreatLevel {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "safe";
}

// ======================== HELPER: GENERATE ENGINE RESULTS ==================

function generateEngineResults(
  rng: () => number,
  engines: { name: string; version: string; method: EngineMethod }[],
  score: number,
  detectionNames: string[],
  isEmail = false,
): EngineResult[] {
  const factor = score / 100;

  return engines.map((engine, i) => {
    // Each engine has its own threshold influenced by its index (deterministic per input)
    const engineBias = (rng() * 0.3 - 0.15); // -0.15 to +0.15 per engine
    const adjustedFactor = Math.max(0, Math.min(1, factor + engineBias));

    let result: EngineVerdict;
    let detectionName = "clean";

    if (adjustedFactor >= 0.65) {
      result = "malicious";
      detectionName = detectionNames[Math.floor(rng() * detectionNames.length)];
    } else if (adjustedFactor >= 0.42) {
      result = "suspicious";
      detectionName = detectionNames.length > 0
        ? "Suspicious:" + detectionNames[Math.floor(rng() * detectionNames.length)]
        : "Suspicious.Generic";
    } else if (adjustedFactor >= 0.22) {
      result = "undetected";
    } else {
      result = "safe";
    }

    // First engine (CyberDefender AI) is more sensitive
    if (i === 0 && factor >= 0.35) {
      result = factor >= 0.6 ? "malicious" : "suspicious";
      detectionName = detectionNames[Math.floor(rng() * detectionNames.length)];
    }

    const scanTime = (rng() * 2.5 + 0.1).toFixed(1) + "s";
    const lastUpdated = generateDate(rng, 90).slice(0, 10);

    return {
      name: engine.name,
      version: engine.version,
      lastUpdated,
      result,
      detectionName,
      scanTime,
      method: engine.method,
    };
  });
}

// ======================== MALWARE ANALYSIS =================================

function detectInputType(target: string): "hash" | "url" | "filename" {
  if (/^[a-fA-F0-9]{32}$/.test(target.trim())) return "hash";
  if (/^[a-fA-F0-9]{40}$/.test(target.trim())) return "hash";
  if (/^[a-fA-F0-9]{64}$/.test(target.trim())) return "hash";
  if (/^https?:\/\//i.test(target.trim())) return "url";
  return "filename";
}

function inferFileType(filename: string): { type: string; magic: string; trid: string[]; riskBase: number } {
  const lower = filename.toLowerCase();

  // Executables — high risk
  if (lower.endsWith(".exe") || lower.endsWith(".scr") || lower.endsWith(".com")) {
    return {
      type: "Win32 EXE",
      magic: "PE32 executable (GUI) x86-64, for MS Windows",
      trid: ["Win64 Executable (generic)", "Win32 EXE", "Generic CIL Executable"],
      riskBase: 50,
    };
  }
  if (lower.endsWith(".msi")) {
    return { type: "Windows Installer", magic: "MSI Installer package", trid: ["Windows Installer Package"], riskBase: 35 };
  }
  if (lower.endsWith(".bat") || lower.endsWith(".cmd")) {
    return { type: "Batch Script", magic: "Batch file (ASCII text)", trid: ["Batch Script", "ASCII text"], riskBase: 40 };
  }
  if (lower.endsWith(".ps1")) {
    return { type: "PowerShell Script", magic: "UTF-8 Unicode (with BOM) text, with CRLF line terminators", trid: ["PowerShell Script", "ASCII text"], riskBase: 55 };
  }
  if (lower.endsWith(".vbs") || lower.endsWith(".vbe")) {
    return { type: "VBScript", magic: "VBScript Script File", trid: ["VBScript", "ASCII text"], riskBase: 45 };
  }
  if (lower.endsWith(".js") || lower.endsWith(".jse")) {
    return { type: "JavaScript", magic: "UTF-8 Unicode text, with CRLF line terminators", trid: ["JavaScript Source", "ASCII text"], riskBase: 35 };
  }
  if (lower.endsWith(".wsf") || lower.endsWith(".hta")) {
    return { type: "Windows Script File", magic: "XML document text", trid: ["XML Document", "Windows Script"], riskBase: 40 };
  }
  if (lower.endsWith(".dll")) {
    return { type: "Win32 DLL", magic: "PE32 DLL (GUI) x86-64, for MS Windows", trid: ["Win64 DLL", "Dynamic Link Library"], riskBase: 40 };
  }
  if (lower.endsWith(".sys")) {
    return { type: "Windows Driver", magic: "PE32 executable (native) x86-64", trid: ["Windows Driver", "PE Executable"], riskBase: 45 };
  }

  // Documents — medium risk
  if (lower.endsWith(".docm") || lower.endsWith(".dotm")) {
    return { type: "MS Word Macro Doc", magic: "Composite Document File V2 Document, Little Endian", trid: ["Microsoft Word 2007+ Document", "OLE2 Compound Document"], riskBase: 45 };
  }
  if (lower.endsWith(".xlsm") || lower.endsWith(".xlsb")) {
    return { type: "MS Excel Macro Sheet", magic: "Composite Document File V2 Document", trid: ["Microsoft Excel 2007+ Workbook", "OLE2 Compound Document"], riskBase: 40 };
  }
  if (lower.endsWith(".pptm")) {
    return { type: "MS PowerPoint Macro", magic: "Composite Document File V2 Document", trid: ["Microsoft PowerPoint 2007+ Presentation"], riskBase: 40 };
  }
  if (lower.endsWith(".doc") || lower.endsWith(".dot")) {
    return { type: "MS Word Document", magic: "Composite Document File V2 Document, Little Endian", trid: ["Microsoft Word 97-2003 Document", "OLE2 Compound Document"], riskBase: 20 };
  }
  if (lower.endsWith(".xls") || lower.endsWith(".xlt")) {
    return { type: "MS Excel Spreadsheet", magic: "Composite Document File V2 Document", trid: ["Microsoft Excel 97-2003 Workbook", "OLE2 Compound Document"], riskBase: 15 };
  }
  if (lower.endsWith(".pdf")) {
    return { type: "PDF Document", magic: "PDF document, version 1.5", trid: ["PDF Document", "Adobe PDF"], riskBase: 18 };
  }
  if (lower.endsWith(".docx") || lower.endsWith(".xlsx") || lower.endsWith(".pptx")) {
    return { type: lower.endsWith(".docx") ? "MS Word Doc" : lower.endsWith(".xlsx") ? "MS Excel Sheet" : "MS PowerPoint",
      magic: "Microsoft OOXML Document (ZIP archive)", trid: ["Microsoft OOXML Document", "ZIP Archive"], riskBase: 8 };
  }

  // Archives — medium-high risk
  if (lower.endsWith(".zip") || lower.endsWith(".rar") || lower.endsWith(".7z") || lower.endsWith(".tar") || lower.endsWith(".gz")) {
    return { type: "Archive File", magic: lower.endsWith(".zip") ? "Zip archive data" : lower.endsWith(".rar") ? "RAR archive data" : "7-zip archive data",
      trid: [lower.endsWith(".zip") ? "ZIP Archive" : lower.endsWith(".rar") ? "RAR Archive" : "7-Zip Archive"], riskBase: 25 };
  }

  // Images — low risk
  if (/\.(jpg|jpeg|png|gif|bmp|webp|svg|ico)$/i.test(lower)) {
    return { type: "Image File", magic: "image data", trid: ["Image File"], riskBase: 5 };
  }

  // APK — high risk
  if (lower.endsWith(".apk")) {
    return { type: "Android APK", magic: "Java archive data (JAR)", trid: ["Android Application Package", "ZIP Archive", "JAR Archive"], riskBase: 45 };
  }

  // DMG / APP — medium risk
  if (lower.endsWith(".dmg")) {
    return { type: "macOS DMG", magic: "Macintosh HFS Extended filesystem data", trid: ["Apple Disk Image", "DMG Disk Image"], riskBase: 20 };
  }
  if (lower.endsWith(".app")) {
    return { type: "macOS Application", magic: "Mach-O universal binary", trid: ["macOS Application Bundle"], riskBase: 25 };
  }

  // Scripts
  if (lower.endsWith(".py")) {
    return { type: "Python Script", magic: "Python script, ASCII text executable", trid: ["Python Script", "ASCII text"], riskBase: 20 };
  }
  if (lower.endsWith(".sh")) {
    return { type: "Shell Script", magic: "Bourne-Again shell script, ASCII text executable", trid: ["Shell Script", "ASCII text"], riskBase: 25 };
  }

  // Default
  return { type: "Unknown File", magic: "data", trid: ["Unknown"], riskBase: 15 };
}

function analyzeMalwareInput(target: string, rng: () => number): {
  score: number;
  detectionNames: string[];
  tags: string[];
  extraIndicators: string[];
} {
  const inputType = detectInputType(target);
  let score = 0;
  const tags: string[] = [];
  const extraIndicators: string[] = [];
  let detectionPool: string[] = [...MALWARE_TYPES.low];

  if (inputType === "hash") {
    // Known suspicious hash patterns
    const t = target.toLowerCase().trim();
    // Some "known" malicious hash prefixes (these are fake but deterministic)
    if (t.startsWith("e3b0c44") || t.startsWith("d41d8cd")) {
      score = 5;
      tags.push("empty-file", "known-safe");
    } else {
      // Generate a score based on hash characteristics
      score = 15;
      // If hash has certain patterns, increase score
      const digitRatio = (t.match(/\d/g) || []).length / t.length;
      if (digitRatio > 0.6) score += 20;
      if (digitRatio < 0.3) score += 10;
      // Use hash value to determine score range (deterministic)
      const hashVal = hashString(target);
      score += (hashVal & 0xFF); // Add 0-255, will be clamped later
    }
  } else if (inputType === "url") {
    // URL analysis
    const lower = target.toLowerCase();

    // Protocol check
    if (lower.startsWith("http://")) {
      score += 15;
      extraIndicators.push("Non-HTTPS protocol detected");
    }

    // IP address in URL
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(target)) {
      score += 25;
      tags.push("ip-address");
      extraIndicators.push("IP address used instead of domain name");
    }

    // Suspicious TLDs
    for (const tld of SUSPICIOUS_TLDS) {
      if (lower.includes(tld)) {
        score += 20;
        tags.push("suspicious-tld");
        extraIndicators.push(`Suspicious TLD: ${tld}`);
        break;
      }
    }

    // Brand impersonation
    for (const brand of BRAND_NAMES) {
      if (lower.includes(brand) && !lower.includes(`${brand}.com`) && !lower.includes(`${brand}.org`) && !lower.includes(`www.${brand}`)) {
        score += 30;
        tags.push("brand-impersonation", "phishing-suspect");
        extraIndicators.push(`Potential brand impersonation: ${brand}`);
        break;
      }
    }

    // Suspicious path patterns
    const suspiciousPaths = /\/(login|secure|verify|account|update|confirm|signin|auth|banking|wallet)\b/i;
    if (suspiciousPaths.test(target)) {
      score += 15;
      tags.push("credential-harvest");
      extraIndicators.push("Suspicious URL path pattern detected");
    }

    // Encoded characters
    if (/%[0-9a-f]{2}/i.test(target)) {
      score += 10;
      tags.push("url-encoding");
      extraIndicators.push("URL encoding detected — possible obfuscation");
    }

    // Double extensions
    if (/\.\w+\.\w{2,4}(\/|$|\?)/i.test(target)) {
      score += 15;
      tags.push("double-extension");
    }

    // Long URL
    if (target.length > 100) {
      score += 10;
      tags.push("long-url");
    }

    // Multiple subdomains
    const domainPart = target.replace(/^https?:\/\//, "").split("/")[0];
    const subdomainCount = (domainPart.match(/\./g) || []).length;
    if (subdomainCount > 3) {
      score += 10;
      tags.push("excessive-subdomains");
    }

    // Download-related keywords
    if (/download|free|crack|keygen|patch|serial/i.test(target)) {
      score += 15;
      tags.push("software-piracy");
    }

    score += 10; // base score for URL
  } else {
    // Filename analysis
    const lower = target.toLowerCase();
    const fileInfo = inferFileType(target);
    score = fileInfo.riskBase;

    // Double extension
    if (/\.\w+\.\w{2,4}$/i.test(target) && !/\.\w{2,4}\.\w{2,4}$/i.test(target)) {
      // e.g., file.pdf.exe
      const extParts = target.split(".");
      if (extParts.length >= 3) {
        score += 30;
        tags.push("double-extension");
        extraIndicators.push(`Double extension detected: ${extParts.slice(-2).join(".")}`);
      }
    }

    // Known malware naming patterns
    const malwarePatterns = [
      /crack|keygen|patch|serial|activat/i,
      /trojan|malware|virus|worm|ransom/i,
      /free\s+(download|version|full)|key\s*gen/i,
      /setup_\d{4,}|installer_\d{4,}|update_\d{4,}/i,
      /[a-z0-9]{20,}/i, // random long strings
      /_([a-z]{6,10})_\d{1,3}\./i,
    ];
    for (const pattern of malwarePatterns) {
      if (pattern.test(lower)) {
        score += 20;
        tags.push("suspicious-naming");
        extraIndicators.push("Suspicious filename pattern detected");
        break;
      }
    }

    // Uppercase extension (sometimes used to bypass filters)
    if (/\.[A-Z]{2,4}$/.test(target)) {
      score += 10;
      tags.push("uppercase-extension");
    }

    // Spaces in filename
    if (target.includes(" ")) {
      score += 5;
    }

    // Very long filename
    if (target.length > 50) {
      score += 10;
      tags.push("long-filename");
    }
  }

  // Clamp score
  score = Math.max(0, Math.min(100, score));

  // Select detection names based on score
  if (score >= 60) {
    detectionPool = [...MALWARE_TYPES.high, ...MALWARE_TYPES.medium];
  } else if (score >= 30) {
    detectionPool = [...MALWARE_TYPES.medium, ...MALWARE_TYPES.low];
  }

  const detectionNames = pickItems(rng, detectionPool, 4 + Math.floor(rng() * 4));

  return { score, detectionNames, tags, extraIndicators };
}

/** Main malware analysis function */
export function analyzeMalware(target: string): MalwareAnalysisResult {
  const rng = createRNG(hashString(target));
  const inputType = detectInputType(target);
  const { score: rawScore, detectionNames, tags, extraIndicators } = analyzeMalwareInput(target, rng);

  // Small deterministic jitter
  const score = Math.max(0, Math.min(100, Math.round(rawScore + (rng() * 10 - 5))));
  const threatLevel = scoreToThreatLevel(score);

  // Generate engine results
  const engines = generateEngineResults(rng, MALWARE_ENGINES, score, detectionNames);
  const maliciousCount = engines.filter(e => e.result === "malicious").length;
  const uniqueDetections = [...new Set(engines.filter(e => e.detectionName !== "clean").map(e => e.detectionName))];

  // Determine malware type and family
  const typePool = score >= 60 ? MALWARE_TYPES.high : score >= 30 ? MALWARE_TYPES.medium : MALWARE_TYPES.low;
  const familyPool = score >= 60 ? MALWARE_FAMILIES.high : score >= 30 ? MALWARE_FAMILIES.medium : MALWARE_FAMILIES.low;
  const malwareType = pickItems(rng, typePool, 1)[0];
  const malwareFamily = pickItems(rng, familyPool, 1)[0];

  // Generate file metadata
  const fileInfo = inputType === "filename" ? inferFileType(target) : {
    type: inputType === "url" ? "URL" : "Win32 EXE",
    magic: inputType === "url" ? "URL resource" : "PE32 executable (GUI) x86-64",
    trid: inputType === "url" ? ["URL Resource"] : ["Win64 Executable (generic)"],
    riskBase: 0,
  };

  // Generate hashes
  const md5Hash = inputType === "hash" && target.trim().length === 32
    ? target.trim().toLowerCase()
    : generateHash(rng, 128);
  const sha1Hash = inputType === "hash" && target.trim().length === 40
    ? target.trim().toLowerCase()
    : generateHash(rng, 160);
  const sha256Hash = inputType === "hash" && target.trim().length === 64
    ? target.trim().toLowerCase()
    : generateHash(rng, 256);
  const ssdeepHash = inputType === "hash"
    ? `${Math.floor(rng() * 96 + 3)}:${hexFromRNG(rng, 6)}:${hexFromRNG(rng, 6)}`
    : `${Math.floor(rng() * 96 + 3)}:${hexFromRNG(rng, 6)}:${hexFromRNG(rng, 6)}`;

  const firstSeen = generateDate(rng, 365);
  const lastAnalysis = generateDate(rng, 3);
  const submissionCount = score >= 60 ? Math.floor(rng() * 500) + 50 : Math.floor(rng() * 50) + 1;
  const reputationScore = Math.round(-100 + (200 * (1 - score / 100)) + (rng() * 20 - 10));

  const fileMetadata: FileMetadata = {
    target,
    inputType,
    fileType: fileInfo.type,
    fileSize: inputType === "url" ? "N/A" : generateFileSize(rng),
    md5: md5Hash,
    sha1: sha1Hash,
    sha256: sha256Hash,
    ssdeep: ssdeepHash,
    firstSeen: formatDate(firstSeen),
    lastAnalysis: formatDate(lastAnalysis),
    submissionCount,
    reputationScore: Math.max(-100, Math.min(100, reputationScore)),
    magic: fileInfo.magic,
    trid: fileInfo.trid,
    packers: score >= 50 && inputType !== "url"
      ? pickItems(rng, ["UPX", "Themida", "VMProtect", "ASPack", "PECompact", "tElock", "MPRESS"], 1 + Math.floor(rng() * 2))
      : [],
  };

  // Generate indicators
  const baseIndicators: string[] = [...extraIndicators];
  if (maliciousCount > 0) baseIndicators.push(`${maliciousCount}/${engines.length} engines detected as malicious`);
  if (score >= 60) baseIndicators.push("Multiple AV engines flagged this sample");
  if (score >= 80) baseIndicators.push("Critical threat — immediate action required");
  if (tags.includes("double-extension")) baseIndicators.push("Double extension used to disguise executable");
  if (tags.includes("brand-impersonation")) baseIndicators.push("Potential brand impersonation attempt");
  if (tags.includes("suspicious-tld")) baseIndicators.push("Hosted on suspicious TLD domain");
  if (tags.includes("ip-address")) baseIndicators.push("Direct IP address used (no domain)");
  if (tags.includes("url-encoding")) baseIndicators.push("URL obfuscation via encoding detected");
  if (inputType === "hash" && score >= 30) baseIndicators.push("Hash matched in threat intelligence databases");
  if (fileMetadata.packers.length > 0) baseIndicators.push(`Packed with: ${fileMetadata.packers.join(", ")}`);
  if (tags.length === 0 && score < 20) baseIndicators.push("No significant threat indicators detected");

  // Generate recommendations
  const recommendations: string[] = [];
  if (score >= 80) {
    recommendations.push(" Quarantine this sample immediately and do not execute");
    recommendations.push("Isolate any system that has interacted with this file");
    recommendations.push("Submit to your organization's incident response team");
    recommendations.push("Block all associated hashes and domains in your SIEM");
  } else if (score >= 60) {
    recommendations.push("Do not execute or open this file");
    recommendations.push("Run in an isolated sandbox environment for further analysis");
    recommendations.push("Scan all systems that may have downloaded this file");
    recommendations.push("Add hashes to blocklist in endpoint protection");
  } else if (score >= 40) {
    recommendations.push("Exercise caution — treat as potentially unwanted");
    recommendations.push("Verify file origin and digital signature");
    recommendations.push("Monitor for suspicious behavior if executed");
  } else if (score >= 20) {
    recommendations.push("Low risk but verify file source before opening");
    recommendations.push("Keep antivirus definitions updated");
  } else {
    recommendations.push("No immediate action required");
    recommendations.push("Continue with standard security practices");
  }

  // Generate relations
  const numRelations = score >= 60 ? 5 : score >= 30 ? 3 : 1;
  const relations: Relations = {
    contactedDomains: pickItems(rng, BRAND_NAMES.map(b => generateDomain(rng, true)), numRelations),
    contactedIPs: Array.from({ length: numRelations }, () => generateIPv4(rng)),
    contactedURLs: Array.from({ length: Math.min(numRelations, 3) }, () =>
      `http://${generateDomain(rng, true)}/` + hexFromRNG(rng, 8)
    ),
    downloadedFiles: score >= 50 ? Array.from({ length: Math.floor(rng() * 3) + 1 }, () =>
      `${hexFromRNG(rng, 8)}.${pickItems(rng, ["exe", "dll", "tmp", "dat"], 1)[0]}`
    ) : [],
    executingFiles: score >= 70 ? Array.from({ length: Math.floor(rng() * 2) + 1 }, () =>
      `C:\\Users\\${hexFromRNG(rng, 6)}\\AppData\\Local\\Temp\\${hexFromRNG(rng, 8)}.exe`
    ) : [],
    similarFiles: Array.from({ length: Math.floor(rng() * 3) }, () => generateHash(rng, 256)),
  };

  // Generate behavior
  const behaviorCount = score >= 70 ? 6 : score >= 40 ? 3 : score >= 20 ? 1 : 0;
  const behavior: Behavior = {
    network: score >= 30 ? Array.from({ length: Math.min(behaviorCount, 4) }, () => ({
      action: pickItems(rng, ["connection", "dns_query", "http_request", "https_request", "udp_send"], 1)[0],
      destination: generateDomain(rng, true),
      port: pickItems(rng, [80, 443, 8080, 8443, 53, 25, 587, 3389, 445, 135], 1)[0],
      protocol: pickItems(rng, ["TCP", "UDP", "DNS", "HTTP", "HTTPS"], 1)[0],
    })) : [],
    filesystem: score >= 40 ? Array.from({ length: Math.min(behaviorCount, 3) }, () => ({
      action: pickItems(rng, ["write", "read", "delete", "create", "modify"], 1)[0],
      target: `C:\\Windows\\${pickItems(rng, ["System32", "Temp", "AppData", "ProgramData"], 1)[0]}\\${hexFromRNG(rng, 8)}.dll`,
      description: pickItems(rng, [
        "Dropped potentially malicious file",
        "Modified system configuration",
        "Created persistence mechanism",
        "Accessed sensitive directory",
      ], 1)[0],
    })) : [],
    registry: score >= 50 ? Array.from({ length: Math.min(behaviorCount, 3) }, () => ({
      action: pickItems(rng, ["set", "add", "delete", "modify"], 1)[0],
      key: `HKEY_\\${pickItems(rng, ["LOCAL_MACHINE", "CURRENT_USER"], 1)[0]}\\Software\\Microsoft\\Windows\\CurrentVersion\\${pickItems(rng, ["Run", "RunOnce", "Services", "Policies"], 1)[0]}\\${hexFromRNG(rng, 8)}`,
      description: pickItems(rng, [
        "Added persistence registry key",
        "Modified startup configuration",
        "Disabled security software via registry",
        "Created scheduled task entry",
      ], 1)[0],
    })) : [],
    process: score >= 60 ? Array.from({ length: Math.min(behaviorCount, 3) }, () => ({
      action: pickItems(rng, ["injected", "spawned", "terminated", "created"], 1)[0],
      process: pickItems(rng, [
        "svchost.exe", "explorer.exe", "rundll32.exe", "powershell.exe",
        "cmd.exe", "wmiprvse.exe", "taskhostw.exe", "lsass.exe",
      ], 1)[0],
      description: pickItems(rng, [
        "Process injection detected",
        "Spawned suspicious child process",
        "Terminated security-related process",
        "Created process from temp directory",
      ], 1)[0],
    })) : [],
  };

  // Generate community data
  const harmlessVotes = score < 40 ? Math.floor(rng() * 50) + 10 : Math.floor(rng() * 15);
  const maliciousVotes = score >= 40 ? Math.floor(rng() * 50) + 10 : Math.floor(rng() * 8);
  const totalVotes = harmlessVotes + maliciousVotes;
  const communityScore = totalVotes > 0 ? Math.round((maliciousVotes / totalVotes) * 100) : 0;

  const commentTemplates = score >= 60
    ? [
        "Confirmed malware — multiple AV detections.",
        "Sample is part of an active campaign. Block immediately.",
        "Contains credential stealer component.",
        "Sandbox analysis shows network callbacks to C2 infrastructure.",
        "This is a known variant with recent activity.",
        "DO NOT EXECUTE. Contains ransomware payload.",
        "Phishing dropper — downloads additional payloads from C2.",
      ]
    : score >= 30
      ? [
        "Suspicious but not definitively malicious. Investigate further.",
        "Could be a PUP. Review before allowing.",
        "Unusual behavior in sandbox. Monitor closely.",
        "Low confidence detection. False positive possible.",
      ]
      : [
        "Clean file. No issues detected.",
        "Legitimate software verified.",
        "False positive. Known good file.",
        "Scanned multiple times — always clean.",
      ];

  const community: CommunityData = {
    votes: { harmless: harmlessVotes, malicious: maliciousVotes },
    comments: Array.from({ length: Math.min(Math.floor(rng() * 4) + 1, commentTemplates.length) }, (_, i) => ({
      date: formatDate(generateDate(rng, 90)),
      user: generateUsername(rng),
      text: commentTemplates[i % commentTemplates.length],
      verdict: score >= 60 ? "malicious" : score >= 30 ? "suspicious" : "harmless",
    })),
    popularityRank: Math.floor(rng() * 100000) + 100,
    totalVotes,
    communityScore,
  };

  // Generate detailed analysis text
  const details = generateMalwareDetails(target, inputType, score, threatLevel, malwareType, malwareFamily, engines, fileMetadata, tags);

  return {
    score,
    threatLevel,
    malwareType,
    malwareFamily,
    details,
    engines,
    fileMetadata,
    detectionNames: uniqueDetections,
    tags: tags.length > 0 ? tags : (score < 20 ? ["clean"] : ["suspicious"]),
    indicators: baseIndicators,
    recommendations,
    relations,
    behavior,
    community,
  };
}

function generateMalwareDetails(
  target: string,
  inputType: "hash" | "url" | "filename",
  score: number,
  threatLevel: ThreatLevel,
  malwareType: string,
  malwareFamily: string,
  engines: EngineResult[],
  fileMetadata: FileMetadata,
  tags: string[],
): string {
  const maliciousCount = engines.filter(e => e.result === "malicious").length;
  const suspiciousCount = engines.filter(e => e.result === "suspicious").length;

  const inputDesc = inputType === "hash"
    ? `File hash "${target.slice(0, 16)}..."`
    : inputType === "url"
      ? `URL "${target.length > 80 ? target.slice(0, 80) + "..." : target}"`
      : `File "${target}"`;

  if (score >= 80) {
    return `Comprehensive multi-engine analysis of ${inputDesc} reveals a CRITICAL threat. ${maliciousCount} out of ${engines.length} security engines flagged this sample as malicious with an average confidence score of ${score}/100. The primary detection identifies this as "${malwareType}" associated with the ${malwareFamily} malware family.\n\n${fileMetadata.packers.length > 0 ? `The sample appears to be packed using ${fileMetadata.packers.join(", ")}, which is commonly used by threat actors to evade signature-based detection. ` : ""}Behavioral analysis indicates suspicious network activity including potential C2 (command & control) communication, filesystem modifications in system directories, and persistence mechanism creation through registry manipulation.\n\nThis threat has been submitted ${fileMetadata.submissionCount} times to threat intelligence platforms with a community risk assessment of ${maliciousCount > 15 ? "overwhelmingly malicious" : "predominantly malicious"}. Immediate containment and forensic investigation is strongly recommended.`;
  }

  if (score >= 60) {
    return `Multi-engine analysis of ${inputDesc} indicates a HIGH risk threat. ${maliciousCount} engines detected malicious activity and ${suspiciousCount} flagged suspicious behavior out of ${engines.length} total engines. The sample was classified as "${malwareType}" with potential association to the ${malwareFamily} family.\n\n${tags.includes("double-extension") ? "A double extension pattern was detected, which is a common technique used to disguise executable files. " : ""}${fileMetadata.reputationScore < -30 ? `The file has a poor reputation score of ${fileMetadata.reputationScore}/100 based on community feedback and threat intelligence. ` : ""}Behavioral heuristics indicate possible unauthorized network connections and system modifications.\n\nThe threat intelligence community has flagged this sample with ${maliciousCount} engine detections. Exercise extreme caution and do not execute this file on any production system.`;
  }

  if (score >= 40) {
    return `Analysis of ${inputDesc} shows MODERATE risk indicators. ${maliciousCount} engines flagged this as malicious and ${suspiciousCount} as suspicious. The classification "${malwareType}" suggests potential unwanted behavior, though some detections may be heuristic-based rather than signature-confirmed.\n\nThe sample ${tags.includes("suspicious-naming") ? "uses naming conventions commonly associated with potentially unwanted programs or malware " : "has characteristics that trigger heuristic rules in multiple engines"}. ${fileMetadata.inputType === "filename" ? `File type was identified as ${fileMetadata.fileType} with magic bytes: ${fileMetadata.magic}.` : ""}\n\nWhile the threat level is not immediately critical, this file should be handled with caution. Verify the file's origin and consider running it in a sandbox environment before use.`;
  }

  if (score >= 20) {
    return `Low-level analysis of ${inputDesc} detected ${suspiciousCount} suspicious indicators from heuristic engines, but no confirmed malicious signatures were found. The sample scored ${score}/100 on the threat assessment scale.\n\nMinor indicators detected include ${tags.length > 0 ? tags.join(", ") : "generic heuristic patterns"}. These may represent false positives or legitimate software flagged by overly sensitive heuristic rules.\n\nThe file appears to have been analyzed ${fileMetadata.submissionCount} time(s) previously with no critical findings. Standard security precautions are recommended.`;
  }

  return `Comprehensive analysis of ${inputDesc} shows NO significant threats detected. The sample was scanned across ${engines.length} security engines with ${maliciousCount} detections classified as malicious and ${suspiciousCount} as suspicious. The threat assessment score is ${score}/100 (SAFE).\n\n${fileMetadata.inputType === "hash" ? "This hash was not found in any known malware databases." : fileMetadata.inputType === "url" ? "No URL reputation or blacklisting services flagged this resource." : `The file type ${fileMetadata.fileType} is not typically associated with malware delivery.`} Community feedback and threat intelligence data show no evidence of malicious activity.\n\nThis resource can be considered safe for normal use with standard security precautions.`;
}

// ======================== PHISHING ANALYSIS =================================

function analyzePhishingURL(url: string, rng: () => number): {
  score: number;
  indicators: string[];
  tags: string[];
  sslData: SSLData;
  whoisData: WHOISData;
  dnsData: DNSData;
  domainExtracted: string;
  brandImpersonated: string | null;
} {
  let score = 0;
  const indicators: string[] = [];
  const tags: string[] = [];
  const lower = url.toLowerCase();

  // Extract domain
  let domain = "";
  try {
    const urlObj = new URL(url);
    domain = urlObj.hostname;
  } catch {
    domain = url.replace(/^https?:\/\//, "").split("/")[0];
  }

  let brandImpersonated: string | null = null;

  // Protocol check
  if (lower.startsWith("http://")) {
    score += 20;
    indicators.push("Non-HTTPS protocol — data not encrypted");
    tags.push("no-https");
  }

  // IP address as domain
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
    score += 25;
    indicators.push("IP address used as domain (no DNS resolution)");
    tags.push("ip-domain");
  }

  // Suspicious TLDs
  for (const tld of SUSPICIOUS_TLDS) {
    if (domain.includes(tld) || domain.endsWith(tld)) {
      score += 20;
      indicators.push(`Suspicious TLD detected: ${tld}`);
      tags.push("suspicious-tld");
      break;
    }
  }

  // Brand impersonation
  for (const brand of BRAND_NAMES) {
    if (lower.includes(brand)) {
      // Check if it's the legitimate domain
      if (domain === `${brand}.com` || domain === `www.${brand}.com` || domain === `${brand}.org`) {
        score = Math.max(0, score - 20);
        break;
      }
      score += 30;
      brandImpersonated = brand;
      indicators.push(`Brand impersonation detected: ${brand}`);
      tags.push("brand-impersonation");
      break;
    }
  }

  // Homograph attack detection (lookalike characters)
  const homographPatterns = [/\b(g00gle|paypa1|amaz0n|m1crosoft|app1e)\b/i, /[а-яА-Я]/]; // Cyrillic chars
  for (const pattern of homographPatterns) {
    if (pattern.test(url)) {
      score += 25;
      indicators.push("Potential homograph attack — lookalike characters detected");
      tags.push("homograph");
      break;
    }
  }

  // Suspicious path patterns
  const suspiciousPaths = [
    /\/login/i, /\/secure/i, /\/verify/i, /\/account/i, /\/update/i,
    /\/confirm/i, /\/signin/i, /\/auth/i, /\/banking/i, /\/wallet/i,
    /\/restore/i, /\/recover/i, /\/unlimited/i, /\/activate/i,
  ];
  for (const pattern of suspiciousPaths) {
    if (pattern.test(url)) {
      score += 12;
      indicators.push(`Suspicious path pattern: ${pattern.source}`);
      tags.push("credential-path");
      break;
    }
  }

  // URL encoding
  if (/%[0-9a-f]{2}/i.test(url)) {
    score += 10;
    indicators.push("URL encoding detected — possible obfuscation");
    tags.push("url-encoding");
  }

  // Excessive subdomains
  const subdomainParts = domain.split(".");
  if (subdomainParts.length > 4) {
    score += 10;
    indicators.push(`Excessive subdomains: ${subdomainParts.length - 2} subdomains`);
    tags.push("excessive-subdomains");
  }

  // Long URL
  if (url.length > 150) {
    score += 8;
    indicators.push("Unusually long URL — may contain tracking or obfuscation");
    tags.push("long-url");
  }

  // URL shortener
  if (/bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rb\.gy|short\.io/i.test(url)) {
    score += 15;
    indicators.push("URL shortener service detected — destination obscured");
    tags.push("url-shortener");
  }

  // Data URI
  if (/^data:/i.test(url)) {
    score += 20;
    indicators.push("Data URI scheme detected");
    tags.push("data-uri");
  }

  // Base score for URL analysis
  score += 8;

  // Clamp
  score = Math.max(0, Math.min(100, score));

  // Generate SSL data
  const sslData: SSLData = {
    issuer: score >= 50 && !lower.startsWith("https://")
      ? "Self-Signed Certificate"
      : pickItems(rng, [
        "Let's Encrypt Authority X3", "DigiCert SHA2 Secure Server CA",
        "Sectigo RSA Domain Validation", "Cloudflare Inc ECC CA-3",
        "GlobalSign Domain Validation CA", "cPanel, Inc. Certification Authority",
      ], 1)[0],
    validFrom: formatDate(generateDate(rng, 400)),
    validTo: formatDate(new Date(Date.now() + Math.floor(rng() * 365) * 86400000).toISOString()),
    protocol: lower.startsWith("https://") ? "TLS 1.3" : "None (HTTP)",
    isExpired: score >= 50 && rng() > 0.5,
    isSelfSigned: score >= 40 && !lower.startsWith("https://") && rng() > 0.4,
  };

  // Generate WHOIS data
  const registrars = ["NameCheap, Inc.", "GoDaddy.com, LLC", "PDR Ltd. d/b/a PublicDomainRegistry.com", "Tucows Domains Inc.", "ENOM, Inc.", "Gandi SAS", "CloudFlare, Inc.", "Alibaba Cloud Computing Ltd.", "Google Domains LLC", "Dynadot LLC"];
  const countries = ["CN", "RU", "UA", "BR", "IN", "NG", "ID", "PH", "VN", "GH", "US", "DE", "RO", "PA", "KY"];

  const whoisData: WHOISData = {
    registrar: pickItems(rng, registrars, 1)[0],
    creationDate: formatDate(generateDate(rng, score >= 50 ? 90 : 730)),
    expirationDate: formatDate(new Date(Date.now() + Math.floor(rng() * 365) * 86400000).toISOString()),
    nameServers: pickItems(rng, ["ns1.example.com", "ns2.example.com", "ns3.example.com", "ns4.example.com", "dns1.registrar-servers.com", "dns2.registrar-servers.com"], 2),
    registrantOrg: score >= 50 ? "REDACTED FOR PRIVACY" : pickItems(rng, [`${brandImpersonated || "Online"} Services Ltd.`, `${brandImpersonated || "Digital"} Solutions Inc.`, "Internet Services LLC", "Web Hosting Inc."], 1)[0],
    registrantCountry: score >= 50 ? pickItems(rng, countries, 1)[0] : pickItems(rng, ["US", "DE", "GB", "NL", "JP", "CA"], 1)[0],
  };

  // Generate DNS data
  const dnsData: DNSData = {
    aRecords: Array.from({ length: 1 + Math.floor(rng() * 2) }, () => generateIPv4(rng)),
    mxRecords: score < 60
      ? pickItems(rng, [`${hexFromRNG(rng, 6)}@${domain}`, `mail.${domain}`], 1)
      : [],
    nsRecords: whoisData.nameServers.slice(0, 2),
    txtRecords: score < 50
      ? [pickItems(rng, [`v=spf1 include:_spf.${domain} ~all`, `google-site-verification=${hexFromRNG(rng, 32)}`], 1)[0]]
      : [],
    soaRecord: `ns1.${domain} hostmaster.${domain} ${Math.floor(rng() * 2024000000) + 1000000000}`,
  };

  return { score, indicators, tags, sslData, whoisData, dnsData, domainExtracted: domain, brandImpersonated };
}

function analyzePhishingEmail(email: string, rng: () => number): {
  score: number;
  indicators: string[];
  tags: string[];
  senderDomain: string;
  senderEmail: string;
  brandImpersonated: string | null;
} {
  let score = 0;
  const indicators: string[] = [];
  const tags: string[] = [];
  const lower = email.toLowerCase();

  let senderEmail = "unknown@unknown.com";
  let senderDomain = "unknown.com";
  let brandImpersonated: string | null = null;

  // Extract sender from common patterns
  const fromMatch = email.match(/from\s*[:：]\s*["<]?\s*([^\s"<>,;]+@[^\s"<>,;]+)/i);
  if (fromMatch) {
    senderEmail = fromMatch[1].toLowerCase();
    const domainMatch = senderEmail.match(/@(.+)/);
    if (domainMatch) senderDomain = domainMatch[1];
  }

  // Sender analysis: free email for business context
  const freeEmailProviders = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com", "mail.ru", "163.com", "qq.com"];
  if (freeEmailProviders.includes(senderDomain)) {
    // Check if claiming to be a business
    const businessKeywords = ["bank", "paypal", "amazon", "microsoft", "apple", "chase", "wells fargo", "citi", "bank of america", "netflix", "spotify", "adobe", "support", "service", "security", "admin", "team"];
    for (const kw of businessKeywords) {
      if (lower.includes(kw)) {
        score += 25;
        indicators.push(`Sender uses free email provider (${senderDomain}) while claiming to represent a business entity`);
        tags.push("free-email-business");
        break;
      }
    }
  }

  // Sender display name mismatch
  const displayNameMatch = email.match(/from\s*[:：]\s*"([^"]+)"/i);
  if (displayNameMatch && fromMatch) {
    const displayName = displayNameMatch[1].toLowerCase();
    for (const brand of BRAND_NAMES) {
      if (displayName.includes(brand) && !senderDomain.includes(brand)) {
        score += 20;
        brandImpersonated = brand;
        indicators.push(`Sender display name mentions "${brand}" but email domain is ${senderDomain}`);
        tags.push("sender-mismatch");
        break;
      }
    }
  }

  // Brand impersonation in content
  if (!brandImpersonated) {
    for (const brand of BRAND_NAMES) {
      if (lower.includes(brand)) {
        brandImpersonated = brand;
        // Only flag if not from legitimate domain
        if (!senderDomain.includes(brand)) {
          score += 15;
          indicators.push(`Content references "${brand}" but sender domain does not match`);
          tags.push("brand-mention");
        }
        break;
      }
    }
  }

  // Social engineering keywords
  const socialEngineering = [
    { pattern: /\burgent\b/i, points: 10, msg: "Urgency language detected" },
    { pattern: /\bimmediate\s*(action|attention|response)\b/i, points: 15, msg: "Immediate action demanded" },
    { pattern: /\bsuspend(ed)?\b/i, points: 15, msg: "Account suspension threat" },
    { pattern: /\bexpir(es?|ed|ation|ing)\b/i, points: 10, msg: "Expiration threat language" },
    { pattern: /\baction\s*required\b/i, points: 12, msg: "Action required pressure tactic" },
    { pattern: /\bconfirm\s*your\b/i, points: 10, msg: "Confirmation request pattern" },
    { pattern: /\bverify\s*your\b/i, points: 12, msg: "Verification request pattern" },
    { pattern: /\bupdate\s*your\b/i, points: 10, msg: "Update request pattern" },
    { pattern: /\b24\s*hours?\b/i, points: 10, msg: "Time pressure: 24 hours deadline" },
    { pattern: /\b48\s*hours?\b/i, points: 8, msg: "Time pressure: 48 hours deadline" },
    { pattern: /\bimmediately\b/i, points: 12, msg: "Immediate action demanded" },
    { pattern: /\bunusual\s*(activity|login|sign-in)\b/i, points: 10, msg: "Unusual activity claim (common phishing tactic)" },
    { pattern: /\baccount\s*(will be|has been)?\s*(locked|disabled|suspended|restricted|limited)\b/i, points: 15, msg: "Account restriction threat" },
    { pattern: /\bsecurity\s*(alert|breach|issue|warning|notification|concern)\b/i, points: 8, msg: "Security alert claim" },
    { pattern: /\bclick\s*(here|below|the\s*link|now)\b/i, points: 10, msg: "Click action directive" },
  ];

  let socialCount = 0;
  for (const se of socialEngineering) {
    if (se.pattern.test(email) && socialCount < 5) {
      score += se.points;
      indicators.push(se.msg);
      socialCount++;
      if (socialCount === 1) tags.push("social-engineering");
    }
  }

  // Call-to-action with link patterns
  const linkPatterns = [
    { pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, msg: "Link uses raw IP address" },
    { pattern: /https?:\/\/[^\s]*\.(xyz|tk|ml|ga|cc|top|click|download|win|bid)/i, msg: "Link points to suspicious TLD" },
    { pattern: /https?:\/\/[^\s]*(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly)[^\s]*/i, msg: "Link uses URL shortener" },
  ];
  for (const lp of linkPatterns) {
    if (lp.pattern.test(email)) {
      score += 12;
      indicators.push(lp.msg);
      tags.push("suspicious-link");
      break;
    }
  }

  // Check for generic personalization
  const genericGreetings = [
    /\bdear\s+(customer|user|member|subscriber|client|account\s*holder)\b/i,
    /\bdear\s+(valued|esteemed|respected)/i,
    /\bgood\s+(morning|afternoon|evening),?\s*(customer|user|member)\b/i,
    /\bhello\s+(customer|user|member)\b/i,
  ];
  for (const greeting of genericGreetings) {
    if (greeting.test(email)) {
      score += 8;
      indicators.push("Generic personalization — no name used");
      tags.push("generic-greeting");
      break;
    }
  }

  // Request for sensitive info
  const sensitiveRequests = [
    /\bpassword\b/i, /\bssn\b/i, /\bsocial\s*security\b/i,
    /\bcredit\s*card\b/i, /\bbank\s*account\b/i, /\brouting\s*number\b/i,
    /\bdate\s*of\s*birth\b/i, /\bfull\s*name\b/i,
    /\bmother'?s\s*maiden\s*name\b/i, /\bpin\s*number\b/i,
    /\bcard\s*(number|details|info)\b/i,
    /\bsocial\s*insurance\b/i,
  ];
  let sensitiveCount = 0;
  for (const sr of sensitiveRequests) {
    if (sr.test(email) && sensitiveCount < 3) {
      score += 10;
      sensitiveCount++;
    }
  }
  if (sensitiveCount > 0) {
    indicators.push(`Requests sensitive information (${sensitiveCount} sensitive data types referenced)`);
    tags.push("data-harvest");
  }

  // Grammar/spelling indicators (heuristic: mixed case, excessive exclamation, ALL CAPS sentences)
  const exclamationCount = (email.match(/!/g) || []).length;
  if (exclamationCount > 3) {
    score += 8;
    indicators.push(`Excessive exclamation marks (${exclamationCount}) — common in phishing`);
    tags.push("urgency-punctuation");
  }

  // ALL CAPS sections
  if (/[A-Z]{10,}/.test(email.replace(/\s/g, ""))) {
    score += 5;
    indicators.push("Excessive uppercase text — possible urgency tactic");
  }

  // Subject line patterns
  const subjectMatch = email.match(/subject\s*[:：]\s*["<]?(.+?)(?:["\n\r]|$)/i);
  if (subjectMatch) {
    const subject = subjectMatch[1].trim();
    if (/urgent|immediate|alert|warning|suspended|locked|expired/i.test(subject)) {
      score += 8;
      indicators.push("Urgent/alert subject line detected");
    }
  }

  // Presence of HTML link tags
  if (/<a\s+href/i.test(email)) {
    score += 5;
    indicators.push("HTML links detected in email content");
  }

  // Attachments mentioned
  if (/attachment|attached|enclosed/i.test(email)) {
    score += 8;
    indicators.push("Email mentions attachments");
    tags.push("attachment-mentioned");
  }

  // Base score for email
  score += 5;

  // Clamp
  score = Math.max(0, Math.min(100, score));

  return { score, indicators, tags, senderDomain, senderEmail, brandImpersonated };
}

/** Main phishing analysis function */
export function analyzePhishing(target: string, mode: "url" | "email"): PhishingAnalysisResult {
  const rng = createRNG(hashString(target + mode));
  let score: number;
  let urlIndicators: string[] = [];
  let emailIndicators: string[] = [];
  let allTags: string[] = [];
  let phishingType = "Unknown";
  let brandImpersonated: string | null = null;
  let sslData: SSLData | undefined;
  let whoisData: WHOISData | undefined;
  let dnsData: DNSData | undefined;
  let domainExtracted = "";

  if (mode === "url") {
    const urlResult = analyzePhishingURL(target, rng);
    score = urlResult.score;
    urlIndicators = urlResult.indicators;
    allTags = urlResult.tags;
    sslData = urlResult.sslData;
    whoisData = urlResult.whoisData;
    dnsData = urlResult.dnsData;
    domainExtracted = urlResult.domainExtracted;
    brandImpersonated = urlResult.brandImpersonated;

    const typePool = score >= 60 ? PHISHING_TYPES_URL.high : score >= 30 ? PHISHING_TYPES_URL.medium : PHISHING_TYPES_URL.low;
    phishingType = pickItems(rng, typePool, 1)[0];
  } else {
    const emailResult = analyzePhishingEmail(target, rng);
    score = emailResult.score;
    emailIndicators = emailResult.indicators;
    allTags = emailResult.tags;
    brandImpersonated = emailResult.brandImpersonated;
    domainExtracted = emailResult.senderDomain;

    const typePool = score >= 60 ? PHISHING_TYPES_EMAIL.high : score >= 30 ? PHISHING_TYPES_EMAIL.medium : PHISHING_TYPES_EMAIL.low;
    phishingType = pickItems(rng, typePool, 1)[0];
  }

  // Deterministic jitter
  score = Math.max(0, Math.min(100, Math.round(score + (rng() * 6 - 3))));
  const threatLevel = scoreToThreatLevel(score);

  // Select engines
  const engineList = mode === "url" ? PHISHING_URL_ENGINES : PHISHING_EMAIL_ENGINES;
  const detectionNames = mode === "url"
    ? (score >= 60
      ? [...PHISHING_TYPES_URL.high, ...PHISHING_TYPES_URL.medium]
      : [...PHISHING_TYPES_URL.medium, ...PHISHING_TYPES_URL.low])
    : (score >= 60
      ? [...PHISHING_TYPES_EMAIL.high, ...PHISHING_TYPES_EMAIL.medium]
      : [...PHISHING_TYPES_EMAIL.medium, ...PHISHING_TYPES_EMAIL.low]);

  const engines = generateEngineResults(rng, engineList, score, detectionNames, mode === "email");
  const maliciousCount = engines.filter(e => e.result === "malicious").length;

  // Combine indicators
  const indicators = [...urlIndicators, ...emailIndicators];
  if (indicators.length === 0) {
    if (score < 20) indicators.push("No significant phishing indicators detected");
    else indicators.push("Minor heuristic pattern detected");
  }

  // Recommendations
  const recommendations: string[] = [];
  if (score >= 80) {
    recommendations.push("Do NOT click any links or open any attachments");
    recommendations.push("Report this as a phishing attempt to your IT security team");
    recommendations.push("Block the associated domain in your email gateway");
    recommendations.push("Alert all potential targets of this phishing campaign");
    if (brandImpersonated) recommendations.push(`Notify ${brandImpersonated.charAt(0).toUpperCase() + brandImpersonated.slice(1)} of brand abuse`);
  } else if (score >= 60) {
    recommendations.push("Verify the sender through official channels before taking any action");
    recommendations.push("Do not provide any personal or financial information");
    recommendations.push("Check the actual URL destination before clicking any links");
    if (mode === "email") recommendations.push("Check the email headers for SPF/DKIM/DMARC failures");
  } else if (score >= 40) {
    recommendations.push("Exercise caution and verify the sender's identity");
    recommendations.push("Look for official communication channels for confirmation");
    recommendations.push("Do not enter credentials on unfamiliar pages");
  } else if (score >= 20) {
    recommendations.push("Low risk but verify the source through official channels");
    recommendations.push("Standard email safety practices apply");
  } else {
    recommendations.push("No significant phishing indicators — appears legitimate");
    recommendations.push("Continue with standard security awareness practices");
  }

  // File metadata
  const firstSeen = generateDate(rng, 180);
  const lastAnalysis = generateDate(rng, 2);
  const submissionCount = score >= 50 ? Math.floor(rng() * 200) + 20 : Math.floor(rng() * 30) + 1;
  const reputationScore = Math.round(-100 + (200 * (1 - score / 100)) + (rng() * 20 - 10));

  const fileMetadata: PhishingFileMetadata = {
    target,
    targetType: mode,
    firstSeen: formatDate(firstSeen),
    lastAnalysis: formatDate(lastAnalysis),
    submissionCount,
    reputationScore: Math.max(-100, Math.min(100, reputationScore)),
    category: score >= 60 ? "Phishing" : score >= 30 ? "Suspicious" : "Benign",
    threatClassification: phishingType,
  };

  // Relations
  const numRelations = score >= 60 ? 4 : score >= 30 ? 2 : 1;
  const relations: Relations = {
    contactedDomains: Array.from({ length: numRelations }, () => generateDomain(rng, score >= 50)),
    contactedIPs: Array.from({ length: numRelations }, () => generateIPv4(rng)),
    contactedURLs: score >= 50
      ? Array.from({ length: Math.min(numRelations, 3) }, () =>
        `http://${generateDomain(rng, true)}/${pickItems(rng, ["login", "verify", "account", "secure", "update"], 1)[0]}`
      ) : [],
    downloadedFiles: [],
    executingFiles: [],
    similarFiles: Array.from({ length: Math.floor(rng() * 3) }, () =>
      mode === "url"
        ? `https://${generateDomain(rng, true)}/${pickItems(rng, ["login", "signin", "verify"], 1)[0]}`
        : `phishing_email_${hexFromRNG(rng, 8)}`,
    ),
  };

  // Behavior
  const behaviorCount = score >= 70 ? 4 : score >= 40 ? 2 : 0;
  const behavior: Behavior = {
    network: score >= 30 ? Array.from({ length: Math.min(behaviorCount + 1, 4) }, () => ({
      action: "http_request",
      destination: generateDomain(rng, true),
      port: pickItems(rng, [80, 443, 8080, 8443], 1)[0],
      protocol: "HTTPS",
    })) : [],
    filesystem: mode === "email" && score >= 60 ? Array.from({ length: Math.floor(rng() * 2) + 1 }, () => ({
      action: "download",
      target: `/tmp/${hexFromRNG(rng, 8)}.html`,
      description: "Phishing page downloaded for credential harvesting",
    })) : [],
    registry: [],
    process: mode === "email" && score >= 70 ? Array.from({ length: Math.floor(rng() * 2) + 1 }, () => ({
      action: "spawned",
      process: pickItems(rng, ["python", "curl", "wget", "powershell"], 1)[0],
      description: "Script execution for credential exfiltration",
    })) : [],
  };

  // Community
  const harmlessVotes = score < 40 ? Math.floor(rng() * 40) + 5 : Math.floor(rng() * 10);
  const maliciousVotes = score >= 40 ? Math.floor(rng() * 40) + 5 : Math.floor(rng() * 5);
  const totalVotes = harmlessVotes + maliciousVotes;
  const communityScore = totalVotes > 0 ? Math.round((maliciousVotes / totalVotes) * 100) : 0;

  const commentTemplates = score >= 60
    ? [
        "Confirmed phishing. Multiple users have reported this.",
        "This is a known phishing campaign targeting credentials.",
        `${brandImpersonated ? `Impersonating ${brandImpersonated}. ` : ""}Classic social engineering attack.`,
        "Active phishing kit detected on this domain.",
        "Has been reported to hosting provider for takedown.",
      ]
    : score >= 30
      ? [
        "Suspicious — could not fully verify legitimacy.",
        "Some indicators present but not confirmed phishing.",
        "Flagged by multiple engines. Proceed with caution.",
      ]
      : [
        "Appears to be legitimate. No phishing indicators.",
        "Checked — seems safe.",
        "No issues found in multiple scans.",
      ];

  const community: CommunityData = {
    votes: { harmless: harmlessVotes, malicious: maliciousVotes },
    comments: Array.from({ length: Math.min(Math.floor(rng() * 3) + 1, commentTemplates.length) }, (_, i) => ({
      date: formatDate(generateDate(rng, 60)),
      user: generateUsername(rng),
      text: commentTemplates[i % commentTemplates.length],
      verdict: score >= 60 ? "malicious" : score >= 30 ? "suspicious" : "harmless",
    })),
    popularityRank: Math.floor(rng() * 50000) + 50,
    totalVotes,
    communityScore,
  };

  // Details text
  const details = generatePhishingDetails(target, mode, score, threatLevel, phishingType, engines, indicators, brandImpersonated, sslData, whoisData, domainExtracted);

  return {
    score,
    threatLevel,
    phishingType,
    details,
    engines,
    fileMetadata,
    indicators,
    recommendations,
    relations,
    behavior,
    community,
    sslData,
    whoisData,
    dnsData,
  };
}

function generatePhishingDetails(
  target: string,
  mode: "url" | "email",
  score: number,
  threatLevel: ThreatLevel,
  phishingType: string,
  engines: EngineResult[],
  indicators: string[],
  brandImpersonated: string | null,
  sslData?: SSLData,
  whoisData?: WHOISData,
  domainExtracted?: string,
): string {
  const maliciousCount = engines.filter(e => e.result === "malicious").length;
  const suspiciousCount = engines.filter(e => e.result === "suspicious").length;

  const targetDesc = mode === "url"
    ? `URL "${target.length > 80 ? target.slice(0, 80) + "..." : target}"`
    : `email content from "${domainExtracted || "unknown sender"}"`;

  if (score >= 80) {
    const sslNote = mode === "url" && sslData
      ? ` SSL analysis ${sslData.isSelfSigned ? "reveals a self-signed certificate, " : ""}${sslData.isExpired ? "shows an expired certificate, " : ""}${!sslData.isSelfSigned && !sslData.isExpired ? "reveals no SSL issues, " : ""}but multiple other indicators confirm phishing.`
      : "";

    const whoisNote = mode === "url" && whoisData
      ? ` WHOIS records indicate the domain was recently registered (${whoisData.creationDate}) by ${whoisData.registrantOrg} through ${whoisData.registrar}.`
      : "";

    return `CRITICAL phishing threat detected. Analysis of ${targetDesc} reveals ${maliciousCount} out of ${engines.length} engines classified this as a confirmed phishing attempt with classification: ${phishingType}.${brandImpersonated ? ` Active brand impersonation of ${brandImpersonated} was detected.` : ""}\n\nKey indicators include: ${indicators.slice(0, 3).join("; ")}.${sslNote}${whoisNote} The threat intelligence community has flagged this ${maliciousCount > 10 ? "with overwhelming consensus" : "with significant agreement"} across multiple detection engines.\n\nThis represents an active phishing campaign. Immediate blocking and user notification is required. ${brandImpersonated ? `The affected brand should be notified of this impersonation attempt.` : "All associated infrastructure should be reported for takedown."}`;
  }

  if (score >= 60) {
    const brandNote = brandImpersonated
      ? ` The content ${mode === "url" ? "uses" : "references"} ${brandImpersonated} branding elements in an attempt to deceive recipients.`
      : "";

    return `HIGH risk phishing detection for ${targetDesc}. ${maliciousCount} engines flagged this as malicious and ${suspiciousCount} as suspicious out of ${engines.length} total. Classification: ${phishingType}.${brandNote}\n\nPrimary indicators: ${indicators.slice(0, 4).join("; ")}.${mode === "email" ? " Social engineering tactics were identified in the email content, including pressure language and requests for sensitive information." : " URL structure analysis revealed multiple red flags in the domain and path components."} This has been submitted to threat intelligence platforms multiple times with consistent malicious classification.\n\nDo not interact with this ${mode === "url" ? "URL" : "email"}. Report to your security team and block the associated domain.`;
  }

  if (score >= 40) {
    return `MODERATE risk assessment for ${targetDesc}. ${maliciousCount} engines detected malicious patterns and ${suspiciousCount} flagged suspicious content. The primary classification is ${phishingType}.\n\nIndicators detected include: ${indicators.slice(0, 3).join("; ")}.${brandImpersonated ? ` Some references to ${brandImpersonated} were found, though the full context is unclear.` : ""} While some engines flagged this content, the results are mixed and could potentially represent false positives or borderline cases.\n\nVerify through official channels before taking any action. Do not provide credentials or personal information.`;
  }

  if (score >= 20) {
    return `LOW risk analysis of ${targetDesc} detected ${suspiciousCount} minor suspicious indicators from heuristic engines, but no confirmed phishing signatures were identified. The threat score is ${score}/100.\n\nMinor flags include: ${indicators.slice(0, 3).join("; ")}. These indicators alone are not sufficient to classify this as a confirmed phishing attempt, but warrant cautious verification of the source.\n\nStandard security awareness practices are recommended. Verify the sender or website through official channels if uncertain.`;
  }

  return `Analysis of ${targetDesc} shows NO significant phishing indicators. The sample was evaluated by ${engines.length} detection engines with ${maliciousCount} malicious classifications and ${suspiciousCount} suspicious flags. Threat score: ${score}/100 (SAFE).\n\n${mode === "url" ? "The URL structure, domain reputation, and SSL configuration do not exhibit known phishing patterns." : "The email content does not contain typical phishing indicators such as social engineering tactics, urgency language, or suspicious link patterns."} Community feedback and threat intelligence data show no evidence of phishing activity.\n\nThis ${mode === "url" ? "URL" : "email"} can be considered safe with standard security precautions.`;
}
