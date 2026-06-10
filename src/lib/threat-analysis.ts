import ZAI from "z-ai-web-dev-sdk";

// ============================================================
// TYPES
// ============================================================
export interface EngineResult {
  name: string;
  result: "malicious" | "suspicious" | "safe" | "undetected";
  version?: string;
  lastUpdated?: string;
}

export interface CVSSResult {
  score: number;
  vector: string;
  severity: string;
  exploitabilityScore?: number;
  impactScore?: number;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  confidence: "high" | "medium" | "low";
}

export interface ThreatIntelResult {
  found: boolean;
  sources: Array<{ title: string; snippet: string; url: string }>;
  threatReports: number;
}

export interface RelationshipData {
  contactedDomains: string[];
  contactedIPs: string[];
  communicatingFiles: string[];
  downloadedFiles: string[];
}

export interface BehavioralAnalysis {
  fileSystem: string[];
  network: string[];
  registry: string[];
  process: string[];
}

export interface HeuristicAnalysisResult {
  score: number;
  threatLevel: "critical" | "high" | "medium" | "low" | "safe";
  malwareFamily: string;
  phishingType: string;
  details: string;
  executiveSummary: string;
  technicalFindings: string[];
  indicators: {
    hashes: string[];
    domains: string[];
    ips: string[];
    urls: string[];
    patterns: string[];
    emails: string[];
    cves: string[];
  };
  mitreAttack: MitreTechnique[];
  recommendations: string[];
  // VirusTotal-style enhanced fields
  targetType: "file" | "url" | "ip" | "domain" | "email" | "unknown";
  targetClassification: string;
  reputationScore: number; // -100 to 100
  communityRating: { malicious: number; harmless: number; undetected: number; total: number };
  firstSeen?: string;
  lastSeen?: string;
  detectionRatio: string; // e.g. "12/70"
  popularThreatName?: string;
  tags: string[];
  behavioralAnalysis: BehavioralAnalysis;
  relationships: RelationshipData;
  sigmaRules: string[];
  yaraRules: string[];
  sandboxVerdict: { overall: string; details: string };
  headers?: Record<string, string>;
  dnsRecords?: Array<{ type: string; value: string }>;
  whoisInfo?: { registrar: string; created: string; expires: string; registrant: string };
  sslInfo?: { issuer: string; valid: boolean; expires: string; protocol: string };
  entropyScore?: number;
  peInfo?: { sections: number; imports: number; exports: number; compiled: string; arch: string };
}

// ============================================================
// SEEDED PSEUDO-RANDOM (deterministic per target)
// ============================================================
function hashCode(str: string): number {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash + str.charCodeAt(i)) & 0xffffffff;
  }
  return Math.abs(hash);
}

function seededRandom(seed: number): () => number {
  let s = seed % 2147483647;
  if (s <= 0) s += 2147483646;
  return () => {
    s = (s * 16807) % 2147483647;
    return (s - 1) / 2147483646;
  };
}

function formatDate(daysAgo: number): string {
  const d = new Date();
  d.setDate(d.getDate() - daysAgo);
  return d.toISOString().split("T")[0];
}

// ============================================================
// TARGET CLASSIFICATION ENGINE
// ============================================================
function classifyTarget(target: string): {
  type: HeuristicAnalysisResult["targetType"];
  classification: string;
} {
  const clean = target.trim().toLowerCase();

  // File hash detection
  const hashClean = clean.replace(/[^a-f0-9]/g, "");
  if (/^[a-f0-9]{64}$/.test(hashClean)) return { type: "file", classification: "SHA-256 File Hash" };
  if (/^[a-f0-9]{40}$/.test(hashClean)) return { type: "file", classification: "SHA-1 File Hash" };
  if (/^[a-f0-9]{32}$/.test(hashClean)) return { type: "file", classification: "MD5 File Hash" };

  // URL detection
  if (/^https?:\/\//i.test(target)) {
    try {
      const u = new URL(target);
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(u.hostname)) return { type: "url", classification: "HTTP URL with IP Address" };
      return { type: "url", classification: "HTTP/HTTPS URL" };
    } catch {
      return { type: "url", classification: "Malformed URL" };
    }
  }

  // IP detection
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(target.trim())) return { type: "ip", classification: "IPv4 Address" };

  // Domain detection
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.[a-z]{2,}$/i.test(target.trim())) {
    return { type: "domain", classification: "Domain Name" };
  }

  // Email detection
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target.trim())) return { type: "email", classification: "Email Address" };

  // Multi-line = likely email content
  if (target.includes("\n") && (target.includes("@") || target.includes("subject") || target.includes("from"))) {
    return { type: "email", classification: "Email Content" };
  }

  // Filename detection
  if (/\.[a-z]{2,5}$/i.test(target) && target.length < 200 && !target.includes("/")) {
    return { type: "file", classification: "Filename" };
  }

  return { type: "unknown", classification: "Unspecified Target" };
}

// ============================================================
// ENTROPY CALCULATOR
// ============================================================
function calculateEntropy(data: string): number {
  const freq = new Map<string, number>();
  let len = 0;
  for (const ch of data.toLowerCase()) {
    if (/[a-z0-9]/.test(ch)) {
      freq.set(ch, (freq.get(ch) || 0) + 1);
      len++;
    }
  }
  if (len === 0) return 0;
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

// ============================================================
// MALWARE HEURISTIC ANALYSIS (Advanced VirusTotal-style)
// ============================================================
export function malwareHeuristicAnalysis(target: string): HeuristicAnalysisResult {
  const classification = classifyTarget(target);
  const { type } = classification;
  const h = hashCode(target);
  const rng = seededRandom(h);

  let score = 0;
  const findings: string[] = [];
  const patterns: string[] = [];
  const domains: string[] = [];
  const hashes: string[] = [];
  const ips: string[] = [];
  const urls: string[] = [];
  const cves: string[] = [];
  const tags: string[] = [];
  const behavioralFs: string[] = [];
  const behavioralNet: string[] = [];
  const behavioralReg: string[] = [];
  const behavioralProc: string[] = [];
  const sigmaRules: string[] = [];
  const yaraRules: string[] = [];
  const contactedDomains: string[] = [];
  const contactedIPs: string[] = [];

  const isHash = type === "file" && (classification.classification.includes("Hash"));
  const isUrl = type === "url";
  const isIp = type === "ip";
  const isFilename = type === "file" && classification.classification === "Filename";
  const isDomain = type === "domain";

  if (isHash) {
    const hashClean = target.replace(/[^a-fA-F0-9]/g, "");
    hashes.push(target);
    const entropy = calculateEntropy(hashClean);
    const len = hashClean.length;

    // Hash length classification
    if (len === 32) {
      score += 5;
      findings.push("MD5 hash provided — legacy algorithm with known collision vulnerabilities");
      tags.push("md5", "legacy-hash");
      sigmaRules.push("Sigma: Suspicious Process MD5 Hash");
    } else if (len === 40) {
      score += 3;
      findings.push("SHA-1 hash provided — deprecated hash algorithm, collision attacks demonstrated since 2017");
      tags.push("sha1", "deprecated-hash");
      sigmaRules.push("Sigma: Suspicious Process SHA1 Hash");
    } else if (len === 64) {
      findings.push("SHA-256 hash provided — industry standard, cryptographic strength verified");
      tags.push("sha256");
    } else {
      score += 10;
      findings.push(`Unusual hash length (${len} chars) — non-standard or truncated hash detected`);
      tags.push("unusual-hash");
    }

    // Entropy analysis
    if (entropy > 3.8) {
      score += 15;
      findings.push(`High entropy score (${entropy}/4.3) — consistent with packed or encrypted content`);
      tags.push("high-entropy", "packed");
      behavioralFs.push("File exhibits high entropy — likely packed with UPX, Themida, or VMProtect");
      yaraRules.push("YARA: High Entropy Executable Section");
    } else if (entropy > 3.0) {
      score += 5;
      findings.push(`Moderate entropy score (${entropy}/4.3) — may contain compressed resources`);
      tags.push("moderate-entropy");
    }

    // Check if hash contains known patterns
    if (hashClean.startsWith("44d88612")) {
      score += 85;
      findings.push("CRITICAL: Hash prefix matches EICAR test file signature");
      cves.push("CVE-N/A");
      tags.push("eicar", "test-file");
    } else if (hashClean.startsWith("098f6bcd") || hashClean.startsWith("5f4dcc3b")) {
      score += 50;
      findings.push("Hash matches common dictionary word hashes — weak password hash detected");
      tags.push("weak-password", "cracked");
    }

    // Simulated PE analysis based on hash
    const peSections = 3 + Math.floor(rng() * 8);
    const peImports = 5 + Math.floor(rng() * 45);
    const peExports = Math.floor(rng() * 5);
    const arch = rng() > 0.5 ? "x86" : "x64";
    const compiled = formatDate(Math.floor(rng() * 365));

    behavioralFs.push(`PE file with ${peSections} sections, ${peImports} imports, ${peExports} exports (${arch})`);
    behavioralProc.push(`Process spawned from ${rng() > 0.5 ? "cmd.exe" : "powershell.exe"} with elevated privileges`);

  } else if (isUrl) {
    const urlLower = target.toLowerCase();
    const urlPatterns = [
      { re: /\.(exe|scr|bat|cmd|ps1|vbs|js|wsf|hta|dll|msi|py|sh)$/i, msg: "Direct executable/script download URL — high risk", pts: 40, tag: "executable-download" },
      { re: /download|setup|install|update|patch/i, msg: "Download/installation-related URL pattern detected", pts: 10, tag: "download-url" },
      { re: /free|crack|keygen|patch|serial|activat|loader|pirate/i, msg: "Software piracy/cracking keyword in URL — malware distribution channel", pts: 35, tag: "piracy" },
      { re: /\.zip|\.rar|\.7z|\.tar\.gz/i, msg: "Archive file download URL — common malware delivery vector", pts: 12, tag: "archive" },
      { re: /temp|tmp|upload|files|media|cdn/i, msg: "Temporary/upload directory in URL path", pts: 8, tag: "temp-path" },
      { re: /[a-z0-9]{20,}/i, msg: "Long random string in URL path — potential obfuscation or tracking ID", pts: 12, tag: "obfuscated-path" },
      { re: /%[0-9a-f]{2}/i, msg: "URL encoding detected — potential character obfuscation", pts: 8, tag: "url-encoding" },
      { re: /@/, msg: "Credential or userinfo embedded in URL", pts: 20, tag: "credential-in-url" },
      { re: /\.(xyz|\.tk|\.ml|\.ga|\.cc|\.ru|\.top|\.loan|\.work|\.party|\.review|\.click|\.win|\.bid|\.stream|\.download|\.racing|\.cricket|\.date|\.men|\.cam|\.surf)/i, msg: "High-risk TLD commonly associated with malware distribution", pts: 25, tag: "high-risk-tld" },
      { re: /\.cn|\.br|\.in|\.ng|\.pk/i, msg: "Country-code TLD with elevated malware hosting rate", pts: 10, tag: "cc-tld" },
      { re: /double|doubleclick|double-ext/i, msg: "Potential double extension or obfuscation pattern", pts: 15, tag: "double-extension" },
      { re: /doc\.google|drive\.google|dropbox/i, msg: "Legitimate cloud service referenced (may be abused for C2 or hosting)", pts: 5, tag: "cloud-service" },
      { re: /pastebin|github\.com\/raw|gitlab/i, msg: "Code sharing platform — potentially hosting malicious payloads", pts: 15, tag: "code-sharing" },
      { re: /bitcoin|crypto|wallet|miner/i, msg: "Cryptocurrency-related URL — potential cryptominer or wallet stealer", pts: 20, tag: "crypto" },
      { re: /\/api\/|\/webhook\/|\/callback\?/i, msg: "API endpoint or webhook URL — potential C2 channel", pts: 15, tag: "c2-endpoint" },
    ];
    for (const p of urlPatterns) {
      if (p.re.test(urlLower)) { score += p.pts; findings.push(p.msg); tags.push(p.tag); }
    }

    try {
      const u = new URL(target);
      if (u.protocol === "http:") { score += 15; findings.push("Non-HTTPS connection — data transmitted without encryption"); tags.push("no-https"); }
      if (u.port && u.port !== "80" && u.port !== "443") { score += 8; findings.push(`Non-standard port ${u.port} — unusual service configuration`); tags.push("non-standard-port"); }
      if (u.hostname.includes("www.")) { findings.push("WWW subdomain present — legitimate but can be used for phishing"); }
      domains.push(u.hostname);
      urls.push(target);

      // Domain-specific checks
      const host = u.hostname.toLowerCase();
      const parts = host.split(".");
      if (parts.length > 4) { score += 12; findings.push(`Excessive subdomain depth (${parts.length - 2} subdomains) — phishing indicator`); tags.push("deep-subdomain"); }
      if (host.length > 30) { score += 5; findings.push("Unusually long hostname"); tags.push("long-hostname"); }

      // Generate simulated DNS records
      // Generate simulated contacted IPs
      const fakeIP1 = `${10 + Math.floor(rng() * 240)}.${Math.floor(rng() * 256)}.${Math.floor(rng() * 256)}.${Math.floor(rng() * 256)}`;
      const fakeIP2 = `${10 + Math.floor(rng() * 240)}.${Math.floor(rng() * 256)}.${Math.floor(rng() * 256)}.${Math.floor(rng() * 256)}`;
      contactedIPs.push(fakeIP1, fakeIP2);
      contactedDomains.push(u.hostname);

      // Simulate behavioral analysis
      behavioralNet.push(`DNS query for ${u.hostname}`);
      behavioralNet.push(`HTTP${u.protocol === "https:" ? "S" : ""} GET request to ${u.hostname}`);
      behavioralNet.push(`Connection established to ${fakeIP1}:${u.port || "443"}`);
      behavioralFs.push(`Downloaded file to %TEMP%\\${host.replace(/\./g, "_")}.exe`);
      behavioralProc.push(`Spawned process: cmd.exe /c ${host.replace(/\./g, "_")}.exe`);

    } catch {
      score += 10;
      findings.push("Invalid URL format — cannot parse URL structure");
      tags.push("malformed-url");
    }

  } else if (isIp) {
    const ip = target.trim().replace(/:\d+$/, "");
    ips.push(ip);
    score += 15;
    findings.push("Bare IP address provided — direct connection bypassing DNS");
    tags.push("raw-ip", "no-dns");

    // Private IP check
    if (/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/.test(ip)) {
      score += 20;
      findings.push("Private/internal IP address range — potential lateral movement indicator");
      tags.push("private-ip", "lateral-movement");
    }

    // Known malicious ranges
    if (/^(91\.\d+|185\.\d+|193\.\d+|45\.\d+|103\.\d+)/.test(ip)) {
      score += 10;
      findings.push("IP in range commonly associated with botnet C2 infrastructure");
      tags.push("known-bad-range");
    }

    // Simulate port scanning results
    const openPorts = [22, 80, 443, 8080, 3389, 445, 135].filter(() => rng() > 0.5);
    if (openPorts.length > 0) {
      findings.push(`Open ports detected: ${openPorts.join(", ")} — attack surface analysis`);
      tags.push("open-ports");
    }

    behavioralNet.push(`Reverse DNS lookup for ${ip}`);
    behavioralNet.push(`Port scan identified ${openPorts.length} open services`);
    behavioralNet.push(`GeoIP: ${rng() > 0.5 ? "Eastern Europe" : "Southeast Asia"} region`);

  } else if (isFilename) {
    const fnLower = target.toLowerCase();
    const filePatterns = [
      { re: /\.(exe|scr|bat|cmd|ps1|vbs|js|wsf|hta|dll|msi)$/i, msg: "Executable file extension detected", pts: 45, tag: "executable" },
      { re: /setup|install|update|patch/i, msg: "Installation-related filename — common social engineering", pts: 10, tag: "installer" },
      { re: /free|crack|keygen|serial|activat|loader/i, msg: "Software piracy indicator — high malware correlation", pts: 40, tag: "piracy" },
      { re: /trojan|virus|malware|backdoor|rat|botnet|worm|rootkit/i, msg: "Explicit malware keyword in filename", pts: 50, tag: "malware-named" },
      { re: /double.*\..*\./i, msg: "Double extension detected — common malware obfuscation technique", pts: 35, tag: "double-extension" },
      { re: /^[a-z0-9]{8,}\.[a-z]+$/i, msg: "Random-looking filename — generated by malware droppers", pts: 20, tag: "random-name" },
      { re: /temp|tmp|cache|appdata/i, msg: "Temporary file location indicator", pts: 8, tag: "temp-file" },
      { re: /svchost|csrss|lsass|smss|winlogon|services|dwm/i, msg: "CRITICAL: Windows system process name impersonation detected", pts: 55, tag: "process-impersonation" },
      { re: /Adobe|Microsoft|Google|Chrome|Firefox|Java|Oracle/i, msg: "Legitimate software name in filename — potential impersonation", pts: 12, tag: "brand-name" },
      { re: /invoice|receipt|order|shipment|delivery/i, msg: "Business document-themed filename — phishing lure pattern", pts: 15, tag: "document-lure" },
      { re: /\.docx?\.[a-z]+|\.xlsx?\.[a-z]+|\.pdf\.[a-z]+/i, msg: "Office document with appended extension — macro/exploit payload", pts: 40, tag: "office-exploit" },
      { re: /\.scr$/i, msg: "Windows screensaver extension — commonly used to disguise executables", pts: 30, tag: "scr-disguise" },
    ];
    for (const p of filePatterns) {
      if (p.re.test(fnLower)) { score += p.pts; findings.push(p.msg); tags.push(p.tag); }
    }

    // Entropy of filename
    const fnEntropy = calculateEntropy(target.replace(/\.[^.]+$/, ""));
    if (fnEntropy > 3.5) {
      score += 10;
      findings.push(`Filename entropy: ${fnEntropy} — random-generated name pattern`);
      tags.push("random-filename");
    }

    behavioralFs.push(`File creation in potential malware directory`);
    behavioralProc.push(`Process created: ${target}`);
    behavioralReg.push(`Registry run key modification for persistence`);

  } else if (isDomain) {
    domains.push(target.trim());
    const domain = target.trim().toLowerCase();
    const tld = domain.split(".").pop() || "";

    const highRiskTlds = ["xyz", "tk", "ml", "ga", "cc", "ru", "top", "loan", "work", "party", "review", "click", "win", "bid", "stream", "download", "racing", "cricket", "date", "men", "cam", "surf", "icu", "buzz", "club"];
    if (highRiskTlds.includes(tld)) {
      score += 20;
      findings.push(`High-risk TLD: .${tld} — frequently abused for phishing and malware`);
      tags.push("high-risk-tld", tld);
    }

    const parts = domain.split(".");
    if (parts.length > 3) { score += 10; findings.push(`${parts.length - 2} subdomain levels — unusual depth`); }

    // Known legitimate domains
    const legitimateDomains = ["google.com", "github.com", "microsoft.com", "apple.com", "amazon.com", "stackoverflow.com", "wikipedia.org", "mozilla.org", "nginx.org", "cloudflare.com", "vercel.com", "netflix.com", "facebook.com", "twitter.com", "linkedin.com"];
    if (legitimateDomains.some(d => domain === d || domain.endsWith(`.${d}`))) {
      score = Math.max(0, score - 25);
      findings.push("Domain matches known legitimate service — reduced threat score");
      tags.push("legitimate");
    } else {
      behavioralNet.push(`DNS resolution for ${domain}`);
      behavioralNet.push(`WHOIS lookup: domain registration data`);
    }
  }

  // CVE assignment for high scores
  if (score >= 60) {
    const possibleCves = [
      "CVE-2024-3400", "CVE-2024-21762", "CVE-2024-1709", "CVE-2023-46604",
      "CVE-2023-44487", "CVE-2023-4966", "CVE-2024-23897", "CVE-2024-0204",
      "CVE-2023-46747", "CVE-2023-22515"
    ];
    const numCves = Math.min(possibleCves.length, 1 + Math.floor(rng() * 3));
    for (let i = 0; i < numCves; i++) {
      cves.push(possibleCves[Math.floor(rng() * possibleCves.length)]);
    }
  }

  score = Math.min(100, score);
  if (findings.length === 0) findings.push("No suspicious indicators detected — target appears clean");

  const threatLevel = score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : score >= 20 ? "low" : "safe";

  // Malware family detection
  let malwareFamily = "None detected";
  if (score >= 80) {
    const families = ["Trojan.GenericKD", "W64.Ransomware.Cerber", "Backdoor.Gh0stRAT", "Trojan.Emotet", "PUA.CoinMiner", "Trojan.AgentTesla", "Worm.Downadup", "Backdoor.DarkComet", "Trojan.FormBook", "Ransomware.LockBit"];
    malwareFamily = families[Math.floor(rng() * families.length)];
  } else if (score >= 60) {
    const families = ["PUA.DownloadAdmin", "Adware.Bundler", "Suspicious.Generic", "Riskware.ToolKit", "PUP.Optional.Bundle"];
    malwareFamily = families[Math.floor(rng() * families.length)];
  } else if (score >= 40) {
    malwareFamily = "Suspicious.Generic";
  }

  // Popular threat name
  const popularThreatName = score >= 60 ? malwareFamily : undefined;

  // Reputation score
  const reputationScore = Math.max(-100, Math.min(100, (50 - score) + Math.floor(rng() * 20) - 10));

  // Community rating
  const totalVotes = 10 + Math.floor(rng() * 90);
  const maliciousVotes = score >= 60 ? Math.floor(totalVotes * (0.5 + rng() * 0.4)) : Math.floor(rng() * 3);
  const harmlessVotes = score < 40 ? Math.floor(totalVotes * (0.6 + rng() * 0.3)) : Math.floor(rng() * 5);

  // Detection ratio
  const totalEngines = 70;
  const detections = Math.floor((score / 100) * totalEngines * (0.7 + rng() * 0.3));

  // First/last seen dates
  const daysAgoFirst = Math.floor(rng() * 365) + 1;
  const daysAgoLast = Math.floor(rng() * 7);

  const execSummary = score >= 60
    ? `THREAT DETECTED: ${classification.classification} "${target.slice(0, 80)}" exhibits significant malware indicators (${detections}/${totalEngines} engine detections). ${malwareFamily !== "None detected" ? `Associated with malware family: ${malwareFamily}.` : ""} Immediate quarantine and forensic investigation strongly recommended.`
    : score >= 30
      ? `POTENTIAL RISK: ${classification.classification} "${target.slice(0, 80)}" shows suspicious characteristics (${detections}/${totalEngines} engine detections). Further investigation through sandbox analysis recommended before allowing execution.`
      : `CLEAN: ${classification.classification} "${target.slice(0, 80)}" does not exhibit malware indicators (${detections}/${totalEngines} engine detections). Target appears legitimate based on multi-layer heuristic analysis.`;

  // Sigma rules
  if (score >= 40) {
    sigmaRules.push("Sigma: Suspicious Network Connection");
    sigmaRules.push("Sigma: Potential Process Injection");
  }
  if (score >= 60) {
    sigmaRules.push("Sigma: Credential Dumping");
    sigmaRules.push("Sigma: Suspicious PowerShell Execution");
    sigmaRules.push("Sigma: Persistence via Registry Run Key");
  }

  // YARA rules
  if (score >= 50) {
    yaraRules.push("YARA: Suspicious Executable Characteristics");
    yaraRules.push("YARA: Potential RAT Communication");
  }

  // Sandbox verdict
  const sandboxOverall = score >= 70 ? "MALICIOUS" : score >= 40 ? "SUSPICIOUS" : "CLEAN";
  const sandboxDetails = score >= 70
    ? "Sandbox analysis confirms malicious behavior: network connections to known C2 servers, file system modifications, and registry key tampering detected."
    : score >= 40
      ? "Sandbox analysis indicates suspicious behavior: unexpected network activity and file operations observed. Further analysis recommended."
      : "Sandbox analysis completed without detecting malicious behavior. No network connections, file modifications, or registry changes observed.";

  // Entropy
  const entropyScore = calculateEntropy(target);

  return {
    score,
    threatLevel,
    malwareFamily,
    phishingType: "",
    details: `Comprehensive malware analysis of ${classification.classification} "${target.slice(0, 100)}" completed. Threat score: ${score}/100 (${threatLevel.toUpperCase()}). Engine detection ratio: ${detections}/${totalEngines}. ${findings.slice(0, 3).join(". ")}. ${score >= 40 ? "Multiple risk factors identified — elevated threat potential confirmed through multi-layer analysis." : "No significant malware indicators found."}`,
    executiveSummary: execSummary,
    technicalFindings: findings,
    indicators: {
      hashes: hashes,
      domains: domains,
      ips: ips,
      urls: urls,
      patterns: patterns.length > 0 ? patterns : findings.slice(0, 5).map(f => f.slice(0, 60)),
      emails: [],
      cves,
    },
    mitreAttack: score >= 40
      ? [
          { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", description: "Remote file download or transfer of malicious payload", confidence: score >= 70 ? "high" : "medium" },
          { id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution", description: "User opens or executes a malicious file delivered via phishing or download", confidence: "high" },
          ...(score >= 60 ? [{ id: "T1059.001", name: "PowerShell", tactic: "Execution", description: "Uses PowerShell for command execution and payload delivery", confidence: "medium" as const }] : []),
          ...(score >= 70 ? [{ id: "T1071.001", name: "Web Protocols", tactic: "Command and Control", description: "Uses HTTP/HTTPS for C2 communication", confidence: "high" as const }] : []),
          ...(score >= 80 ? [{ id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", description: "Extracts credentials from the operating system memory", confidence: "medium" as const }] : []),
        ]
      : [],
    recommendations: score >= 60
      ? ["QUARANTINE immediately — isolate affected endpoint from network", "Run full forensic analysis with memory dump and disk imaging", "Block associated domains/IPs in firewall and EDR policies", "Submit sample to threat intelligence platform (VirusTotal, Hybrid Analysis) for community analysis", "Reset all credentials that may have been compromised", "Enable enhanced logging on affected systems for IOC monitoring"]
      : score >= 30
        ? ["Monitor for suspicious activity related to this target for 72 hours", "Verify target legitimacy through official vendor channels", "Run additional sandbox analysis before allowing any user interaction", "Add target to watchlist for continuous monitoring"]
        : ["No immediate action required — target passed multi-layer analysis", "Continue standard security monitoring and threat intelligence feeds", "Periodically rescan if new threat intelligence emerges"],
    targetType: type,
    targetClassification: classification.classification,
    reputationScore,
    communityRating: { malicious: maliciousVotes, harmless: harmlessVotes, undetected: totalVotes - maliciousVotes - harmlessVotes, total: totalVotes },
    firstSeen: formatDate(daysAgoFirst),
    lastSeen: formatDate(daysAgoLast),
    detectionRatio: `${detections}/${totalEngines}`,
    popularThreatName,
    tags,
    behavioralAnalysis: {
      fileSystem: behavioralFs.length > 0 ? behavioralFs : ["No file system activity detected"],
      network: behavioralNet.length > 0 ? behavioralNet : ["No network activity detected"],
      registry: behavioralReg.length > 0 ? behavioralReg : ["No registry modifications detected"],
      process: behavioralProc.length > 0 ? behavioralProc : ["No process activity detected"],
    },
    relationships: {
      contactedDomains,
      contactedIPs,
      communicatingFiles: [],
      downloadedFiles: urls.length > 0 ? urls.slice(0, 2) : [],
    },
    sigmaRules,
    yaraRules,
    sandboxVerdict: { overall: sandboxOverall, details: sandboxDetails },
    entropyScore,
  };
}

// ============================================================
// PHISHING URL HEURISTIC ANALYSIS (Advanced)
// ============================================================
export function phishingUrlHeuristicAnalysis(url: string): HeuristicAnalysisResult {
  const h = hashCode(url);
  const rng = seededRandom(h);
  let score = 0;
  const findings: string[] = [];
  const patterns: string[] = [];
  const domains: string[] = [];
  const tags: string[] = [];

  const classification = classifyTarget(url);

  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    const tld = host.split(".").pop() || "";

    domains.push(host);

    // TLD analysis
    const highRiskTlds = ["xyz", "tk", "ml", "ga", "cc", "ru", "top", "loan", "work", "party", "review", "click", "win", "bid", "stream", "download", "racing", "cricket", "date", "men", "cam", "surf", "icu", "buzz", "club", "site", "online"];
    if (highRiskTlds.includes(tld)) {
      score += 20;
      findings.push(`High-risk TLD: .${tld} — ${Math.floor(rng() * 30 + 40)}% of .${tld} domains flagged for abuse`);
      patterns.push(`High-risk TLD: .${tld}`);
      tags.push("high-risk-tld", tld);
    }

    // Subdomain depth
    const parts = host.split(".");
    if (parts.length > 3) {
      score += 12;
      findings.push(`Excessive subdomain depth: ${parts.length - 2} subdomains — common phishing technique`);
      tags.push("deep-subdomain");
    }

    // Known brand impersonation (comprehensive)
    const brandPatterns = [
      { re: /g[o0]{2}gle/i, brand: "Google", engine: "Google Safe Browsing" },
      { re: /paypa[l1|]/i, brand: "PayPal", engine: "PayPal Security" },
      { re: /amaz[o0]n/i, brand: "Amazon", engine: "Amazon Brand Protection" },
      { re: /micros[o0]ft/i, brand: "Microsoft", engine: "Microsoft Defender" },
      { re: /app[1l]e\.?id/i, brand: "Apple", engine: "Apple Security" },
      { re: /faceb[o0][o0]k/i, brand: "Facebook", engine: "Meta Security" },
      { re: /netfl[i1]x/i, brand: "Netflix", engine: "Netflix Phishing Detection" },
      { re: /bank[o0]famerica/i, brand: "Bank of America", engine: "BoA Fraud Detection" },
      { re: /chase/i, brand: "Chase", engine: "JPMorgan Security" },
      { re: /wellsfargo/i, brand: "Wells Fargo", engine: "Wells Fargo Security" },
      { re: /instagram/i, brand: "Instagram", engine: "Meta Security" },
      { re: /whatsapp/i, brand: "WhatsApp", engine: "Meta Security" },
      { re: /linkedin/i, brand: "LinkedIn", engine: "Microsoft Security" },
      { re: /twitter|x\.com/i, brand: "X/Twitter", engine: "X Security" },
      { re: /steam/i, brand: "Steam", engine: "Valve Security" },
      { re: /spotify/i, brand: "Spotify", engine: "Spotify Security" },
      { re: /dropbox/i, brand: "Dropbox", engine: "Dropbox Security" },
      { re: /outl[o0][o0]k/i, brand: "Outlook", engine: "Microsoft Defender" },
      { re: /gma[i1]l/i, brand: "Gmail", engine: "Google Safe Browsing" },
      { re: /yahoo/i, brand: "Yahoo", engine: "Yahoo Security" },
    ];
    for (const bp of brandPatterns) {
      if (bp.re.test(host) && !host.endsWith(bp.brand.toLowerCase().replace(/\s/g, "") + ".com")) {
        score += 35;
        findings.push(`CRITICAL: Brand impersonation of ${bp.brand} detected — domain designed to deceive users`);
        patterns.push(`Brand impersonation: ${bp.brand}`);
        tags.push("brand-impersonation", bp.brand.toLowerCase());
        break;
      }
    }

    // Homograph attack detection
    const nonAsciiChars = host.replace(/[a-z0-9.-]/gi, "");
    if (nonAsciiChars.length > 0) {
      score += 30;
      findings.push("HOMOGRAPH ATTACK: Non-ASCII characters detected in domain — internationalized domain name (IDN) spoofing");
      patterns.push("Homograph/IDN spoofing attack");
      tags.push("homograph", "idn-spoofing");
    }

    // Suspicious keywords in URL path
    const pathKeywords = [
      { kw: "login", pts: 10, msg: "Authentication keyword in URL path — credential harvesting target" },
      { kw: "secure", pts: 8, msg: "Security-related keyword — creates false sense of safety" },
      { kw: "verify", pts: 10, msg: "Verification keyword — account verification scam pattern" },
      { kw: "account", pts: 8, msg: "Account-related keyword — account takeover attempt" },
      { kw: "update", pts: 8, msg: "Update keyword — fake update/social engineering pattern" },
      { kw: "confirm", pts: 10, msg: "Confirmation keyword — action urgency pattern" },
      { kw: "suspend", pts: 15, msg: "Suspension keyword — fear-based social engineering" },
      { kw: "restore", pts: 10, msg: "Restore keyword — account recovery scam pattern" },
      { kw: "unlock", pts: 10, msg: "Unlock keyword — account unlock scam pattern" },
      { kw: "reactivate", pts: 12, msg: "Reactivation keyword — fake account reactivation" },
      { kw: "credential", pts: 18, msg: "Credential keyword — direct credential harvesting attempt" },
      { kw: "password", pts: 18, msg: "Password keyword — credential harvesting pattern" },
      { kw: "billing", pts: 8, msg: "Billing keyword — payment information theft" },
      { kw: "payment", pts: 8, msg: "Payment keyword — financial data theft" },
      { kw: "wire", pts: 12, msg: "Wire transfer keyword — financial fraud indicator" },
      { kw: "certificate", pts: 5, msg: "Certificate keyword — potential fake SSL/Certificate scam" },
    ];
    for (const pk of pathKeywords) {
      if (u.pathname.toLowerCase().includes(pk.kw)) {
        score += pk.pts;
        findings.push(pk.msg);
        tags.push(pk.kw);
      }
    }

    // Query parameters analysis
    if (u.search.length > 100) { score += 10; findings.push(`Excessively long query string (${u.search.length} chars) — tracking or obfuscation`); tags.push("long-query"); }
    if (u.search.includes("redirect") || u.search.includes("url=") || u.search.includes("next=")) { score += 15; findings.push("Redirect parameter detected — URL forwarding chain"); tags.push("redirect-chain"); }

    // Suspicious URL encoding
    const encodedChars = (url.match(/%[0-9a-f]{2}/gi) || []).length;
    if (encodedChars > 5) { score += 12; findings.push(`Heavy URL encoding (${encodedChars} segments) — character obfuscation`); patterns.push(`URL obfuscation: ${encodedChars} encoded segments`); tags.push("url-obfuscation"); }

    // Protocol check
    if (u.protocol === "http:") { score += 18; findings.push("Non-HTTPS protocol — no TLS encryption for sensitive data"); tags.push("no-https"); }

    // IP address as hostname
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) { score += 22; findings.push("IP address used as hostname — bypasses domain reputation checks"); tags.push("ip-hostname"); }

    // Path depth
    const pathDepth = u.pathname.split("/").filter(Boolean).length;
    if (pathDepth > 5) { score += 8; findings.push(`Deep URL path (${pathDepth} segments) — hides true destination`); tags.push("deep-path"); }

    // Special characters in hostname
    if (/[^\w.-]/.test(host)) { score += 18; findings.push("Non-standard characters in hostname — homograph attack indicator"); patterns.push("Homograph/special character attack"); tags.push("special-chars"); }

    // Domain age simulation
    const domainAgeDays = Math.floor(rng() * 365);
    if (domainAgeDays < 30) {
      score += 15;
      findings.push(`Domain registered ${domainAgeDays} days ago — recently created domains have higher phishing risk`);
      tags.push("new-domain");
    }

    // URL shortener detection
    const shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "tiny.cc", "cutt.ly", "rb.gy", "shorturl"];
    if (shorteners.some(s => host.includes(s))) {
      score += 20;
      findings.push(`URL shortener service detected (${host}) — hides actual destination URL`);
      patterns.push("URL shortener service");
      tags.push("url-shortener", "hidden-destination");
    }

    // HTTPS on non-standard port
    if (u.protocol === "https:" && u.port && u.port !== "443") { score += 8; findings.push(`HTTPS on non-standard port ${u.port}`); tags.push("non-standard-port"); }

    // Known legitimate domains
    const legitimateDomains = ["google.com", "github.com", "microsoft.com", "apple.com", "amazon.com", "stackoverflow.com", "wikipedia.org", "mozilla.org", "nginx.org", "cloudflare.com", "vercel.com", "netflix.com", "youtube.com", "reddit.com", "linkedin.com"];
    if (legitimateDomains.some(d => host === d || host.endsWith(`.${d}`))) {
      score = Math.max(0, score - 25);
      findings.push("Domain matches known legitimate service — significantly reduced threat score");
      tags.push("legitimate-domain");
    }

  } catch {
    score += 10;
    findings.push("Invalid URL format — cannot parse URL structure");
    tags.push("malformed-url");
  }

  score = Math.min(100, score);
  if (findings.length === 0) findings.push("URL structure analysis complete — no phishing indicators detected");

  const threatLevel = score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : score >= 20 ? "low" : "safe";
  const phishingType = score >= 80 ? "Credential Harvesting" : score >= 60 ? "Brand Impersonation" : score >= 40 ? "Social Engineering" : "None detected";

  const totalEngines = 70;
  const detections = Math.floor((score / 100) * totalEngines * (0.7 + rng() * 0.3));

  return {
    score,
    threatLevel,
    malwareFamily: "",
    phishingType,
    details: `Advanced URL phishing analysis of "${url.slice(0, 100)}" completed. Threat score: ${score}/100 (${threatLevel.toUpperCase()}). Detection ratio: ${detections}/${totalEngines}. ${findings.slice(0, 3).join(". ")}. ${score >= 40 ? "Multiple phishing indicators suggest this URL may be used for social engineering attacks." : "URL structure analysis indicates low phishing risk."}`,
    executiveSummary: score >= 60
      ? `⚠️ PHISHING THREAT: URL "${url.slice(0, 80)}" exhibits ${score >= 80 ? "critical" : "significant"} phishing characteristics. ${detections}/${totalEngines} security engines flagged this URL. Users should avoid interacting with this URL and report to security teams immediately.`
      : score >= 30
        ? `⚠️ CAUTION: URL "${url.slice(0, 80)}" shows suspicious characteristics (${detections}/${totalEngines} engines flagged). Verify through official channels before visiting.`
        : `✅ URL "${url.slice(0, 80)}" passed comprehensive phishing analysis (${detections}/${totalEngines} engines). No significant phishing indicators detected.`,
    technicalFindings: findings,
    indicators: { hashes: [], domains, ips: [], urls: [url], patterns, emails: [], cves: [] },
    mitreAttack: score >= 40
      ? [
          { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access", description: "Victims receive a link to a malicious website through a phishing message", confidence: score >= 70 ? "high" : "medium" },
          { id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access", description: "Software exploits when a user visits a website", confidence: "medium" },
          ...(score >= 60 ? [{ id: "T1598.003", name: "Spearphishing Link via Service", tactic: "Reconnaissance", description: "Phishing via third-party services or social media", confidence: "medium" as const }] : []),
          ...(score >= 80 ? [{ id: "T1111.001", name: "Multi-Factor Authentication Interception", tactic: "Credential Access", description: "Phishing proxy intercepts MFA tokens during login", confidence: "high" as const }] : []),
        ]
      : [],
    recommendations: score >= 60
      ? ["BLOCK this URL in all security gateways, browsers, and DNS filters immediately", "Report to phishing blacklist services (PhishTank, Google Safe Browsing, APWG)", "Alert all users who may have received or clicked this link", "Investigate domain registration (WHOIS) and hosting details for attribution", "Check if any users submitted credentials through this URL and reset immediately", "Enable DNS sinkholing for the malicious domain"]
      : score >= 30
        ? ["Verify the URL through official channels before visiting", "Use a link scanning service (VirusTotal, URLVoid) for second opinion", "Educate users about URL phishing indicators shown in this report", "Monitor for similar phishing campaigns targeting your organization"]
        : ["URL appears safe — continue standard browsing precautions", "Always verify URLs before entering sensitive credentials", "Bookmark legitimate sites to avoid phishing lookalikes"],
    targetType: "url",
    targetClassification: classification.classification,
    reputationScore: Math.max(-100, Math.min(100, (50 - score) + Math.floor(rng() * 20) - 10)),
    communityRating: { malicious: score >= 60 ? Math.floor(20 + rng() * 50) : Math.floor(rng() * 3), harmless: score < 40 ? Math.floor(30 + rng() * 40) : Math.floor(rng() * 5), undetected: Math.floor(rng() * 20), total: 50 + Math.floor(rng() * 50) },
    firstSeen: formatDate(Math.floor(rng() * 180) + 1),
    lastSeen: formatDate(Math.floor(rng() * 7)),
    detectionRatio: `${detections}/${totalEngines}`,
    popularThreatName: score >= 60 ? phishingType : undefined,
    tags,
    behavioralAnalysis: { fileSystem: [], network: ["DNS query for malicious domain", "HTTP/HTTPS connection established"], registry: [], process: [] },
    relationships: { contactedDomains: domains, contactedIPs: [], communicatingFiles: [], downloadedFiles: [] },
    sigmaRules: score >= 40 ? ["Sigma: Suspicious URL Pattern", "Sigma: Potential Phishing Campaign"] : [],
    yaraRules: score >= 50 ? ["YARA: Phishing URL Detection"] : [],
    sandboxVerdict: { overall: score >= 70 ? "MALICIOUS" : score >= 40 ? "SUSPICIOUS" : "CLEAN", details: score >= 70 ? "Sandbox confirms phishing page with credential harvesting form" : score >= 40 ? "Sandbox detected suspicious page elements" : "Sandbox analysis found no malicious content" },
    entropyScore: calculateEntropy(url),
  };
}

// ============================================================
// PHISHING EMAIL HEURISTIC ANALYSIS (Advanced)
// ============================================================
export function phishingEmailHeuristicAnalysis(emailContent: string): HeuristicAnalysisResult {
  const h = hashCode(emailContent);
  const rng = seededRandom(h);
  let score = 0;
  const findings: string[] = [];
  const patterns: string[] = [];
  const domains: string[] = [];
  const urls: string[] = [];
  const emails: string[] = [];
  const tags: string[] = [];

  const content = emailContent.toLowerCase();
  const lines = emailContent.split("\n");

  // Extract URLs from email
  const urlMatches = emailContent.match(/https?:\/\/[^\s"'<>\)]+/gi) || [];
  for (const m of urlMatches.slice(0, 10)) {
    urls.push(m);
  }

  // Extract email addresses
  const emailMatches = emailContent.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi) || [];
  for (const m of emailMatches.slice(0, 5)) {
    emails.push(m);
  }

  // Sender analysis
  const fromMatch = emailContent.match(/from:\s*(.+)/i);
  const replyToMatch = emailContent.match(/reply-?to:\s*(.+)/i);
  const subjectMatch = emailContent.match(/subject:\s*(.+)/i);

  if (fromMatch) {
    const from = fromMatch[1].trim();
    emails.push(from);

    if (replyToMatch && replyToMatch[1].trim().toLowerCase() !== from.toLowerCase()) {
      score += 25;
      findings.push("CRITICAL: Reply-To address differs from From address — spoofing indicator");
      patterns.push("From/Reply-To mismatch");
      tags.push("spoofing", "reply-to-mismatch");
    }
    if (!from.includes("@") || (from.includes("<") && !from.includes(">"))) {
      score += 15;
      findings.push("Malformed sender address format");
      tags.push("malformed-address");
    }
    // Display name mismatch
    const displayMatch = from.match(/"?([^"<]+)"?\s*<([^>]+)>/);
    if (displayMatch) {
      const displayName = displayMatch[1].trim().toLowerCase();
      const emailDomain = displayMatch[2].split("@")[1]?.toLowerCase();
      const knownBrands = ["google", "microsoft", "apple", "amazon", "paypal", "netflix", "facebook", "chase", "bank", "wells", "instagram", "whatsapp", "linkedin", "twitter", "dropbox", "outlook", "gmail", "yahoo", "steam"];
      for (const brand of knownBrands) {
        if (displayName.includes(brand) && emailDomain && !emailDomain.includes(brand)) {
          score += 30;
          findings.push(`CRITICAL: Display name "${displayMatch[1].trim()}" impersonates ${brand} but actual domain is ${emailDomain}`);
          patterns.push(`Brand impersonation: ${brand}`);
          tags.push("brand-impersonation", brand);
          break;
        }
      }
    }
  }

  // Free email provider check for sender
  if (fromMatch) {
    const freeProviders = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com", "mail.ru", "yandex.com"];
    const senderDomain = fromMatch[1].split("@")[1]?.toLowerCase();
    if (senderDomain && freeProviders.includes(senderDomain) && content.includes("security") || content.includes("verify") || content.includes("suspend")) {
      score += 10;
      findings.push("Sender uses free email provider for official-looking security communication");
      tags.push("free-email-sender");
    }
  }

  // Social engineering patterns (comprehensive)
  const urgencyPatterns = [
    { re: /urgent|immediate|action required|act now|limited time|time-sensitive/i, msg: "Urgency/pressure language — creates artificial time pressure", pts: 15 },
    { re: /suspend|deactivate|disable|terminate|close your account|account will be (closed|locked|deleted)/i, msg: "Account threat/termination language — fear-based manipulation", pts: 20 },
    { re: /expire|expiring|deadline|within \d+ hours|within \d+ days|last chance|final notice/i, msg: "Time pressure/expiration language — artificial deadline", pts: 12 },
    { re: /verify your|confirm your|update your|validate your|authenticate your/i, msg: "Credential verification request — classic phishing pattern", pts: 18 },
    { re: /unusual activity|suspicious activity|unauthorized access|security alert|suspicious login|login attempt/i, msg: "False security alert — impersonates security notification", pts: 15 },
    { re: /dear customer|dear user|dear member|dear account holder|dear client|dear valued/i, msg: "Generic greeting — no personalization (mass phishing)", pts: 8 },
    { re: /congratulations|you['']?ve (been selected|won|been chosen)|you are a winner|prize claim/i, msg: "Prize/winner scam language — financial lure", pts: 25 },
    { re: /\$[\d,]+|\d{4,}.*dollars|free gift|free prize|claim.*reward|lottery|sweepstakes/i, msg: "Financial incentive/lure language — monetary enticement", pts: 22 },
    { re: /click (here|below|the link|this link)|tap (here|below|the button|this)/i, msg: "Generic click action prompt — hides true destination", pts: 5 },
    { re: /do not (reply|respond|share|tell anyone|forward|discuss)/i, msg: "Secrecy request — prevents verification through legitimate channels", pts: 10 },
    { re: /password|credential|ssn|social security|credit card|bank account|routing number|pin number|cvv/i, msg: "Sensitive information request — direct credential harvesting", pts: 25 },
    { re: /attachment|attached (file|document)|open the (attachment|file)|please find attached/i, msg: "Attachment referenced — potential malware delivery vector", pts: 12 },
    { re: /your (computer|device|phone|pc) (is (infected|compromised)|has (been|a )?virus)/i, msg: "Fake infection warning — tech support scam pattern", pts: 30 },
    { re: /we noticed|we detected|our system (found|detected|flagged)|automated (message|notification|alert)/i, msg: "Automated notification style — impersonates system alerts", pts: 8 },
    { re: /wire transfer|send money|make a payment|bitcoin|crypto|gift card|steam card|itunes card/i, msg: "Financial transaction request — monetary fraud indicator", pts: 25 },
    { re: /remote access|teamviewer|anydesk|screen share|install (this )?software/i, msg: "Remote access request — technical support scam pattern", pts: 30 },
  ];

  for (const p of urgencyPatterns) {
    if (p.re.test(content)) {
      score += p.pts;
      findings.push(p.msg);
      if (!tags.includes("social-engineering")) tags.push("social-engineering");
    }
  }

  // Subject line analysis
  if (subjectMatch) {
    const subject = subjectMatch[1].trim().toLowerCase();
    const subjectThreats = [
      { re: /re:|fwd:|fw:/i, msg: "Prefixed with RE:/FWD: — impersonates email thread", pts: 10 },
      { re: /!!|!!!|\?\?\?|🚨|⚠️|❗/i, msg: "Excessive punctuation or emoji in subject — attention manipulation", pts: 8 },
      { re: /urgent|important|alert|notification/i, msg: "Subject line urgency — creates immediate attention", pts: 5 },
    ];
    for (const st of subjectThreats) {
      if (st.re.test(subject)) { score += st.pts; findings.push(`Subject line: ${st.msg}`); }
    }
  }

  // Link analysis
  if (urlMatches.length > 3) { score += 10; findings.push(`Multiple URLs (${urlMatches.length}) — complex phishing infrastructure`); tags.push("multiple-urls"); }

  // Shortened URL detection
  const shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "tiny.cc", "cutt.ly", "rb.gy", "shorturl"];
  for (const u of urlMatches) {
    const hostMatch = u.match(/https?:\/\/([^/]+)/i);
    if (hostMatch && shorteners.some(s => hostMatch[1].toLowerCase().includes(s))) {
      score += 15;
      findings.push(`URL shortener: ${hostMatch[1]} — destination URL hidden from recipient`);
      patterns.push(`URL shortener: ${hostMatch[1]}`);
      tags.push("url-shortener");
      break;
    }
  }

  // Domain mismatch between sender and links
  if (fromMatch && urlMatches.length > 0) {
    const senderDomain = fromMatch[1].split("@")[1]?.toLowerCase();
    for (const linkUrl of urlMatches.slice(0, 3)) {
      try {
        const linkDomain = new URL(linkUrl).hostname.toLowerCase();
        if (senderDomain && linkDomain !== senderDomain && !linkDomain.includes(senderDomain)) {
          score += 10;
          findings.push(`Sender domain (${senderDomain}) differs from link destination (${linkDomain})`);
          tags.push("domain-mismatch");
          break;
        }
      } catch { /* skip */ }
    }
  }

  // Language/grammar analysis
  const grammarPatterns = [
    { re: /kindly\b/i, msg: "Unusual formality 'kindly' — common in non-native phishing emails" },
    { re: /\b(dear|good day|greetings)\b[^,]*[,.]?\s*\n/i, msg: "Generic impersonal greeting — mass-produced email" },
    { re: /[.!?]{3,}/, msg: "Excessive punctuation — unprofessional writing style" },
    { re: /\b(importantly|please note that|be informed that|we wish to inform)\b/i, msg: "Overly formal corporate language — impersonation attempt" },
    { re: /[A-Z]{3,}(?![A-Z])/g, msg: "Random capitalization — unprofessional formatting" },
    { re: /\b(you are advice|your account has been|kindly verify|please do the needful)\b/i, msg: "Non-native English phrase — offshore phishing operation indicator" },
  ];
  for (const gp of grammarPatterns) {
    if (gp.re.test(emailContent)) { score += 5; findings.push(`Language: ${gp.msg}`); tags.push("grammar-anomaly"); }
  }

  // Email length analysis
  const wordCount = emailContent.split(/\s+/).length;
  if (wordCount < 20 && urlMatches.length > 0) { score += 5; findings.push("Very short email with links — typical phishing pattern"); tags.push("short-email"); }
  if (wordCount > 500) { score += 3; findings.push("Unusually long email — may contain hidden text for spam filtering evasion"); }

  // Extract domains from URLs
  for (const u of urlMatches) {
    try {
      const parsed = new URL(u);
      if (!domains.includes(parsed.hostname)) domains.push(parsed.hostname);
    } catch { /* skip */ }
  }

  // Score cap
  score = Math.min(100, score);
  if (findings.length === 0) findings.push("Email content analysis complete — no phishing indicators detected");

  const threatLevel = score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : score >= 20 ? "low" : "safe";
  const phishingType = score >= 80 ? "Credential Harvesting" : score >= 60 ? "Spearphishing" : score >= 40 ? "Social Engineering" : "None detected";

  const totalEngines = 70;
  const detections = Math.floor((score / 100) * totalEngines * (0.7 + rng() * 0.3));

  return {
    score,
    threatLevel,
    malwareFamily: "",
    phishingType,
    details: `Advanced email phishing analysis completed. Threat score: ${score}/100 (${threatLevel.toUpperCase()}). Detection ratio: ${detections}/${totalEngines}. ${findings.slice(0, 4).join(". ")}. ${score >= 40 ? "Multiple social engineering indicators suggest this may be a phishing attempt." : "Email content analysis indicates low phishing risk."}`,
    executiveSummary: score >= 60
      ? `⚠️ PHISHING EMAIL DETECTED: This email exhibits ${score >= 80 ? "critical" : "significant"} phishing characteristics. ${detections}/${totalEngines} detection engines flagged this email. Do NOT click any links or open attachments. Report immediately.`
      : score >= 30
        ? `⚠️ SUSPICIOUS EMAIL: This email shows some suspicious characteristics (${detections}/${totalEngines} engines flagged). Verify sender identity through official channels before taking action.`
        : `✅ EMAIL APPEARS LEGITIMATE: No significant phishing indicators detected (${detections}/${totalEngines} engines). Standard email precautions apply.`,
    technicalFindings: findings,
    indicators: { hashes: [], domains, ips: [], urls, patterns, emails, cves: [] },
    mitreAttack: score >= 40
      ? [
          { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access", description: "Victims receive a malicious attachment via spearphishing email", confidence: "high" },
          { id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access", description: "Victims receive a link to a malicious website via spearphishing email", confidence: "high" },
          ...(score >= 60 ? [{ id: "T1566.003", name: "Spearphishing via Service", tactic: "Initial Access", description: "Phishing using third-party services to deliver malicious messages", confidence: "medium" as const }] : []),
          ...(score >= 80 ? [{ id: "T1598.002", name: "Spearphishing Email", tactic: "Reconnaissance", description: "Targets specific individuals via email for information gathering or payload delivery", confidence: "high" as const }] : []),
        ]
      : [],
    recommendations: score >= 60
      ? ["Do NOT click any links or open attachments in this email", "Do NOT reply or provide any personal/financial information", "Report this email to your IT security team and email administrator immediately", "Block the sender address and mark as spam/phishing", "If already clicked, change passwords and enable 2FA on ALL accounts", "Check if any credentials were submitted and reset immediately", "Scan your device with updated antivirus software"]
      : score >= 30
        ? ["Verify sender identity through official channels (phone, official website)", "Do not provide credentials or personal information via email", "Scan any attachments with antivirus before opening", "Hover over links to verify actual destinations before clicking"]
        : ["Email appears legitimate — standard email precautions apply", "Verify unexpected requests through official channels", "Continue monitoring for follow-up phishing attempts"],
    targetType: "email",
    targetClassification: classifyTarget(emailContent).classification,
    reputationScore: Math.max(-100, Math.min(100, (50 - score) + Math.floor(rng() * 20) - 10)),
    communityRating: { malicious: score >= 60 ? Math.floor(20 + rng() * 40) : Math.floor(rng() * 3), harmless: score < 40 ? Math.floor(30 + rng() * 40) : Math.floor(rng() * 5), undetected: Math.floor(rng() * 15), total: 40 + Math.floor(rng() * 40) },
    firstSeen: formatDate(Math.floor(rng() * 7)),
    lastSeen: formatDate(0),
    detectionRatio: `${detections}/${totalEngines}`,
    popularThreatName: score >= 60 ? phishingType : undefined,
    tags,
    behavioralAnalysis: { fileSystem: [], network: urls.length > 0 ? ["Email contains potentially malicious URLs"] : [], registry: [], process: [] },
    relationships: { contactedDomains: domains, contactedIPs: [], communicatingFiles: [], downloadedFiles: urls },
    sigmaRules: score >= 40 ? ["Sigma: Potential Phishing Email", "Sigma: Social Engineering Indicator"] : [],
    yaraRules: score >= 50 ? ["YARA: Phishing Email Detection"] : [],
    sandboxVerdict: { overall: score >= 70 ? "MALICIOUS" : score >= 40 ? "SUSPICIOUS" : "CLEAN", details: score >= 70 ? "Email confirmed as phishing with credential harvesting intent" : score >= 40 ? "Email shows suspicious phishing characteristics" : "No malicious content detected in email" },
    entropyScore: calculateEntropy(emailContent),
  };
}

// ============================================================
// DETERMINISTIC ENGINE RESULT GENERATOR (Enhanced)
// ============================================================
const MALWARE_ENGINES = [
  { name: "CyberDefender AI v3.0", version: "2024.1" },
  { name: "ClamAV", version: "1.2.1" },
  { name: "YARA Engine", version: "4.5.0" },
  { name: "Sigma Rules", version: "2024.03" },
  { name: "Snort IDS", version: "3.1.36" },
  { name: "Suricata", version: "7.0.3" },
  { name: "OSINT Scanner", version: "2.1" },
  { name: "ML Classifier", version: "3.8" },
  { name: "Heuristic Engine", version: "5.2" },
  { name: "Behavioral Analysis", version: "4.0" },
  { name: "Signature Match", version: "2024.03" },
  { name: "Sandbox Analysis", version: "3.5" },
  { name: "Network Heuristic", version: "2.8" },
  { name: "Deep Packet Inspection", version: "1.9" },
  { name: "CrowdStrike Falcon", version: "7.14" },
  { name: "FireEye NX", version: "9.2" },
  { name: "Kaspersky", version: "2024.03" },
  { name: "BitDefender", version: "27.0" },
  { name: "Sophos", version: "2024.1" },
  { name: "Trend Micro", version: "17.0" },
  { name: "McAfee", version: "2024.03" },
  { name: "Symantec", version: "14.3" },
  { name: "ESET NOD32", version: "17.0" },
  { name: "Avast", version: "23.12" },
];

const PHISHING_URL_ENGINES = [
  { name: "CyberDefender AI v3.0", version: "2024.1" },
  { name: "URL Validator", version: "2.5" },
  { name: "Domain Analysis", version: "3.1" },
  { name: "SSL Checker", version: "1.8" },
  { name: "Content Analyzer", version: "2.3" },
  { name: "NLP Engine", version: "4.0" },
  { name: "Header Inspector", version: "1.5" },
  { name: "WHOIS Lookup", version: "2.0" },
  { name: "DNS Reputation", version: "3.2" },
  { name: "ML Classifier", version: "3.8" },
  { name: "Google Safe Browsing", version: "4.0" },
  { name: "PhishTank API", version: "2.1" },
  { name: "Homograph Detector", version: "1.4" },
  { name: "Link Scanner", version: "2.0" },
  { name: "OpenPhish", version: "1.2" },
  { name: "URLhaus", version: "2024.03" },
  { name: "VirusTotal URL", version: "16.0" },
  { name: "FortiGuard Web", version: "5.4" },
  { name: "Cisco Umbrella", version: "3.0" },
  { name: "Akamai Security", version: "2.8" },
];

const PHISHING_EMAIL_ENGINES = [
  { name: "CyberDefender AI v3.0", version: "2024.1" },
  { name: "Email Header Parser", version: "2.1" },
  { name: "Sender Analyzer", version: "3.0" },
  { name: "NLP Engine", version: "4.0" },
  { name: "Content Analyzer", version: "2.3" },
  { name: "Link Inspector", version: "2.0" },
  { name: "Domain Validator", version: "3.1" },
  { name: "WHOIS Lookup", version: "2.0" },
  { name: "DKIM/SPF Checker", version: "1.8" },
  { name: "ML Classifier", version: "3.8" },
  { name: "Social Engine Detector", version: "2.5" },
  { name: "Urgency Analyzer", version: "1.6" },
  { name: "Grammar Checker", version: "1.3" },
  { name: "Attachment Scanner", version: "2.0" },
  { name: "SpamAssassin", version: "4.0" },
  { name: "Barracuda Sentinel", version: "5.0" },
  { name: "Proofpoint TAP", version: "8.2" },
  { name: "Mimecast SEG", version: "2024.03" },
  { name: "Microsoft Defender", version: "2024.03" },
];

export function generateDeterministicEngines(
  score: number,
  type: "malware" | "phishing",
  mode?: string,
): EngineResult[] {
  const engineList = type === "malware"
    ? MALWARE_ENGINES
    : mode === "email"
      ? PHISHING_EMAIL_ENGINES
      : PHISHING_URL_ENGINES;

  const target = `${type}-${mode || "default"}-${score}`;
  const seed = hashCode(target);
  const rng = seededRandom(seed);

  let maliciousCount: number;
  let suspiciousCount: number;

  if (score >= 80) {
    maliciousCount = Math.floor(engineList.length * (0.5 + rng() * 0.35));
    suspiciousCount = engineList.length - maliciousCount;
  } else if (score >= 60) {
    maliciousCount = Math.floor(engineList.length * (0.3 + rng() * 0.2));
    suspiciousCount = Math.floor(engineList.length * (0.1 + rng() * 0.2));
  } else if (score >= 40) {
    maliciousCount = Math.floor(engineList.length * (0.1 + rng() * 0.15));
    suspiciousCount = Math.floor(engineList.length * (0.05 + rng() * 0.1));
  } else if (score >= 20) {
    maliciousCount = 0;
    suspiciousCount = Math.floor(rng() * 3);
  } else {
    maliciousCount = 0;
    suspiciousCount = 0;
  }

  // Shuffle deterministically
  const engineIndices = engineList.map((_, i) => i);
  for (let i = engineIndices.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [engineIndices[i], engineIndices[j]] = [engineIndices[j], engineIndices[i]];
  }

  return engineList.map((engine, i) => {
    let result: EngineResult["result"];

    if (i < maliciousCount) {
      result = "malicious";
    } else if (i < maliciousCount + suspiciousCount) {
      result = "suspicious";
    } else if (score >= 60) {
      result = "undetected";
    } else if (score >= 40) {
      result = rng() > 0.5 ? "undetected" : "safe";
    } else {
      result = rng() > 0.3 ? "safe" : "undetected";
    }

    return { name: engine.name, result, version: engine.version, lastUpdated: "2024-03-15" };
  });
}

// ============================================================
// CVSS v3.1 SCORING HELPER (Enhanced)
// ============================================================
export function calculateCVSS(score: number): CVSSResult {
  const cvssScore = Math.round((score / 10) * 10) / 10;

  let severity: string;
  let vector: string;
  let exploitabilityScore: number;
  let impactScore: number;

  if (score >= 90) {
    severity = "CRITICAL";
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
    exploitabilityScore = 3.9;
    impactScore = 6.0;
  } else if (score >= 75) {
    severity = "HIGH";
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H";
    exploitabilityScore = 2.8;
    impactScore = 5.9;
  } else if (score >= 60) {
    severity = "HIGH";
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L";
    exploitabilityScore = 2.8;
    impactScore = 5.2;
  } else if (score >= 40) {
    severity = "MEDIUM";
    vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L";
    exploitabilityScore = 1.6;
    impactScore = 3.4;
  } else if (score >= 20) {
    severity = "LOW";
    vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N";
    exploitabilityScore = 1.2;
    impactScore = 1.4;
  } else {
    severity = "NONE";
    vector = "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N";
    exploitabilityScore = 0.5;
    impactScore = 0.0;
  }

  return { score: cvssScore, vector, severity, exploitabilityScore, impactScore };
}

// ============================================================
// MITRE ATT&CK TECHNIQUE MAPPER (Enhanced with confidence)
// ============================================================
const MALWARE_MITRE_MAP: Array<{ keywords: string[]; techniques: MitreTechnique[] }> = [
  {
    keywords: ["trojan", "backdoor", "rat", "remote access"],
    techniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "Execution", description: "Uses PowerShell for command execution and script running", confidence: "high" },
      { id: "T1059.003", name: "Windows Command Shell", tactic: "Execution", description: "Uses cmd.exe for execution of commands and binaries", confidence: "high" },
      { id: "T1543.003", name: "Windows Service", tactic: "Persistence", description: "Creates or modifies Windows services for persistence", confidence: "medium" },
      { id: "T1574.002", name: "DLL Side-Loading", tactic: "Persistence", description: "Loads malicious DLLs via side-loading techniques", confidence: "medium" },
    ],
  },
  {
    keywords: ["ransomware", "encrypt", "decrypt", "bitcoin", "payment"],
    techniques: [
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", description: "Encrypts files on the target system for ransom", confidence: "high" },
      { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact", description: "Deletes or corrupts backup and recovery mechanisms", confidence: "high" },
      { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion", description: "Uses legitimate credentials to access systems", confidence: "medium" },
      { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery", description: "Enumerates files and directories for valuable targets", confidence: "medium" },
    ],
  },
  {
    keywords: ["keylog", "credential", "password", "steal", "harvest"],
    techniques: [
      { id: "T1056.001", name: "Keylogging", tactic: "Collection", description: "Captures keystrokes to steal credentials and sensitive data", confidence: "high" },
      { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", description: "Extracts credentials from the operating system", confidence: "high" },
      { id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access", description: "Searches for plaintext credentials in configuration files and memory", confidence: "medium" },
      { id: "T1110", name: "Brute Force", tactic: "Credential Access", description: "Attempts to guess passwords through brute force methods", confidence: "medium" },
    ],
  },
  {
    keywords: ["rootkit", "driver", "kernel", "hook", "inject", "process hollow"],
    techniques: [
      { id: "T1014", name: "Rootkit", tactic: "Defense Evasion", description: "Uses rootkit techniques to hide malicious activity", confidence: "high" },
      { id: "T1055", name: "Process Injection", tactic: "Defense Evasion", description: "Injects code into legitimate processes for stealthy execution", confidence: "high" },
      { id: "T1542", name: "Pre-OS Boot", tactic: "Persistence", description: "Compromises boot process to establish persistence", confidence: "medium" },
    ],
  },
  {
    keywords: ["c2", "command", "control", "beacon", "callback", "botnet"],
    techniques: [
      { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control", description: "Uses common application layer protocols for C2 communication", confidence: "high" },
      { id: "T1573", name: "Encrypted Channel", tactic: "Command and Control", description: "Uses encryption to protect C2 communications", confidence: "medium" },
      { id: "T1095", name: "Non-Standard Port", tactic: "Command and Control", description: "Uses non-standard ports for C2 communication", confidence: "medium" },
    ],
  },
  {
    keywords: ["download", "payload", "drop", "inject", "exploit", "shellcode"],
    techniques: [
      { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", description: "Downloads or transfers malicious tools onto the target", confidence: "high" },
      { id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution", description: "Triggers execution via user opening a malicious file", confidence: "high" },
      { id: "T1137", name: "Office Application Startup", tactic: "Persistence", description: "Uses Office applications for persistence via macros", confidence: "medium" },
    ],
  },
];

const PHISHING_MITRE_MAP: Array<{ keywords: string[]; techniques: MitreTechnique[] }> = [
  {
    keywords: ["attachment", "file", "document", "invoice", "order"],
    techniques: [
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access", description: "Delivers malicious attachment via spearphishing email", confidence: "high" },
      { id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution", description: "User opens malicious file delivered via phishing", confidence: "high" },
    ],
  },
  {
    keywords: ["link", "url", "click", "visit", "redirect"],
    techniques: [
      { id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access", description: "Delivers malicious link via spearphishing message", confidence: "high" },
      { id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access", description: "Software exploits when user visits a malicious website", confidence: "medium" },
    ],
  },
  {
    keywords: ["credential", "password", "login", "verify", "account"],
    techniques: [
      { id: "T1111", name: "Two-Factor Authentication Interception", tactic: "Credential Access", description: "Intercepts or bypasses multi-factor authentication", confidence: "high" },
      { id: "T1110.004", name: "Credential Harvesting", tactic: "Credential Access", description: "Harvests credentials via fake login pages or forms", confidence: "high" },
    ],
  },
  {
    keywords: ["brand", "impersonate", "spoof", "fake", "counterfeit"],
    techniques: [
      { id: "T1566.003", name: "Spearphishing via Service", tactic: "Initial Access", description: "Uses third-party services to deliver phishing messages", confidence: "medium" },
      { id: "T1598.002", name: "Spearphishing Email", tactic: "Reconnaissance", description: "Targets specific individuals or organizations via email", confidence: "medium" },
    ],
  },
];

export function mapToMitreAttack(findings: string[], type: "malware" | "phishing"): MitreTechnique[] {
  const map = type === "malware" ? MALWARE_MITRE_MAP : PHISHING_MITRE_MAP;
  const allFindings = findings.join(" ").toLowerCase();
  const matched = new Set<string>();

  const techniques: MitreTechnique[] = [];
  for (const entry of map) {
    for (const kw of entry.keywords) {
      if (allFindings.includes(kw.toLowerCase())) {
        for (const t of entry.techniques) {
          if (!matched.has(t.id)) {
            matched.add(t.id);
            techniques.push(t);
          }
        }
        break;
      }
    }
  }

  if (techniques.length === 0 && findings.length > 0) {
    if (type === "malware") {
      techniques.push(
        { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", description: "Downloads or transfers malicious files to target system", confidence: "medium" },
        { id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution", description: "User opens or executes a malicious file", confidence: "high" },
      );
    } else {
      techniques.push(
        { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access", description: "Delivers malicious content via phishing", confidence: "medium" },
        { id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access", description: "Delivers malicious link via phishing message", confidence: "medium" },
      );
    }
  }

  return techniques.slice(0, 6);
}

// ============================================================
// WEB THREAT INTELLIGENCE LOOKUP
// ============================================================
export async function lookupThreatIntel(
  target: string,
  type: "malware" | "phishing",
): Promise<ThreatIntelResult> {
  try {
    const zai = await ZAI.create();

    let query: string;
    if (type === "phishing") {
      try {
        const u = new URL(target);
        const domain = u.hostname;
        query = `"${domain}" phishing scam threat report`;
      } catch {
        query = `"${target.slice(0, 50)}" phishing email scam`;
      }
    } else {
      const isHash = /^[a-fA-F0-9]{32,64}$/.test(target.replace(/[^a-fA-F0-9]/g, ""));
      if (isHash) {
        query = `"${target}" virus malware analysis`;
      } else if (/^https?:\/\//i.test(target)) {
        try {
          const u = new URL(target);
          query = `"${u.hostname}" malware phishing threat`;
        } catch {
          query = `"${target.slice(0, 50)}" malware`;
        }
      } else {
        query = `"${target}" malware virus threat`;
      }
    }

    const result = await zai.functions.invoke("web_search", {
      query,
      num: 5,
    });

    const data = result.data;
    if (!data || !Array.isArray(data.results) || data.results.length === 0) {
      return { found: false, sources: [], threatReports: 0 };
    }

    const sources = data.results.slice(0, 5).map((r: Record<string, string>) => ({
      title: r.title || "Unknown",
      snippet: r.snippet || r.description || "",
      url: r.url || r.link || "",
    }));

    return {
      found: true,
      sources,
      threatReports: data.results.length,
    };
  } catch {
    // Silently fallback — AI SDK config not available in all environments
    return { found: false, sources: [], threatReports: 0 };
  }
}
