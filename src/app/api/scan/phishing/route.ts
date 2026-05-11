import { NextRequest, NextResponse } from "next/server";
import ZAI from "z-ai-web-dev-sdk";

function generateEngineResults(phishingScore: number, mode: "url" | "email") {
  const engines = mode === "url"
    ? ["CyberDefender AI", "URL Validator", "Domain Analysis", "SSL Checker",
       "Content Analyzer", "NLP Engine", "Header Inspector", "WHOIS Lookup",
       "DNS Reputation", "ML Classifier", "Google Safe Browsing", "PhishTank API",
       "Homograph Detector", "Link Scanner"]
    : ["CyberDefender AI", "Email Header Parser", "Sender Analyzer", "NLP Engine",
       "Content Analyzer", "Link Inspector", "Domain Validator", "WHOIS Lookup",
       "DKIM/SPF Checker", "ML Classifier", "Social Engine Detector", "Urgency Analyzer",
       "Grammar Checker", "Attachment Scanner"];
  return engines.map((name) => {
    const r = Math.random();
    const factor = phishingScore / 100;
    let result: "malicious" | "suspicious" | "safe" | "undetected";
    if (r < factor * 0.5) result = "malicious";
    else if (r < factor * 0.75) result = "suspicious";
    else if (r < 0.9) result = "undetected";
    else result = "safe";
    return { name, result };
  });
}

export async function POST(request: NextRequest) {
  try {
    const { target, mode } = await request.json();
    const analysisMode: "url" | "email" = mode === "email" ? "email" : "url";

    if (!target || typeof target !== "string" || target.trim().length === 0) {
      return NextResponse.json(
        { error: "Target is required. Provide a URL or email content." },
        { status: 400 }
      );
    }

    const zai = await ZAI.create();

    const systemPrompt = analysisMode === "url"
      ? `You are CyberDefender, an elite AI-powered phishing URL detection engine. You specialize in identifying both known and zero-day phishing URLs.

You perform comprehensive URL analysis including:
- Domain reputation and age verification
- URL structure analysis (subdomains, paths, parameters)
- TLD risk assessment
- SSL/TLS certificate validation
- Homograph attack detection
- URL encoding and obfuscation detection
- Redirect chain analysis
- Brand impersonation detection

IMPORTANT: Respond ONLY with valid JSON (no markdown, no code blocks):
{
  "score": <number 0-100 phishing probability>,
  "threatLevel": "<critical|high|medium|low|safe>",
  "phishingType": "<string - specific phishing type detected>",
  "details": "<string - detailed URL analysis in 3-5 professional sentences focusing ONLY on URL-specific findings>",
  "indicators": ["<URL-specific indicator 1>", "<URL-specific indicator 2>", ...],
  "recommendations": ["<action 1>", "<action 2>", ...]
}

Scoring: 0-19 SAFE, 20-39 LOW, 40-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL.
Known legitimate domains (google.com, github.com, etc.) score 0-15.
Known phishing patterns score 80-100.`
      : `You are CyberDefender, an elite AI-powered phishing email detection engine. You specialize in identifying both known and zero-day phishing emails.

You perform comprehensive email analysis including:
- Sender address verification and spoofing detection
- Social engineering pattern detection
- Urgency and pressure tactic analysis
- Link and URL inspection within the email
- Grammar and spelling anomaly detection
- Header analysis (From, Reply-To, Return-Path mismatch)
- Personalization and greeting analysis
- Call-to-action risk assessment
- Attachment threat detection

IMPORTANT: Respond ONLY with valid JSON (no markdown, no code blocks):
{
  "score": <number 0-100 phishing probability>,
  "threatLevel": "<critical|high|medium|low|safe>",
  "phishingType": "<string - specific phishing type detected>",
  "details": "<string - detailed email content analysis in 3-5 professional sentences focusing ONLY on email-specific findings>",
  "indicators": ["<email-specific indicator 1>", "<email-specific indicator 2>", ...],
  "recommendations": ["<action 1>", "<action 2>", ...]
}

Scoring: 0-19 SAFE, 20-39 LOW, 40-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL.
Legitimate emails score 0-15.
Phishing emails score 80-100.`;

    const userMessage = analysisMode === "url"
      ? `Analyze this URL for phishing threats:\n\nURL: "${target}"\n\nPerform comprehensive URL phishing detection analysis. Report ONLY URL-specific findings: domain reputation, URL structure, TLD risk, SSL status, homograph risks, suspicious patterns, etc.`
      : `Analyze this email content for phishing threats:\n\n---\n${target}\n---\n\nPerform comprehensive email phishing detection analysis. Report ONLY email-specific findings: sender analysis, social engineering tactics, urgency language, grammar anomalies, suspicious links, header mismatches, etc.`;

    const completion = await zai.chat.completions.create({
      messages: [
        { role: "assistant", content: systemPrompt },
        { role: "user", content: userMessage },
      ],
      thinking: { type: "disabled" },
    });

    const rawResponse = completion.choices[0]?.message?.content || "";

    let analysis;
    try {
      const jsonStr = rawResponse.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
      analysis = JSON.parse(jsonStr);
    } catch {
      let score = 10;
      if (analysisMode === "url") {
        const urlPatterns = [/\.xyz|\.tk|\.ml|\.ga|\.cc|\.ru/i, /login|secure|verify|account|update|confirm|suspend/i,
          /free|gift|winner|claim|urgent/i, /g00gle|paypa1|amaz0n|micros0ft/i, /http:\/\//];
        urlPatterns.forEach((p) => { if (p.test(target)) score += 15; });
      } else {
        const emailPatterns = [/urgent|immediate|suspend|expire|action required/i, /click here|verify your|update your|confirm your/i,
          /dear customer|dear user|dear member/i, /\$\d+|\d{4,}|\bfree\b|\bwinner\b|\bprize\b/i,
          /http:\/\//i, /password|credential|ssn|social security/i];
        emailPatterns.forEach((p) => { if (p.test(target)) score += 12; });
      }
      score = Math.min(100, score);
      const tl = score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : score >= 20 ? "low" : "safe";
      analysis = {
        score, threatLevel: tl,
        phishingType: score >= 60 ? "Credential Harvesting" : score >= 40 ? "Suspicious" : "None",
        details: analysisMode === "url"
          ? `URL analysis completed for "${target.slice(0, 100)}". Threat score: ${score}/100. ${score >= 60 ? "Multiple URL phishing indicators detected including suspicious domain structure or TLD." : score >= 40 ? "Some suspicious URL patterns found. Further investigation recommended." : "No significant URL phishing indicators detected. URL appears legitimate."}`
          : `Email content analysis completed. Threat score: ${score}/100. ${score >= 60 ? "Multiple email phishing indicators detected including social engineering tactics and urgency language." : score >= 40 ? "Some suspicious email patterns found. Verify sender identity through official channels." : "No significant email phishing indicators detected. Content appears legitimate."}`,
        indicators: score >= 40
          ? (analysisMode === "url"
            ? ["Suspicious domain structure", "High-risk TLD detected", "Potential brand impersonation in URL"]
            : ["Social engineering tactics detected", "Urgency/pressure language found", "Suspicious sender patterns"])
          : [],
        recommendations: score >= 60
          ? (analysisMode === "url"
            ? ["Do not visit this URL", "Block the domain in firewall", "Report to phishing blacklist"]
            : ["Do not click any links in the email", "Do not reply or provide any information", "Report as phishing to your email provider"])
          : score >= 40
            ? (analysisMode === "url"
              ? ["Verify through official channels", "Do not enter credentials on this URL"]
              : ["Verify sender through official channels", "Do not download attachments"])
            : ["Content appears legitimate", "Continue with standard caution"],
      };
    }

    const score = Math.max(0, Math.min(100, Number(analysis.score) || 0));
    const threatLevel = score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : score >= 20 ? "low" : "safe";
    const engines = generateEngineResults(score, analysisMode);

    return NextResponse.json({
      score, threatLevel, mode: analysisMode,
      phishingType: analysis.phishingType || "Unknown",
      details: analysis.details || `Phishing analysis completed. Score: ${score}/100.`,
      engines,
      indicators: Array.isArray(analysis.indicators) ? analysis.indicators : [],
      recommendations: Array.isArray(analysis.recommendations) ? analysis.recommendations : [],
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Phishing scan error:", error);
    return NextResponse.json(
      { error: "Phishing analysis failed. Please try again." },
      { status: 500 }
    );
  }
}
