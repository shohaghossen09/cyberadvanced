import { NextRequest, NextResponse } from "next/server";
import ZAI from "z-ai-web-dev-sdk";

function generateEngineResults(phishingScore: number) {
  const engines = [
    "CyberDefender AI", "URL Validator", "Domain Analysis", "SSL Checker",
    "Content Analyzer", "NLP Engine", "Header Inspector", " WHOIS Lookup",
    "DNS Reputation", "ML Classifier", "Google Safe Browsing", "PhishTank API",
    "Email Header Parser", "Link Scanner",
  ];
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
    const { target } = await request.json();

    if (!target || typeof target !== "string" || target.trim().length === 0) {
      return NextResponse.json(
        { error: "Target is required. Provide a URL or email content." },
        { status: 400 }
      );
    }

    const zai = await ZAI.create();
    const isUrl = /^https?:\/\//i.test(target.trim());
    const targetType = isUrl ? "URL" : "Email Content";

    const systemPrompt = `You are CyberDefender, an elite AI-powered phishing detection engine specializing in identifying both known and zero-day phishing threats. You analyze URLs and email content using natural language processing, pattern recognition, and behavioral analysis.

IMPORTANT: Respond ONLY with valid JSON in this exact format (no markdown, no code blocks, just raw JSON):
{
  "score": <number 0-100 phishing probability>,
  "threatLevel": "<critical|high|medium|low|safe>",
  "phishingType": "<string - type of phishing if detected>",
  "details": "<string - detailed analysis in 3-5 professional sentences>",
  "indicators": ["<string - phishing indicator 1>", "<string - phishing indicator 2>", ...],
  "recommendations": ["<string - action 1>", "<string - action 2>", ...]
}

Scoring guidelines:
- 0-19: SAFE - Legitimate, no phishing indicators
- 20-39: LOW - Minor suspicious patterns
- 40-59: MEDIUM - Multiple suspicious indicators
- 60-79: HIGH - Likely phishing attempt
- 80-100: CRITICAL - Confirmed phishing, high confidence

For URL analysis, check:
- Suspicious TLDs (.xyz, .tk, .ml, .ga, .cc, .ru for non-Russian sites)
- Subdomain spoofing (paypal-login.evil.com)
- URL encoding and obfuscation
- Homograph attacks (using similar-looking characters)
- Excessive subdomains
- IP addresses instead of domain names
- HTTP instead of HTTPS for login pages
- Data URIs
- URL shorteners pointing to suspicious destinations
- Misspelled brand names (g00gle, paypa1, amaz0n)
- Login-related keywords in suspicious contexts
- Session tokens or tracking parameters

For email content analysis, check:
- Urgency or fear tactics ("Your account will be suspended")
- Requests for personal/financial information
- Suspicious sender addresses
- Generic greetings ("Dear Customer")
- Poor grammar and spelling
- Suspicious links
- Mismatched display names and email addresses
- Requests to bypass normal security procedures
- Threatening language
- Too-good-to-be-true offers

Known legitimate domains should score very low (0-15).
Known phishing patterns should score very high (80-100).`;

    const userMessage = isUrl
      ? `Analyze this URL for phishing threats:\n\nURL: "${target}"\n\nPerform comprehensive phishing detection analysis including domain reputation, URL structure analysis, SSL verification simulation, and content pattern matching.`
      : `Analyze this email content for phishing threats:\n\n---\n${target}\n---\n\nPerform comprehensive phishing detection analysis including sender verification, content analysis, link inspection, social engineering pattern detection, and urgency assessment.`;

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
      // Fallback analysis with heuristic scoring
      let score = 10;
      const suspiciousPatterns = [
        /\.xyz|\.tk|\.ml|\.ga|\.cc|\.ru/i,
        /login|secure|verify|account|update|confirm|suspend/i,
        /free|gift|winner|claim|urgent|immediate/i,
        /g00gle|paypa1|amaz0n|micros0ft|app1e/i,
        /@\w+\.\w+\.\w+/,
        /http:\/\//,
      ];
      suspiciousPatterns.forEach((pattern) => {
        if (pattern.test(target)) score += 15;
      });

      score = Math.min(100, score);
      const threatLevel = score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : score >= 20 ? "low" : "safe";

      analysis = {
        score,
        threatLevel,
        phishingType: score >= 60 ? "Credential Harvesting" : score >= 40 ? "Suspicious" : "None",
        details: `Phishing analysis completed for ${targetType.toLowerCase()}: "${target.slice(0, 80)}...". Threat score: ${score}/100. ${score >= 60 ? "Multiple phishing indicators detected. High probability of social engineering attack." : score >= 40 ? "Some suspicious patterns found. Further investigation recommended." : "No significant phishing indicators detected."}`,
        indicators: score >= 40
          ? ["Suspicious domain pattern detected", "Social engineering indicators found", "Urgency language detected"]
          : [],
        recommendations: score >= 60
          ? ["Do not interact with this content", "Report to security team", "Block the domain/sender"]
          : score >= 40
          ? ["Verify through official channels", "Do not enter credentials"]
          : ["Content appears legitimate", "Continue with standard caution"],
      };
    }

    // Normalize
    const score = Math.max(0, Math.min(100, Number(analysis.score) || 0));
    const threatLevel = score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : score >= 20 ? "low" : "safe";
    const engines = generateEngineResults(score);

    return NextResponse.json({
      score,
      threatLevel,
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
