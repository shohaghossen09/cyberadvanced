import { NextRequest, NextResponse } from "next/server";
import { analyzePhishing } from "@/lib/analysis-engine";

const AI_TIMEOUT = 8000;

async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T | null> {
  return Promise.race([
    promise,
    new Promise<null>((resolve) => setTimeout(() => resolve(null), ms)),
  ]);
}

export async function POST(request: NextRequest) {
  try {
    const { target, mode } = await request.json();
    const analysisMode: "url" | "email" = mode === "email" ? "email" : "url";
    if (!target || typeof target !== "string" || target.trim().length === 0) {
      return NextResponse.json({ error: "Target is required" }, { status: 400 });
    }

    // Try AI enhancement, but always work with heuristic base
    let aiEnhanced = false;
    let aiDetails = "";
    try {
      const ZAI = (await import("z-ai-web-dev-sdk")).default;
      const zai = await withTimeout(ZAI.create(), AI_TIMEOUT);
      if (zai) {
        const completion = await withTimeout(
          zai.chat.completions.create({
            messages: [
              {
                role: "assistant",
                content: `You are a cybersecurity AI phishing detection expert. Provide ONLY a brief (2-3 sentence) additional analysis. ${analysisMode === "url" ? "Focus on URL structure, domain reputation, and brand impersonation." : "Focus on social engineering tactics, sender spoofing, and urgency language."}`,
              },
              { role: "user", content: `Analyze for phishing: ${analysisMode === "url" ? target.slice(0, 500) : target.slice(0, 1000)}` },
            ],
            thinking: { type: "disabled" },
          }),
          AI_TIMEOUT
        );
        if (completion) {
          aiDetails = completion.choices[0]?.message?.content || "";
          if (aiDetails) aiEnhanced = true;
        }
      }
    } catch {
      // AI unavailable, use pure heuristic
    }

    const result = analyzePhishing(target, analysisMode);

    return NextResponse.json({
      ...result,
      mode: analysisMode,
      aiEnhanced,
      aiAnalysis: aiDetails || result.details,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Phishing scan error:", error);
    return NextResponse.json({ error: "Analysis failed" }, { status: 500 });
  }
}
