import { useState } from "react";
import { Brain, Check, X } from "lucide-react";
import { toast } from "sonner";
import { Panel } from "@/components/common/Panel";
import { DemoTag, StatusPill, toneClasses } from "@/components/common/indicators";
import { Button } from "@/components/ui/button";
import { getAiPrediction } from "@/lib/mock-data";
import type { DemoState } from "@/lib/types";
import { cn } from "@/lib/utils";

function predTone(p: string) {
  if (p === "RANSOMWARE") return "critical" as const;
  if (p === "SUSPICIOUS") return "medium" as const;
  return "low" as const;
}

export function AIExplanation({
  state,
  showFeedback = true,
}: {
  state: DemoState;
  showFeedback?: boolean;
}) {
  const ai = getAiPrediction(state);
  const tone = toneClasses[predTone(ai.prediction)]!;
  const [answered, setAnswered] = useState<string | null>(null);

  return (
    <Panel
      title="Why did the AI decide this?"
      subtitle="Feature attribution for the current classification"
      icon={<Brain className="h-4 w-4" />}
      actions={<DemoTag label="Prototype Model" />}
      className="h-full"
    >
      <div className="mb-4 flex flex-wrap items-center gap-4">
        <div>
          <p className="text-[10px] tracking-wider text-muted-foreground uppercase">Prediction</p>
          <p className={cn("text-xl font-semibold", tone.text)}>{ai.prediction}</p>
        </div>
        <div>
          <p className="text-[10px] tracking-wider text-muted-foreground uppercase">Confidence</p>
          <p className="num text-xl font-semibold">{ai.confidence}%</p>
        </div>
        <StatusPill tone="info" className="ml-auto">
          Stage {ai.stage} / 6
        </StatusPill>
      </div>

      <p className="mb-3 text-[10px] tracking-wider text-muted-foreground uppercase">
        Top contributing indicators
      </p>
      <ol className="space-y-3">
        {ai.indicators.map((i, idx) => {
          const t =
            i.weight >= 80
              ? "critical"
              : i.weight >= 60
                ? "high"
                : i.weight >= 35
                  ? "medium"
                  : "low";
          return (
            <li key={i.label}>
              <div className="mb-1 flex items-baseline justify-between gap-3 text-xs">
                <span className="text-foreground">
                  <span className="num mr-2 text-muted-foreground">{idx + 1}.</span>
                  {i.label}
                </span>
                <span className={cn("num font-semibold", toneClasses[t]!.text)}>{i.weight}%</span>
              </div>
              <div className="h-2 overflow-hidden rounded-sm bg-secondary">
                <div
                  className={cn("h-full transition-all duration-700", toneClasses[t]!.dot)}
                  style={{ width: `${i.weight}%` }}
                />
              </div>
            </li>
          );
        })}
      </ol>

      <p className="mt-4 rounded-lg border border-border bg-background/40 p-3 text-xs leading-relaxed text-muted-foreground">
        {ai.explanation}
      </p>

      {showFeedback && (
        <div className="mt-4 rounded-lg border border-dashed border-border p-3">
          <p className="text-xs font-medium">Was this detection correct?</p>
          <div className="mt-2 flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="outline"
              className="h-8 border-safe/40 text-safe hover:bg-safe/10"
              onClick={() => {
                setAnswered("correct");
                toast.success("Feedback recorded (prototype)", {
                  description: "Marked as a correct detection for future model retraining.",
                });
              }}
            >
              <Check className="mr-1 h-3.5 w-3.5" /> Correct Detection
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-8 border-critical/40 text-critical hover:bg-critical/10"
              onClick={() => {
                setAnswered("false-positive");
                toast("Feedback recorded (prototype)", {
                  description: "Flagged as a false positive for analyst review.",
                });
              }}
            >
              <X className="mr-1 h-3.5 w-3.5" /> False Positive
            </Button>
          </div>
          {answered && (
            <p className="mt-2 text-[11px] text-muted-foreground">
              Simulation only — feedback is stored locally in this prototype session.
            </p>
          )}
        </div>
      )}
    </Panel>
  );
}
