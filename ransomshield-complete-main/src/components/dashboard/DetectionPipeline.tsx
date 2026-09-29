import { ArrowRight } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag } from "@/components/common/indicators";
import { detectionStages } from "@/lib/mock-data";
import { cn } from "@/lib/utils";

export function DetectionPipeline({ currentStage }: { currentStage: number }) {
  return (
    <Panel
      title="Multi-Stage Detection Pipeline"
      subtitle="How raw telemetry becomes a response decision"
      actions={<DemoTag />}
    >
      <ol className="grid gap-3 lg:grid-cols-6">
        {detectionStages.map((s, i) => {
          const active = s.id === currentStage;
          const passed = s.id < currentStage;
          return (
            <li
              key={s.id}
              className={cn(
                "relative rounded-lg border p-3 transition-colors",
                active
                  ? "border-info/50 bg-info/10"
                  : passed
                    ? "border-safe/30 bg-safe/5"
                    : "border-border bg-background/40",
              )}
            >
              <p
                className={cn(
                  "text-[10px] font-semibold tracking-wider uppercase",
                  active ? "text-info" : passed ? "text-safe" : "text-muted-foreground",
                )}
              >
                Stage {s.id}
              </p>
              <p className="mt-1 text-sm font-medium">{s.name}</p>
              <p className="mt-1 text-[11px] text-muted-foreground">{s.detail}</p>
              {i < detectionStages.length - 1 && (
                <ArrowRight className="absolute top-1/2 -right-3 hidden h-4 w-4 -translate-y-1/2 text-border lg:block" />
              )}
            </li>
          );
        })}
      </ol>
    </Panel>
  );
}
