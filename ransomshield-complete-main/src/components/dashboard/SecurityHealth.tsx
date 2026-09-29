import { HeartPulse } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag, MetricBar } from "@/components/common/indicators";
import { getHealthScore } from "@/lib/mock-data";
import type { DemoState } from "@/lib/types";

function toneFor(v: number) {
  if (v >= 85) return "low" as const;
  if (v >= 70) return "medium" as const;
  if (v >= 55) return "high" as const;
  return "critical" as const;
}

export function SecurityHealth({ state }: { state: DemoState }) {
  const { score, breakdown } = getHealthScore(state);
  return (
    <Panel
      title="Security Health Score"
      subtitle="Plain-language posture for SME management"
      icon={<HeartPulse className="h-4 w-4" />}
      actions={<DemoTag />}
      className="h-full"
    >
      <div className="mb-4 flex items-end gap-3">
        <p className="num text-4xl font-semibold text-foreground">{score}</p>
        <p className="pb-1.5 text-sm text-muted-foreground">/ 100</p>
      </div>
      <div className="space-y-3.5">
        {breakdown.map((b) => (
          <MetricBar key={b.label} label={b.label} value={b.value} tone={toneFor(b.value)} />
        ))}
      </div>
    </Panel>
  );
}
