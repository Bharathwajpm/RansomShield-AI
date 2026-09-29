import { AlertTriangle, Radar } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag, StatusPill, toneClasses } from "@/components/common/indicators";
import { getEarlyWarningIndicators } from "@/lib/mock-data";
import type { DemoState, EarlyWarning as EW } from "@/lib/types";
import { cn } from "@/lib/utils";

const stateMap: Record<EW, { label: string; tone: keyof typeof toneClasses }> = {
  NORMAL: { label: "🟢 Normal", tone: "low" },
  SUSPICIOUS: { label: "🟡 Suspicious Activity", tone: "medium" },
  POSSIBLE: { label: "🟠 Possible Ransomware", tone: "high" },
  DETECTED: { label: "🔴 Ransomware Detected", tone: "critical" },
};

export function EarlyWarning({ state, warning }: { state: DemoState; warning: EW }) {
  const data = getEarlyWarningIndicators(state);
  const meta = stateMap[warning];
  const tone = toneClasses[meta.tone]!;

  return (
    <Panel
      title="Ransomware Early Warning"
      subtitle="Detect behavior before widespread encryption"
      icon={<Radar className="h-4 w-4" />}
      actions={<DemoTag />}
      className="h-full"
    >
      <div className={cn("rounded-lg border p-3", tone.bg, tone.border)}>
        <div className="flex items-center justify-between gap-3">
          <p className={cn("text-sm font-semibold", tone.text)}>{meta.label}</p>
          <StatusPill tone={meta.tone}>AI {data.confidence}%</StatusPill>
        </div>
        <p className="mt-1 flex items-start gap-1.5 text-xs text-muted-foreground">
          <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
          {data.message}
        </p>
      </div>

      <ul className="mt-4 space-y-2.5">
        {data.indicators.map((i) => (
          <li key={i.label} className="flex items-center justify-between gap-3 text-sm">
            <span className="text-muted-foreground">{i.label}</span>
            <span className={cn("num text-xs font-semibold", toneClasses[i.tone]!.text)}>
              {i.value}
            </span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
