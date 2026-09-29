import { AlertTriangle, Ban, FileWarning, Flag, Radar, ShieldAlert, Zap } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag, toneClasses } from "@/components/common/indicators";
import { attackTimeline } from "@/lib/mock-data";
import type { TimelineStep } from "@/lib/types";
import { cn } from "@/lib/utils";

const icons = [Flag, FileWarning, AlertTriangle, Zap, Radar, ShieldAlert, Ban, Ban, Flag];

export function AttackTimeline({
  steps = attackTimeline,
  activeIndex,
  title = "Attack Timeline",
}: {
  steps?: TimelineStep[];
  activeIndex?: number;
  title?: string;
}) {
  return (
    <Panel
      title={title}
      subtitle="Reconstructed incident sequence"
      icon={<Radar className="h-4 w-4" />}
      actions={<DemoTag />}
      className="h-full"
    >
      <ol className="relative space-y-4 border-l border-border pl-6">
        {steps.map((s, i) => {
          const Icon = icons[i % icons.length]!;
          const tone = toneClasses[s.severity] ?? toneClasses["info"]!;
          const dim = activeIndex !== undefined && i > activeIndex;
          return (
            <li key={`${s.time}-${s.title}`} className={cn("relative", dim && "opacity-30")}>
              <span
                className={cn(
                  "absolute top-0 -left-[34px] grid h-6 w-6 place-items-center rounded-full border bg-background",
                  tone.border,
                  tone.text,
                  activeIndex === i && "ring-2 ring-info/50",
                )}
              >
                <Icon className="h-3 w-3" />
              </span>
              <p className="num text-[11px] text-muted-foreground">{s.time}</p>
              <p className={cn("text-sm font-medium", tone.text)}>{s.title}</p>
              <p className="text-xs text-muted-foreground">{s.detail}</p>
            </li>
          );
        })}
      </ol>
    </Panel>
  );
}
