import { useEffect, useMemo, useState } from "react";
import { Activity } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag, LiveDot, toneClasses } from "@/components/common/indicators";
import { getLiveStream } from "@/lib/mock-data";
import { useDemo } from "@/lib/demo-context";
import type { DemoState, SecurityEvent } from "@/lib/types";
import { cn } from "@/lib/utils";

export function LiveEventStream({
  state,
  height = "h-[420px]",
}: {
  state: DemoState;
  height?: string;
}) {
  const { tick } = useDemo();
  const source = useMemo(() => getLiveStream(state), [state]);
  const [rows, setRows] = useState<SecurityEvent[]>(source);

  useEffect(() => setRows(source), [source]);

  useEffect(() => {
    setRows((prev) => {
      const next = source[(tick + prev.length) % source.length];
      if (!next) return prev;
      return [{ ...next, id: `${next.id}-${tick}` }, ...prev].slice(0, 40);
    });
  }, [tick, source]);

  return (
    <Panel
      title="Live Event Stream"
      subtitle="Agent telemetry as it arrives"
      icon={<Activity className="h-4 w-4" />}
      actions={
        <div className="flex items-center gap-3">
          <DemoTag label="Simulated Feed" />
          <LiveDot tone={state === "CRITICAL" ? "critical" : "low"} />
        </div>
      }
      bodyClassName="p-0"
    >
      <ul className={cn("divide-y divide-border/70 overflow-y-auto", height)}>
        {rows.map((e) => {
          const tone = toneClasses[e.severity] ?? toneClasses["info"]!;
          return (
            <li key={e.id} className="flex items-start gap-3 px-5 py-2.5 text-sm">
              <span className="num w-16 shrink-0 text-xs text-muted-foreground">{e.timestamp}</span>
              <span className={cn("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", tone.dot)} />
              <span className="min-w-0 flex-1">
                <span className={cn("font-medium", tone.text)}>{e.type}</span>
                <span className="num ml-2 text-xs text-muted-foreground">{e.process}</span>
                {e.detail && (
                  <span className="block text-[11px] text-muted-foreground">{e.detail}</span>
                )}
              </span>
              <span className="num hidden shrink-0 text-[11px] text-muted-foreground sm:block">
                {e.endpoint}
              </span>
              <span className="hidden w-24 shrink-0 text-right text-[11px] text-muted-foreground md:block">
                {e.source}
              </span>
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}
