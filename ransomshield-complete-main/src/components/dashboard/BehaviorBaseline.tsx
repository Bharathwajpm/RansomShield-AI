import { GitCompareArrows } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag, toneClasses } from "@/components/common/indicators";
import { getBaseline } from "@/lib/mock-data";
import type { DemoState } from "@/lib/types";
import { cn } from "@/lib/utils";

export function BehaviorBaseline({ state }: { state: DemoState }) {
  const rows = getBaseline(state);
  return (
    <Panel
      title="Behavior Deviation"
      subtitle="Learned normal baseline vs current behavior"
      icon={<GitCompareArrows className="h-4 w-4" />}
      actions={<DemoTag />}
      className="h-full"
      bodyClassName="p-0"
    >
      <table className="w-full text-sm">
        <thead>
          <tr className="text-[10px] tracking-wider text-muted-foreground uppercase">
            <th className="px-5 py-2 text-left font-medium">Metric</th>
            <th className="px-3 py-2 text-right font-medium">Baseline</th>
            <th className="px-3 py-2 text-right font-medium">Current</th>
            <th className="px-5 py-2 text-right font-medium">Deviation</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const dev = Math.round(((r.current - r.normal) / r.normal) * 100);
            const tone = dev > 400 ? "critical" : dev > 120 ? "high" : dev > 30 ? "medium" : "low";
            return (
              <tr key={r.metric} className="border-t border-border/70">
                <td className="px-5 py-2.5 text-muted-foreground">{r.metric}</td>
                <td className="num px-3 py-2.5 text-right text-muted-foreground">
                  {r.normal}
                  {r.unit}
                </td>
                <td
                  className={cn(
                    "num px-3 py-2.5 text-right font-semibold",
                    toneClasses[tone]!.text,
                  )}
                >
                  {r.current.toLocaleString()}
                  {r.unit}
                </td>
                <td className="px-5 py-2.5 text-right">
                  <span className={cn("num text-xs font-semibold", toneClasses[tone]!.text)}>
                    {dev >= 0 ? "↑" : "↓"} {Math.abs(dev).toLocaleString()}%
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Panel>
  );
}
