import { Radar } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag, MetricBar } from "@/components/common/indicators";
import { dataSourceCoverage, getEndpointSummary } from "@/lib/mock-data";
import type { DemoState } from "@/lib/types";

export function SecurityCoverage({ state }: { state: DemoState }) {
  const summary = getEndpointSummary(state);
  const monitored = summary.total - summary.offline;

  return (
    <Panel
      title="Security Coverage"
      subtitle="Telemetry collectors reporting into the detection pipeline"
      icon={<Radar className="h-4 w-4" />}
      actions={<DemoTag label="Prototype Data" />}
      className="h-full"
    >
      <div className="mb-4 rounded-lg border border-border bg-background/40 p-3.5">
        <p className="text-[11px] tracking-wide text-muted-foreground uppercase">
          Endpoint monitoring
        </p>
        <p className="num mt-1 text-2xl font-semibold text-info">
          {monitored} / {summary.total}
        </p>
        <p className="mt-0.5 text-[11px] text-muted-foreground">
          {summary.offline} agent(s) offline · {summary.protected} fully protected
        </p>
      </div>

      <div className="space-y-3.5">
        {dataSourceCoverage.map((d) => (
          <MetricBar
            key={d.name}
            label={d.name}
            value={d.value}
            tone={d.value >= 99 ? "low" : d.value >= 95 ? "info" : "medium"}
          />
        ))}
      </div>

      <p className="mt-4 text-[11px] leading-relaxed text-muted-foreground">
        Coverage reflects the proportion of monitored endpoints currently streaming each telemetry
        source. Values are simulated prototype data until the Python monitoring agent is connected.
      </p>
    </Panel>
  );
}
