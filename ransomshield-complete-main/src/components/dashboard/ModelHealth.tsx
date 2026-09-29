import { Brain } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Panel } from "@/components/common/Panel";
import { DemoTag, StatusPill } from "@/components/common/indicators";
import { getConfidenceHistory, modelHealth } from "@/lib/mock-data";
import type { DemoState } from "@/lib/types";

export function ModelHealth({ state }: { state: DemoState }) {
  const history = getConfidenceHistory(state);

  const tiles = [
    { label: "Model", value: "XGBoost Behavioral Classifier" },
    { label: "Version", value: modelHealth.version },
    { label: "Status", value: modelHealth.status },
    { label: "Predictions today", value: modelHealth.predictionsToday.toLocaleString() },
    { label: "Ransomware predictions", value: modelHealth.ransomwarePredictions },
    { label: "Average confidence", value: `${modelHealth.averageConfidence}%` },
  ];

  return (
    <Panel
      title="Model Health"
      subtitle="Behavioral classifier serving the live detection pipeline"
      icon={<Brain className="h-4 w-4" />}
      actions={<DemoTag label="Prototype / Demonstration Data" />}
    >
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {tiles.map((t) => (
          <div key={t.label} className="rounded-lg border border-border bg-background/40 p-3.5">
            <p className="text-[11px] tracking-wide text-muted-foreground uppercase">{t.label}</p>
            <p className="num mt-1 text-sm font-semibold break-words">{t.value}</p>
          </div>
        ))}
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-border bg-background/40 p-3.5">
          <p className="mb-2 text-[11px] tracking-wider text-muted-foreground uppercase">
            Confidence trend
          </p>
          <div className="h-44">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={history} margin={{ top: 4, right: 8, left: -22, bottom: 0 }}>
                <defs>
                  <linearGradient id="mh-conf" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--info)" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="var(--info)" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="t"
                  tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
                  interval={6}
                />
                <YAxis tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} domain={[0, 100]} />
                <Tooltip
                  contentStyle={{
                    background: "var(--surface)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="confidence"
                  stroke="var(--info)"
                  fill="url(#mh-conf)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-lg border border-border bg-background/40 p-3.5">
          <p className="mb-2 text-[11px] tracking-wider text-muted-foreground uppercase">
            Prediction distribution (today)
          </p>
          <div className="h-44">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={modelHealth.distribution}
                margin={{ top: 4, right: 8, left: -22, bottom: 0 }}
              >
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                <YAxis tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                <Tooltip
                  cursor={{ fill: "var(--secondary)" }}
                  contentStyle={{
                    background: "var(--surface)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="value" fill="var(--info)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        {modelHealth.metrics.map((m) => (
          <StatusPill key={m.label} tone="info" dot={false}>
            {m.label} {m.value}%
          </StatusPill>
        ))}
      </div>
      <p className="mt-3 text-[11px] text-muted-foreground">
        Prototype / demonstration metrics produced on a synthetic dataset. They are not validated
        real-world performance claims.
      </p>
    </Panel>
  );
}
