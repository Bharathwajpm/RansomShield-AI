import { createFileRoute } from "@tanstack/react-router";
import { toast } from "sonner";
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

import { useDemo } from "@/lib/demo-context";
import {
  executiveSummary,
  getEndpoints,
  getThreats,
  getThreatsOverTime,
  severityDistribution,
  threatSources,
} from "@/lib/mock-data";
import { Panel, PageHeader } from "@/components/common/Panel";
import { StatTile, DemoTag } from "@/components/common/indicators";
import { Button } from "@/components/ui/button";
import { ManagementSummary } from "@/components/dashboard/ManagementSummary";

const title = "RansomShield AI — Security Reports";
const description =
  "Detection, response and coverage metrics for SME management: threats detected and blocked, protected endpoints and confidence trends.";

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
    ],
  }),
  component: ReportsPage,
});

function ReportsPage() {
  const { state } = useDemo();
  const threats = getThreats(state);
  const endpoints = getEndpoints(state);
  const overTime = getThreatsOverTime();
  const risk = endpoints
    .slice()
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 8)
    .map((e) => ({ name: e.name, risk: e.riskScore }));

  const avgConfidence =
    threats.length > 0
      ? (threats.reduce((a, t) => a + t.confidence, 0) / threats.length).toFixed(1)
      : "0.0";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Reports"
        description="Aggregated prototype metrics for management review and academic evaluation."
        actions={
          <Button
            variant="secondary"
            onClick={() => toast.info("Report generation is a prototype action.")}
          >
            Generate Report
          </Button>
        }
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <StatTile
          label="Threats detected"
          value={executiveSummary.threatsThisMonth}
          tone="medium"
        />
        <StatTile label="Threats blocked" value={executiveSummary.threatsBlocked} tone="low" />
        <StatTile label="Protected endpoints" value={executiveSummary.protected} tone="low" />
        <StatTile
          label="High-risk events"
          value={threats.filter((t) => t.severity === "high" || t.severity === "critical").length}
          tone="critical"
        />
        <StatTile label="Detection confidence" value={`${avgConfidence}%`} tone="info" />
        <StatTile label="Incidents prevented" value={executiveSummary.incidentsPrevented} />
      </div>

      <Panel
        title="Threats Over Time"
        subtitle="Detected vs blocked, last 30 days"
        actions={<DemoTag />}
      >
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={overTime}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
              <XAxis dataKey="day" tick={{ fontSize: 11 }} stroke="var(--color-muted-foreground)" />
              <YAxis tick={{ fontSize: 11 }} stroke="var(--color-muted-foreground)" />
              <Tooltip
                contentStyle={{
                  background: "var(--color-card)",
                  border: "1px solid var(--color-border)",
                  fontSize: 12,
                }}
              />
              <Area
                type="monotone"
                dataKey="detected"
                stroke="var(--color-warn)"
                fill="var(--color-warn)"
                fillOpacity={0.18}
              />
              <Area
                type="monotone"
                dataKey="blocked"
                stroke="var(--color-safe)"
                fill="var(--color-safe)"
                fillOpacity={0.18}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Severity Distribution" actions={<DemoTag />}>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityDistribution}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                <XAxis
                  dataKey="name"
                  tick={{ fontSize: 11 }}
                  stroke="var(--color-muted-foreground)"
                />
                <YAxis tick={{ fontSize: 11 }} stroke="var(--color-muted-foreground)" />
                <Tooltip
                  contentStyle={{
                    background: "var(--color-card)",
                    border: "1px solid var(--color-border)",
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="value" fill="var(--color-info)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Endpoint Risk" subtitle="Highest risk endpoints" actions={<DemoTag />}>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={risk} layout="vertical" margin={{ left: 30 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                <XAxis
                  type="number"
                  tick={{ fontSize: 11 }}
                  stroke="var(--color-muted-foreground)"
                />
                <YAxis
                  dataKey="name"
                  type="category"
                  width={90}
                  tick={{ fontSize: 10 }}
                  stroke="var(--color-muted-foreground)"
                />
                <Tooltip
                  contentStyle={{
                    background: "var(--color-card)",
                    border: "1px solid var(--color-border)",
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="risk" fill="var(--color-high)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <Panel title="Response Metrics" subtitle="Where detections originated" actions={<DemoTag />}>
        <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {threatSources.map((s) => (
            <li key={s.name} className="rounded-lg border border-border bg-background/40 p-3.5">
              <p className="text-xs text-muted-foreground">{s.name}</p>
              <p className="num mt-1 text-xl font-semibold">{s.value}</p>
            </li>
          ))}
        </ul>
      </Panel>

      <ManagementSummary />
    </div>
  );
}
