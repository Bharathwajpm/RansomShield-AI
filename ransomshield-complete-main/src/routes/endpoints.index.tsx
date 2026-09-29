import { useMemo, useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { Search } from "lucide-react";

import { useDemo } from "@/lib/demo-context";
import { getEndpoints, getEndpointSummary } from "@/lib/mock-data";
import { Panel, PageHeader } from "@/components/common/Panel";
import { StatusPill, StatTile, severityTone, DemoTag } from "@/components/common/indicators";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

const title = "RansomShield AI — Endpoints";
const description =
  "Monitored SME endpoints with agent status, resource usage, behavioral risk score and last heartbeat.";

export const Route = createFileRoute("/endpoints/")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
    ],
  }),
  component: EndpointsPage,
});

const filters = ["All", "Protected", "Warning", "Critical", "Offline"] as const;
type Filter = (typeof filters)[number];

function EndpointsPage() {
  const { state } = useDemo();
  const all = getEndpoints(state);
  const summary = getEndpointSummary(state);
  const [filter, setFilter] = useState<Filter>("All");
  const [q, setQ] = useState("");

  const rows = useMemo(
    () =>
      all.filter((e) => {
        if (filter === "Protected" && e.severity !== "low") return false;
        if (filter === "Warning" && e.severity !== "medium" && e.severity !== "high") return false;
        if (filter === "Critical" && e.severity !== "critical") return false;
        if (filter === "Offline" && e.severity !== "offline") return false;
        if (q) {
          const text = `${e.name} ${e.user} ${e.department} ${e.os}`.toLowerCase();
          if (!text.includes(q.toLowerCase())) return false;
        }
        return true;
      }),
    [all, filter, q],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Endpoints"
        description="Every workstation reporting into the RansomShield AI monitoring agent."
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <StatTile label="Total" value={summary.total} />
        <StatTile label="Protected" value={summary.protected} tone="low" />
        <StatTile label="Warning" value={summary.warning} tone="medium" />
        <StatTile label="Critical" value={summary.critical} tone="critical" />
        <StatTile label="Offline" value={summary.offline} tone="offline" />
      </div>

      <Panel
        title="Endpoint Inventory"
        subtitle={`${rows.length} of ${all.length} endpoints`}
        actions={<DemoTag />}
        bodyClassName="p-0"
      >
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-4">
          <div className="relative min-w-[220px] flex-1">
            <Search className="pointer-events-none absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search endpoint, user, department…"
              className="h-9 pl-9 text-sm"
            />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {filters.map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={cn(
                  "rounded-md border border-border px-2.5 py-1.5 text-xs transition-colors",
                  filter === f
                    ? "bg-info/15 text-info ring-1 ring-info/30"
                    : "text-muted-foreground hover:bg-secondary/70",
                )}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {rows.length === 0 ? (
          <p className="p-8 text-center text-sm text-muted-foreground">
            No endpoints match the current filters.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-[11px] tracking-wider text-muted-foreground uppercase">
                  <th className="px-4 py-2.5">Endpoint</th>
                  <th className="px-4 py-2.5">User</th>
                  <th className="px-4 py-2.5">Department</th>
                  <th className="px-4 py-2.5">OS</th>
                  <th className="px-4 py-2.5">Agent</th>
                  <th className="px-4 py-2.5">CPU</th>
                  <th className="px-4 py-2.5">Memory</th>
                  <th className="px-4 py-2.5">Risk</th>
                  <th className="px-4 py-2.5">Status</th>
                  <th className="px-4 py-2.5">Heartbeat</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id} className="border-b border-border/60 hover:bg-secondary/40">
                    <td className="px-4 py-2.5 font-medium">
                      <Link
                        to="/endpoints/$endpointId"
                        params={{ endpointId: e.id }}
                        className="text-info hover:underline"
                      >
                        {e.name}
                      </Link>
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground">{e.user}</td>
                    <td className="px-4 py-2.5 text-muted-foreground">{e.department}</td>
                    <td className="px-4 py-2.5 text-muted-foreground">{e.os}</td>
                    <td className="px-4 py-2.5 text-muted-foreground">{e.agentStatus}</td>
                    <td className="num px-4 py-2.5">{e.cpu}%</td>
                    <td className="num px-4 py-2.5">{e.memory}%</td>
                    <td className="num px-4 py-2.5">{e.riskScore}</td>
                    <td className="px-4 py-2.5">
                      <StatusPill tone={severityTone(e.severity)}>{e.severity}</StatusPill>
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground">{e.lastHeartbeat}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
