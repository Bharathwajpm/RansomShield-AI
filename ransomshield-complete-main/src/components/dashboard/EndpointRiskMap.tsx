import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { MonitorSmartphone } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag, StatusPill } from "@/components/common/indicators";
import { Button } from "@/components/ui/button";
import { getEndpoints, getEndpointSummary } from "@/lib/mock-data";
import type { DemoState } from "@/lib/types";
import { cn } from "@/lib/utils";

const filters = ["All", "Protected", "Warning", "Critical", "Offline"] as const;
type Filter = (typeof filters)[number];

export function EndpointRiskMap({ state, limit }: { state: DemoState; limit?: number }) {
  const [filter, setFilter] = useState<Filter>("All");
  const summary = getEndpointSummary(state);
  const all = getEndpoints(state);

  const filtered = all.filter((e) => {
    if (filter === "All") return true;
    if (filter === "Protected") return e.severity === "low";
    if (filter === "Warning") return e.severity === "medium" || e.severity === "high";
    if (filter === "Critical") return e.severity === "critical";
    return e.severity === "offline";
  });

  const shown = limit ? filtered.slice(0, limit) : filtered;

  return (
    <Panel
      title="Endpoint Risk Map"
      subtitle={`${summary.total} monitored endpoints`}
      icon={<MonitorSmartphone className="h-4 w-4" />}
      actions={<DemoTag />}
    >
      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-5">
        {[
          ["Total", summary.total, "info"],
          ["Protected", summary.protected, "low"],
          ["Warning", summary.warning, "medium"],
          ["Critical", summary.critical, "critical"],
          ["Offline", summary.offline, "offline"],
        ].map(([label, value, tone]) => (
          <div key={String(label)} className="rounded-lg border border-border bg-background/40 p-3">
            <p className="text-[10px] tracking-wide text-muted-foreground uppercase">{label}</p>
            <p className="num mt-1 text-lg font-semibold">{value}</p>
            <StatusPill tone={tone as never} className="mt-1.5" dot={false}>
              {tone === "offline" ? "no agent" : String(tone)}
            </StatusPill>
          </div>
        ))}
      </div>

      <div className="mb-4 flex flex-wrap gap-2">
        {filters.map((f) => (
          <Button
            key={f}
            size="sm"
            variant={filter === f ? "secondary" : "ghost"}
            className={cn("h-7 px-3 text-xs", filter === f && "ring-1 ring-info/30")}
            onClick={() => setFilter(f)}
          >
            {f}
          </Button>
        ))}
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {shown.map((e) => (
          <Link
            key={e.id}
            to="/endpoints/$endpointId"
            params={{ endpointId: e.id }}
            className="group rounded-lg border border-border bg-background/40 p-3 transition-colors hover:border-info/40 hover:bg-secondary/40"
          >
            <div className="flex items-center justify-between gap-2">
              <p className="num truncate text-sm font-medium">{e.name}</p>
              <StatusPill tone={e.severity === "offline" ? "offline" : e.severity}>
                {e.severity === "offline" ? "offline" : e.severity}
              </StatusPill>
            </div>
            <p className="mt-1 text-[11px] text-muted-foreground">
              {e.user} · {e.department}
            </p>
            <div className="mt-2.5 flex items-center justify-between text-[11px] text-muted-foreground">
              <span>Risk</span>
              <span className="num text-foreground">{e.riskScore}</span>
            </div>
            <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-secondary">
              <div
                className={cn(
                  "h-full rounded-full",
                  e.riskScore > 80
                    ? "bg-critical"
                    : e.riskScore > 60
                      ? "bg-high"
                      : e.riskScore > 30
                        ? "bg-warn"
                        : "bg-safe",
                )}
                style={{ width: `${Math.max(3, e.riskScore)}%` }}
              />
            </div>
          </Link>
        ))}
      </div>
    </Panel>
  );
}
