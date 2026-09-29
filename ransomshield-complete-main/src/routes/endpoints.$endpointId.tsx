import { createFileRoute, Link } from "@tanstack/react-router";

import { useDemo } from "@/lib/demo-context";
import { getEndpoints, getEvents, getThreats } from "@/lib/mock-data";
import { Panel, PageHeader } from "@/components/common/Panel";
import {
  StatusPill,
  StatTile,
  MetricBar,
  severityTone,
  DemoTag,
} from "@/components/common/indicators";
import { RiskGauge } from "@/components/dashboard/RiskGauge";

export const Route = createFileRoute("/endpoints/$endpointId")({
  head: ({ params }) => {
    const title = `RansomShield AI — Endpoint ${params.endpointId}`;
    const description = `Behavioral analysis, threat history and recent telemetry for monitored endpoint ${params.endpointId}.`;
    return {
      meta: [
        { title },
        { name: "description", content: description },
        { property: "og:title", content: title },
        { property: "og:description", content: description },
      ],
    };
  },
  component: EndpointDetail,
});

function EndpointDetail() {
  const { endpointId } = Route.useParams();
  const { state } = useDemo();
  const endpoint = getEndpoints(state).find((e) => e.id === endpointId);

  if (!endpoint) {
    return (
      <Panel title="Endpoint not found">
        <p className="text-sm text-muted-foreground">
          No monitored endpoint matches the identifier <span className="num">{endpointId}</span>. It
          may have been decommissioned or the link is invalid.
        </p>
        <Link
          to="/endpoints"
          className="mt-4 inline-flex rounded-md bg-info/15 px-4 py-2 text-sm font-medium text-info ring-1 ring-info/30 hover:bg-info/25"
        >
          Back to endpoints
        </Link>
      </Panel>
    );
  }

  const threats = getThreats(state).filter((t) => t.endpoint === endpoint.name);
  const events = getEvents(state)
    .filter((e) => e.endpoint === endpoint.name)
    .slice(0, 12);

  return (
    <div className="space-y-6">
      <PageHeader
        title={endpoint.name}
        description={`${endpoint.user} · ${endpoint.department} · ${endpoint.os}`}
        actions={
          <StatusPill tone={severityTone(endpoint.severity)}>{endpoint.severity}</StatusPill>
        }
      />

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Endpoint Identity" className="xl:col-span-2">
          <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {[
              ["User", endpoint.user],
              ["Department", endpoint.department],
              ["Operating system", endpoint.os],
              ["Agent status", endpoint.agentStatus],
              ["Last heartbeat", endpoint.lastHeartbeat],
              ["Running processes", String(endpoint.processes)],
            ].map(([k, v]) => (
              <div key={k}>
                <dt className="text-[11px] tracking-wider text-muted-foreground uppercase">{k}</dt>
                <dd className="mt-1 text-sm text-foreground">{v}</dd>
              </div>
            ))}
          </dl>
          <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile label="CPU" value={`${endpoint.cpu}%`} />
            <StatTile label="Memory" value={`${endpoint.memory}%`} />
            <StatTile label="Disk" value={`${endpoint.disk}%`} />
            <StatTile label="Network" value={`${endpoint.network}%`} />
          </div>
        </Panel>

        <Panel title="Risk Score" subtitle="Composite behavioral risk" actions={<DemoTag />}>
          <div className="flex justify-center py-2">
            <RiskGauge score={endpoint.riskScore} size={170} />
          </div>
        </Panel>
      </div>

      <Panel
        title="Behavior Analysis"
        subtitle="Deviation across monitored behavior domains"
        actions={<DemoTag />}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <MetricBar
            label="File activity"
            value={endpoint.behavior.fileActivity}
            tone={
              endpoint.behavior.fileActivity > 70
                ? "critical"
                : endpoint.behavior.fileActivity > 40
                  ? "medium"
                  : "low"
            }
          />
          <MetricBar
            label="Process activity"
            value={endpoint.behavior.processActivity}
            tone={
              endpoint.behavior.processActivity > 70
                ? "critical"
                : endpoint.behavior.processActivity > 40
                  ? "medium"
                  : "low"
            }
          />
          <MetricBar
            label="Network activity"
            value={endpoint.behavior.networkActivity}
            tone={
              endpoint.behavior.networkActivity > 70
                ? "critical"
                : endpoint.behavior.networkActivity > 40
                  ? "medium"
                  : "low"
            }
          />
          <MetricBar
            label="Registry activity"
            value={endpoint.behavior.registryActivity}
            tone={
              endpoint.behavior.registryActivity > 70
                ? "critical"
                : endpoint.behavior.registryActivity > 40
                  ? "medium"
                  : "low"
            }
          />
        </div>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel
          title="Threat History"
          subtitle="Detections associated with this endpoint"
          bodyClassName="p-0"
        >
          {threats.length === 0 ? (
            <p className="p-8 text-center text-sm text-muted-foreground">
              No threats recorded for this endpoint in the current demo state.
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-[11px] tracking-wider text-muted-foreground uppercase">
                  <th className="px-4 py-2.5">Threat</th>
                  <th className="px-4 py-2.5">Type</th>
                  <th className="px-4 py-2.5">Severity</th>
                  <th className="px-4 py-2.5">Status</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((t) => (
                  <tr key={t.id} className="border-b border-border/60 hover:bg-secondary/40">
                    <td className="px-4 py-2.5">
                      <Link
                        to="/threats/$threatId"
                        params={{ threatId: t.id }}
                        className="num text-info hover:underline"
                      >
                        {t.id}
                      </Link>
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground">{t.type}</td>
                    <td className="px-4 py-2.5">
                      <StatusPill tone={severityTone(t.severity)}>{t.severity}</StatusPill>
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground">{t.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel
          title="Recent Events"
          subtitle="Latest telemetry from this endpoint"
          bodyClassName="p-0"
        >
          {events.length === 0 ? (
            <p className="p-8 text-center text-sm text-muted-foreground">No recent events.</p>
          ) : (
            <ul className="divide-y divide-border/60">
              {events.map((e) => (
                <li key={e.id} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                  <span className="num shrink-0 text-xs text-muted-foreground">{e.timestamp}</span>
                  <span className="min-w-0 flex-1 truncate">{e.type}</span>
                  <StatusPill tone={severityTone(e.severity)}>{e.severity}</StatusPill>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
