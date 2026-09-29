import { createFileRoute, Link } from "@tanstack/react-router";

import { useDemo } from "@/lib/demo-context";
import {
  auditLog,
  getEvents,
  getProcesses,
  getThreats,
  getFileImpact,
  getBaseline,
} from "@/lib/mock-data";
import { Panel, PageHeader } from "@/components/common/Panel";
import { StatusPill, StatTile, severityTone, DemoTag } from "@/components/common/indicators";
import { AIExplanation } from "@/components/dashboard/AIExplanation";
import { AttackTimeline } from "@/components/dashboard/AttackTimeline";
import { ResponseCenter } from "@/components/dashboard/ResponseCenter";

const title = "RansomShield AI — Incident Investigation";
const description =
  "SOC investigation workspace combining incident summary, AI explanation, attack timeline, process, file, network and registry activity with an audit log.";

export const Route = createFileRoute("/incidents")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
    ],
  }),
  component: IncidentsPage,
});

function IncidentsPage() {
  const { state } = useDemo();
  const threats = getThreats(state);
  const incident = threats[0];
  const processes = getProcesses(state);
  const impact = getFileImpact(state);
  const baseline = getBaseline(state);
  const events = getEvents(state).slice(0, 10);

  if (!incident) {
    return (
      <div className="space-y-6">
        <PageHeader title="Incident Investigation" description="No open incidents." />
        <Panel title="No active incident">
          <p className="text-sm text-muted-foreground">
            There is no incident to investigate in the current demo state. Switch to WARNING or
            CRITICAL mode to load an investigation workspace.
          </p>
        </Panel>
      </div>
    );
  }

  const network = baseline.find((b) => b.metric === "Outbound connections");
  const registry = baseline.find((b) => b.metric === "Registry writes");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Incident Investigation"
        description="Full investigation workspace for the highest-priority active detection."
        actions={
          <StatusPill tone={severityTone(incident.severity)}>{incident.severity}</StatusPill>
        }
      />

      <Panel
        title="Incident Summary"
        subtitle={incident.summary}
        actions={
          <Link
            to="/threats/$threatId"
            params={{ threatId: incident.id }}
            className="text-xs text-info hover:underline"
          >
            Open threat record
          </Link>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatTile label="Incident ID" value={incident.id} />
          <StatTile label="Endpoint" value={incident.endpoint} />
          <StatTile label="Process" value={incident.process} />
          <StatTile
            label="Threat type"
            value={incident.type}
            tone={severityTone(incident.severity)}
          />
          <StatTile label="AI confidence" value={`${incident.confidence}%`} tone="info" />
          <StatTile label="Detected" value={incident.detectedAt} />
          <StatTile label="Files affected" value={incident.filesAffected.toLocaleString()} />
          <StatTile label="Status" value={incident.status} />
        </div>
      </Panel>

      <AIExplanation state={state} />

      <AttackTimeline />

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel
          title="Process Activity"
          subtitle="Processes observed during the incident window"
          bodyClassName="p-0"
        >
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-[11px] tracking-wider text-muted-foreground uppercase">
                <th className="px-4 py-2.5">Process</th>
                <th className="px-4 py-2.5">PID</th>
                <th className="px-4 py-2.5">CPU</th>
                <th className="px-4 py-2.5">File ops</th>
                <th className="px-4 py-2.5">Risk</th>
              </tr>
            </thead>
            <tbody>
              {processes.map((p) => (
                <tr key={p.pid} className="border-b border-border/60">
                  <td className="num px-4 py-2.5 text-xs">{p.name}</td>
                  <td className="num px-4 py-2.5 text-xs text-muted-foreground">{p.pid}</td>
                  <td className="num px-4 py-2.5">{p.cpu}%</td>
                  <td className="num px-4 py-2.5">{p.fileActivity}</td>
                  <td className="px-4 py-2.5">
                    <StatusPill tone={severityTone(p.risk)}>{p.risk}</StatusPill>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>

        <Panel title="File Activity" subtitle="Scope of file-system impact" actions={<DemoTag />}>
          <div className="grid grid-cols-3 gap-3">
            <StatTile
              label="Files affected"
              value={impact.affected.toLocaleString()}
              tone="critical"
            />
            <StatTile
              label="Files protected"
              value={impact.protected.toLocaleString()}
              tone="low"
            />
            <StatTile label="Damage estimate" value={impact.damage} tone="medium" />
          </div>
          <ul className="mt-4 space-y-2">
            {impact.categories.map((c) => (
              <li key={c.name} className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">{c.name}</span>
                <span className="num font-semibold">{c.value.toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Network Activity" subtitle="Outbound connection behavior vs baseline">
          <div className="grid grid-cols-2 gap-3">
            <StatTile label="Baseline" value={`${network?.normal ?? 0} /min`} />
            <StatTile
              label="Current"
              value={`${network?.current ?? 0} /min`}
              tone={(network?.current ?? 0) > (network?.normal ?? 0) * 2 ? "critical" : "low"}
            />
          </div>
        </Panel>

        <Panel title="Registry Activity" subtitle="Registry write behavior vs baseline">
          <div className="grid grid-cols-2 gap-3">
            <StatTile label="Baseline" value={`${registry?.normal ?? 0} /min`} />
            <StatTile
              label="Current"
              value={`${registry?.current ?? 0} /min`}
              tone={(registry?.current ?? 0) > (registry?.normal ?? 0) * 2 ? "critical" : "low"}
            />
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <ResponseCenter autoExecuted={incident.status === "Blocked"} />

        <Panel title="Audit Log" subtitle="Recorded analyst and system actions" bodyClassName="p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-[11px] tracking-wider text-muted-foreground uppercase">
                <th className="px-4 py-2.5">Time</th>
                <th className="px-4 py-2.5">Actor</th>
                <th className="px-4 py-2.5">Action</th>
                <th className="px-4 py-2.5">Result</th>
              </tr>
            </thead>
            <tbody>
              {auditLog.map((a, i) => (
                <tr key={i} className="border-b border-border/60">
                  <td className="num px-4 py-2.5 text-xs text-muted-foreground">{a.timestamp}</td>
                  <td className="px-4 py-2.5 text-muted-foreground">{a.actor}</td>
                  <td className="px-4 py-2.5">{a.action}</td>
                  <td className="px-4 py-2.5">
                    <StatusPill tone={a.result === "Success" ? "low" : "critical"}>
                      {a.result}
                    </StatusPill>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>

      <Panel title="Recent Correlated Events" bodyClassName="p-0">
        <ul className="divide-y divide-border/60">
          {events.map((e) => (
            <li key={e.id} className="flex items-center gap-3 px-4 py-2.5 text-sm">
              <span className="num shrink-0 text-xs text-muted-foreground">{e.timestamp}</span>
              <span className="shrink-0 text-xs text-muted-foreground">{e.source}</span>
              <span className="min-w-0 flex-1 truncate">{e.type}</span>
              <StatusPill tone={severityTone(e.severity)}>{e.severity}</StatusPill>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
