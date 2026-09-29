import { createFileRoute, Link } from "@tanstack/react-router";

import { useDemo } from "@/lib/demo-context";
import { getThreat } from "@/lib/mock-data";
import { Panel, PageHeader } from "@/components/common/Panel";
import { StatusPill, StatTile, severityTone, DemoTag } from "@/components/common/indicators";
import { AIExplanation } from "@/components/dashboard/AIExplanation";
import { AttackTimeline } from "@/components/dashboard/AttackTimeline";
import { ResponseCenter } from "@/components/dashboard/ResponseCenter";

export const Route = createFileRoute("/threats/$threatId")({
  head: ({ params }) => {
    const title = `RansomShield AI — Threat ${params.threatId}`;
    const description = `Incident detail, AI explanation, attack timeline and simulated response actions for detection ${params.threatId}.`;
    return {
      meta: [
        { title },
        { name: "description", content: description },
        { property: "og:title", content: title },
        { property: "og:description", content: description },
      ],
    };
  },
  component: ThreatDetail,
});

function ThreatDetail() {
  const { threatId } = Route.useParams();
  const { state } = useDemo();
  const threat = getThreat(threatId);

  if (!threat) {
    return (
      <Panel title="Threat not found">
        <p className="text-sm text-muted-foreground">
          No detection record matches the identifier <span className="num">{threatId}</span>.
        </p>
        <Link
          to="/threats"
          className="mt-4 inline-flex rounded-md bg-info/15 px-4 py-2 text-sm font-medium text-info ring-1 ring-info/30 hover:bg-info/25"
        >
          Back to threats
        </Link>
      </Panel>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={`Incident ${threat.id}`}
        description={threat.summary}
        actions={<StatusPill tone={severityTone(threat.severity)}>{threat.severity}</StatusPill>}
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Endpoint" value={threat.endpoint} />
        <StatTile label="Process" value={threat.process} />
        <StatTile label="Threat type" value={threat.type} tone={severityTone(threat.severity)} />
        <StatTile label="AI confidence" value={`${threat.confidence}%`} tone="info" />
        <StatTile label="Detected at" value={threat.detectedAt} />
        <StatTile label="Files affected" value={threat.filesAffected.toLocaleString()} />
        <StatTile label="Status" value={threat.status} />
        <StatTile label="Incident ID" value={threat.id} />
      </div>

      <AIExplanation state={state} />

      <AttackTimeline />

      <Panel
        title="Response"
        subtitle="All response actions in this prototype are simulated"
        actions={<DemoTag label="Simulation Action" />}
      >
        <p className="mb-4 rounded-md border border-warn/30 bg-warn/10 p-3 text-xs text-warn">
          SIMULATION ACTION — no real process is terminated and no real endpoint is isolated. These
          controls demonstrate the intended response policy only.
        </p>
        <ResponseCenter autoExecuted={threat.status === "Blocked"} />
      </Panel>
    </div>
  );
}
