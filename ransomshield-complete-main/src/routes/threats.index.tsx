import { createFileRoute } from "@tanstack/react-router";

import { useDemo } from "@/lib/demo-context";
import { getThreats } from "@/lib/mock-data";
import { PageHeader } from "@/components/common/Panel";
import { StatTile } from "@/components/common/indicators";
import { ThreatTable } from "@/components/dashboard/ThreatTable";

const title = "RansomShield AI — Threat Detection";
const description =
  "All behavioral detections raised by the AI classifier, with severity, confidence, affected endpoint and response status.";

export const Route = createFileRoute("/threats/")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
    ],
  }),
  component: ThreatsPage,
});

function ThreatsPage() {
  const { state } = useDemo();
  const threats = getThreats(state);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Detection"
        description="Detections produced by the XGBoost behavioral classifier across all monitored endpoints."
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Total detections" value={threats.length} />
        <StatTile
          label="Critical"
          value={threats.filter((t) => t.severity === "critical").length}
          tone="critical"
        />
        <StatTile
          label="Blocked"
          value={threats.filter((t) => t.status === "Blocked").length}
          tone="low"
        />
        <StatTile
          label="Investigating"
          value={threats.filter((t) => t.status === "Investigating").length}
          tone="medium"
        />
      </div>

      <ThreatTable state={state} />
    </div>
  );
}
