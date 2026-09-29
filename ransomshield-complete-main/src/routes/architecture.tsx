import { createFileRoute } from "@tanstack/react-router";

import { useDemo } from "@/lib/demo-context";
import { getAiPrediction } from "@/lib/mock-data";
import { PageHeader } from "@/components/common/Panel";
import { DemoTag } from "@/components/common/indicators";
import { ArchitectureDiagram } from "@/components/dashboard/ArchitectureDiagram";
import { SecurityCoverage } from "@/components/dashboard/SecurityCoverage";
import { DetectionPipeline } from "@/components/dashboard/DetectionPipeline";

const title = "RansomShield AI — System Architecture";
const description =
  "End-to-end RansomShield AI architecture: offline XGBoost training pipeline, live endpoint telemetry collection, inference, response and dashboard layers.";

export const Route = createFileRoute("/architecture")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
    ],
  }),
  component: Architecture,
});

function Architecture() {
  const { state } = useDemo();
  const ai = getAiPrediction(state);

  return (
    <div className="space-y-6">
      <PageHeader
        title="System Architecture"
        description="How RansomShield AI is put together — from offline model training to live endpoint detection and response."
        actions={<DemoTag label="Target Architecture" />}
      />

      <ArchitectureDiagram />

      <DetectionPipeline currentStage={ai.stage} />

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-1">
          <SecurityCoverage state={state} />
        </div>
      </div>
    </div>
  );
}
