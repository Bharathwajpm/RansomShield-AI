import { createFileRoute } from "@tanstack/react-router";

import { useDemo } from "@/lib/demo-context";
import { getSystemStatus } from "@/lib/mock-data";
import { getAiPrediction } from "@/lib/mock-data";
import { PageHeader } from "@/components/common/Panel";
import { StatusCard } from "@/components/dashboard/StatusCard";
import { RiskGauge } from "@/components/dashboard/RiskGauge";
import { SecurityHealth } from "@/components/dashboard/SecurityHealth";
import { EarlyWarning } from "@/components/dashboard/EarlyWarning";
import { FileVelocityChart } from "@/components/dashboard/FileVelocityChart";
import { FileImpact } from "@/components/dashboard/FileImpact";
import { ProcessBehavior } from "@/components/dashboard/ProcessBehavior";
import { BehaviorBaseline } from "@/components/dashboard/BehaviorBaseline";
import { AIExplanation } from "@/components/dashboard/AIExplanation";
import { DetectionPipeline } from "@/components/dashboard/DetectionPipeline";
import { EndpointRiskMap } from "@/components/dashboard/EndpointRiskMap";
import { LiveEventStream } from "@/components/dashboard/LiveEventStream";
import { AttackTimeline } from "@/components/dashboard/AttackTimeline";
import { ResponseCenter } from "@/components/dashboard/ResponseCenter";
import { DemoSimulator } from "@/components/dashboard/DemoSimulator";
import { Panel } from "@/components/common/Panel";

const title = "RansomShield AI — Security Command Center";
const description =
  "AI-powered behavioral ransomware detection and response for SME endpoints. Live risk scoring, explainable AI classification and simulated automated containment.";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
    ],
  }),
  component: Overview,
});

function Overview() {
  const { state } = useDemo();
  const status = getSystemStatus(state);
  const ai = getAiPrediction(state);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Command Center"
        description="AI-powered behavioral ransomware detection and response for SME endpoints."
      />

      <StatusCard status={status} />

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Current Risk Score" subtitle="Composite behavioral risk" className="h-full">
          <div className="flex justify-center py-2">
            <RiskGauge score={status.riskScore} />
          </div>
        </Panel>
        <SecurityHealth state={state} />
        <EarlyWarning state={state} warning={status.earlyWarning} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <FileVelocityChart state={state} />
        </div>
        <FileImpact state={state} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <ProcessBehavior state={state} />
        </div>
        <BehaviorBaseline state={state} />
      </div>

      <DetectionPipeline currentStage={ai.stage} />

      <div className="grid gap-4 xl:grid-cols-2">
        <AIExplanation state={state} />
        <EndpointRiskMap state={state} limit={8} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <LiveEventStream state={state} />
        </div>
        <ResponseCenter autoExecuted={state === "CRITICAL"} />
      </div>

      <AttackTimeline />

      <DemoSimulator />
    </div>
  );
}
