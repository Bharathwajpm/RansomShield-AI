import { createFileRoute } from "@tanstack/react-router";

import { useDemo } from "@/lib/demo-context";
import { getAiPrediction, getSystemStatus } from "@/lib/mock-data";
import { Panel, PageHeader } from "@/components/common/Panel";
import { LiveDot, StatusPill, DemoTag } from "@/components/common/indicators";
import { RiskGauge } from "@/components/dashboard/RiskGauge";
import { EarlyWarning } from "@/components/dashboard/EarlyWarning";
import { FileVelocityChart } from "@/components/dashboard/FileVelocityChart";
import { ProcessBehavior } from "@/components/dashboard/ProcessBehavior";
import { BehaviorBaseline } from "@/components/dashboard/BehaviorBaseline";
import { DetectionPipeline } from "@/components/dashboard/DetectionPipeline";
import { LiveEventStream } from "@/components/dashboard/LiveEventStream";
import { ResponseCenter } from "@/components/dashboard/ResponseCenter";

const title = "RansomShield AI — Live Monitoring";
const description =
  "Live endpoint telemetry: collect, analyze, detect and respond. Continuous behavioral monitoring with AI classification and confidence scoring.";

export const Route = createFileRoute("/monitoring")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
    ],
  }),
  component: Monitoring,
});

const flow = [
  { label: "Collect", detail: "Event Logs · Sysmon · psutil · watchdog" },
  { label: "Analyze", detail: "Rolling behavioral feature extraction" },
  { label: "Detect", detail: "XGBoost classification + risk score" },
  { label: "Respond", detail: "Policy-driven containment actions" },
];

function Monitoring() {
  const { state } = useDemo();
  const status = getSystemStatus(state);
  const ai = getAiPrediction(state);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Live Monitoring"
        description="Continuous behavioral telemetry from the endpoint agents, classified in real time."
        actions={<LiveDot tone={state === "CRITICAL" ? "critical" : "low"} />}
      />

      <Panel
        title="Monitoring Flow"
        subtitle="Collect → Analyze → Detect → Respond"
        actions={<DemoTag />}
      >
        <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {flow.map((f, i) => (
            <li key={f.label} className="rounded-lg border border-border bg-background/40 p-3.5">
              <p className="num text-[11px] text-muted-foreground">STEP {i + 1}</p>
              <p className="mt-1 text-sm font-semibold text-foreground">{f.label}</p>
              <p className="mt-1 text-xs text-muted-foreground">{f.detail}</p>
            </li>
          ))}
        </ol>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel
          title="Current Risk"
          subtitle="Composite behavioral risk score"
          actions={
            <StatusPill
              tone={state === "CRITICAL" ? "critical" : state === "WARNING" ? "medium" : "low"}
            >
              {status.status}
            </StatusPill>
          }
        >
          <div className="flex justify-center py-2">
            <RiskGauge score={status.riskScore} />
          </div>
        </Panel>
        <Panel
          title="AI Classification"
          subtitle="Current model verdict"
          actions={<DemoTag label="Prototype Model" />}
          className="h-full"
        >
          <p className="text-3xl font-semibold tracking-tight">{ai.prediction}</p>
          <p className="num mt-2 text-sm text-muted-foreground">
            Threat confidence {ai.confidence}%
          </p>
          <p className="mt-4 text-sm text-muted-foreground">{ai.explanation}</p>
          <div className="mt-4 space-y-2">
            {ai.indicators.slice(0, 3).map((ind) => (
              <div key={ind.label} className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">{ind.label}</span>
                <span className="num font-semibold">{ind.weight}</span>
              </div>
            ))}
          </div>
        </Panel>
        <EarlyWarning state={state} warning={status.earlyWarning} />
      </div>

      <DetectionPipeline currentStage={ai.stage} />

      <FileVelocityChart state={state} />

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <ProcessBehavior state={state} />
        </div>
        <BehaviorBaseline state={state} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <LiveEventStream state={state} />
        </div>
        <ResponseCenter autoExecuted={state === "CRITICAL"} />
      </div>
    </div>
  );
}
