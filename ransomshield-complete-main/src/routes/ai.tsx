import { createFileRoute } from "@tanstack/react-router";

import { useDemo } from "@/lib/demo-context";
import { getAiPrediction, getSystemStatus } from "@/lib/mock-data";
import { Panel, PageHeader } from "@/components/common/Panel";
import { MetricBar, StatTile, DemoTag } from "@/components/common/indicators";
import { RiskGauge } from "@/components/dashboard/RiskGauge";
import { ModelHealth } from "@/components/dashboard/ModelHealth";
import { AIExplanation } from "@/components/dashboard/AIExplanation";
import { DetectionPipeline } from "@/components/dashboard/DetectionPipeline";

const title = "RansomShield AI — AI Detection";
const description =
  "XGBoost behavioral classifier: current prediction, confidence and the top contributing behavioral features.";

export const Route = createFileRoute("/ai")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
    ],
  }),
  component: AiPage,
});

function AiPage() {
  const { state } = useDemo();
  const ai = getAiPrediction(state);
  const status = getSystemStatus(state);

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Detection"
        description="XGBoost Behavioral Classifier — explainable ransomware classification from endpoint behavior."
        actions={<DemoTag label="Prototype / Demonstration Data" />}
      />

      <p className="rounded-md border border-info/30 bg-info/10 p-3 text-xs text-info">
        All model metrics shown on this page are prototype / demonstration values produced for
        academic evaluation. They do not represent validated production accuracy.
      </p>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel
          title="Current Prediction"
          subtitle="Live classification of the active feature vector"
        >
          <p className="text-3xl font-semibold tracking-tight">{ai.prediction}</p>
          <p className="num mt-2 text-sm text-muted-foreground">Confidence {ai.confidence}%</p>
          <div className="mt-4 grid grid-cols-3 gap-2 text-center text-[11px]">
            {(["BENIGN", "SUSPICIOUS", "RANSOMWARE"] as const).map((c) => (
              <span
                key={c}
                className={
                  c === ai.prediction
                    ? "rounded-md bg-info/15 px-2 py-1.5 font-semibold text-info ring-1 ring-info/30"
                    : "rounded-md border border-border px-2 py-1.5 text-muted-foreground"
                }
              >
                {c}
              </span>
            ))}
          </div>
          <p className="mt-4 text-sm text-muted-foreground">{ai.explanation}</p>
        </Panel>

        <Panel
          title="Top Contributing Features"
          subtitle="Relative feature attribution"
          actions={<DemoTag />}
        >
          <div className="space-y-4">
            {ai.indicators.map((i) => (
              <MetricBar
                key={i.label}
                label={i.label}
                value={i.weight}
                tone={i.weight > 70 ? "critical" : i.weight > 40 ? "medium" : "low"}
              />
            ))}
          </div>
        </Panel>

        <Panel title="Derived Risk Score" subtitle="Confidence mapped to response policy band">
          <div className="flex justify-center py-2">
            <RiskGauge score={status.riskScore} size={170} />
          </div>
        </Panel>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Model" value="XGBoost" hint="Gradient-boosted trees" />
        <StatTile label="Prediction" value={ai.prediction} tone="info" />
        <StatTile label="Confidence" value={`${ai.confidence}%`} tone="info" />
        <StatTile label="Pipeline stage" value={`${ai.stage} / 6`} />
      </div>

      <DetectionPipeline currentStage={ai.stage} />

      <ModelHealth state={state} />

      <AIExplanation state={state} />
    </div>
  );
}
