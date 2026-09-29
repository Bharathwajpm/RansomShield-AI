import { createFileRoute } from "@tanstack/react-router";
import {
  Brain,
  Database,
  FileCog,
  Gauge,
  Save,
  Scissors,
  SplitSquareVertical,
  ArrowDown,
} from "lucide-react";

import { modelHealth, trainingData } from "@/lib/mock-data";
import { Panel, PageHeader } from "@/components/common/Panel";
import { DemoTag, MetricBar, StatTile } from "@/components/common/indicators";

const title = "RansomShield AI — Training Data & XGBoost Pipeline";
const description =
  "The offline training pipeline behind RansomShield AI: historical dataset, cleaning, feature engineering, train/test split, XGBoost training, evaluation and the saved model artifact.";

export const Route = createFileRoute("/training")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
    ],
  }),
  component: Training,
});

const steps = [
  {
    label: "Historical Dataset",
    icon: Database,
    detail: `${trainingData.rows.toLocaleString()} labelled behavioral samples collected offline`,
  },
  {
    label: "Data Cleaning",
    icon: Scissors,
    detail: "De-duplication, missing value handling and outlier removal",
  },
  {
    label: "Feature Engineering",
    icon: FileCog,
    detail: `${trainingData.features.length} rolling behavioral features per observation window`,
  },
  {
    label: "Train / Test Split",
    icon: SplitSquareVertical,
    detail: "Stratified 80 / 20 holdout preserving class balance",
  },
  {
    label: "XGBoost Training",
    icon: Brain,
    detail: "Gradient-boosted decision trees with cross-validated hyperparameters",
  },
  {
    label: "Evaluation",
    icon: Gauge,
    detail: "Accuracy, precision, recall, F1 and ROC-AUC on the holdout set",
  },
  {
    label: "Saved Model",
    icon: Save,
    detail: `${modelHealth.version} artifact loaded by the live inference service`,
  },
];

function Training() {
  const total = trainingData.classes.reduce((sum, c) => sum + c.value, 0);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Training Data"
        description="How the XGBoost behavioral classifier is trained offline before it is deployed to the live detection pipeline."
        actions={<DemoTag label="Prototype Dataset" />}
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Dataset rows" value={trainingData.rows.toLocaleString()} />
        <StatTile label="Features" value={trainingData.features.length} />
        <StatTile label="Model" value={modelHealth.version} />
        <StatTile label="Accuracy" value={`${modelHealth.metrics[0]!.value}%`} />
      </div>

      <Panel
        title="Training Pipeline"
        subtitle="Historical dataset → Saved model (offline, no live telemetry)"
        actions={<DemoTag label="Target Architecture" />}
      >
        <ol className="mx-auto max-w-2xl">
          {steps.map((s, i) => (
            <li key={s.label}>
              <div className="flex items-start gap-3 rounded-lg border border-info/25 bg-background/40 px-3.5 py-3">
                <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md bg-info/10 text-info">
                  <s.icon className="h-4 w-4" />
                </span>
                <div className="min-w-0">
                  <p className="num text-[10px] tracking-wider text-muted-foreground uppercase">
                    Step {i + 1}
                  </p>
                  <p className="text-sm font-semibold text-foreground">{s.label}</p>
                  <p className="mt-0.5 text-xs text-muted-foreground">{s.detail}</p>
                </div>
              </div>
              {i < steps.length - 1 && (
                <div className="flex justify-center py-1 text-muted-foreground">
                  <ArrowDown className="h-4 w-4" />
                </div>
              )}
            </li>
          ))}
        </ol>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel
          title="Class Distribution"
          subtitle="Labelled samples per class"
          actions={<DemoTag label="Prototype Data" />}
        >
          <div className="space-y-3.5">
            {trainingData.classes.map((c) => (
              <MetricBar
                key={c.name}
                label={`${c.name} · ${c.value.toLocaleString()}`}
                value={Math.round((c.value / total) * 100)}
                tone={c.name === "Benign" ? "low" : c.name === "Ransomware" ? "critical" : "medium"}
              />
            ))}
          </div>
        </Panel>

        <Panel
          title="Evaluation Metrics"
          subtitle={`Holdout performance of ${modelHealth.version}`}
          actions={<DemoTag label="Prototype Model" />}
        >
          <div className="space-y-3.5">
            {modelHealth.metrics.map((m) => (
              <MetricBar key={m.label} label={m.label} value={m.value} tone="info" />
            ))}
          </div>
        </Panel>
      </div>

      <Panel
        title="Engineered Features"
        subtitle="Identical feature set is computed at inference time on live telemetry"
        actions={<DemoTag />}
      >
        <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {trainingData.features.map((f) => (
            <li
              key={f}
              className="rounded-lg border border-border bg-background/40 px-3 py-2 text-xs text-muted-foreground"
            >
              {f}
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
