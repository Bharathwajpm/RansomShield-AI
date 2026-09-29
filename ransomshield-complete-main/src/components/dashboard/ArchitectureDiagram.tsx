import type { ReactNode } from "react";
import {
  ArrowDown,
  Boxes,
  Brain,
  Database,
  FileCog,
  FlaskConical,
  Gauge,
  LayoutDashboard,
  Monitor,
  Network,
  Save,
  Scissors,
  Server,
  Sparkles,
  SplitSquareVertical,
} from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag } from "@/components/common/indicators";
import { cn } from "@/lib/utils";

type Node = { label: string; sub?: string; icon: typeof Monitor; items?: string[] };

const training: Node[] = [
  { label: "Historical Dataset", sub: "Labelled behavioral telemetry", icon: Database },
  { label: "Data Cleaning", sub: "De-duplication, missing values, outliers", icon: Scissors },
  { label: "Feature Engineering", sub: "Rolling behavioral feature vectors", icon: FileCog },
  { label: "Train / Test Split", sub: "Stratified holdout", icon: SplitSquareVertical },
  { label: "XGBoost Training", sub: "Gradient-boosted decision trees", icon: Brain },
  { label: "Model Evaluation", sub: "Accuracy, precision, recall, ROC-AUC", icon: Gauge },
  { label: "Saved Model", sub: "XGB-v1.0 artifact", icon: Save },
];

const live: Node[] = [
  { label: "Windows Endpoint", sub: "SME workstation under protection", icon: Monitor },
  {
    label: "Telemetry Collectors",
    icon: Boxes,
    items: ["Windows Event Logs", "Sysmon", "psutil", "watchdog"],
  },
  { label: "Python Monitoring Agent", sub: "Normalizes and buffers raw telemetry", icon: Server },
  { label: "Feature Extraction", sub: "Same features as training pipeline", icon: FileCog },
  { label: "XGBoost Inference", sub: "Loaded XGB-v1.0 model", icon: Brain },
  { label: "Prediction", sub: "BENIGN / SUSPICIOUS / RANSOMWARE", icon: Sparkles },
  { label: "Risk Score", sub: "Confidence mapped to 0–100 risk", icon: Gauge },
  { label: "FastAPI", sub: "REST + realtime stream", icon: Network },
  { label: "MongoDB", sub: "Events, threats, incidents, audit", icon: Database },
  { label: "React Dashboard", sub: "This console", icon: LayoutDashboard },
];

function Flow({ nodes, tone }: { nodes: Node[]; tone: "info" | "critical" }) {
  return (
    <ol className="space-y-1.5">
      {nodes.map((n, i) => (
        <li key={n.label}>
          <div
            className={cn(
              "flex items-start gap-3 rounded-lg border bg-background/40 px-3 py-2.5",
              tone === "info" ? "border-info/25" : "border-critical/25",
            )}
          >
            <span
              className={cn(
                "mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-md",
                tone === "info" ? "bg-info/12 text-info" : "bg-critical/12 text-critical",
              )}
            >
              <n.icon className="h-3.5 w-3.5" />
            </span>
            <div className="min-w-0">
              <p className="text-[13px] font-medium">{n.label}</p>
              {n.sub && <p className="text-[11px] text-muted-foreground">{n.sub}</p>}
              {n.items && (
                <ul className="mt-1.5 flex flex-wrap gap-1.5">
                  {n.items.map((it) => (
                    <li
                      key={it}
                      className="num rounded border border-border bg-surface/60 px-1.5 py-0.5 text-[10px] text-muted-foreground"
                    >
                      {it}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
          {i < nodes.length - 1 && (
            <div className="flex justify-center py-0.5" aria-hidden="true">
              <ArrowDown
                className={cn("h-3.5 w-3.5", tone === "info" ? "text-info/50" : "text-critical/50")}
              />
            </div>
          )}
        </li>
      ))}
    </ol>
  );
}

function Column({
  eyebrow,
  title,
  description,
  tone,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  tone: "info" | "critical";
  children: ReactNode;
}) {
  return (
    <div
      className={cn(
        "rounded-xl border p-4",
        tone === "info" ? "border-info/30 bg-info/[0.04]" : "border-critical/30 bg-critical/[0.04]",
      )}
    >
      <p
        className={cn(
          "text-[10px] font-semibold tracking-widest uppercase",
          tone === "info" ? "text-info" : "text-critical",
        )}
      >
        {eyebrow}
      </p>
      <h3 className="mt-1 text-sm font-semibold">{title}</h3>
      <p className="mt-1 mb-4 text-[11px] leading-relaxed text-muted-foreground">{description}</p>
      {children}
    </div>
  );
}

export function ArchitectureDiagram() {
  return (
    <Panel
      title="System Architecture"
      subtitle="Two distinct pipelines: offline model training and live endpoint detection"
      icon={<FlaskConical className="h-4 w-4" />}
      actions={<DemoTag label="Target Architecture" />}
    >
      <div className="grid gap-4 xl:grid-cols-2">
        <Column
          eyebrow="Pipeline 1 · Training data (offline)"
          title="Historical Model Training"
          description="Runs once, offline, on a labelled historical dataset. No live endpoint telemetry is used here — this pipeline only produces the saved model artifact."
          tone="info"
        >
          <Flow nodes={training} tone="info" />
        </Column>

        <Column
          eyebrow="Pipeline 2 · Live data (runtime)"
          title="Live Endpoint Detection"
          description="Runs continuously on protected endpoints. Live telemetry never trains the model — it is scored by the saved model and surfaced in this dashboard."
          tone="critical"
        >
          <Flow nodes={live} tone="critical" />
        </Column>
      </div>

      <p className="mt-4 rounded-lg border border-dashed border-border bg-background/40 p-3 text-[11px] leading-relaxed text-muted-foreground">
        <strong className="text-foreground">Training data vs live data:</strong> the left pipeline
        consumes a static labelled dataset to build XGB-v1.0. The right pipeline consumes real-time
        Windows telemetry and only performs inference. The frontend you are viewing currently runs
        on simulated data until the Python agent and FastAPI service are connected.
      </p>
    </Panel>
  );
}
