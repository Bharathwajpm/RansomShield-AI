import { useState } from "react";
import { SlidersHorizontal } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag, toneClasses } from "@/components/common/indicators";
import { Slider } from "@/components/ui/slider";
import { riskBand } from "@/lib/mock-data";
import { cn } from "@/lib/utils";

const factors = [
  { key: "file", label: "File Modification Rate", weight: 0.3 },
  { key: "cpu", label: "CPU Usage", weight: 0.18 },
  { key: "process", label: "Process Anomaly", weight: 0.24 },
  { key: "network", label: "Network Activity", weight: 0.13 },
  { key: "registry", label: "Registry Activity", weight: 0.15 },
] as const;

export function RiskSimulator() {
  const [values, setValues] = useState<Record<string, number>>({
    file: 20,
    cpu: 30,
    process: 15,
    network: 25,
    registry: 10,
  });

  const score = Math.round(factors.reduce((acc, f) => acc + (values[f.key] ?? 0) * f.weight, 0));
  const band = riskBand(score);
  const tone = toneClasses[band.tone]!;

  return (
    <Panel
      title="What-If Risk Simulator"
      subtitle="Explore how each behavioral feature drives the risk score"
      icon={<SlidersHorizontal className="h-4 w-4" />}
      actions={<DemoTag label="Prototype Simulation" />}
      className="h-full"
    >
      <div className="space-y-5">
        {factors.map((f) => (
          <div key={f.key}>
            <div className="mb-2 flex items-baseline justify-between text-xs">
              <span className="text-muted-foreground">
                {f.label}
                <span className="ml-2 text-[10px] opacity-70">weight {f.weight}</span>
              </span>
              <span className="num font-semibold">{values[f.key]}%</span>
            </div>
            <Slider
              value={[values[f.key] ?? 0]}
              max={100}
              step={1}
              onValueChange={([v]) => setValues((s) => ({ ...s, [f.key]: v ?? 0 }))}
            />
          </div>
        ))}
      </div>

      <div className={cn("mt-6 rounded-lg border p-4 text-center", tone.bg, tone.border)}>
        <p className="text-[10px] tracking-wider text-muted-foreground uppercase">
          Demonstration risk score
        </p>
        <p className={cn("num text-4xl font-semibold", tone.text)}>{score}</p>
        <p className={cn("text-xs font-semibold tracking-widest uppercase", tone.text)}>
          {band.label}
        </p>
        <p className="mt-2 text-[11px] text-muted-foreground">
          Illustrative weighted model for teaching purposes — not the trained XGBoost classifier.
        </p>
      </div>
    </Panel>
  );
}
