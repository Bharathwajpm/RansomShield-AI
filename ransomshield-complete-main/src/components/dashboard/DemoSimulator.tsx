import { FlaskConical, Pause, Play, ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import { toast } from "sonner";
import { Panel } from "@/components/common/Panel";
import { DemoTag, StatusPill } from "@/components/common/indicators";
import { Button } from "@/components/ui/button";
import { useDemo } from "@/lib/demo-context";
import { getSystemStatus } from "@/lib/mock-data";
import { cn } from "@/lib/utils";
import type { DemoState } from "@/lib/types";

const modes: {
  value: DemoState;
  label: string;
  desc: string;
  tone: "low" | "medium" | "critical";
  icon: typeof ShieldCheck;
}[] = [
  {
    value: "SAFE",
    label: "Normal Activity",
    desc: "Baseline endpoint behavior — risk 8, PROTECTED",
    tone: "low",
    icon: ShieldCheck,
  },
  {
    value: "WARNING",
    label: "Suspicious Activity",
    desc: "Deviation from baseline — risk 58, WARNING",
    tone: "medium",
    icon: TriangleAlert,
  },
  {
    value: "CRITICAL",
    label: "Ransomware Attack",
    desc: "Encryption-like behavior — risk 98, CRITICAL",
    tone: "critical",
    icon: ShieldAlert,
  },
];

export function DemoSimulator({ compact = false }: { compact?: boolean }) {
  const { state, setState, runScenario, stopScenario, scenarioRunning, scenarioProgress } =
    useDemo();
  const status = getSystemStatus(state);

  return (
    <Panel
      title="Demo Mode"
      subtitle="Academic demonstration control — drives every panel in the console"
      icon={<FlaskConical className="h-4 w-4" />}
      actions={<DemoTag label="Simulation Only" />}
    >
      <div className={cn("grid gap-3", compact ? "sm:grid-cols-3" : "md:grid-cols-3")}>
        {modes.map((m) => {
          const active = state === m.value;
          return (
            <button
              key={m.value}
              type="button"
              aria-pressed={active}
              onClick={() => {
                stopScenario();
                setState(m.value);
                toast.info(`Demo state changed to ${m.label}`, {
                  description: "Simulation data only — no real endpoint is affected.",
                });
              }}
              className={cn(
                "rounded-lg border p-3.5 text-left transition-colors focus-visible:ring-2 focus-visible:ring-info/60 focus-visible:outline-none",
                active
                  ? "border-info/45 bg-info/10"
                  : "border-border bg-background/40 hover:bg-secondary/50",
              )}
            >
              <span className="flex items-center gap-2">
                <m.icon
                  className={cn(
                    "h-4 w-4",
                    m.tone === "low" && "text-safe",
                    m.tone === "medium" && "text-warn",
                    m.tone === "critical" && "text-critical",
                  )}
                />
                <span className="text-sm font-semibold">{m.label}</span>
              </span>
              <span className="mt-1 block text-[11px] text-muted-foreground">{m.desc}</span>
            </button>
          );
        })}
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-border pt-4">
        <StatusPill tone={state === "SAFE" ? "low" : state === "WARNING" ? "medium" : "critical"}>
          {status.status}
        </StatusPill>
        <span className="num text-xs text-muted-foreground">Risk score {status.riskScore}</span>
        <span className="num text-xs text-muted-foreground">
          Early warning {status.earlyWarning}
        </span>

        <div className="ml-auto flex items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            className="h-8 text-xs"
            onClick={() => {
              if (scenarioRunning) {
                stopScenario();
                toast.info("Attack scenario paused");
              } else {
                runScenario();
                toast.warning("Running scripted ransomware scenario", {
                  description: "SAFE → WARNING → CRITICAL. Simulation only.",
                });
              }
            }}
          >
            {scenarioRunning ? (
              <>
                <Pause className="mr-1.5 h-3.5 w-3.5" /> Pause scenario
              </>
            ) : (
              <>
                <Play className="mr-1.5 h-3.5 w-3.5" /> Run attack scenario
              </>
            )}
          </Button>
        </div>
      </div>

      {(scenarioRunning || scenarioProgress > 0) && (
        <div className="mt-3">
          <div className="h-1.5 overflow-hidden rounded-full bg-secondary">
            <div
              className="h-full rounded-full bg-critical transition-all duration-200"
              style={{ width: `${Math.round(scenarioProgress * 100)}%` }}
            />
          </div>
          <p className="mt-1.5 text-[11px] text-muted-foreground">
            Scenario progress {Math.round(scenarioProgress * 100)}%
          </p>
        </div>
      )}
    </Panel>
  );
}
