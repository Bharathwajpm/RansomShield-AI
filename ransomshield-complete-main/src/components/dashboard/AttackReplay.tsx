import { useCallback, useEffect, useMemo, useState } from "react";
import { Pause, Play, RotateCcw, SkipForward } from "lucide-react";
import { toast } from "sonner";
import { Panel } from "@/components/common/Panel";
import { DemoTag, LiveDot, StatusPill, toneClasses } from "@/components/common/indicators";
import { Button } from "@/components/ui/button";
import { RiskGauge } from "@/components/dashboard/RiskGauge";
import { useDemo } from "@/lib/demo-context";
import { cn } from "@/lib/utils";
import type { DemoState, Severity } from "@/lib/types";

interface Stage {
  title: string;
  detail: string;
  time: string;
  risk: number;
  confidence: number;
  files: number;
  state: DemoState;
  severity: Severity | "info";
  threat: string;
}

const stages: Stage[] = [
  {
    title: "Suspicious executable launched",
    detail: "invoice_update.exe (PID 9184) spawned by OUTLOOK.EXE",
    time: "10:42:40",
    risk: 14,
    confidence: 4,
    files: 0,
    state: "SAFE",
    severity: "info",
    threat: "None",
  },
  {
    title: "Process anomaly detected",
    detail: "Unsigned binary from Downloads, shadow-copy utility invoked",
    time: "10:42:41",
    risk: 34,
    confidence: 21,
    files: 12,
    state: "WARNING",
    severity: "medium",
    threat: "Observing",
  },
  {
    title: "File modification rate increases",
    detail: "Modification rate climbs from 15/min to 180/min",
    time: "10:42:41",
    risk: 58,
    confidence: 46,
    files: 186,
    state: "WARNING",
    severity: "medium",
    threat: "Suspicious",
  },
  {
    title: "Encryption-like behavior detected",
    detail: "High-entropy writes with .lockxx rename pattern",
    time: "10:42:42",
    risk: 76,
    confidence: 71,
    files: 640,
    state: "WARNING",
    severity: "high",
    threat: "Escalating",
  },
  {
    title: "AI classification: RANSOMWARE",
    detail: "XGB-v1.0 classifies the feature vector as ransomware",
    time: "10:42:43",
    risk: 90,
    confidence: 92,
    files: 1024,
    state: "CRITICAL",
    severity: "critical",
    threat: "Active",
  },
  {
    title: "Threat confidence increases",
    detail: "Confidence stabilizes at 98.7% across consecutive windows",
    time: "10:42:43",
    risk: 98,
    confidence: 98.7,
    files: 1248,
    state: "CRITICAL",
    severity: "critical",
    threat: "Confirmed",
  },
  {
    title: "Response triggered",
    detail: "Process terminated, binary quarantined, endpoint isolated",
    time: "10:42:44",
    risk: 72,
    confidence: 98.7,
    files: 1248,
    state: "CRITICAL",
    severity: "critical",
    threat: "Containing",
  },
  {
    title: "Incident contained",
    detail: "HR-PC-03 isolated, incident THR-0017 opened, admin notified",
    time: "10:42:46",
    risk: 24,
    confidence: 98.7,
    files: 1248,
    state: "CRITICAL",
    severity: "high",
    threat: "Contained",
  },
];

export function AttackReplay() {
  const { setState, stopScenario } = useDemo();
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);

  const stage = stages[index]!;

  useEffect(() => {
    setState(stage.state);
  }, [stage.state, setState]);

  useEffect(() => {
    if (!playing) return;
    const id = setInterval(() => {
      setIndex((i) => {
        if (i >= stages.length - 1) {
          setPlaying(false);
          return i;
        }
        return i + 1;
      });
    }, 1800);
    return () => clearInterval(id);
  }, [playing]);

  const restart = useCallback(() => {
    stopScenario();
    setPlaying(false);
    setIndex(0);
    setState("SAFE");
    toast.info("Attack replay restarted");
  }, [setState, stopScenario]);

  const progress = useMemo(() => ((index + 1) / stages.length) * 100, [index]);

  return (
    <div className="space-y-4">
      <Panel
        title="Attack Replay — Simulation"
        subtitle="Step-by-step reconstruction of a ransomware incident on HR-PC-03"
        icon={<Play className="h-4 w-4" />}
        actions={
          <div className="flex items-center gap-2">
            {playing && <LiveDot label="REPLAYING" />}
            <DemoTag label="Simulation Only" />
          </div>
        }
      >
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            className="h-8 text-xs"
            variant="secondary"
            onClick={() => setPlaying(true)}
            disabled={playing || index === stages.length - 1}
          >
            <Play className="mr-1.5 h-3.5 w-3.5" /> Play
          </Button>
          <Button
            size="sm"
            className="h-8 text-xs"
            variant="secondary"
            onClick={() => setPlaying(false)}
            disabled={!playing}
          >
            <Pause className="mr-1.5 h-3.5 w-3.5" /> Pause
          </Button>
          <Button
            size="sm"
            className="h-8 text-xs"
            variant="secondary"
            onClick={() => setIndex((i) => Math.min(stages.length - 1, i + 1))}
            disabled={index === stages.length - 1}
          >
            <SkipForward className="mr-1.5 h-3.5 w-3.5" /> Step forward
          </Button>
          <Button size="sm" className="h-8 text-xs" variant="ghost" onClick={restart}>
            <RotateCcw className="mr-1.5 h-3.5 w-3.5" /> Restart
          </Button>
          <span className="num ml-auto text-xs text-muted-foreground">
            Stage {index + 1} / {stages.length}
          </span>
        </div>

        <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-secondary">
          <div
            className="h-full rounded-full bg-info transition-all duration-500"
            style={{ width: `${progress}%` }}
          />
        </div>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel
          title="Replay State"
          subtitle="Values as of the current stage"
          className="xl:col-span-1"
        >
          <div className="flex justify-center">
            <RiskGauge score={Math.round(stage.risk)} size={170} />
          </div>
          <dl className="mt-4 space-y-2.5">
            {[
              { k: "AI confidence", v: `${stage.confidence}%` },
              { k: "Files affected", v: stage.files.toLocaleString() },
              { k: "Threat state", v: stage.threat },
              { k: "Demo state", v: stage.state },
              { k: "Timestamp", v: stage.time },
            ].map((r) => (
              <div key={r.k} className="flex items-center justify-between gap-3 text-sm">
                <dt className="text-muted-foreground">{r.k}</dt>
                <dd className="num font-semibold">{r.v}</dd>
              </div>
            ))}
          </dl>
        </Panel>

        <Panel
          title="Replay Timeline"
          subtitle="Highlighted step is the current stage"
          className="xl:col-span-2"
        >
          <ol className="space-y-2">
            {stages.map((s, i) => {
              const active = i === index;
              const done = i < index;
              const t = toneClasses[s.severity] ?? toneClasses["info"]!;
              return (
                <li key={s.title}>
                  <button
                    type="button"
                    onClick={() => {
                      setPlaying(false);
                      setIndex(i);
                    }}
                    aria-current={active ? "step" : undefined}
                    className={cn(
                      "flex w-full items-start gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors focus-visible:ring-2 focus-visible:ring-info/60 focus-visible:outline-none",
                      active
                        ? cn(t.border, t.bg)
                        : done
                          ? "border-border bg-background/40 opacity-80"
                          : "border-border bg-background/20 opacity-55",
                    )}
                  >
                    <span
                      className={cn(
                        "num mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-full border text-[11px] font-semibold",
                        active ? cn(t.border, t.text) : "border-border text-muted-foreground",
                      )}
                    >
                      {i + 1}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex flex-wrap items-center gap-2">
                        <span className="text-[13px] font-medium">{s.title}</span>
                        <span className="num text-[10px] text-muted-foreground">{s.time}</span>
                        {active && (
                          <StatusPill tone={s.severity === "info" ? "info" : s.severity}>
                            Current
                          </StatusPill>
                        )}
                      </span>
                      <span className="mt-0.5 block text-[11px] text-muted-foreground">
                        {s.detail}
                      </span>
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>
        </Panel>
      </div>
    </div>
  );
}
