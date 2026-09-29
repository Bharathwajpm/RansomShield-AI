import { createFileRoute } from "@tanstack/react-router";

import { Panel, PageHeader } from "@/components/common/Panel";
import { DemoTag } from "@/components/common/indicators";
import { AttackReplay } from "@/components/dashboard/AttackReplay";
import { AttackTimeline } from "@/components/dashboard/AttackTimeline";

const title = "RansomShield AI — Attack Replay";
const description =
  "Step-by-step simulated replay of a ransomware attack: suspicious process, file activity spike, encryption behavior, AI detection, response and containment.";

export const Route = createFileRoute("/replay")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
    ],
  }),
  component: ReplayPage,
});

const chain = [
  "Suspicious process",
  "File activity spike",
  "Encryption-like behavior",
  "AI detection",
  "High confidence",
  "Response",
  "Containment",
];

function ReplayPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack Replay — Simulation"
        description="Replay the full detection chain at your own pace to demonstrate how RansomShield AI reacts."
        actions={<DemoTag label="Simulation Only" />}
      />

      <p className="rounded-md border border-warn/30 bg-warn/10 p-3 text-xs text-warn">
        ATTACK REPLAY — SIMULATION. Nothing shown here is a live attack; the sequence is a scripted
        demonstration driven by the shared demo state.
      </p>

      <AttackReplay />

      <Panel
        title="Detection Chain"
        subtitle="Stages the replay walks through"
        actions={<DemoTag />}
      >
        <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {chain.map((c, i) => (
            <li key={c} className="rounded-lg border border-border bg-background/40 p-3">
              <p className="num text-[11px] text-muted-foreground">
                {String(i + 1).padStart(2, "0")}
              </p>
              <p className="mt-1 text-sm text-foreground">{c}</p>
            </li>
          ))}
        </ol>
      </Panel>

      <AttackTimeline />
    </div>
  );
}
