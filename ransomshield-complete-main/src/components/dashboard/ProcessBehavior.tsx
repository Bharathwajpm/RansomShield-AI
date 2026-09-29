import { useState } from "react";
import { Cpu } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag, StatusPill, toneClasses } from "@/components/common/indicators";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { getProcesses } from "@/lib/mock-data";
import type { DemoState, ProcessRow } from "@/lib/types";
import { cn } from "@/lib/utils";

export function ProcessBehavior({ state }: { state: DemoState }) {
  const rows = getProcesses(state);
  const [selected, setSelected] = useState<ProcessRow | null>(null);

  return (
    <>
      <Panel
        title="Process Behavior Analysis"
        subtitle="Live process telemetry from psutil + Sysmon"
        icon={<Cpu className="h-4 w-4" />}
        actions={<DemoTag />}
        bodyClassName="p-0"
      >
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead>
              <tr className="text-[10px] tracking-wider text-muted-foreground uppercase">
                <th className="px-5 py-2 text-left font-medium">Process</th>
                <th className="px-3 py-2 text-right font-medium">PID</th>
                <th className="px-3 py-2 text-right font-medium">CPU</th>
                <th className="px-3 py-2 text-right font-medium">Memory</th>
                <th className="px-3 py-2 text-right font-medium">File act.</th>
                <th className="px-3 py-2 text-right font-medium">Network</th>
                <th className="px-5 py-2 text-right font-medium">Risk</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <tr
                  key={p.pid}
                  onClick={() => setSelected(p)}
                  className={cn(
                    "cursor-pointer border-t border-border/70 transition-colors hover:bg-secondary/50",
                    p.risk === "critical" && "bg-critical/8",
                  )}
                >
                  <td className="px-5 py-2.5">
                    <span className="num text-foreground">{p.name}</span>
                    {!p.signed && <span className="ml-2 text-[10px] text-warn">unsigned</span>}
                  </td>
                  <td className="num px-3 py-2.5 text-right text-muted-foreground">{p.pid}</td>
                  <td className={cn("num px-3 py-2.5 text-right", p.cpu > 70 && "text-critical")}>
                    {p.cpu}%
                  </td>
                  <td className="num px-3 py-2.5 text-right text-muted-foreground">{p.memory}%</td>
                  <td
                    className={cn(
                      "num px-3 py-2.5 text-right",
                      p.fileActivity > 70 && "text-critical",
                    )}
                  >
                    {p.fileActivity}
                  </td>
                  <td className="num px-3 py-2.5 text-right text-muted-foreground">
                    {p.networkActivity}
                  </td>
                  <td className="px-5 py-2.5 text-right">
                    <StatusPill tone={p.risk}>{p.risk === "low" ? "Normal" : p.risk}</StatusPill>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Dialog open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <DialogContent className="max-w-lg">
          {selected && (
            <>
              <DialogHeader>
                <DialogTitle className="num flex items-center gap-3">
                  {selected.name}
                  <StatusPill tone={selected.risk}>{selected.risk}</StatusPill>
                </DialogTitle>
                <DialogDescription className="num text-xs break-all">
                  {selected.path}
                </DialogDescription>
              </DialogHeader>
              <dl className="grid grid-cols-2 gap-3 text-sm">
                {[
                  ["PID", selected.pid],
                  ["Parent", selected.parent],
                  ["CPU", `${selected.cpu}%`],
                  ["Memory", `${selected.memory}%`],
                  ["File activity index", selected.fileActivity],
                  ["Network activity index", selected.networkActivity],
                  ["Signature", selected.signed ? "Signed" : "Unsigned"],
                ].map(([k, v]) => (
                  <div
                    key={String(k)}
                    className="rounded-md border border-border bg-background/40 p-2.5"
                  >
                    <dt className="text-[10px] tracking-wider text-muted-foreground uppercase">
                      {k}
                    </dt>
                    <dd className={cn("num mt-0.5", toneClasses[selected.risk]!.text)}>{v}</dd>
                  </div>
                ))}
              </dl>
              <p className="text-[11px] text-muted-foreground">
                Prototype data — process details are simulated and no action is taken on a real
                host.
              </p>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
