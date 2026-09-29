import { Briefcase } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag } from "@/components/common/indicators";
import { executiveSummary } from "@/lib/mock-data";

export function ManagementSummary() {
  const s = executiveSummary;
  const items = [
    { label: "Overall security", value: `${s.overall} / 100`, note: "Higher is safer" },
    { label: "Computers monitored", value: s.endpoints, note: "Across the organization" },
    { label: "Fully protected", value: s.protected, note: "Behaving normally" },
    { label: "Needs attention", value: s.atRisk, note: "Unusual behavior seen" },
    { label: "Urgent", value: s.critical, note: "Being contained now" },
    { label: "Threats this month", value: s.threatsThisMonth, note: "Detected by the system" },
    { label: "Threats stopped", value: s.threatsBlocked, note: "Blocked automatically" },
    {
      label: "Incidents likely prevented",
      value: s.incidentsPrevented,
      note: "Prototype estimate",
    },
  ];

  return (
    <Panel
      title="Executive Security Summary"
      subtitle="Written for business owners, not security engineers"
      icon={<Briefcase className="h-4 w-4" />}
      actions={<DemoTag label="Demo Estimates" />}
    >
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {items.map((i) => (
          <div key={i.label} className="rounded-lg border border-border bg-background/40 p-3.5">
            <p className="text-xs text-muted-foreground">{i.label}</p>
            <p className="num mt-1 text-2xl font-semibold">{i.value}</p>
            <p className="mt-0.5 text-[11px] text-muted-foreground">{i.note}</p>
          </div>
        ))}
      </div>
      <p className="mt-4 text-xs leading-relaxed text-muted-foreground">
        In plain terms: RansomShield AI watches how each office computer behaves. When a program
        suddenly starts changing thousands of files — the signature of ransomware — the system stops
        it within seconds, isolates that computer and tells you what happened and why.
      </p>
    </Panel>
  );
}
