import { ShieldAlert, ShieldCheck, ShieldQuestion, Siren } from "lucide-react";
import type { SystemStatusPayload } from "@/lib/types";
import { StatusPill, toneClasses } from "@/components/common/indicators";
import { cn } from "@/lib/utils";

const map = {
  PROTECTED: { tone: "low", icon: ShieldCheck, emoji: "🟢" },
  WARNING: { tone: "medium", icon: ShieldQuestion, emoji: "🟡" },
  "HIGH RISK": { tone: "high", icon: ShieldAlert, emoji: "🟠" },
  CRITICAL: { tone: "critical", icon: Siren, emoji: "🔴" },
} as const;

export function StatusCard({ status }: { status: SystemStatusPayload }) {
  const meta = map[status.status];
  const tone = toneClasses[meta.tone]!;
  const Icon = meta.icon;

  return (
    <section className={cn("panel relative overflow-hidden p-5 sm:p-6", tone.border)}>
      <div className={cn("absolute inset-0 opacity-[0.09]", tone.dot)} />
      <div className="relative flex flex-wrap items-start justify-between gap-6">
        <div className="flex items-start gap-4">
          <span
            className={cn(
              "grid h-14 w-14 shrink-0 place-items-center rounded-xl border",
              tone.bg,
              tone.border,
              tone.text,
            )}
          >
            <Icon className="h-7 w-7" />
          </span>
          <div>
            <p className="text-[11px] tracking-[0.2em] text-muted-foreground uppercase">
              System Security Status
            </p>
            <h2 className={cn("mt-1 text-3xl font-semibold tracking-tight", tone.text)}>
              {status.status}
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">{status.headline}</p>
          </div>
        </div>

        <dl className="grid grid-cols-2 gap-x-8 gap-y-3 sm:grid-cols-3">
          <div>
            <dt className="text-[10px] tracking-wider text-muted-foreground uppercase">
              Risk Score
            </dt>
            <dd className={cn("num text-xl font-semibold", tone.text)}>{status.riskScore} / 100</dd>
          </div>
          <div>
            <dt className="text-[10px] tracking-wider text-muted-foreground uppercase">
              Protection
            </dt>
            <dd className="mt-1">
              <StatusPill tone="low">{status.protection}</StatusPill>
            </dd>
          </div>
          <div>
            <dt className="text-[10px] tracking-wider text-muted-foreground uppercase">
              Last Updated
            </dt>
            <dd className="num text-sm text-foreground">{status.lastUpdatedSeconds}s ago</dd>
          </div>
        </dl>
      </div>
    </section>
  );
}
