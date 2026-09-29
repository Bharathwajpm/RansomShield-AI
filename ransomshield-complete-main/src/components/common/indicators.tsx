import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

export const toneClasses: Record<
  string,
  { text: string; bg: string; border: string; dot: string }
> = {
  low: {
    text: "text-safe",
    bg: "bg-safe/10",
    border: "border-safe/30",
    dot: "bg-safe",
  },
  medium: {
    text: "text-warn",
    bg: "bg-warn/10",
    border: "border-warn/30",
    dot: "bg-warn",
  },
  high: {
    text: "text-high",
    bg: "bg-high/10",
    border: "border-high/30",
    dot: "bg-high",
  },
  critical: {
    text: "text-critical",
    bg: "bg-critical/12",
    border: "border-critical/40",
    dot: "bg-critical",
  },
  info: {
    text: "text-info",
    bg: "bg-info/10",
    border: "border-info/30",
    dot: "bg-info",
  },
  offline: {
    text: "text-muted-foreground",
    bg: "bg-muted/40",
    border: "border-border",
    dot: "bg-muted-foreground",
  },
};

export type Tone = keyof typeof toneClasses;

export function severityTone(s: Severity | "info" | "offline"): Tone {
  return (toneClasses[s] ? s : "info") as Tone;
}

export function StatusPill({
  tone = "info",
  children,
  className,
  dot = true,
}: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
  dot?: boolean;
}) {
  const t = toneClasses[tone] ?? toneClasses["info"]!;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold tracking-wide uppercase",
        t.bg,
        t.border,
        t.text,
        className,
      )}
    >
      {dot && <span className={cn("h-1.5 w-1.5 rounded-full", t.dot)} />}
      {children}
    </span>
  );
}

export function LiveDot({ tone = "critical", label = "LIVE" }: { tone?: Tone; label?: string }) {
  const t = toneClasses[tone] ?? toneClasses["info"]!;
  return (
    <span className={cn("inline-flex items-center gap-2 text-[11px] font-semibold", t.text)}>
      <span className="relative flex h-2 w-2">
        <span
          className={cn(
            "absolute inline-flex h-full w-full animate-ping rounded-full opacity-70",
            t.dot,
          )}
        />
        <span className={cn("relative inline-flex h-2 w-2 rounded-full", t.dot)} />
      </span>
      {label}
    </span>
  );
}

export function DemoTag({ label = "Demo Data" }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded border border-dashed border-info/40 bg-info/5 px-1.5 py-0.5 text-[10px] font-medium tracking-wide text-info uppercase">
      {label}
    </span>
  );
}

export function MetricBar({
  label,
  value,
  max = 100,
  tone = "info",
  suffix = "%",
}: {
  label: string;
  value: number;
  max?: number;
  tone?: Tone;
  suffix?: string;
}) {
  const t = toneClasses[tone] ?? toneClasses["info"]!;
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div>
      <div className="mb-1.5 flex items-baseline justify-between gap-3">
        <span className="truncate text-xs text-muted-foreground">{label}</span>
        <span className={cn("num text-xs font-semibold", t.text)}>
          {value}
          {suffix}
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-secondary">
        <div
          className={cn("h-full rounded-full transition-all duration-700", t.dot)}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

export function StatTile({
  label,
  value,
  hint,
  tone = "info",
  icon,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: Tone;
  icon?: ReactNode;
}) {
  const t = toneClasses[tone] ?? toneClasses["info"]!;
  return (
    <div className="panel p-4">
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs tracking-wide text-muted-foreground uppercase">{label}</p>
        {icon && <span className={cn("shrink-0", t.text)}>{icon}</span>}
      </div>
      <p className={cn("num mt-2 text-2xl font-semibold", t.text)}>{value}</p>
      {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}
