import { riskBand } from "@/lib/mock-data";
import { toneClasses } from "@/components/common/indicators";
import { cn } from "@/lib/utils";

export function RiskGauge({ score, size = 190 }: { score: number; size?: number }) {
  const band = riskBand(score);
  const tone = toneClasses[band.tone]!;
  const r = size / 2 - 14;
  const c = 2 * Math.PI * r;
  const offset = c - (Math.min(100, score) / 100) * c;

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            strokeWidth={12}
            className="stroke-secondary"
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            strokeWidth={12}
            strokeLinecap="round"
            strokeDasharray={c}
            strokeDashoffset={offset}
            className={cn("transition-all duration-700", tone.text)}
            stroke="currentColor"
          />
        </svg>
        <div className="absolute inset-0 grid place-content-center text-center">
          <p className={cn("num text-5xl font-semibold", tone.text)}>{score}</p>
          <p className={cn("text-[11px] font-semibold tracking-[0.2em]", tone.text)}>
            {band.label}
          </p>
        </div>
      </div>
      <div className="mt-3 grid w-full grid-cols-4 gap-1 text-center text-[10px] text-muted-foreground">
        {[
          ["0–30", "low"],
          ["31–60", "medium"],
          ["61–80", "high"],
          ["81–100", "critical"],
        ].map(([range, t]) => (
          <div
            key={range}
            className={cn(
              "rounded border border-transparent py-1",
              band.tone === t && cn(toneClasses[t as string]!.bg, toneClasses[t as string]!.text),
            )}
          >
            {range}
          </div>
        ))}
      </div>
    </div>
  );
}
