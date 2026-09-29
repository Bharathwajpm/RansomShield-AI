import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Gauge } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag, LiveDot } from "@/components/common/indicators";
import { getVelocitySeries, getVelocityStats } from "@/lib/mock-data";
import type { DemoState } from "@/lib/types";

const tooltipStyle = {
  background: "var(--popover)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  fontSize: 12,
  color: "var(--popover-foreground)",
};

export function FileVelocityChart({ state }: { state: DemoState }) {
  const data = getVelocitySeries(state);
  const stats = getVelocityStats(state);

  return (
    <Panel
      title="File Activity Velocity"
      subtitle="Behavioral indicator — file operations per minute"
      icon={<Gauge className="h-4 w-4" />}
      actions={
        <div className="flex items-center gap-3">
          <DemoTag />
          <LiveDot tone={state === "CRITICAL" ? "critical" : "low"} />
        </div>
      }
    >
      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {stats.map((s) => (
          <div key={s.label} className="rounded-lg border border-border bg-background/40 p-3">
            <p className="text-[10px] tracking-wide text-muted-foreground uppercase">{s.label}</p>
            <p className="num mt-1 text-lg font-semibold">{s.value.toLocaleString()}</p>
          </div>
        ))}
      </div>

      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
            <defs>
              <linearGradient id="gMod" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--info)" stopOpacity={0.5} />
                <stop offset="100%" stopColor="var(--info)" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gEnc" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--critical)" stopOpacity={0.5} />
                <stop offset="100%" stopColor="var(--critical)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
            <XAxis
              dataKey="t"
              tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
              minTickGap={40}
            />
            <YAxis tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} width={54} />
            <Tooltip contentStyle={tooltipStyle} />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            <ReferenceLine
              y={60}
              stroke="var(--warn)"
              strokeDasharray="4 4"
              label={{
                value: "Warning zone",
                fill: "var(--warn)",
                fontSize: 10,
                position: "insideTopLeft",
              }}
            />
            <ReferenceLine
              y={500}
              stroke="var(--critical)"
              strokeDasharray="4 4"
              label={{
                value: "Critical zone",
                fill: "var(--critical)",
                fontSize: 10,
                position: "insideTopLeft",
              }}
            />
            <Area
              type="monotone"
              dataKey="modified"
              name="Modified"
              stroke="var(--info)"
              fill="url(#gMod)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="encrypted"
              name="Encryption-like"
              stroke="var(--critical)"
              fill="url(#gEnc)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="renamed"
              name="Renamed"
              stroke="var(--warn)"
              fill="transparent"
              strokeWidth={1.5}
            />
            <Area
              type="monotone"
              dataKey="deleted"
              name="Deleted"
              stroke="var(--muted-foreground)"
              fill="transparent"
              strokeWidth={1.5}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Panel>
  );
}
