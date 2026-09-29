import { FolderLock } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag } from "@/components/common/indicators";
import { getFileImpact } from "@/lib/mock-data";
import type { DemoState } from "@/lib/types";

export function FileImpact({ state }: { state: DemoState }) {
  const impact = getFileImpact(state);
  const max = Math.max(1, ...impact.categories.map((c) => c.value));

  return (
    <Panel
      title="Potential File Impact"
      subtitle="Scope estimate for the current behavior"
      icon={<FolderLock className="h-4 w-4" />}
      actions={<DemoTag label="Prototype Estimate" />}
      className="h-full"
    >
      <div className="grid grid-cols-3 gap-3">
        <div>
          <p className="text-[10px] tracking-wider text-muted-foreground uppercase">Affected</p>
          <p className="num text-xl font-semibold text-critical">
            {impact.affected.toLocaleString()}
          </p>
        </div>
        <div>
          <p className="text-[10px] tracking-wider text-muted-foreground uppercase">
            Est. protected
          </p>
          <p className="num text-xl font-semibold text-safe">{impact.protected.toLocaleString()}</p>
        </div>
        <div>
          <p className="text-[10px] tracking-wider text-muted-foreground uppercase">Est. damage</p>
          <p className="num text-xl font-semibold text-warn">{impact.damage}</p>
        </div>
      </div>

      <ul className="mt-4 space-y-2.5">
        {impact.categories.map((c) => (
          <li key={c.name}>
            <div className="mb-1 flex justify-between text-xs">
              <span className="text-muted-foreground">{c.name}</span>
              <span className="num">{c.value.toLocaleString()}</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-secondary">
              <div
                className="h-full rounded-full bg-info transition-all duration-700"
                style={{ width: `${(c.value / max) * 100}%` }}
              />
            </div>
          </li>
        ))}
      </ul>
      <p className="mt-3 text-[11px] text-muted-foreground">
        Estimates are illustrative only and are not measured protection guarantees.
      </p>
    </Panel>
  );
}
