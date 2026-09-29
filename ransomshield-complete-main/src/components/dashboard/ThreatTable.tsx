import { useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import { Search, ShieldAlert } from "lucide-react";
import { Panel } from "@/components/common/Panel";
import { DemoTag, StatusPill, severityTone } from "@/components/common/indicators";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { getThreats } from "@/lib/mock-data";
import type { DemoState } from "@/lib/types";

const statusTone: Record<string, "low" | "medium" | "high" | "info"> = {
  Blocked: "low",
  Investigating: "high",
  Monitoring: "medium",
  Resolved: "info",
};

export function ThreatTable({ state }: { state: DemoState }) {
  const threats = getThreats(state);
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("all");
  const [status, setStatus] = useState("all");
  const [endpoint, setEndpoint] = useState("all");

  const endpoints = useMemo(
    () => Array.from(new Set(threats.map((t) => t.endpoint))).sort(),
    [threats],
  );

  const rows = threats.filter((t) => {
    const text = `${t.id} ${t.endpoint} ${t.process} ${t.type}`.toLowerCase();
    if (q && !text.includes(q.toLowerCase())) return false;
    if (sev !== "all" && t.severity !== sev) return false;
    if (status !== "all" && t.status !== status) return false;
    if (endpoint !== "all" && t.endpoint !== endpoint) return false;
    return true;
  });

  return (
    <Panel
      title="Detected Threats"
      subtitle="Behavioral detections raised by the XGBoost classifier"
      icon={<ShieldAlert className="h-4 w-4" />}
      actions={<DemoTag />}
      bodyClassName="p-0"
    >
      <div className="flex flex-wrap items-center gap-2 border-b border-border p-4">
        <div className="relative min-w-[200px] flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            aria-label="Search threats"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search threat, endpoint or process…"
            className="h-9 bg-background/50 pl-9 text-sm"
          />
        </div>
        <Select value={sev} onValueChange={setSev}>
          <SelectTrigger className="h-9 w-[140px] text-xs" aria-label="Severity filter">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger className="h-9 w-[150px] text-xs" aria-label="Status filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="Blocked">Blocked</SelectItem>
            <SelectItem value="Investigating">Investigating</SelectItem>
            <SelectItem value="Monitoring">Monitoring</SelectItem>
            <SelectItem value="Resolved">Resolved</SelectItem>
          </SelectContent>
        </Select>
        <Select value={endpoint} onValueChange={setEndpoint}>
          <SelectTrigger className="h-9 w-[160px] text-xs" aria-label="Endpoint filter">
            <SelectValue placeholder="Endpoint" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All endpoints</SelectItem>
            {endpoints.map((e) => (
              <SelectItem key={e} value={e}>
                {e}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[980px] text-sm">
          <caption className="sr-only">Detected ransomware and anomaly threats</caption>
          <thead>
            <tr className="border-b border-border text-[11px] tracking-wider text-muted-foreground uppercase">
              <th scope="col" className="px-4 py-2.5 text-left font-medium">
                Threat ID
              </th>
              <th scope="col" className="px-4 py-2.5 text-left font-medium">
                Endpoint
              </th>
              <th scope="col" className="px-4 py-2.5 text-left font-medium">
                Process
              </th>
              <th scope="col" className="px-4 py-2.5 text-left font-medium">
                Type
              </th>
              <th scope="col" className="px-4 py-2.5 text-left font-medium">
                Severity
              </th>
              <th scope="col" className="px-4 py-2.5 text-right font-medium">
                Confidence
              </th>
              <th scope="col" className="px-4 py-2.5 text-left font-medium">
                Detected
              </th>
              <th scope="col" className="px-4 py-2.5 text-left font-medium">
                Status
              </th>
              <th scope="col" className="px-4 py-2.5 text-right font-medium">
                Files
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => (
              <tr
                key={t.id}
                className="border-b border-border/60 transition-colors hover:bg-secondary/40"
              >
                <td className="px-4 py-2.5">
                  <Link
                    to="/threats/$threatId"
                    params={{ threatId: t.id }}
                    className="num font-semibold text-info underline-offset-4 hover:underline focus-visible:ring-2 focus-visible:ring-info/60 focus-visible:outline-none"
                  >
                    {t.id}
                  </Link>
                </td>
                <td className="px-4 py-2.5">{t.endpoint}</td>
                <td className="num px-4 py-2.5 text-xs">{t.process}</td>
                <td className="px-4 py-2.5">{t.type}</td>
                <td className="px-4 py-2.5">
                  <StatusPill tone={severityTone(t.severity)}>{t.severity}</StatusPill>
                </td>
                <td className="num px-4 py-2.5 text-right">{t.confidence}%</td>
                <td className="num px-4 py-2.5 text-xs text-muted-foreground">{t.detectedAt}</td>
                <td className="px-4 py-2.5">
                  <StatusPill tone={statusTone[t.status] ?? "info"} dot={false}>
                    {t.status}
                  </StatusPill>
                </td>
                <td className="num px-4 py-2.5 text-right">{t.filesAffected}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={9} className="px-4 py-10 text-center text-sm text-muted-foreground">
                  No threats match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
