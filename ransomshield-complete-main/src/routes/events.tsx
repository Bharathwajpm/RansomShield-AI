import { useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Search } from "lucide-react";

import { useDemo } from "@/lib/demo-context";
import { getEvents } from "@/lib/mock-data";
import { Panel, PageHeader } from "@/components/common/Panel";
import { StatusPill, severityTone, DemoTag } from "@/components/common/indicators";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const title = "RansomShield AI — Security Events";
const description =
  "Raw endpoint telemetry collected from Windows Event Logs, Sysmon, psutil and watchdog collectors.";

export const Route = createFileRoute("/events")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
    ],
  }),
  component: EventsPage,
});

const sources = ["Windows Event Log", "Sysmon", "psutil", "watchdog"];
const severities = ["info", "low", "medium", "high", "critical"];

function EventsPage() {
  const { state } = useDemo();
  const events = getEvents(state);
  const [q, setQ] = useState("");
  const [source, setSource] = useState("all");
  const [sev, setSev] = useState("all");
  const [endpoint, setEndpoint] = useState("all");

  const endpoints = useMemo(
    () => Array.from(new Set(events.map((e) => e.endpoint))).sort(),
    [events],
  );

  const rows = events.filter((e) => {
    if (source !== "all" && e.source !== source) return false;
    if (sev !== "all" && e.severity !== sev) return false;
    if (endpoint !== "all" && e.endpoint !== endpoint) return false;
    if (q) {
      const text = `${e.type} ${e.endpoint} ${e.process} ${e.source}`.toLowerCase();
      if (!text.includes(q.toLowerCase())) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Events"
        description="Normalized telemetry stream from every collector feeding the detection pipeline."
      />

      <Panel
        title="Event Log"
        subtitle={`${rows.length} of ${events.length} events`}
        actions={<DemoTag />}
        bodyClassName="p-0"
      >
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-4">
          <div className="relative min-w-[220px] flex-1">
            <Search className="pointer-events-none absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search event, process, endpoint…"
              className="h-9 pl-9 text-sm"
            />
          </div>
          <Select value={source} onValueChange={setSource}>
            <SelectTrigger className="h-9 w-[190px] text-sm">
              <SelectValue placeholder="Source" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All sources</SelectItem>
              {sources.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={sev} onValueChange={setSev}>
            <SelectTrigger className="h-9 w-[150px] text-sm">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All severities</SelectItem>
              {severities.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={endpoint} onValueChange={setEndpoint}>
            <SelectTrigger className="h-9 w-[170px] text-sm">
              <SelectValue placeholder="Endpoint" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All endpoints</SelectItem>
              {endpoints.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {rows.length === 0 ? (
          <p className="p-8 text-center text-sm text-muted-foreground">
            No events match the current filters.
          </p>
        ) : (
          <div className="max-h-[640px] overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-surface/95 backdrop-blur">
                <tr className="border-b border-border text-left text-[11px] tracking-wider text-muted-foreground uppercase">
                  <th className="px-4 py-2.5">Timestamp</th>
                  <th className="px-4 py-2.5">Source</th>
                  <th className="px-4 py-2.5">Event</th>
                  <th className="px-4 py-2.5">Endpoint</th>
                  <th className="px-4 py-2.5">Process</th>
                  <th className="px-4 py-2.5">Severity</th>
                  <th className="px-4 py-2.5">Status</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id} className="border-b border-border/60 hover:bg-secondary/40">
                    <td className="num px-4 py-2.5 text-xs text-muted-foreground">{e.timestamp}</td>
                    <td className="px-4 py-2.5 text-muted-foreground">{e.source}</td>
                    <td className="px-4 py-2.5">
                      {e.type}
                      {e.detail && (
                        <span className="block text-xs text-muted-foreground">{e.detail}</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground">{e.endpoint}</td>
                    <td className="num px-4 py-2.5 text-xs text-muted-foreground">{e.process}</td>
                    <td className="px-4 py-2.5">
                      <StatusPill tone={severityTone(e.severity)}>{e.severity}</StatusPill>
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground">{e.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
