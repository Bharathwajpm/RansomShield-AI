import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { toast } from "sonner";

import { Panel, PageHeader } from "@/components/common/Panel";
import { DemoTag } from "@/components/common/indicators";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";

const title = "RansomShield AI — Settings";
const description =
  "Prototype configuration for monitoring collectors, AI detection thresholds, response policy, notifications and the endpoint agent.";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
    ],
  }),
  component: SettingsPage,
});

const toggleGroups = [
  {
    section: "Monitoring",
    subtitle: "Telemetry collectors feeding the detection pipeline",
    items: [
      {
        key: "wel",
        label: "Windows Event Logs",
        detail: "Logon, service and process events",
        on: true,
      },
      {
        key: "sysmon",
        label: "Sysmon",
        detail: "Process, network and registry telemetry",
        on: true,
      },
      {
        key: "psutil",
        label: "psutil resource sampling",
        detail: "CPU, memory and I/O sampling",
        on: true,
      },
      {
        key: "watchdog",
        label: "watchdog file monitoring",
        detail: "File create / modify / rename events",
        on: true,
      },
    ],
  },
  {
    section: "Response",
    subtitle: "Automated containment policy (simulated)",
    items: [
      {
        key: "terminate",
        label: "Auto-terminate process",
        detail: "On CRITICAL classification",
        on: true,
      },
      {
        key: "quarantine",
        label: "Auto-quarantine binary",
        detail: "Move to encrypted store",
        on: true,
      },
      {
        key: "isolate",
        label: "Auto-isolate endpoint",
        detail: "Restrict to management channel",
        on: false,
      },
      {
        key: "evidence",
        label: "Collect evidence",
        detail: "Process tree and file snapshot",
        on: true,
      },
    ],
  },
  {
    section: "Notifications",
    subtitle: "Where alerts are delivered",
    items: [
      { key: "email", label: "Email alerts", detail: "security@sme.example", on: true },
      {
        key: "dashboard",
        label: "Dashboard alerts",
        detail: "In-console toast + banner",
        on: true,
      },
      { key: "digest", label: "Daily digest", detail: "Summary of detections", on: false },
    ],
  },
  {
    section: "Agent",
    subtitle: "Endpoint monitoring agent behaviour",
    items: [
      {
        key: "autoupdate",
        label: "Automatic agent updates",
        detail: "Roll out new agent builds",
        on: true,
      },
      {
        key: "offline",
        label: "Offline buffering",
        detail: "Cache telemetry when unreachable",
        on: true,
      },
      { key: "verbose", label: "Verbose logging", detail: "Increases disk usage", on: false },
    ],
  },
];

function SettingsPage() {
  const [values, setValues] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(toggleGroups.flatMap((g) => g.items.map((i) => [i.key, i.on]))),
  );
  const [threshold, setThreshold] = useState(75);
  const [interval, setIntervalValue] = useState(5);
  const [recipient, setRecipient] = useState("security@sme.example");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Prototype configuration surface. These controls illustrate the intended product behaviour only."
        actions={
          <Button
            variant="secondary"
            onClick={() => toast.info("Saving settings is a prototype action.")}
          >
            Save changes
          </Button>
        }
      />

      <p className="rounded-md border border-warn/30 bg-warn/10 p-3 text-xs text-warn">
        These settings are simulated. They do not modify Windows security policy, real endpoints or
        any live agent configuration.
      </p>

      <Panel
        title="Monitoring"
        subtitle={toggleGroups[0]!.subtitle}
        actions={<DemoTag label="Prototype Setting" />}
      >
        <div className="space-y-4">
          {toggleGroups[0]!.items.map((i) => (
            <Row
              key={i.key}
              label={i.label}
              detail={i.detail}
              checked={values[i.key] ?? false}
              onChange={(v) => setValues((s) => ({ ...s, [i.key]: v }))}
            />
          ))}
          <div className="border-t border-border pt-4">
            <Label className="text-xs text-muted-foreground">
              Telemetry sampling interval — {interval}s
            </Label>
            <Slider
              className="mt-3"
              value={[interval]}
              min={1}
              max={60}
              step={1}
              onValueChange={([v]) => setIntervalValue(v ?? 5)}
            />
          </div>
        </div>
      </Panel>

      <Panel
        title="AI Detection"
        subtitle="Classification thresholds"
        actions={<DemoTag label="Prototype Setting" />}
      >
        <Label className="text-xs text-muted-foreground">
          Ransomware classification threshold — {threshold}% confidence
        </Label>
        <Slider
          className="mt-3"
          value={[threshold]}
          min={40}
          max={99}
          step={1}
          onValueChange={([v]) => setThreshold(v ?? 75)}
        />
        <p className="mt-3 text-xs text-muted-foreground">
          Detections below this confidence are recorded as SUSPICIOUS and do not trigger automated
          containment.
        </p>
      </Panel>

      {toggleGroups.slice(1).map((g) => (
        <Panel
          key={g.section}
          title={g.section}
          subtitle={g.subtitle}
          actions={<DemoTag label="Prototype Setting" />}
        >
          <div className="space-y-4">
            {g.items.map((i) => (
              <Row
                key={i.key}
                label={i.label}
                detail={i.detail}
                checked={values[i.key] ?? false}
                onChange={(v) => setValues((s) => ({ ...s, [i.key]: v }))}
              />
            ))}
            {g.section === "Notifications" && (
              <div className="border-t border-border pt-4">
                <Label className="text-xs text-muted-foreground">Alert recipient</Label>
                <Input
                  value={recipient}
                  onChange={(e) => setRecipient(e.target.value)}
                  className="mt-2 h-9 max-w-sm text-sm"
                />
              </div>
            )}
          </div>
        </Panel>
      ))}
    </div>
  );
}

function Row({
  label,
  detail,
  checked,
  onChange,
}: {
  label: string;
  detail: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="min-w-0">
        <p className="text-sm text-foreground">{label}</p>
        <p className="text-xs text-muted-foreground">{detail}</p>
      </div>
      <Switch checked={checked} onCheckedChange={onChange} />
    </div>
  );
}
