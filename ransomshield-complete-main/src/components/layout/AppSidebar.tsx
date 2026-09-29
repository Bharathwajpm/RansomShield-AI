import { Link } from "@tanstack/react-router";
import {
  Activity,
  Bot,
  Cpu,
  Database,
  FileBarChart,
  Gauge,
  LayoutDashboard,
  Monitor,
  Network,
  PlayCircle,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Table2,
} from "lucide-react";
import { cn } from "@/lib/utils";

const nav = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/monitoring", label: "Live Monitoring", icon: Activity },
  { to: "/endpoints", label: "Endpoints", icon: Monitor },
  { to: "/threats", label: "Threats", icon: ShieldAlert },
  { to: "/events", label: "Events", icon: Table2 },
  { to: "/ai", label: "AI Detection", icon: Bot },
  { to: "/incidents", label: "Incident Investigation", icon: Search },
  { to: "/replay", label: "Attack Replay", icon: PlayCircle },
  { to: "/reports", label: "Reports", icon: FileBarChart },
  { to: "/architecture", label: "Architecture", icon: Network },
  { to: "/training", label: "Training Data", icon: Cpu },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

const systemStatus = [
  { label: "Monitoring Agent", value: "Online" },
  { label: "AI Model", value: "Active" },
  { label: "Database", value: "Connected" },
  { label: "Protection", value: "Active" },
];

export function AppSidebar({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <div className="flex h-full flex-col border-r border-border bg-surface/60 backdrop-blur-xl">
      <div className="flex items-center gap-2.5 px-5 py-4">
        <span className="grid h-9 w-9 place-items-center rounded-lg bg-info/15 text-info ring-1 ring-info/30">
          <ShieldCheck className="h-5 w-5" />
        </span>
        <div className="leading-tight">
          <p className="text-sm font-semibold tracking-tight">RansomShield AI</p>
          <p className="text-[10px] tracking-wider text-muted-foreground uppercase">
            SME Ransomware Defense
          </p>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-2">
        {nav.map((item) => (
          <Link
            key={item.to}
            to={item.to}
            onClick={onNavigate}
            activeOptions={{ exact: item.to === "/" }}
            className="group flex items-center gap-3 rounded-md px-3 py-2 text-[13px] text-muted-foreground transition-colors hover:bg-secondary/70 hover:text-foreground"
            activeProps={{
              className: cn("bg-info/10 text-foreground ring-1 ring-inset ring-info/25"),
            }}
          >
            <item.icon className="h-4 w-4 shrink-0" />
            <span className="truncate">{item.label}</span>
          </Link>
        ))}
      </nav>

      <div className="m-3 rounded-lg border border-border bg-background/40 p-3">
        <p className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold tracking-wider text-muted-foreground uppercase">
          <Gauge className="h-3 w-3" /> System Status
        </p>
        <ul className="space-y-1.5">
          {systemStatus.map((s) => (
            <li key={s.label} className="flex items-center justify-between text-[11px]">
              <span className="flex items-center gap-1.5 text-muted-foreground">
                <span className="h-1.5 w-1.5 rounded-full bg-safe" />
                {s.label}
              </span>
              <span className="font-medium text-safe">{s.value}</span>
            </li>
          ))}
        </ul>
        <p className="mt-2.5 flex items-center gap-1 border-t border-border pt-2 text-[10px] text-muted-foreground">
          <Database className="h-3 w-3" /> Last data 2 s ago · prototype feed
        </p>
      </div>
    </div>
  );
}
