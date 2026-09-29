import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { Bell, Building2, FlaskConical, Menu, Search, ShieldCheck, LogIn, LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { AppSidebar } from "./AppSidebar";
import { StatusPill } from "@/components/common/indicators";
import { useDemo } from "@/lib/demo-context";
import { useAuth } from "@/lib/auth-context";
import { getThreats } from "@/lib/mock-data";
import { cn } from "@/lib/utils";
import type { DemoState } from "@/lib/types";

const modes: { value: DemoState; label: string }[] = [
  { value: "SAFE", label: "Normal Activity" },
  { value: "WARNING", label: "Suspicious Activity" },
  { value: "CRITICAL", label: "Ransomware Attack" },
];

export function Topbar() {
  const { state, setState } = useDemo();
  const { user, logout, setAuthModalOpen } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const alerts = getThreats(state).slice(0, 4);

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-background/85 px-3 backdrop-blur-xl sm:px-5">
      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <SheetTrigger asChild>
          <Button variant="ghost" size="icon" className="lg:hidden">
            <Menu className="h-5 w-5" />
          </Button>
        </SheetTrigger>
        <SheetContent side="left" className="w-72 p-0">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <AppSidebar onNavigate={() => setMobileOpen(false)} />
        </SheetContent>
      </Sheet>

      <div className="relative hidden max-w-sm flex-1 md:block">
        <Search className="pointer-events-none absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search endpoints, threats, processes…"
          className="h-9 border-border bg-surface/70 pl-9 text-sm"
        />
      </div>

      <div className="ml-auto flex items-center gap-2 sm:gap-3">
        <span className="hidden items-center gap-1.5 rounded-md border border-border bg-surface/70 px-2.5 py-1.5 text-xs text-muted-foreground xl:inline-flex">
          <Building2 className="h-3.5 w-3.5" /> Northgate Textiles Ltd
        </span>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border border-dashed border-info/40 bg-info/10 px-2.5 py-1.5 text-[11px] font-semibold tracking-wide text-info uppercase",
              )}
            >
              <FlaskConical className="h-3.5 w-3.5" />
              Demo Mode: {modes.find((m) => m.value === state)?.label}
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel className="text-xs">Simulation state</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {modes.map((m) => (
              <DropdownMenuItem key={m.value} onClick={() => setState(m.value)}>
                {m.label}
              </DropdownMenuItem>
            ))}
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link to="/replay">Open Attack Replay</Link>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="relative">
              <Bell className="h-4.5 w-4.5" />
              {alerts.length > 0 && (
                <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-critical" />
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-80">
            <DropdownMenuLabel className="text-xs">Alert Center</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {alerts.map((a) => (
              <DropdownMenuItem key={a.id} asChild>
                <Link
                  to="/threats/$threatId"
                  params={{ threatId: a.id }}
                  className="flex-col items-start gap-1 py-2"
                >
                  <span className="flex w-full items-center justify-between gap-2">
                    <span className="text-xs font-semibold">{a.type}</span>
                    <StatusPill tone={a.severity}>{a.severity}</StatusPill>
                  </span>
                  <span className="text-[11px] text-muted-foreground">
                    {a.endpoint} · {a.process} · {a.confidence}%
                  </span>
                </Link>
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        <StatusPill tone="low" className="hidden sm:inline-flex">
          <ShieldCheck className="h-3 w-3" /> Protection Active
        </StatusPill>

        {user ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button className="flex items-center gap-2 rounded-md px-1.5 py-1 hover:bg-secondary/70">
                <span className="grid h-7 w-7 place-items-center rounded-full bg-secondary text-[11px] font-semibold text-foreground">
                  {(user.username || "US").slice(0, 2).toUpperCase()}
                </span>
                <span className="hidden text-left leading-tight sm:block">
                  <span className="block text-xs font-medium text-foreground">{user.full_name || user.username}</span>
                  <span className="block text-[10px] text-muted-foreground uppercase">{user.role}</span>
                </span>
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuLabel className="text-xs">
                Role: <span className="text-info font-medium">{user.role}</span>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem asChild>
                <Link to="/settings">Settings</Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link to="/architecture">System architecture</Link>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={logout} className="text-destructive focus:text-destructive cursor-pointer">
                <LogOut className="mr-2 h-3.5 w-3.5" />
                <span>Sign Out</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        ) : (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setAuthModalOpen(true)}
            className="flex items-center gap-1.5 text-xs h-8 px-2.5 border-info/40 text-info hover:bg-info/10"
          >
            <LogIn className="h-3.5 w-3.5" />
            <span>Sign In</span>
          </Button>
        )}
      </div>
    </header>
  );
}
