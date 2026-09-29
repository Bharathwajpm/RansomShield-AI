import type { ReactNode } from "react";
import { AppSidebar } from "./AppSidebar";
import { Topbar } from "./Topbar";

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 lg:block">
        <AppSidebar />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col lg:pl-64">
        <Topbar />
        <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8">{children}</main>
        <footer className="border-t border-border px-6 py-4 text-[11px] text-muted-foreground">
          RansomShield AI — academic research prototype. All telemetry, detections and response
          actions shown are simulated demonstration data; no real endpoints are monitored or
          modified.
        </footer>
      </div>
    </div>
  );
}
