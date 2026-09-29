import { useState, useEffect, useCallback } from "react";
import { CheckCircle2, Shield, Zap, AlertTriangle, Play, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { Panel } from "@/components/common/Panel";
import { DemoTag, StatusPill, toneClasses } from "@/components/common/indicators";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { responseActions, responsePolicy } from "@/lib/mock-data";
import { cn } from "@/lib/utils";
import { api, subscribeToStream } from "@/services/api";
import { useAuth } from "@/lib/auth-context";
import type { ResponseAction } from "@/lib/types";

export function ResponseCenter({ autoExecuted = false }: { autoExecuted?: boolean }) {
  const { user } = useAuth();
  const isViewer = user?.role === "VIEWER";

  const [liveActions, setLiveActions] = useState<ResponseAction[]>([]);
  const [selectedAction, setSelectedAction] = useState<typeof responseActions[0] | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [done, setDone] = useState<string[]>(
    autoExecuted ? ["Terminate Process", "Quarantine File", "Notify Administrator"] : [],
  );

  const fetchActions = useCallback(async () => {
    try {
      const data = await api.getResponseActions(20);
      setLiveActions(data);
    } catch {
      // Fallback cleanly without breaking UI
    }
  }, []);

  useEffect(() => {
    fetchActions();

    // Subscribe to live WebSocket updates
    const unsubscribe = subscribeToStream((event: any) => {
      if (event && (event.type === "response.created" || event.type === "response.updated")) {
        fetchActions();
      }
    });

    return () => {
      unsubscribe();
    };
  }, [fetchActions]);

  const mapActionToParams = (actionName: string) => {
    switch (actionName) {
      case "Terminate Process":
        return {
          action_type: "TERMINATE_PROCESS",
          target: "9184",
          parameters: { pid: 9184, process_name: "invoice_update.exe" },
          risk_level: "CRITICAL",
        };
      case "Quarantine File":
        return {
          action_type: "QUARANTINE_FILE",
          target: "C:\\Users\\a.novak\\Downloads\\invoice_update.exe",
          parameters: { file_path: "C:\\Users\\a.novak\\Downloads\\invoice_update.exe" },
          risk_level: "HIGH",
        };
      case "Isolate Endpoint":
        return {
          action_type: "ISOLATE_NETWORK",
          target: "endpoint",
          parameters: { backend_host: "127.0.0.1", backend_port: 8000 },
          risk_level: "CRITICAL",
          requires_approval: true,
        };
      case "Block Process":
        return {
          action_type: "TERMINATE_PROCESS",
          target: "7314",
          parameters: { pid: 7314, process_name: "backup_sync.exe" },
          risk_level: "MEDIUM",
        };
      default:
        return {
          action_type: "TERMINATE_PROCESS",
          target: "9184",
          parameters: { process_name: actionName },
          risk_level: "MEDIUM",
        };
    }
  };

  const handleOpenModal = (action: typeof responseActions[0]) => {
    if (isViewer) {
      toast.error("Access Forbidden", {
        description: "Viewers cannot execute containment actions. Contact an Analyst or Administrator.",
      });
      return;
    }
    setSelectedAction(action);
    setModalOpen(true);
  };

  const handleExecuteAction = async () => {
    if (!selectedAction) return;
    setExecuting(true);

    const params = mapActionToParams(selectedAction.name);

    try {
      const result = await api.createResponseAction({
        ...params,
        dry_run: true,
        auto_execute: true,
      });

      setDone((prev) => [...prev, selectedAction.name]);
      setModalOpen(false);

      if (result.status === "SUCCESS") {
        toast.success(`${selectedAction.name} Executed`, {
          description: `Result: ${result.result?.message || "Verified successfully"} (Dry Run: Safe Simulation)`,
        });
      } else if (result.status === "PENDING") {
        toast.info(`${selectedAction.name} Pending Approval`, {
          description: "This high-risk action requires a second analyst's approval.",
        });
      } else if (result.status === "REFUSED") {
        toast.warning(`${selectedAction.name} Refused`, {
          description: result.error_message || "Action blocked by safety invariants.",
        });
      } else {
        toast.error(`${selectedAction.name} Failed`, {
          description: result.error_message || "Execution encountered an error.",
        });
      }

      await fetchActions();
    } catch (err: any) {
      toast.error("Execution Error", {
        description: err.message || "Failed to communicate with response engine.",
      });
    } finally {
      setExecuting(false);
    }
  };

  return (
    <Panel
      title="Automated Response Center"
      subtitle="Policy-driven containment actions & verification"
      icon={<Zap className="h-4 w-4" />}
      actions={<DemoTag label="Dry Run Active" />}
      className="h-full"
    >
      <ul className="space-y-2">
        {responseActions.map((a) => {
          const executed = done.includes(a.name);
          return (
            <li
              key={a.name}
              className="flex items-center justify-between gap-3 rounded-lg border border-border bg-background/40 px-3 py-2.5"
            >
              <div className="min-w-0">
                <p className="flex items-center gap-2 text-sm font-medium">
                  {executed && <CheckCircle2 className="h-3.5 w-3.5 text-safe" />}
                  {a.name}
                </p>
                <p className="truncate text-[11px] text-muted-foreground">{a.detail}</p>
              </div>
              <Button
                size="sm"
                variant={executed ? "ghost" : "secondary"}
                className="h-7 shrink-0 px-3 text-xs"
                disabled={executed || isViewer}
                onClick={() => handleOpenModal(a)}
                title={isViewer ? "Viewers cannot execute containment actions" : "Execute response action"}
              >
                {executed ? "Executed" : "Run"}
              </Button>
            </li>
          );
        })}
      </ul>

      {/* Safety Confirmation Dialog */}
      <Dialog open={modalOpen} onOpenChange={setModalOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-foreground">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              Confirm Containment Action
            </DialogTitle>
            <DialogDescription className="text-muted-foreground text-xs">
              Review action details and defensive safeguards before initiating execution.
            </DialogDescription>
          </DialogHeader>

          {selectedAction && (
            <div className="space-y-3 py-2 text-xs">
              <div className="rounded-md border border-border bg-muted/40 p-3 space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Action:</span>
                  <span className="font-semibold text-foreground">{selectedAction.name}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Target:</span>
                  <span className="font-mono text-foreground">
                    {selectedAction.name === "Terminate Process"
                      ? "PID 9184 (invoice_update.exe)"
                      : selectedAction.name === "Quarantine File"
                        ? "invoice_update.exe"
                        : "Endpoint Network"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Execution Mode:</span>
                  <span className="font-semibold text-safe">Dry Run (Safe Simulation)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Audit Record:</span>
                  <span className="text-muted-foreground">Append-only MongoDB</span>
                </div>
              </div>

              <p className="text-[11px] text-muted-foreground leading-relaxed">
                Notice: Protected OS processes and critical binaries are automatically safeguarded. All containment
                operations produce cryptographic verification traces.
              </p>
            </div>
          )}

          <DialogFooter className="flex gap-2 sm:justify-end">
            <Button variant="ghost" size="sm" onClick={() => setModalOpen(false)} disabled={executing}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleExecuteAction}
              disabled={executing}
              className="gap-1.5"
            >
              {executing ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              {executing ? "Verifying..." : "Confirm & Execute"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <p className="mt-5 mb-2 flex items-center gap-1.5 text-[10px] font-semibold tracking-wider text-muted-foreground uppercase">
        <Shield className="h-3 w-3" /> Response Policy
      </p>
      <ul className="space-y-1.5">
        {responsePolicy.map((p) => (
          <li
            key={p.risk}
            className={cn(
              "flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs",
              toneClasses[p.tone]!.border,
              toneClasses[p.tone]!.bg,
            )}
          >
            <span className={cn("num font-semibold", toneClasses[p.tone]!.text)}>{p.risk}</span>
            <span className="text-foreground">{p.action}</span>
            <span className="w-full text-[11px] text-muted-foreground sm:w-auto">{p.detail}</span>
          </li>
        ))}
      </ul>
      <StatusPill tone="info" className="mt-4" dot={false}>
        Defensive safeguards and dry-run active
      </StatusPill>
    </Panel>
  );
}
