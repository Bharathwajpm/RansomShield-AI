import React, { useState } from "react";
import { Shield, Lock, User, AlertCircle, CheckCircle2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth, type UserRole } from "@/lib/auth-context";

export function LoginModal() {
  const { authModalOpen, setAuthModalOpen, login, isLoading, error, user } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) return;
    await login(username, password);
  };

  const handleQuickFill = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
  };

  return (
    <Dialog open={authModalOpen} onOpenChange={setAuthModalOpen}>
      <DialogContent className="sm:max-w-md border-border bg-card text-card-foreground">
        <DialogHeader className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-info/15 text-info">
              <Shield className="h-4 w-4" />
            </div>
            <DialogTitle className="text-lg font-semibold tracking-tight">
              RansomShield SOC Authentication
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-muted-foreground">
            Authenticate to access live telemetry feeds, security incidents, and operational controls.
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-2.5 text-xs text-destructive">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 pt-2">
          <div className="space-y-1.5">
            <Label htmlFor="username" className="text-xs font-medium">
              Username
            </Label>
            <div className="relative">
              <User className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                id="username"
                type="text"
                placeholder="e.g. admin or analyst"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="pl-9 text-xs"
                required
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="password" className="text-xs font-medium">
              Password
            </Label>
            <div className="relative">
              <Lock className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                id="password"
                type="password"
                placeholder="Enter account password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="pl-9 text-xs"
                required
              />
            </div>
          </div>

          <div className="pt-1">
            <Button
              type="submit"
              disabled={isLoading}
              className="w-full bg-info/20 text-info hover:bg-info/30 border border-info/30 text-xs font-medium h-9"
            >
              {isLoading ? "Authenticating..." : "Sign In to SOC Console"}
            </Button>
          </div>
        </form>

        <div className="mt-4 border-t border-border/60 pt-3">
          <p className="text-[11px] font-medium text-muted-foreground mb-2">Quick-Fill Accounts:</p>
          <div className="grid grid-cols-3 gap-1.5">
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="text-[10px] h-7 px-2"
              onClick={() => handleQuickFill("admin", "admin123")}
            >
              Admin
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="text-[10px] h-7 px-2"
              onClick={() => handleQuickFill("analyst", "analyst123")}
            >
              Analyst
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="text-[10px] h-7 px-2"
              onClick={() => handleQuickFill("viewer", "viewer123")}
            >
              Viewer
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
