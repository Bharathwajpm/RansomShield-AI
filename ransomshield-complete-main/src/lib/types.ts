export type DemoState = "SAFE" | "WARNING" | "CRITICAL";

export type Severity = "low" | "medium" | "high" | "critical";

export type EarlyWarning = "NORMAL" | "SUSPICIOUS" | "POSSIBLE" | "DETECTED";

export type SystemStatus = "PROTECTED" | "WARNING" | "HIGH RISK" | "CRITICAL";

export interface SystemStatusPayload {
  status: SystemStatus;
  headline: string;
  riskScore: number;
  protection: "ACTIVE" | "DEGRADED";
  lastUpdatedSeconds: number;
  earlyWarning: EarlyWarning;
}

export interface HealthBreakdown {
  label: string;
  value: number;
}

export interface RiskContribution {
  label: string;
  value: number;
}

export interface Endpoint {
  id: string;
  name: string;
  user: string;
  os: string;
  agentStatus: "online" | "offline";
  lastHeartbeat: string;
  cpu: number;
  memory: number;
  disk: number;
  network: number;
  processes: number;
  riskScore: number;
  severity: Severity | "offline";
  department: string;
  behavior: {
    fileActivity: number;
    processActivity: number;
    networkActivity: number;
    registryActivity: number;
  };
  threatHistory: { date: string; threats: number }[];
}

export interface ProcessRow {
  name: string;
  pid: number;
  cpu: number;
  memory: number;
  fileActivity: number;
  networkActivity: number;
  risk: Severity;
  path: string;
  signed: boolean;
  parent: string;
}

export interface Threat {
  id: string;
  endpoint: string;
  process: string;
  type: string;
  severity: Severity;
  confidence: number;
  detectedAt: string;
  status: "Blocked" | "Investigating" | "Monitoring" | "Resolved";
  summary: string;
  filesAffected: number;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  source: "Windows Event Log" | "Sysmon" | "psutil" | "watchdog";
  type: string;
  endpoint: string;
  process: string;
  severity: Severity | "info";
  status: "Logged" | "Flagged" | "Blocked";
  detail?: string | undefined;
}

export interface AiIndicator {
  label: string;
  weight: number;
}

export interface AiPrediction {
  prediction: "BENIGN" | "SUSPICIOUS" | "RANSOMWARE";
  confidence: number;
  indicators: AiIndicator[];
  explanation: string;
  stage: number;
}

export interface VelocityPoint {
  t: string;
  modified: number;
  renamed: number;
  deleted: number;
  encrypted: number;
}

export interface BaselineRow {
  metric: string;
  normal: number;
  current: number;
  unit: string;
}

export interface TimelineStep {
  time: string;
  title: string;
  detail: string;
  severity: Severity | "info";
}

export interface AuditEntry {
  actor: string;
  action: string;
  endpoint: string;
  timestamp: string;
  result: "Success" | "Failed";
}

export type ResponseActionType =
  | "TERMINATE_PROCESS"
  | "QUARANTINE_FILE"
  | "ISOLATE_NETWORK"
  | "RELEASE_NETWORK_ISOLATION";

export type ResponseActionStatus =
  | "PENDING"
  | "APPROVED"
  | "IN_PROGRESS"
  | "SUCCESS"
  | "FAILED"
  | "CANCELLED"
  | "REFUSED";

export interface ResponseAction {
  action_id: string;
  agent_id: string;
  action_type: ResponseActionType;
  target: string;
  parameters: Record<string, any>;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  dry_run: boolean;
  requires_approval: boolean;
  created_by: string;
  approved_by?: string | null;
  status: ResponseActionStatus;
  verification_status: "UNVERIFIED" | "VERIFIED_SUCCESS" | "VERIFIED_FAILURE";
  created_at: number;
  executed_at?: number | null;
  result?: {
    status: ResponseActionStatus;
    verification_status: string;
    execution_time_ms: number;
    message: string;
    details: Record<string, any>;
  } | null;
  error_message?: string | null;
}

export interface ResponseAuditLog {
  log_id: string;
  action_id: string;
  agent_id: string;
  action_type: string;
  actor: string;
  event: string;
  details: Record<string, any>;
  timestamp: number;
}
