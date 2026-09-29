import type {
  AiPrediction,
  AuditEntry,
  BaselineRow,
  DemoState,
  Endpoint,
  HealthBreakdown,
  ProcessRow,
  RiskContribution,
  SecurityEvent,
  Severity,
  SystemStatusPayload,
  Threat,
  TimelineStep,
  VelocityPoint,
} from "./types";

/**
 * Centralized DEMO / SIMULATION data engine.
 * Every value returned here is synthetic prototype data.
 * Replace these functions with real API calls (see src/services/api.ts)
 * once the Python monitoring agent + FastAPI backend are connected.
 */

const pad = (n: number) => n.toString().padStart(2, "0");

export function clockAt(offsetSeconds = 0) {
  const base = new Date(2026, 0, 14, 10, 42, 31);
  base.setSeconds(base.getSeconds() + offsetSeconds);
  return `${pad(base.getHours())}:${pad(base.getMinutes())}:${pad(base.getSeconds())}`;
}

/* ------------------------------------------------------------------ status */

export function getSystemStatus(state: DemoState): SystemStatusPayload {
  switch (state) {
    case "SAFE":
      return {
        status: "PROTECTED",
        headline: "No active ransomware threats detected",
        riskScore: 8,
        protection: "ACTIVE",
        lastUpdatedSeconds: 2,
        earlyWarning: "NORMAL",
      };
    case "WARNING":
      return {
        status: "WARNING",
        headline: "Suspicious behavior observed on 1 endpoint",
        riskScore: 58,
        protection: "ACTIVE",
        lastUpdatedSeconds: 1,
        earlyWarning: "SUSPICIOUS",
      };
    case "CRITICAL":
      return {
        status: "CRITICAL",
        headline: "Ransomware-like behavior detected — response executed",
        riskScore: 98,
        protection: "ACTIVE",
        lastUpdatedSeconds: 1,
        earlyWarning: "DETECTED",
      };
  }
}

export function riskBand(score: number): { label: string; tone: Severity } {
  if (score <= 30) return { label: "LOW", tone: "low" };
  if (score <= 60) return { label: "MEDIUM", tone: "medium" };
  if (score <= 80) return { label: "HIGH", tone: "high" };
  return { label: "CRITICAL", tone: "critical" };
}

export function getRiskContributions(state: DemoState): RiskContribution[] {
  const f = state === "SAFE" ? 0.1 : state === "WARNING" ? 0.55 : 0.96;
  return [
    { label: "Process anomalies", value: Math.round(100 * f * 0.98) },
    { label: "File activity", value: Math.round(100 * f) },
    { label: "Encryption-like activity", value: Math.round(100 * f * 0.94) },
    { label: "CPU anomalies", value: Math.round(100 * f * 0.86) },
    { label: "Registry activity", value: Math.round(100 * f * 0.62) },
    { label: "Network anomalies", value: Math.round(100 * f * 0.58) },
  ];
}

export function getHealthScore(state: DemoState): { score: number; breakdown: HealthBreakdown[] } {
  const penalty = state === "SAFE" ? 0 : state === "WARNING" ? 9 : 22;
  const breakdown: HealthBreakdown[] = [
    { label: "Endpoint Protection", value: 92 - penalty },
    { label: "Monitoring Coverage", value: 95 - Math.round(penalty / 3) },
    { label: "Threat Detection", value: 89 - Math.round(penalty / 2) },
    { label: "Patch / Software Health", value: 76 - Math.round(penalty / 4) },
    { label: "Incident Response", value: 84 - Math.round(penalty / 2) },
  ];
  const score = Math.round(breakdown.reduce((a, b) => a + b.value, 0) / breakdown.length);
  return { score, breakdown };
}

/* --------------------------------------------------------- early warning */

export function getEarlyWarningIndicators(state: DemoState) {
  if (state === "SAFE")
    return {
      message: "Endpoint behavior matches the learned baseline",
      indicators: [
        { label: "File modification rate", value: "↑ 4%", tone: "low" as Severity },
        { label: "Encryption-like activity", value: "NONE", tone: "low" as Severity },
        { label: "Process anomaly", value: "LOW", tone: "low" as Severity },
        { label: "Network anomaly", value: "LOW", tone: "low" as Severity },
      ],
      confidence: 3.1,
    };
  if (state === "WARNING")
    return {
      message: "Unusual file and process activity observed",
      indicators: [
        { label: "File modification rate", value: "↑ 120%", tone: "medium" as Severity },
        { label: "Encryption-like activity", value: "LOW", tone: "medium" as Severity },
        { label: "Process anomaly", value: "MEDIUM", tone: "medium" as Severity },
        { label: "Network anomaly", value: "LOW", tone: "low" as Severity },
      ],
      confidence: 46.4,
    };
  return {
    message: "Potential ransomware behavior detected",
    indicators: [
      { label: "File modification rate", value: "↑ 420%", tone: "critical" as Severity },
      { label: "Encryption-like activity", value: "HIGH", tone: "critical" as Severity },
      { label: "Process anomaly", value: "HIGH", tone: "high" as Severity },
      { label: "Network anomaly", value: "MEDIUM", tone: "medium" as Severity },
    ],
    confidence: 91.7,
  };
}

/* -------------------------------------------------------------- velocity */

export function getVelocitySeries(state: DemoState): VelocityPoint[] {
  const points: VelocityPoint[] = [];
  for (let i = 29; i >= 0; i--) {
    const t = clockAt(-i * 4);
    const progress = (29 - i) / 29;
    let base = 12 + Math.sin(i / 2) * 4;
    if (state === "WARNING") base = 12 + progress * 168 + Math.sin(i) * 6;
    if (state === "CRITICAL")
      base = progress < 0.55 ? 14 + progress * 60 : 60 + (progress - 0.55) * 6200;
    const modified = Math.max(2, Math.round(base));
    points.push({
      t,
      modified,
      renamed: Math.round(modified * 0.72),
      deleted: Math.round(modified * 0.18),
      encrypted: state === "CRITICAL" ? Math.round(modified * 0.81) : Math.round(modified * 0.05),
    });
  }
  return points;
}

export function getVelocityStats(state: DemoState) {
  const last = getVelocitySeries(state).at(-1)!;
  return [
    { label: "Files modified / min", value: last.modified },
    { label: "Files renamed / min", value: last.renamed },
    { label: "Files deleted / min", value: last.deleted },
    { label: "Encryption ops / min", value: last.encrypted },
  ];
}

/* ---------------------------------------------------------- file impact */

export function getFileImpact(state: DemoState) {
  const affected = state === "SAFE" ? 0 : state === "WARNING" ? 186 : 1248;
  return {
    affected,
    protected: 126400,
    damage: state === "SAFE" ? "NONE" : state === "WARNING" ? "LOW" : "MODERATE",
    categories: [
      { name: "Documents", value: Math.round(affected * 0.42) },
      { name: "Images", value: Math.round(affected * 0.21) },
      { name: "Databases", value: Math.round(affected * 0.11) },
      { name: "Archives", value: Math.round(affected * 0.16) },
      { name: "Source Code", value: Math.round(affected * 0.1) },
    ],
  };
}

/* ------------------------------------------------------------- processes */

export function getProcesses(state: DemoState): ProcessRow[] {
  const rows: ProcessRow[] = [
    {
      name: "chrome.exe",
      pid: 4820,
      cpu: 12,
      memory: 18,
      fileActivity: 6,
      networkActivity: 34,
      risk: "low",
      path: "C:\\Program Files\\Google\\Chrome\\chrome.exe",
      signed: true,
      parent: "explorer.exe",
    },
    {
      name: "explorer.exe",
      pid: 1240,
      cpu: 3,
      memory: 6,
      fileActivity: 4,
      networkActivity: 1,
      risk: "low",
      path: "C:\\Windows\\explorer.exe",
      signed: true,
      parent: "userinit.exe",
    },
    {
      name: "OUTLOOK.EXE",
      pid: 6612,
      cpu: 7,
      memory: 11,
      fileActivity: 9,
      networkActivity: 22,
      risk: "low",
      path: "C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE",
      signed: true,
      parent: "explorer.exe",
    },
    {
      name: "svchost.exe",
      pid: 992,
      cpu: 2,
      memory: 4,
      fileActivity: 2,
      networkActivity: 8,
      risk: "low",
      path: "C:\\Windows\\System32\\svchost.exe",
      signed: true,
      parent: "services.exe",
    },
    {
      name: "backup_sync.exe",
      pid: 7314,
      cpu: 21,
      memory: 9,
      fileActivity: 61,
      networkActivity: 12,
      risk: "medium",
      path: "C:\\ProgramData\\Sync\\backup_sync.exe",
      signed: false,
      parent: "explorer.exe",
    },
  ];

  if (state === "SAFE") return rows;

  rows.splice(2, 0, {
    name: "invoice_update.exe",
    pid: 9184,
    cpu: state === "CRITICAL" ? 94 : 41,
    memory: state === "CRITICAL" ? 38 : 17,
    fileActivity: state === "CRITICAL" ? 100 : 58,
    networkActivity: state === "CRITICAL" ? 63 : 24,
    risk: state === "CRITICAL" ? "critical" : "medium",
    path: "C:\\Users\\a.novak\\Downloads\\invoice_update.exe",
    signed: false,
    parent: "OUTLOOK.EXE",
  });
  return rows;
}

/* ------------------------------------------------------------------- AI */

export function getAiPrediction(state: DemoState): AiPrediction {
  if (state === "SAFE")
    return {
      prediction: "BENIGN",
      confidence: 96.4,
      stage: 2,
      indicators: [
        { label: "File modification rate", weight: 9 },
        { label: "Process behavior", weight: 12 },
        { label: "File rename rate", weight: 6 },
        { label: "CPU activity", weight: 18 },
        { label: "Network anomaly", weight: 11 },
      ],
      explanation:
        "Observed endpoint telemetry stays within the learned behavioral baseline. No clustering of file, process or entropy indicators consistent with ransomware.",
    };
  if (state === "WARNING")
    return {
      prediction: "SUSPICIOUS",
      confidence: 62.8,
      stage: 3,
      indicators: [
        { label: "Rapid file modification", weight: 58 },
        { label: "Abnormal process behavior", weight: 64 },
        { label: "High file rename rate", weight: 41 },
        { label: "Unusual CPU activity", weight: 47 },
        { label: "Network anomaly", weight: 29 },
      ],
      explanation:
        "An unsigned process launched from a mail client is generating elevated file activity. The pattern deviates from baseline but has not yet reached the ransomware classification threshold.",
    };
  return {
    prediction: "RANSOMWARE",
    confidence: 98.7,
    stage: 6,
    indicators: [
      { label: "Rapid file modification", weight: 94 },
      { label: "Abnormal process behavior", weight: 89 },
      { label: "High file rename rate", weight: 87 },
      { label: "Unusual CPU activity", weight: 72 },
      { label: "Network anomaly", weight: 51 },
    ],
    explanation:
      "The model detected a combination of rapid file modifications, abnormal process execution and unusual file activity consistent with ransomware-like behavior.",
  };
}

export const detectionStages = [
  { id: 1, name: "Activity Monitoring", detail: "Agent collects raw endpoint telemetry" },
  { id: 2, name: "Behavior Analysis", detail: "Rolling behavioral features are computed" },
  { id: 3, name: "Anomaly Detection", detail: "Deviation from learned baseline is scored" },
  { id: 4, name: "AI Classification", detail: "XGBoost classifies the feature vector" },
  { id: 5, name: "Threat Confidence", detail: "Confidence and risk score are derived" },
  { id: 6, name: "Response Decision", detail: "Policy engine selects response actions" },
];

export function getConfidenceHistory(state: DemoState) {
  const target = getAiPrediction(state).confidence;
  return Array.from({ length: 24 }, (_, i) => {
    const p = i / 23;
    const value =
      state === "SAFE" ? 2 + Math.sin(i) * 1.4 + 2 : Math.max(1, target * Math.pow(p, 3));
    return { t: clockAt(-(23 - i) * 5), confidence: Number(value.toFixed(1)) };
  });
}

/* -------------------------------------------------------------- baseline */

export function getBaseline(state: DemoState): BaselineRow[] {
  const f = state === "SAFE" ? 1 : state === "WARNING" ? 4 : 100;
  return [
    {
      metric: "CPU usage",
      normal: 35,
      current: state === "SAFE" ? 38 : state === "WARNING" ? 61 : 94,
      unit: "%",
    },
    {
      metric: "File modifications",
      normal: 15,
      current: state === "SAFE" ? 17 : state === "WARNING" ? 180 : 1850,
      unit: "/min",
    },
    {
      metric: "Process creation",
      normal: 4,
      current: state === "SAFE" ? 5 : state === "WARNING" ? 11 : 29,
      unit: "/min",
    },
    {
      metric: "File renames",
      normal: 3,
      current: state === "SAFE" ? 3 : state === "WARNING" ? 74 : 1310,
      unit: "/min",
    },
    {
      metric: "Registry writes",
      normal: 6,
      current: state === "SAFE" ? 7 : state === "WARNING" ? 21 : 148,
      unit: "/min",
    },
    {
      metric: "Outbound connections",
      normal: 9,
      current: state === "SAFE" ? 10 : state === "WARNING" ? 18 : 42,
      unit: "/min",
    },
  ].map((r) => ({ ...r, current: Math.round(r.current * (f > 4 ? 1 : 1)) }));
}

/* ------------------------------------------------------------- endpoints */

const departments = ["Finance", "HR", "Sales", "Admin", "Operations", "IT"];

function makeEndpoint(i: number, state: DemoState): Endpoint {
  const dept = departments[i % departments.length]!;
  const name = `${dept.slice(0, 5).toUpperCase()}-PC-${pad((i % 6) + 1)}`;
  let risk = 4 + ((i * 13) % 22);
  let severity: Endpoint["severity"] = "low";
  if (i % 8 === 3) {
    risk = 42 + (i % 9);
    severity = "medium";
  }
  if (i === 17) {
    risk = 0;
    severity = "offline";
  }
  if (i === 5) {
    risk = state === "SAFE" ? 12 : state === "WARNING" ? 58 : 98;
    severity = state === "SAFE" ? "low" : state === "WARNING" ? "medium" : "critical";
  }
  const hot = i === 5 && state !== "SAFE";
  return {
    id: `ep-${pad(i + 1)}`,
    name: i === 5 ? "HR-PC-03" : name,
    user: ["a.novak", "j.silva", "m.chen", "r.patel", "d.owusu", "s.karim"][i % 6]!,
    os: i % 4 === 0 ? "Windows 11 Pro 23H2" : "Windows 10 Pro 22H2",
    agentStatus: severity === "offline" ? "offline" : "online",
    lastHeartbeat: severity === "offline" ? "3 h ago" : `${(i % 8) + 1} s ago`,
    cpu: hot ? (state === "CRITICAL" ? 94 : 61) : 12 + (i % 30),
    memory: hot ? 78 : 30 + (i % 40),
    disk: 40 + (i % 45),
    network: hot ? 66 : 8 + (i % 30),
    processes: 84 + (i % 40),
    riskScore: risk,
    severity,
    department: dept,
    behavior: {
      fileActivity: hot ? (state === "CRITICAL" ? 100 : 62) : 8 + (i % 20),
      processActivity: hot ? 88 : 10 + (i % 25),
      networkActivity: hot ? 64 : 12 + (i % 22),
      registryActivity: hot ? 71 : 6 + (i % 18),
    },
    threatHistory: Array.from({ length: 7 }, (_, d) => ({
      date: `D-${6 - d}`,
      threats: hot && d === 6 ? 3 : (i + d) % 3 === 0 ? 1 : 0,
    })),
  };
}

export function getEndpoints(state: DemoState): Endpoint[] {
  return Array.from({ length: 24 }, (_, i) => makeEndpoint(i, state));
}

export function getEndpointSummary(state: DemoState) {
  const eps = getEndpoints(state);
  return {
    total: eps.length,
    protected: eps.filter((e) => e.severity === "low").length,
    warning: eps.filter((e) => e.severity === "medium" || e.severity === "high").length,
    critical: eps.filter((e) => e.severity === "critical").length,
    offline: eps.filter((e) => e.severity === "offline").length,
  };
}

/* --------------------------------------------------------------- threats */

const baseThreats: Threat[] = [
  {
    id: "THR-0017",
    endpoint: "HR-PC-03",
    process: "invoice_update.exe",
    type: "Ransomware",
    severity: "critical",
    confidence: 98.7,
    detectedAt: "10:42:43",
    status: "Blocked",
    summary:
      "Unsigned executable delivered via mail attachment initiated mass file modification and rename operations consistent with encryption.",
    filesAffected: 1248,
  },
  {
    id: "THR-0016",
    endpoint: "SALES-PC-02",
    process: "sync_helper.exe",
    type: "Suspicious File Activity",
    severity: "high",
    confidence: 81.4,
    detectedAt: "09:18:02",
    status: "Investigating",
    summary: "Elevated rename rate on shared drive outside business hours baseline.",
    filesAffected: 314,
  },
  {
    id: "THR-0015",
    endpoint: "FINAN-PC-01",
    process: "powershell.exe",
    type: "Script Anomaly",
    severity: "medium",
    confidence: 64.2,
    detectedAt: "08:51:37",
    status: "Monitoring",
    summary: "Encoded PowerShell command spawned from an Office document process tree.",
    filesAffected: 0,
  },
  {
    id: "THR-0014",
    endpoint: "ADMIN-PC-01",
    process: "reg.exe",
    type: "Registry Persistence",
    severity: "high",
    confidence: 77.9,
    detectedAt: "Yesterday 17:04",
    status: "Blocked",
    summary: "Run-key persistence attempt blocked by response policy.",
    filesAffected: 0,
  },
  {
    id: "THR-0013",
    endpoint: "OPERA-PC-04",
    process: "chrome.exe",
    type: "Suspicious Download",
    severity: "low",
    confidence: 38.6,
    detectedAt: "Yesterday 14:22",
    status: "Resolved",
    summary: "Archive download flagged by reputation heuristics; no execution observed.",
    filesAffected: 0,
  },
  {
    id: "THR-0012",
    endpoint: "HR-PC-03",
    process: "wscript.exe",
    type: "Script Anomaly",
    severity: "medium",
    confidence: 58.1,
    detectedAt: "2 days ago",
    status: "Resolved",
    summary: "Script host launched from temp directory, terminated by analyst.",
    filesAffected: 0,
  },
];

export function getThreats(state: DemoState): Threat[] {
  if (state === "CRITICAL") return baseThreats;
  if (state === "WARNING")
    return baseThreats
      .slice(1)
      .map((t, i) => (i === 0 ? { ...t, severity: "medium" as Severity, confidence: 62.8 } : t));
  return baseThreats.slice(2);
}

export function getThreat(id: string) {
  return baseThreats.find((t) => t.id === id);
}

/* ---------------------------------------------------------------- events */

const eventTemplates: Array<Omit<SecurityEvent, "id" | "timestamp">> = [
  {
    source: "Sysmon",
    type: "Process Created",
    endpoint: "FINAN-PC-01",
    process: "chrome.exe",
    severity: "info",
    status: "Logged",
  },
  {
    source: "watchdog",
    type: "File Modified",
    endpoint: "FINAN-PC-01",
    process: "EXCEL.EXE",
    severity: "info",
    status: "Logged",
  },
  {
    source: "psutil",
    type: "CPU Sample",
    endpoint: "SALES-PC-02",
    process: "system",
    severity: "info",
    status: "Logged",
  },
  {
    source: "Windows Event Log",
    type: "Logon Success",
    endpoint: "HR-PC-03",
    process: "winlogon.exe",
    severity: "info",
    status: "Logged",
  },
  {
    source: "Sysmon",
    type: "Network Connection",
    endpoint: "OPERA-PC-04",
    process: "OUTLOOK.EXE",
    severity: "info",
    status: "Logged",
  },
  {
    source: "watchdog",
    type: "File Created",
    endpoint: "IT-PC-06",
    process: "teams.exe",
    severity: "info",
    status: "Logged",
  },
  {
    source: "Windows Event Log",
    type: "Service Installed",
    endpoint: "ADMIN-PC-01",
    process: "services.exe",
    severity: "low",
    status: "Logged",
  },
  {
    source: "Sysmon",
    type: "Registry Value Set",
    endpoint: "ADMIN-PC-01",
    process: "reg.exe",
    severity: "medium",
    status: "Flagged",
  },
];

const escalationEvents: Array<Omit<SecurityEvent, "id" | "timestamp">> = [
  {
    source: "Sysmon",
    type: "Suspicious Process",
    endpoint: "HR-PC-03",
    process: "invoice_update.exe",
    severity: "high",
    status: "Flagged",
    detail: "Unsigned binary spawned by OUTLOOK.EXE",
  },
  {
    source: "psutil",
    type: "CPU Spike",
    endpoint: "HR-PC-03",
    process: "invoice_update.exe",
    severity: "medium",
    status: "Flagged",
    detail: "94% sustained CPU",
  },
  {
    source: "watchdog",
    type: "Mass File Modification",
    endpoint: "HR-PC-03",
    process: "invoice_update.exe",
    severity: "critical",
    status: "Flagged",
    detail: "1,248 files in 9 s",
  },
  {
    source: "Sysmon",
    type: "High File Rename Rate",
    endpoint: "HR-PC-03",
    process: "invoice_update.exe",
    severity: "critical",
    status: "Flagged",
    detail: "1,310 renames/min",
  },
  {
    source: "psutil",
    type: "Ransomware Behavior Detected",
    endpoint: "HR-PC-03",
    process: "invoice_update.exe",
    severity: "critical",
    status: "Flagged",
    detail: "AI confidence 98.7%",
  },
  {
    source: "Windows Event Log",
    type: "Process Blocked",
    endpoint: "HR-PC-03",
    process: "invoice_update.exe",
    severity: "critical",
    status: "Blocked",
    detail: "Automated response policy CRITICAL",
  },
];

export function getEvents(state: DemoState, count = 60): SecurityEvent[] {
  const pool =
    state === "CRITICAL"
      ? [...eventTemplates, ...escalationEvents]
      : state === "WARNING"
        ? [...eventTemplates, ...escalationEvents.slice(0, 2)]
        : eventTemplates;
  return Array.from({ length: count }, (_, i) => {
    const tpl = pool[i % pool.length]!;
    return { ...tpl, id: `evt-${pad(i)}`, timestamp: clockAt(-i * 3) };
  });
}

export function getLiveStream(state: DemoState): SecurityEvent[] {
  if (state === "CRITICAL")
    return escalationEvents
      .map((e, i) => ({ ...e, id: `live-${i}`, timestamp: clockAt(9 + i) }))
      .reverse();
  if (state === "WARNING")
    return [...eventTemplates.slice(0, 3), ...escalationEvents.slice(0, 2)]
      .map((e, i) => ({ ...e, id: `live-${i}`, timestamp: clockAt(i * 2) }))
      .reverse();
  return eventTemplates
    .map((e, i) => ({ ...e, id: `live-${i}`, timestamp: clockAt(i * 2) }))
    .reverse();
}

/* -------------------------------------------------------------- timeline */

export const attackTimeline: TimelineStep[] = [
  {
    time: "10:42:39",
    title: "Mail attachment opened",
    detail: "invoice_update.zip extracted by user a.novak",
    severity: "info",
  },
  {
    time: "10:42:40",
    title: "Suspicious executable launched",
    detail: "invoice_update.exe (PID 9184) spawned by OUTLOOK.EXE",
    severity: "medium",
  },
  {
    time: "10:42:41",
    title: "Process behavior anomaly",
    detail: "Unsigned binary, shadow-copy utility invoked",
    severity: "high",
  },
  {
    time: "10:42:42",
    title: "File modification rate increased",
    detail: "1,248 files touched in 9 seconds",
    severity: "high",
  },
  {
    time: "10:42:43",
    title: "Potential encryption behavior detected",
    detail: "High-entropy writes + .lockxx rename pattern",
    severity: "critical",
  },
  {
    time: "10:42:43",
    title: "AI classification: RANSOMWARE",
    detail: "XGB-v1.0 confidence 98.7%",
    severity: "critical",
  },
  {
    time: "10:42:44",
    title: "Process terminated",
    detail: "Automated response: terminate + quarantine",
    severity: "critical",
  },
  {
    time: "10:42:45",
    title: "Endpoint isolated",
    detail: "HR-PC-03 removed from network segment",
    severity: "critical",
  },
  {
    time: "10:42:46",
    title: "Administrator notified",
    detail: "Alert delivered to security@sme.example",
    severity: "info",
  },
];

/* --------------------------------------------------------------- reports */

export function getThreatsOverTime(days = 30) {
  return Array.from({ length: days }, (_, i) => ({
    day: `D-${days - i}`,
    detected: 1 + ((i * 7) % 5),
    blocked: 1 + ((i * 5) % 4),
  }));
}

export const severityDistribution = [
  { name: "Critical", value: 4 },
  { name: "High", value: 6 },
  { name: "Medium", value: 9 },
  { name: "Low", value: 14 },
];

export const threatSources = [
  { name: "Email attachment", value: 11 },
  { name: "Web download", value: 7 },
  { name: "USB / removable", value: 3 },
  { name: "Software update", value: 2 },
  { name: "Remote session", value: 4 },
];

/* --------------------------------------------------------------- model */

export const modelHealth = {
  version: "XGB-v1.0",
  status: "Healthy",
  lastUpdated: "Today",
  predictionsToday: 2431,
  ransomwarePredictions: 17,
  averageConfidence: 94.2,
  metrics: [
    { label: "Accuracy", value: 97.4 },
    { label: "Precision", value: 96.1 },
    { label: "Recall", value: 95.3 },
    { label: "F1 score", value: 95.7 },
    { label: "ROC-AUC", value: 98.2 },
  ],
  distribution: [
    { name: "Benign", value: 2331 },
    { name: "Suspicious", value: 83 },
    { name: "Ransomware", value: 17 },
  ],
};

export const dataSourceCoverage = [
  { name: "Windows Event Logs", value: 100 },
  { name: "Sysmon", value: 96 },
  { name: "psutil", value: 100 },
  { name: "watchdog", value: 92 },
];

/* ---------------------------------------------------------------- audit */

export const auditLog: AuditEntry[] = [
  {
    actor: "Admin",
    action: "Blocked Process (invoice_update.exe)",
    endpoint: "HR-PC-03",
    timestamp: "10:42:44",
    result: "Success",
  },
  {
    actor: "System",
    action: "Isolated Endpoint",
    endpoint: "HR-PC-03",
    timestamp: "10:42:45",
    result: "Success",
  },
  {
    actor: "System",
    action: "Created Incident THR-0017",
    endpoint: "HR-PC-03",
    timestamp: "10:42:46",
    result: "Success",
  },
  {
    actor: "Admin",
    action: "Marked detection as correct",
    endpoint: "HR-PC-03",
    timestamp: "10:47:12",
    result: "Success",
  },
  {
    actor: "j.silva",
    action: "Exported threat report",
    endpoint: "—",
    timestamp: "09:31:04",
    result: "Success",
  },
  {
    actor: "System",
    action: "Agent heartbeat timeout",
    endpoint: "OPERA-PC-06",
    timestamp: "07:12:58",
    result: "Failed",
  },
];

export const responsePolicy = [
  {
    risk: "LOW (0–30)",
    tone: "low" as Severity,
    action: "Monitor",
    detail: "Log telemetry, no user impact",
  },
  {
    risk: "MEDIUM (31–60)",
    tone: "medium" as Severity,
    action: "Generate Warning",
    detail: "Raise dashboard warning + increase sampling",
  },
  {
    risk: "HIGH (61–80)",
    tone: "high" as Severity,
    action: "Alert Administrator",
    detail: "Email + dashboard alert, snapshot evidence",
  },
  {
    risk: "CRITICAL (81–100)",
    tone: "critical" as Severity,
    action: "Block + Isolate + Alert",
    detail: "Terminate process, quarantine files, isolate endpoint",
  },
];

export const responseActions = [
  { name: "Terminate Process", detail: "Kill the offending PID and its children" },
  { name: "Quarantine File", detail: "Move binary to encrypted quarantine store" },
  { name: "Block Process", detail: "Add hash to endpoint block list" },
  { name: "Isolate Endpoint", detail: "Restrict network to management channel only" },
  { name: "Notify Administrator", detail: "Send alert to configured recipients" },
  { name: "Create Incident", detail: "Open an incident record for investigation" },
  { name: "Collect Evidence", detail: "Capture process tree, file list and memory strings" },
];

export const executiveSummary = {
  overall: 87,
  endpoints: 24,
  protected: 20,
  atRisk: 3,
  critical: 1,
  threatsThisMonth: 17,
  threatsBlocked: 15,
  incidentsPrevented: 12,
};

export const trainingData = {
  rows: 184320,
  classes: [
    { name: "Benign", value: 142880 },
    { name: "Ransomware", value: 25640 },
    { name: "Malware (other)", value: 15800 },
  ],
  features: [
    "CPU usage (rolling mean / peak)",
    "Memory pressure",
    "File modification rate",
    "File rename rate",
    "File deletion rate",
    "Write entropy estimate",
    "Process creation rate",
    "Unsigned process ratio",
    "Registry write rate",
    "Outbound connection rate",
  ],
};
