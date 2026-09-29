# RansomShield Dashboard

Build a complete, highly polished, production-style cybersecurity web application prototype called:

========================================================

RansomShield AI

========================================================

Tagline:

"AI-Powered Real-Time Behavioral Ransomware Detection

and Automated Response for Small and Medium Enterprises"

========================================================

PROJECT PURPOSE

========================================================

This is an academic and research-oriented prototype for an

AI-powered ransomware defense platform designed primarily

for Small and Medium Enterprises (SMEs).

The core problem:

Many SMEs do not have expensive enterprise cybersecurity

infrastructure or dedicated security teams. Ransomware can

enter through phishing emails, malicious executables,

compromised software, or unsafe downloads.

Once ransomware executes, it can rapidly:

- modify thousands of files

- encrypt documents

- rename files

- create suspicious processes

- modify registry entries

- consume CPU/resources

- establish network connections

- attempt persistence

- disable security mechanisms

The goal of RansomShield AI is to detect ransomware-like

BEHAVIOR as early as possible instead of waiting until

large-scale file encryption has already occurred.

The system concept is:

MONITOR

→ COLLECT

→ ANALYZE

→ DETECT

→ EXPLAIN

→ ALERT

→ RESPOND

→ PROTECT

========================================================

IMPORTANT PRODUCT PRINCIPLE

========================================================

This frontend is initially a PROTOTYPE.

Use realistic MOCK DATA for the UI.

Do NOT pretend that the frontend is actually monitoring

Windows computers until the real backend is connected.

Clearly distinguish:

DEMO / SIMULATION DATA

from

REAL BACKEND DATA

The architecture must be ready for future integration

with:

Python Monitoring Agent

Windows Event Logs

Sysmon

psutil

watchdog

XGBoost

FastAPI

MongoDB

========================================================

TECH STACK

========================================================

Frontend:

React

TypeScript

Vite

Tailwind CSS

Use:

- reusable React components

- clean TypeScript interfaces

- responsive layouts

- professional charting

- modular architecture

- API service layer

- mock-data service layer

Do not put mock data directly inside every component.

Create a centralized mock-data layer that can later be

replaced by real API calls.

========================================================

DESIGN LANGUAGE

========================================================

Create a professional enterprise cybersecurity/SOC interface.

Theme:

Dark cybersecurity dashboard.

Visual style:

- sophisticated

- clean

- modern

- professional

- enterprise-grade

- high information density

- excellent spacing

- subtle glass effects

- subtle gradients

- minimal glow

- strong typography

- clear status indicators

Avoid:

- gaming UI

- excessive neon

- excessive animations

- hacker-movie aesthetics

- unnecessary 3D effects

- clutter

- generic admin dashboard appearance

The UI should look like a serious cybersecurity product.

========================================================

COLOR SYSTEM

========================================================

Use semantic colors:

GREEN:

Protected / Safe

YELLOW:

Warning / Suspicious

ORANGE:

High Risk

RED:

Critical / Ransomware

BLUE:

Information / Monitoring

Use colors primarily for status and alerts.

========================================================

GLOBAL APPLICATION STRUCTURE

========================================================

Create a persistent sidebar.

Brand:

RansomShield AI

Navigation:

1. Overview

2. Live Monitoring

3. Endpoints

4. Threats

5. Events

6. AI Detection

7. Incident Investigation

8. Attack Replay

9. Reports

10. Settings

Bottom of sidebar:

System Status

● Monitoring Agent: Online

● AI Model: Active

● Database: Connected

● Protection: Active

========================================================

TOP NAVIGATION

========================================================

Top bar:

- Global search

- Current organization

- Notification bell

- Demo Mode indicator

- System status

- User profile

Show:

"Protection Active"

========================================================

FEATURE 1 — SECURITY COMMAND CENTER

========================================================

The Overview page should function as the organization's

main cybersecurity command center.

At the top:

SYSTEM SECURITY STATUS

Large status card:

🟢 PROTECTED

"No active ransomware threats detected"

Risk Score:

8 / 100

Protection:

ACTIVE

Last Updated:

2 seconds ago

The card must dynamically change based on mock state.

Possible states:

SAFE

WARNING

HIGH RISK

CRITICAL

========================================================

FEATURE 2 — ORGANIZATION SECURITY HEALTH SCORE

========================================================

Create:

SECURITY HEALTH SCORE

Example:

87 / 100

Breakdown:

Endpoint Protection

92%

Monitoring Coverage

95%

Threat Detection

89%

Patch/Software Health

76%

Incident Response

84%

This gives SME management a simple overview

instead of requiring them to understand every

technical security metric.

========================================================

FEATURE 3 — REAL-TIME RISK SCORE

========================================================

Create a large circular risk visualization.

Example:

RISK SCORE

8

LOW

Risk calculation concept:

Process anomalies

+

File activity

+

Encryption activity

+

CPU anomalies

+

Registry activity

+

Network anomalies

Show:

Low: 0–30

Medium: 31–60

High: 61–80

Critical: 81–100

========================================================

FEATURE 4 — EARLY RANSOMWARE WARNING

========================================================

Create a special component:

RANSOMWARE EARLY WARNING

Possible states:

🟢 NORMAL

🟡 SUSPICIOUS ACTIVITY

🟠 POSSIBLE RANSOMWARE

🔴 RANSOMWARE DETECTED

Example:

"Potential ransomware behavior detected"

Indicators:

File modification rate:

↑ 420%

Encryption-like activity:

HIGH

Process anomaly:

HIGH

Network anomaly:

MEDIUM

AI confidence:

91.7%

This feature should communicate that the system

attempts to detect ransomware BEFORE widespread

damage occurs.

========================================================

FEATURE 5 — FILE ENCRYPTION VELOCITY

========================================================

Create one of the project's unique visualizations:

FILE ACTIVITY VELOCITY

Display:

Files modified/minute

Files renamed/minute

Files deleted/minute

Potential encryption operations/minute

Example:

Normal:

12 files/min

Suspicious:

180 files/min

Critical:

2,840 files/min

Use a real-time line chart.

Add threshold markers:

Normal Zone

Warning Zone

Critical Zone

This is one of the key behavioral indicators.

========================================================

FEATURE 6 — FILE IMPACT ESTIMATOR

========================================================

Create:

POTENTIAL FILE IMPACT

Example:

Files currently affected:

1,248

Estimated protected files:

126,400

Estimated potential damage:

LOW

Show categories:

Documents

Images

Databases

Archives

Source Code

This should be clearly labelled:

"Prototype Estimate"

Do not claim exact protection numbers unless

real backend data exists.

========================================================

FEATURE 7 — PROCESS BEHAVIOR ANALYSIS

========================================================

Create:

PROCESS BEHAVIOR

Display:

Process Name

PID

CPU

Memory

File Activity

Network Activity

Risk

Example:

chrome.exe

Normal

explorer.exe

Normal

invoice_update.exe

CRITICAL

Show suspicious process highlighted.

Clicking the process opens details.

========================================================

FEATURE 8 — AI EXPLAINABILITY

========================================================

This is VERY IMPORTANT.

Do not only show:

"Ransomware Detected"

Show:

"WHY DID THE AI DETECT THIS?"

Example:

AI DECISION EXPLANATION

Prediction:

RANSOMWARE

Confidence:

98.7%

Top contributing indicators:

1. Rapid file modification

██████████ 94%

2. Abnormal process behavior

█████████░ 89%

3. High file rename rate

█████████░ 87%

4. Unusual CPU activity

███████░░░ 72%

5. Network anomaly

█████░░░░░ 51%

Explanation:

"The model detected a combination of rapid file

modifications, abnormal process execution and

unusual file activity consistent with ransomware-like

behavior."

This makes the AI much more understandable.

========================================================

FEATURE 9 — BEHAVIOR BASELINE

========================================================

Create:

NORMAL BEHAVIOR BASELINE

Compare:

NORMAL BASELINE

vs

CURRENT BEHAVIOR

Example:

CPU

Normal:

35%

Current:

94%

File modifications

Normal:

15/min

Current:

1,850/min

Process creation

Normal:

4/min

Current:

29/min

Show deviations.

Title:

"Behavior Deviation"

This is a key unique feature.

========================================================

FEATURE 10 — ENDPOINT RISK MAP

========================================================

Create an endpoint visualization.

Show:

Total Endpoints:

24

Protected:

20

Warning:

3

Critical:

1

Display endpoint cards:

FINANCE-PC-01

🟢 LOW

HR-PC-03

🟡 MEDIUM

SALES-PC-02

🟢 LOW

ADMIN-PC-01

🔴 CRITICAL

Allow filtering:

All

Protected

Warning

Critical

Offline

========================================================

FEATURE 11 — LIVE MONITORING

========================================================

Create a Live Monitoring page.

Show real-time event stream.

Example:

10:42:31

Process Created

chrome.exe

10:42:35

File Modified

report.xlsx

10:42:41

Suspicious Process

invoice_update.exe

10:42:42

Mass File Modification

1,248 files

10:42:43

Ransomware Behavior Detected

10:42:44

Process Blocked

Add:

LIVE ●

indicator.

========================================================

FEATURE 12 — DATA COLLECTION VISUALIZATION

========================================================

Create a page:

LIVE DATA SOURCES

Show four major collectors.

WINDOWS EVENT LOGS

Collect:

- Security events

- System events

- Process events

SYSMON

Collect:

- Process creation

- Network activity

- Registry activity

- File activity

PSUTIL

Collect:

- CPU

- Memory

- Processes

- Disk activity

WATCHDOG

Collect:

- File creation

- File modification

- File deletion

- Directory activity

Show architecture:

Windows Event Logs ──┐

Sysmon ──────────────┤

psutil ──────────────┤

watchdog ────────────┘

                     ↓

             Python Monitoring Agent

                     ↓

             Feature Extraction

                     ↓

              XGBoost AI Model

========================================================

FEATURE 13 — AI MODEL CENTER

========================================================

Create:

AI DETECTION CENTER

Model:

XGBoost Behavioral Classifier

Status:

ACTIVE

Purpose:

"Classifies endpoint behavior as benign or ransomware-like."

Input:

- CPU usage

- Memory

- File modification rate

- File rename rate

- Process activity

- Registry activity

- Network activity

- Encryption-like behavior

Output:

BENIGN

or

RANSOMWARE

Show prototype evaluation metrics.

Clearly label:

"Demonstration Metrics"

Do not claim they are real measured metrics.

========================================================

FEATURE 14 — MULTI-STAGE DETECTION

========================================================

Instead of showing only one AI prediction,

create a detection pipeline:

STAGE 1

Activity Monitoring

↓

STAGE 2

Behavior Analysis

↓

STAGE 3

Anomaly Detection

↓

STAGE 4

AI Classification

↓

STAGE 5

Threat Confidence

↓

STAGE 6

Response Decision

Show current stage during demo mode.

========================================================

FEATURE 15 — THREAT CONFIDENCE

========================================================

Display:

AI CONFIDENCE

98.7%

Ransomware

Explain:

"This represents the model's confidence in the current

classification. It is not a guarantee of malicious activity."

Include confidence history graph.

========================================================

FEATURE 16 — THREAT DETECTION PAGE

========================================================

Create threat table.

Columns:

Threat ID

Endpoint

Process

Threat Type

Risk

Confidence

Detected

Status

Example:

THR-0017

HR-PC-03

invoice_update.exe

Ransomware

Critical

98.7%

10:42:43

Blocked

Filters:

Severity

Endpoint

Threat Type

Status

Time

========================================================

FEATURE 17 — INCIDENT INVESTIGATION WORKSPACE

========================================================

Create a dedicated investigation page.

When a threat is selected:

INCIDENT:

THR-0017

Severity:

CRITICAL

Endpoint:

HR-PC-03

Process:

invoice_update.exe

Confidence:

98.7%

Show sections:

Summary

Timeline

Process Activity

File Activity

Network Activity

Registry Activity

AI Explanation

Response Actions

This should feel like a mini SOC investigation console.

========================================================

FEATURE 18 — ATTACK TIMELINE

========================================================

Create a visual attack timeline.

Example:

10:42:40

Suspicious executable launched

↓

10:42:41

Process behavior anomaly

↓

10:42:42

File modification rate increased

↓

10:42:43

Potential encryption behavior detected

↓

10:42:43

AI classification:

RANSOMWARE

↓

10:42:44

Process terminated

↓

10:42:45

Endpoint isolated

↓

10:42:46

Administrator notified

Use icons and severity markers.

========================================================

FEATURE 19 — ATTACK REPLAY

========================================================

Create a unique:

ATTACK REPLAY

feature.

Allow the user to replay a previous ransomware

incident step by step.

Controls:

▶ Play

⏸ Pause

↺ Restart

Timeline:

Process Start

File Changes

CPU Spike

Encryption Spike

AI Detection

Response

As the replay runs, update:

Risk Score

Threat Confidence

File Activity

Process Activity

This is useful for academic demonstrations.

========================================================

FEATURE 20 — DEMO ATTACK SIMULATOR

========================================================

Create:

SECURITY DEMO CENTER

Modes:

1. Normal Activity

2. Suspicious Activity

3. Ransomware Attack

When:

NORMAL ACTIVITY

Show:

Risk:

8

Status:

PROTECTED

When:

SUSPICIOUS ACTIVITY

Show:

Risk:

58

Status:

WARNING

When:

RANSOMWARE ATTACK

Show:

Risk:

98

Status:

CRITICAL

Then animate:

File Activity ↑

CPU ↑

Process Anomaly ↑

AI Confidence ↑

Finally:

Ransomware Detected

Response:

Process Blocked

IMPORTANT:

Clearly display:

"SIMULATION MODE"

Do not imply this is a real ransomware attack.

========================================================

FEATURE 21 — WHAT-IF RISK SIMULATOR

========================================================

Create a unique educational feature:

WHAT-IF RISK SIMULATOR

Allow the user to adjust sliders:

File Modification Rate

CPU Usage

Process Anomaly

Network Activity

Registry Activity

Then calculate a DEMONSTRATION risk score.

Example:

File Activity:

80%

CPU:

90%

Process Anomaly:

75%

Result:

Risk:

87

Classification:

HIGH RISK

Clearly label:

"Prototype Simulation"

========================================================

FEATURE 22 — AUTOMATED RESPONSE CENTER

========================================================

Create:

AUTOMATED RESPONSE

Available response actions:

Terminate Process

Quarantine File

Block Process

Isolate Endpoint

Notify Administrator

Create Incident

Collect Evidence

Show response status:

✓ Process terminated

✓ File quarantined

✓ Administrator notified

For prototype actions:

Show:

"Simulation / Prototype Action"

Do not pretend that these actions are actually

executed on the user's computer.

========================================================

FEATURE 23 — RESPONSE POLICY

========================================================

Create:

RESPONSE POLICY

Example:

LOW RISK

Monitor

MEDIUM RISK

Generate Warning

HIGH RISK

Alert Administrator

CRITICAL

Block + Isolate + Alert

Allow the user to view these rules.

========================================================

FEATURE 24 — FALSE POSITIVE FEEDBACK

========================================================

Create:

AI FEEDBACK

When an alert appears:

"Was this detection correct?"

Buttons:

✓ Correct Detection

✕ False Positive

Add:

"Provide Feedback"

This feedback can later be used as part of a

future model improvement workflow.

========================================================

FEATURE 25 — MODEL MONITORING

========================================================

Create:

MODEL HEALTH

Show:

Model Version:

XGB-v1.0

Status:

Healthy

Last Updated:

Today

Predictions Today:

2,431

Ransomware Predictions:

17

Average Confidence:

94.2%

Also show:

Prediction Distribution

Confidence Trend

Detection Count

Clearly label prototype data.

========================================================

FEATURE 26 — EVENT LOGS

========================================================

Create Events page.

Columns:

Timestamp

Source

Event Type

Endpoint

Process

Severity

Status

Sources:

Windows Event Log

Sysmon

psutil

watchdog

Add:

Search

Filter

Sort

========================================================

FEATURE 27 — REPORTING

========================================================

Create Reports page.

Show:

Threats Detected

Threats Blocked

Endpoints Protected

High Risk Events

Average Detection Confidence

Average Response Time

Charts:

Threats Over Time

Severity Distribution

Endpoint Risk

Threat Sources

Buttons:

Generate Report

Export CSV

Export PDF

These should be prototype UI interactions.

========================================================

FEATURE 28 — MANAGEMENT VIEW

========================================================

Create an SME management-friendly summary.

Not every business owner understands cybersecurity.

Create:

EXECUTIVE SECURITY SUMMARY

Overall Security:

87 / 100

Endpoints:

24

Protected:

20

At Risk:

3

Critical:

1

Threats This Month:

17

Threats Blocked:

15

Estimated Incidents Prevented:

12

Clearly label estimates as prototype/demo data.

Use simple language.

========================================================

FEATURE 29 — ALERT CENTER

========================================================

Create notification center.

Example:

CRITICAL

Ransomware behavior detected

Endpoint:

HR-PC-03

Confidence:

98.7%

Process:

invoice_update.exe

Actions:

View Incident

Dismiss

========================================================

FEATURE 30 — ENDPOINT DETAILS

========================================================

For each endpoint show:

Device Name

User

Operating System

Agent Status

Last Heartbeat

CPU

Memory

Disk

Network

Running Processes

Risk Score

Threat History

Behavior:

File Activity

Process Activity

Network Activity

Registry Activity

========================================================

FEATURE 31 — SECURITY COVERAGE

========================================================

Create:

SECURITY COVERAGE

Monitoring coverage:

24 / 24 endpoints

100%

Data source coverage:

Windows Events:

100%

Sysmon:

96%

psutil:

100%

watchdog:

92%

Clearly mark this as demonstration data.

========================================================

FEATURE 32 — THREAT HISTORY

========================================================

Create historical incidents.

Show:

Threat count by day

Threat count by severity

Most targeted endpoint

Most common process

Detection confidence

Allow:

7 days

30 days

90 days

========================================================

FEATURE 33 — DATABASE / AUDIT LOG

========================================================

Create an audit log.

Show:

Who

Action

Endpoint

Timestamp

Result

Example:

Admin

Blocked Process

HR-PC-03

10:42:44

Success

This represents security auditing.

========================================================

FEATURE 34 — SETTINGS

========================================================

Sections:

Monitoring

[ON] Real-time monitoring

[ON] File monitoring

[ON] Process monitoring

[ON] Event monitoring

AI Detection

[ON] AI detection

Detection threshold

Response

[ON] Alert administrator

[ON] Automated response

[ON] Endpoint isolation

Notifications

Email

Dashboard

System notification

Agent

Agent version

Last heartbeat

Connection status

========================================================

FEATURE 35 — SYSTEM ARCHITECTURE PAGE

========================================================

Create a visual architecture page.

Show:

USER ENDPOINT

↓

Windows Event Logs

Sysmon

psutil

watchdog

↓

Python Monitoring Agent

↓

Feature Engineering

↓

XGBoost Model

↓

Risk + Classification

↓

FastAPI

↓

MongoDB

↓

React Dashboard

Also show:

Historical Dataset

↓

Data Cleaning

↓

Feature Engineering

↓

XGBoost Training

↓

Saved Model

↓

Deployment

Clearly distinguish:

TRAINING PIPELINE

and

LIVE DETECTION PIPELINE

========================================================

FEATURE 36 — TRAINING DATA PAGE

========================================================

Create:

MODEL TRAINING DATA

Show:

Historical Dataset

Classes:

Benign

Ransomware

Malware

Features:

CPU

Memory

File activity

Process activity

Network activity

Registry activity

Training pipeline:

Dataset

↓

Cleaning

↓

Feature Engineering

↓

Train/Test Split

↓

XGBoost

↓

Evaluation

↓

Saved Model

This is an explanatory prototype page.

========================================================

FEATURE 37 — ONBOARDING

========================================================

Create a first-time setup flow for an SME.

Step 1:

Organization Information

Step 2:

Add Endpoints

Step 3:

Install Monitoring Agent

Step 4:

Enable Data Sources

Step 5:

Activate AI Detection

Step 6:

Protection Active

Final:

🟢 Your organization is protected

For prototype, installation actions are simulated.

========================================================

FEATURE 38 — LIVE CONNECTION STATUS

========================================================

Show system connection status:

Monitoring Agent:

● Connected

AI Model:

● Active

API:

● Connected

Database:

● Connected

Last Data:

2 seconds ago

This prepares the UI for real backend integration.

========================================================

FEATURE 39 — API ARCHITECTURE

========================================================

Create a clean frontend service layer.

Conceptual endpoints:

GET /api/status

GET /api/endpoints

GET /api/events

GET /api/threats

GET /api/threats/:id

GET /api/ai/prediction

GET /api/metrics

GET /api/model/status

Future real-time connection:

WebSocket or Server-Sent Events

The UI should be designed so polling can initially

be used and WebSocket/SSE can later provide real-time

updates.

========================================================

FEATURE 40 — MOCK DATA ENGINE

========================================================

Create centralized mock data.

Support states:

SAFE

WARNING

CRITICAL

The Demo Mode must be able to switch between states.

When switching state:

Update:

- Dashboard status

- Risk score

- Threat count

- Endpoint status

- Event stream

- AI prediction

- File activity

- Process activity

- Alerts

- Timeline

Everything should remain consistent.

========================================================

IMPORTANT DEMONSTRATION SCENARIO

========================================================

The most important demo should be:

NORMAL COMPUTER

↓

Employee opens malicious attachment

↓

Suspicious process starts

↓

File activity increases

↓

CPU increases

↓

Multiple files modified

↓

Behavior deviates from baseline

↓

AI analyzes features

↓

Ransomware confidence increases

↓

Ransomware detected

↓

Administrator alerted

↓

Process blocked

↓

Endpoint isolated

↓

Incident recorded

↓

Dashboard returns to protected state

This scenario should be possible entirely through

Demo Mode without needing real ransomware.

========================================================

SECURITY AND ETHICAL REQUIREMENTS

========================================================

This is a defensive cybersecurity project.

Do not include:

- Real ransomware

- Real malware execution

- Destructive encryption

- Real attack payloads

- Dangerous code

All attack demonstrations must use simulated data.

========================================================

UI COMPONENT STRUCTURE

========================================================

Create reusable components such as:

Sidebar

Topbar

StatusCard

RiskGauge

SecurityHealth

ThreatCard

ThreatTable

EndpointTable

EndpointCard

EventTimeline

LiveEventStream

AIExplanation

BehaviorBaseline

FileVelocityChart

ProcessBehavior

ThreatConfidence

AttackTimeline

AttackReplay

DemoSimulator

RiskSimulator

ResponseCenter

AlertCenter

ModelHealth

SecurityCoverage

ManagementSummary

ArchitectureDiagram

========================================================

ROUTES

========================================================

/

Overview

/monitoring

Live Monitoring

/endpoints

Endpoints

/endpoints/:id

Endpoint Details

/threats

Threats

/threats/:id

Threat Details

/events

Events

/ai

AI Detection

/incidents

Incident Investigation

/replay

Attack Replay

/reports

Reports

/settings

Settings

/architecture

Architecture

/training

Training Data

========================================================

FINAL DESIGN GOAL

========================================================

The final product must clearly communicate:

THE PROBLEM

SMEs lack advanced affordable ransomware defense.

↓

THE MONITORING

Collect live endpoint behavior.

↓

THE AI

Analyze behavioral features.

↓

THE DETECTION

Identify ransomware-like activity.

↓

THE EXPLANATION

Explain why the AI believes it is malicious.

↓

THE RESPONSE

Block, isolate and alert.

↓

THE RESULT

Reduce potential data loss and business downtime.

========================================================

FINAL UX PRINCIPLE

========================================================

The entire application should revolve around:

MONITOR

→ ANALYZE

→ DETECT

→ EXPLAIN

→ RESPOND

→ PROTECT

Make this story visually obvious throughout the application.

Create a polished, cohesive, responsive, realistic cybersecurity

product prototype with working navigation, charts, interactions,

demo simulation, mock data, threat workflows, AI explanation,

endpoint monitoring, incident investigation and future-ready

API architecture.

Do not create a generic dashboard.

Build a complete RansomShield AI cybersecurity product prototype.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/78d31223-cdf4-4f2b-8178-b86c31effec5).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
