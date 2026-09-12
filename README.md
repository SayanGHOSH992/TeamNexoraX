# 🛡️ Sentinel-MCP | Runtime AI Agent Firewall & Cryptographic Provenance Layer

> **Hackathon Submission**: A production-grade runtime firewall and cryptographic provenance verification layer situated strictly between an AI Agent and MCP servers/tools, performing continuous verification of integrity and behavior.

---

## 🌟 Key Architecture & Capabilities

### 1. Interceptor & Proxy Middleware
- Sits inline between any AI Agent orchestrator and MCP tool runtimes.
- Intercepts requests in real time, inspecting prompts, parameter payloads, and tool metadata **before execution**.

### 2. Cryptographic SHA-256 Provenance Verification
- Computes canonical SHA-256 digests of tool code, schemas, and signatures.
- Rejects any tampered, modified, or unauthorized tool with an **Integrity Failure Block** before tool runtime execution.

### 3. Dynamic Multi-Vector Threat Engine (0–100 Real-Time Score)
- **Zero Static Keyword Lists**: Employs structural entropy, adversarial delimiter detection, and linguistic intent analysis.
- **Three Risk Vectors**:
  1. **Intent Analysis**: Prompt injection, role hijacking (`DAN`, system overrides), data exfiltration channels (outbound webhooks, markdown leaks).
  2. **Schema & Boundary Violations**: Parameter length overflows, SQL injection patterns, command chaining, path traversal sequences (`../../etc/shadow`).
  3. **Behavior Drift Detection**: Statistical frequency anomalies, velocity spikes, and unauthorized tool transitions.
- **Threshold Policy**: If `Threat Score > 50`, request is intercepted, quarantined, and dropped immediately.

### 4. Interactive Hackathon Demo Dashboard
- **Section A: Live Attack Test Bench**:
  - Open prompt editor for judges to type any arbitrary attack payload.
  - **Firewall Guard Toggle (ON / OFF)**:
    - **ON**: Intercepts attacks, blocks malicious tools, returns sanitized explanations.
    - **OFF**: Demonstrates the raw vulnerability by showing simulated data breach / credential leaks!
  - 3 Quick-Action Buttons for judges:
    1. *Safe Request* (Normal Gmail query)
    2. *Prompt Injection Attack* (Command override & Exfiltration)
    3. *Tampered Tool / Provenance Failure* (Modified tool code execution)
- **Section B: Interactive Architecture Pipeline Visualizer**:
  - Live animated visual data path: `[ AI Agent ] ──> [ Sentinel Proxy ] ──> [ MCP Server ]`.
  - Visual color states: **Green** (Safe), **Red Alert** (Firewall Intercepted), **Amber** (Compromised when Firewall is OFF).
- **Section C: Real-Time Telemetry & Forensics Terminal**:
  - Live security indicator (`SECURE` / `THREAT DETECTED` / `COMPROMISED`).
  - Real-time latency tracking (sub-12ms inspection overhead).
  - Multi-vector risk breakdown (Intent / Schema / Drift).
  - Forensic execution log with copyable audit records.
- **Bonus: Live Tool Registry & Supply Chain Tamper Lab**:
  - One-click tool code tampering to demonstrate real-time cryptographic provenance failure.

---

## 🚀 Quick Start Instructions

### Prerequisites
- **Node.js**: v18 or higher (v20+ recommended)
- **npm**: v9 or higher

### 1. Install Dependencies
```bash
npm install
```

### 2. Run Automated Verification Tests
```bash
node tests/verify_firewall.js
```
*Expected: 10/10 assertions pass (cryptographic provenance, prompt injection interception, SQL boundary escape, and bypass simulation).*

### 3. Launch the Application (Backend + Frontend)
```bash
npm run dev
```

- **Frontend Dashboard**: Open your browser at [http://localhost:5174](http://localhost:5174)
- **Backend API Server**: Runs on [http://localhost:3002](http://localhost:3002)

---

## 🧪 Hackathon Judge Demo Script

1. **Step 1: Normal Operation (Safe Request)**
   - Click the quick-action button **"1. Safe Request"**.
   - Click **"Run Inspection"**.
   - Notice: Threat Score is 0–15, Provenance is **VERIFIED**, Pipeline lights up **Green**, and authentic Gmail inbox results are returned.

2. **Step 2: Prompt Injection & Exfiltration Defense**
   - Click **"2. Prompt Injection Attack"** (with Firewall Guard **ON**).
   - Click **"Run Inspection"**.
   - Notice: Threat Score spikes to 92/100, Pipeline flashes **Red Barrier** at the Firewall Proxy, the tool is never invoked, and a sanitized security block notice is displayed.

3. **Step 3: Demonstrating the Danger (Firewall OFF)**
   - Toggle the **Firewall Guard** switch to **OFF**.
   - Click **"Run Inspection"**.
   - Notice: The pipeline turns **Amber/Red Warning**, status shows **COMPROMISED**, and simulated executive credential leaks and confidential memos are dumped.

4. **Step 4: Cryptographic Provenance Failure (Supply Chain Attack)**
   - Turn the **Firewall Guard** back **ON**.
   - In the **MCP Tool Registry & Provenance Lab** (lower left), click **"Inject Tamper Code"** on any tool (or click Quick-Action **"3. Tampered Tool / Provenance Failure"**).
   - Click **"Run Inspection"**.
   - Notice: Cryptographic SHA-256 mismatch is immediately flagged, status changes to **INTEGRITY FAILURE**, and execution is strictly blocked before the backdoored tool code can run!

---

## 📂 Project Structure

```
agent-firewall-demo/
├── server/
│   ├── index.js          # Express API server & telemetry endpoints
│   ├── proxy.js          # Interceptor middleware & simulation runtime
│   ├── provenance.js     # Cryptographic SHA-256 tool registry & tamper simulation
│   └── threatEngine.js   # Dynamic semantic & heuristic multi-vector engine
├── src/
│   ├── App.jsx           # Cyber-defense React dashboard with 3 main sections
│   ├── index.css         # Dark theme styling, glowing keyframes, cyber-grid
│   └── main.jsx          # React DOM entry point
├── tests/
│   └── verify_firewall.js # Automated verification test suite
├── index.html            # Single page app template
├── vite.config.js        # Vite dev & proxy config
├── tailwind.config.js    # Cyber theme color tokens & animations
└── package.json          # Full stack scripts & dependencies
```
