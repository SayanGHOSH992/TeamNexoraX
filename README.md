# 🛡️ Arachne

> **Runtime AI Agent Firewall & Cryptographic Provenance Layer for Model Context Protocol (MCP)**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Protocol](https://img.shields.io/badge/MCP-JSON--RPC%202.0-blueviolet)](https://modelcontextprotocol.io)
[![Cryptography](https://img.shields.io/badge/Provenance-SHA--256%20%2B%20Ed25519-green)](https://en.wikipedia.org/wiki/EdDSA)
[![Security Policy](https://img.shields.io/badge/Policy-Zero--Reach-red)](https://github.com)

Sentinel-MCP is an inline security gateway situated between AI agents and MCP tool servers. It enforces real-time threat inspection, SHA-256 tool provenance verification, and **Zero-Reach** execution blocking against malicious requests.

---

## ⚡ Key Features

- **Inline JSON-RPC 2.0 Gateway**: Transparently proxies MCP methods (`initialize`, `tools/list`, `tools/call`).
- **Cryptographic Provenance**: SHA-256 golden hash verification for tool code + Ed25519 payload signatures.
- **Multi-Vector Threat Engine**: Real-time 0–100 scoring for prompt injections, jailbreaks, data exfiltration, SQLi, and path traversal.
- **Zero-Reach Guarantee**: Blocked or tampered calls are dropped before reaching downstream tool runtimes.
- **Interactive Dashboard**: Cyber-defense control center with attack simulation bench, pipeline visualizer, and live forensics telemetry.
- **Persistent Telemetry**: SQLite-backed audit trails (`server/mcp.db`) capturing inspection verdicts and latency metrics.

---

## 🏗️ Architecture & Data Flow

```
[ AI Agent Orchestrator ]
         │ (Signed JSON-RPC 2.0)
         ▼
[ Sentinel Gateway :3002 ] ──> [ Provenance & Threat Engine ]
         │
         ├─── (Threat Score > 50 OR Hash Mismatch) ──> 🚫 Blocked (Zero-Reach)
         │
         └─── (Verified & Score <= 50)
                     │
                     ▼
         [ Downstream MCP Server :3003 ] ──> [ Sandboxed Tools ]
```

---

## 🚀 Quick Start & Deployment

### 1. Installation

```bash
git clone <repository-url>
cd nexora
npm install
```

### 2. Development Mode

Starts the Gateway (Port `3002`), Downstream MCP Server (Port `3003`), and Web Dashboard (Port `5174`):

```bash
npm run dev
```

- **Dashboard**: [http://localhost:5174](http://localhost:5174)
- **Sentinel Gateway**: [http://localhost:3002](http://localhost:3002)
- **Downstream MCP Server**: [http://localhost:3003](http://localhost:3003)

### 3. Production Deployment

```bash
# Build optimized frontend bundle
npm run build

# Start unified production server
npm start
```

---

## 📡 API Reference

### MCP JSON-RPC 2.0 (`POST /mcp`)

- **`initialize`**: Protocol handshake & capability negotiation.
- **`tools/list`**: Returns registered tools enriched with provenance verification state.
- **`tools/call`**: Intercepts, scores, and proxies tool execution.

### REST Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/inspect` | `POST` | Inspect and execute an agent request through the firewall |
| `/api/tools` | `GET` | List all tools with SHA-256 provenance status |
| `/api/tools/:id/tamper` | `POST` | Tamper a tool's code hash (simulating supply-chain attack) |
| `/api/tools/reset` | `POST` | Reset all tools to canonical golden hashes |
| `/api/telemetry` | `GET` | Retrieve persistent audit and telemetry logs |
| `/api/health` | `GET` | Service health check |

---

## 🧪 Testing

```bash
# Run core verification suite (10/10 assertions)
npm test

# Run end-to-end integration tests
npm run test:e2e

# Run security & zero-reach validations
npm run test:security

# Run all test suites
npm run test:all
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
