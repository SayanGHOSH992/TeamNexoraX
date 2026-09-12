import express from 'express';
import cors from 'cors';
import './mcpServer.js';
import { interceptAndInspect, getTelemetryHistory } from './proxy.js';
import mcpRpcHandler from './mcpRpcHandler.js';
import { getAllTools, tamperTool, resetTools } from './provenance.js';

const app = express();
const PORT = process.env.PORT || 3002;

app.use(cors());
app.use(express.json());

// Request logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ACTIVE',
    service: 'Sentinel-MCP Runtime Firewall & Provenance Layer',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Get all tools and their SHA-256 provenance status
app.get('/api/tools', (req, res) => {
  const tools = getAllTools();
  res.json({ success: true, tools });
});

// Tamper tool code/signature to simulate supply chain attack
app.post('/api/tools/:id/tamper', (req, res) => {
  const toolId = req.params.id;
  const tampered = tamperTool(toolId, req.body.customModification);
  if (!tampered) {
    return res.status(404).json({ success: false, error: 'Tool not found' });
  }
  res.json({
    success: true,
    message: `Tool '${toolId}' code signature has been tampered with. Cryptographic hash invalidated!`,
    tool: tampered
  });
});

// Reset tool registry to canonical golden hashes
app.post('/api/tools/reset', (req, res) => {
  const tools = resetTools();
  res.json({
    success: true,
    message: 'All tool cryptographic signatures reset to trusted canonical baselines.',
    tools
  });
});

// Main Interceptor & Proxy Inspection endpoint
app.post('/api/inspect', async (req, res) => {
  try {
    const { toolName, parameters, agentPrompt, firewallEnabled } = req.body;
    const inspectionReport = await interceptAndInspect({
      toolName,
      parameters,
      agentPrompt,
      firewallEnabled: firewallEnabled !== undefined ? firewallEnabled : true
    });
    res.json({ success: true, data: inspectionReport });
  } catch (err) {
    console.error('Inspection error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get telemetry audit stream
app.get('/api/telemetry', (req, res) => {
  const telemetry = getTelemetryHistory();
  res.json({ success: true, telemetry });
});

// Serve production frontend assets if built
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distPath = path.resolve(__dirname, '../dist');

if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
  app.get('*', (req, res, next) => {
    if (req.url.startsWith('/api')) return next();
    res.sendFile(path.join(distPath, 'index.html'));
  });
}

app.use(mcpRpcHandler);
app.listen(PORT, () => {
  console.log(`🛡️ Sentinel-MCP Firewall & Provenance Server running on http://localhost:${PORT}`);
});

