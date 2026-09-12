// server/mcp.js
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { verifyToolProvenance } from './provenance.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = express.Router();

router.post('/api/mcp/:toolName', async (req, res) => {
  const { toolName } = req.params;
  const params = req.body.parameters || {};
  const provenance = verifyToolProvenance(toolName);
  if (!provenance.verified) {
    return res.status(400).json({ success: false, error: 'Tool provenance verification failed', provenance });
  }
  try {
    const toolModule = await import(`./tools/${toolName}.js`);
    if (!toolModule || typeof toolModule.execute !== 'function') {
      return res.status(404).json({ success: false, error: 'Tool implementation not found' });
    }
    const result = await toolModule.execute(params);
    return res.json({ success: true, toolName, result, provenance });
  } catch (err) {
    console.error('MCP tool execution error:', err);
    return res.status(500).json({ success: false, error: err.message, provenance });
  }
});

export default router;
