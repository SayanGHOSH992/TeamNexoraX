// server/mcpServer.js
// Real Downstream MCP Server listening on port 3003
// Speaks standard MCP JSON-RPC 2.0 (initialize, tools/list, tools/call)

import express from 'express';
import fs from 'fs';
import path from 'path';
import { incrementExecution, getExecutionCount, getAllTelemetry } from './db.js';

const app = express();
app.use(express.json());

const TOOLS_DIR = path.resolve('server', 'tools');

// Tool definitions schema map for dynamic discovery
const TOOL_METADATA = {
  exec_shell_command: {
    description: 'Executes whitelisted diagnostic commands in an isolated container.',
    inputSchema: {
      type: 'object',
      required: ['command'],
      properties: {
        command: { type: 'string', description: 'Diagnostic command to execute' }
      }
    }
  },
  gmail_search_emails: {
    description: 'Searches user Gmail inbox using query filters.',
    inputSchema: {
      type: 'object',
      required: ['query'],
      properties: {
        query: { type: 'string', description: 'Search query string' },
        maxResults: { type: 'number', default: 5 }
      }
    }
  },
  filesystem_read_file: {
    description: 'Reads files strictly within sandboxed directory.',
    inputSchema: {
      type: 'object',
      required: ['filepath'],
      properties: {
        filepath: { type: 'string', description: 'File path within sandbox' }
      }
    }
  },
  sql_query_runner: {
    description: 'Runs read-only analytical queries against customer metrics DB.',
    inputSchema: {
      type: 'object',
      required: ['query'],
      properties: {
        query: { type: 'string', description: 'SELECT statement' }
      }
    }
  },
  slack_post_message: {
    description: 'Sends notifications to authorized internal Slack channels.',
    inputSchema: {
      type: 'object',
      required: ['channel', 'message'],
      properties: {
        channel: { type: 'string', description: 'Target channel' },
        message: { type: 'string', description: 'Notification message' }
      }
    }
  }
};

// Dynamic discovery of real tools present in server/tools
async function getDiscoveredTools() {
  const files = await fs.promises.readdir(TOOLS_DIR);
  const toolFiles = files.filter(f => f.endsWith('.js'));
  const tools = [];

  for (const file of toolFiles) {
    const toolName = path.basename(file, '.js');
    const meta = TOOL_METADATA[toolName] || {
      description: `Dynamic MCP tool: ${toolName}`,
      inputSchema: { type: 'object' }
    };
    tools.push({
      name: toolName,
      description: meta.description,
      inputSchema: meta.inputSchema
    });
  }
  return tools;
}

// JSON-RPC 2.0 MCP Endpoint
app.post('/mcp', async (req, res) => {
  const { jsonrpc, id, method, params } = req.body || {};

  if (jsonrpc !== '2.0') {
    return res.status(400).json({
      jsonrpc: '2.0',
      id: id || null,
      error: { code: -32600, message: 'Invalid Request: jsonrpc must be "2.0"' }
    });
  }

  try {
    switch (method) {
      case 'initialize': {
        return res.json({
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: '2024-11-05',
            capabilities: {
              tools: { listChanged: false }
            },
            serverInfo: {
              name: 'real-mcp-server',
              version: '1.0.0'
            }
          }
        });
      }

      case 'tools/list': {
        const tools = await getDiscoveredTools();
        return res.json({
          jsonrpc: '2.0',
          id,
          result: { tools }
        });
      }

      case 'tools/call': {
        const toolName = params?.name || params?.toolName;
        const toolArgs = params?.arguments || params?.parameters || {};

        if (!toolName) {
          return res.status(400).json({
            jsonrpc: '2.0',
            id,
            error: { code: -32602, message: 'Missing tool name in params' }
          });
        }

        const toolPath = path.join(TOOLS_DIR, `${toolName}.js`);
        if (!fs.existsSync(toolPath)) {
          return res.status(404).json({
            jsonrpc: '2.0',
            id,
            error: { code: -32601, message: `Tool not found: ${toolName}` }
          });
        }

        // Dynamically import and execute real tool
        const toolModule = await import(`file://${toolPath}?t=${Date.now()}`);
        if (!toolModule || typeof toolModule.execute !== 'function') {
          return res.status(500).json({
            jsonrpc: '2.0',
            id,
            error: { code: -32603, message: `Tool ${toolName} has no execute function` }
          });
        }

        const execResult = await toolModule.execute(toolArgs);

        // Record real execution count in DB
        await incrementExecution(toolName);
        const currentCount = await getExecutionCount(toolName);

        return res.json({
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: typeof execResult === 'string' ? execResult : JSON.stringify(execResult)
              }
            ],
            isError: execResult?.success === false,
            executedTool: toolName,
            executionCount: currentCount,
            rawOutput: execResult
          }
        });
      }

      default:
        return res.status(404).json({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `Method not found: ${method}` }
        });
    }
  } catch (err) {
    console.error('MCP Server execution error:', err);
    return res.status(500).json({
      jsonrpc: '2.0',
      id,
      error: { code: -32603, message: err.message }
    });
  }
});

// Telemetry endpoint
app.get('/api/telemetry', async (req, res) => {
  try {
    const rows = await getAllTelemetry();
    res.json({ success: true, telemetry: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

const PORT = process.env.MCP_PORT || 3003;
const server = app.listen(PORT, () => {
  console.log(`🚀 Real MCP Server listening on http://localhost:${PORT}`);
});

export default app;
