// server/mcpRpcHandler.js
// Sentinel-MCP JSON-RPC 2.0 Gateway & Interceptor Router

import express from 'express';
import { verifyToolProvenance } from './provenance.js';
import { signMessage, getPublicKey } from './provenance.js';
import { interceptAndInspect } from './proxy.js';
import { mcpRequest, DOWNSTREAM_ENDPOINT } from './mcpClient.js';

const router = express.Router();
router.use(express.json());

router.post('/mcp', async (req, res) => {
  const { jsonrpc, id, method, params } = req.body || {};

  if (jsonrpc !== '2.0') {
    return res.status(400).json({
      jsonrpc: '2.0',
      id: id || null,
      error: { code: -32600, message: 'Invalid Request: jsonrpc must be "2.0"' }
    });
  }

  try {
    // If request contains an Ed25519 cryptographic signature, verify request provenance
    if (req.body.signature && req.body.publicKey) {
      const { signature, publicKey, ...unsignedPayload } = req.body;
      const { verifyMessage } = await import('./provenance.js');
      const isValid = verifyMessage(JSON.stringify(unsignedPayload), signature, publicKey);
      if (!isValid) {
        return res.status(401).json({
          jsonrpc: '2.0',
          id: id || null,
          error: {
            code: -32002,
            message: 'Cryptographic Provenance Failure: Ed25519 request signature is invalid or tampered with!',
            data: { zeroReach: true, status: 'SIGNATURE_REJECTED' }
          }
        });
      }
    }

    switch (method) {
      case 'initialize': {
        // Sentinel Gateway negotiates MCP capabilities
        const result = {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: { listChanged: false },
            securityGateways: ['Sentinel-Firewall/1.0'],
            provenanceVerification: 'SHA-256/Ed25519',
            zeroReachBlockedCalls: true
          },
          serverInfo: {
            name: 'sentinel-mcp-firewall-gateway',
            version: '1.0.0'
          },
          serverPublicKey: getPublicKey()
        };

        const response = { jsonrpc: '2.0', id, result };
        response.signature = signMessage(JSON.stringify(result));
        response.publicKey = getPublicKey();
        return res.json(response);
      }

      case 'tools/list': {
        // Query downstream MCP server dynamically via JSON-RPC
        const downstreamRes = await mcpRequest('tools/list', {}, DOWNSTREAM_ENDPOINT);
        const toolsList = downstreamRes?.tools || [];

        // Enrich real tools with cryptographic provenance verification
        const enrichedTools = toolsList.map(tool => {
          const prov = verifyToolProvenance(tool.name);
          return {
            ...tool,
            provenance: {
              verified: prov.verified,
              status: prov.status,
              goldenHash: prov.goldenHash,
              actualHash: prov.actualHash,
              isTampered: prov.isTampered,
              tamperDetails: prov.tamperDetails
            }
          };
        });

        const result = { tools: enrichedTools };
        const response = { jsonrpc: '2.0', id, result };
        response.signature = signMessage(JSON.stringify(result));
        response.publicKey = getPublicKey();
        return res.json(response);
      }

      case 'tools/call': {
        const toolName = params?.name || params?.toolName;
        const toolArgs = params?.arguments || params?.parameters || {};
        const agentPrompt = params?.agentPrompt || params?.prompt || '';
        const firewallEnabled = params?.firewallEnabled !== undefined ? params.firewallEnabled : true;

        if (!toolName) {
          return res.status(400).json({
            jsonrpc: '2.0',
            id,
            error: { code: -32602, message: 'Missing tool name in params' }
          });
        }

        // Intercept & inspect through Sentinel Firewall
        const report = await interceptAndInspect({
          toolName,
          parameters: toolArgs,
          agentPrompt,
          firewallEnabled
        });

        if (report.status === 'BLOCKED') {
          // STRICT ZERO-REACH GUARANTEE: Downstream is NOT called!
          const blockError = {
            jsonrpc: '2.0',
            id,
            error: {
              code: -32001,
              message: `[SENTINEL_BLOCKED] ${report.blockReason}`,
              data: {
                status: 'BLOCKED',
                reason: report.blockReason,
                category: report.threatEngine?.category,
                threatScore: report.threatEngine?.threatScore,
                provenanceStatus: report.provenance?.status,
                zeroReach: true,
                triggers: report.threatEngine?.triggers || []
              }
            }
          };
          blockError.signature = signMessage(JSON.stringify(blockError.error));
          blockError.publicKey = getPublicKey();
          return res.status(403).json(blockError);
        }

        // ALLOWED: report.output contains real execution from downstream MCP server
        const result = {
          status: report.status,
          toolName,
          output: report.output?.result || report.output,
          threatScore: report.threatEngine?.threatScore,
          provenance: report.provenance,
          eventId: report.eventId
        };

        const response = { jsonrpc: '2.0', id, result };
        response.signature = signMessage(JSON.stringify(result));
        response.publicKey = getPublicKey();
        return res.json(response);
      }

      default: {
        return res.status(404).json({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `Method '${method}' not recognized` }
        });
      }
    }
  } catch (err) {
    console.error('Sentinel MCP Gateway error:', err);
    return res.status(500).json({
      jsonrpc: '2.0',
      id,
      error: { code: -32603, message: err.message }
    });
  }
});

export default router;
