// server/mcpClient.js
// Genuine MCP JSON-RPC 2.0 Client with Ed25519 provenance signing

import { signMessage, verifyMessage, getPublicKey } from './provenance.js';
import { v4 as uuidv4 } from 'uuid';

export const SENTINEL_ENDPOINT = 'http://localhost:3002/mcp';
export const DOWNSTREAM_ENDPOINT = 'http://localhost:3003/mcp';

/**
 * Execute standard MCP JSON-RPC request
 */
export async function mcpRequest(method, params = {}, targetUrl = SENTINEL_ENDPOINT, timeoutMs = 8000) {
  const id = 'req_' + uuidv4();
  const payload = {
    jsonrpc: '2.0',
    id,
    method,
    params
  };

  const payloadStr = JSON.stringify(payload);
  const signature = signMessage(payloadStr);
  const publicKey = getPublicKey();

  const resp = await fetch(targetUrl, {
    method: 'POST',
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      'Content-Type': 'application/json',
      'X-MCP-Client': 'Sentinel-Agent-Client/1.0',
      'X-MCP-Signature': signature,
      'X-MCP-PublicKey': Buffer.from(publicKey).toString('base64')
    },
    body: JSON.stringify({
      ...payload,
      signature,
      publicKey
    })
  });

  if (!resp.ok && resp.status !== 400 && resp.status !== 403 && resp.status !== 500) {
    throw new Error(`HTTP Error ${resp.status}: ${resp.statusText}`);
  }

  const json = await resp.json();

  // If JSON-RPC error
  if (json.error) {
    const err = new Error(json.error.message || 'MCP JSON-RPC Error');
    err.code = json.error.code;
    err.data = json.error.data;
    throw err;
  }

  // Optional cryptographic signature check of response
  if (json.signature && json.publicKey) {
    const verified = verifyMessage(JSON.stringify(json.result), json.signature, json.publicKey);
    if (!verified) {
      throw new Error('Cryptographic signature verification failed on MCP response!');
    }
  }

  return json.result;
}

export async function initialize(targetUrl = SENTINEL_ENDPOINT) {
  return mcpRequest('initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'sentinel-client', version: '1.0.0' }
  }, targetUrl);
}

export async function listTools(targetUrl = SENTINEL_ENDPOINT) {
  return mcpRequest('tools/list', {}, targetUrl);
}

export async function callTool(toolName, parameters = {}, targetUrl = SENTINEL_ENDPOINT, meta = {}) {
  return mcpRequest('tools/call', {
    name: toolName,
    arguments: parameters,
    ...meta
  }, targetUrl);
}

export default {
  mcpRequest,
  initialize,
  listTools,
  callTool,
  SENTINEL_ENDPOINT,
  DOWNSTREAM_ENDPOINT
};
