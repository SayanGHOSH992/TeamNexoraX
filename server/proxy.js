import { verifyToolProvenance, getAllTools } from './provenance.js';
import { inspectPayload } from './threatEngine.js';

// Rolling telemetry forensics buffer
const forensicTelemetryLog = [];

// Dynamically load and execute real tool implementations

// Inspect and redact confidential tokens from downstream tool responses
export function inspectAndRedactResponse(rawResult) {
  if (!rawResult) return { redacted: false, result: rawResult };

  const text = typeof rawResult === 'string' ? rawResult : JSON.stringify(rawResult);
  let redactedText = text;
  let sensitiveFound = false;
  const detectedSensitivities = [];

  const patterns = [
    { regex: /AKIA[0-9A-Z]{16}/g, label: 'AWS Access Key ID' },
    { regex: /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[:=]\s*["']?[A-Za-z0-9\/+=]{40}["']?/g, label: 'AWS Secret Access Key' },
    { regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g, label: 'RSA Private Key' },
    { regex: /(?:Bearer\s+)[a-zA-Z0-9_\-\.]{25,}/gi, label: 'Bearer Token' },
    { regex: /(?:ghp_[a-zA-Z0-9]{36})/g, label: 'GitHub Personal Access Token' }
  ];

  for (const { regex, label } of patterns) {
    if (regex.test(redactedText)) {
      sensitiveFound = true;
      detectedSensitivities.push(label);
      redactedText = redactedText.replace(regex, `[REDACTED_${label.toUpperCase().replace(/\s+/g, '_')}_BY_SENTINEL]`);
    }
  }

  let finalResult = rawResult;
  if (sensitiveFound) {
    try {
      finalResult = typeof rawResult === 'string' ? redactedText : JSON.parse(redactedText);
    } catch {
      finalResult = redactedText;
    }
  }

  return {
    redacted: sensitiveFound,
    detectedSensitivities,
    result: finalResult
  };
}

// Forward tool execution to the real MCP server
async function executeRealTool(name, params) {
  try {
    // Use the genuine MCP JSON-RPC client targeting downstream MCP server
    const { mcpRequest, DOWNSTREAM_ENDPOINT } = await import('./mcpClient.js');
    const result = await mcpRequest('tools/call', { name, arguments: params }, DOWNSTREAM_ENDPOINT);
    const raw = result.rawOutput || result;
    const { redacted, detectedSensitivities, result: safeResult } = inspectAndRedactResponse(raw);
    return {
      success: true,
      result: safeResult,
      redacted,
      detectedSensitivities
    };
  } catch (e) {
    console.error('MCP tool execution error:', e);
    return { success: false, error: e.message };
  }
}

/**
 * Generates realistic simulation results for tool executions
 */
function simulateToolExecution(toolName, parameters, isCompromised = false) {
  if (isCompromised) {
    switch (toolName) {
      case 'gmail_search_emails':
        return {
          status: 'LEAKED_DATA',
          compromisedVector: 'UNAUTHORIZED_EXFILTRATION',
          exfiltratedData: [
            { id: 'msg_9841', from: 'cfo@company-corp.com', subject: 'CONFIDENTIAL: Q3 Financial Audit & Bank Details', snippet: 'Wire routing: 021000021, Account: 8829-4921-99, Master Passcode: corp_treasury_2026!' },
            { id: 'msg_9842', from: 'security-alerts@internal.corp', subject: 'Production AWS Root Keys - DO NOT FORWARD', snippet: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE, AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' },
            { id: 'msg_9843', from: 'ceo@company-corp.com', subject: 'Board Meeting Acquisition Target Memo', snippet: 'Project Phoenix target: Helios AI for $420M. Keep strictly off the record.' }
          ],
          systemAlert: '🚨 COMPROMISE WARNING: AI Agent exfiltrated confidential executive mail and credentials to unvetted downstream sink!'
        };
      case 'filesystem_read_file':
        return {
          status: 'ARBITRARY_FILE_READ',
          compromisedVector: 'SANDBOX_ESCAPE',
          fileContents: `root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n# MASTER DB CREDENTIALS:\nDATABASE_URL="postgres://admin:Sup3rS3cr3tP@ssw0rd!@internal-prod-db:5432/main"\nJWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0w9+..."`,
          systemAlert: '🚨 COMPROMISE WARNING: Agent executed path traversal and read host system shadow credentials!'
        };
      case 'sql_query_runner':
        return {
          status: 'DATABASE_EXPLOITATION',
          compromisedVector: 'SQL_INJECTION',
          dumpedTables: [
            { user: 'admin', pass_hash: '$2b$12$K89sJ...w2', role: 'SUPERUSER', ssn: '992-01-4482', card_number: '4111-2222-3333-4444' },
            { user: 'sysops', pass_hash: '$2b$12$L77uN...q1', role: 'CLUSTER_ADMIN', ssn: '812-44-1192', card_number: '4242-4242-4242-4242' }
          ],
          systemAlert: '🚨 COMPROMISE WARNING: Unrestricted SQL injection extracted user tables and hashed credentials!'
        };
      default:
        return {
          status: 'ARBITRARY_CODE_EXECUTION',
          compromisedVector: 'UNCHECKED_EXECUTION',
          output: `[ATTACK SUCCESSFUL] Injected payload executed with root permissions. C2 reverse shell established to external gateway. Exfiltrating environment secrets...`,
          systemAlert: '🚨 COMPROMISE WARNING: Rogue tool code or command injected without firewall guardrails!'
        };
    }
  }

  // Authentic Safe Output
  switch (toolName) {
    case 'gmail_search_emails':
      return {
        status: 'SUCCESS',
        queryExecuted: parameters.query || 'general query',
        resultsFound: 2,
        messages: [
          { id: 'msg_101', from: 'calendar-notification@google.com', subject: 'Hackathon Demo Schedule - Tomorrow 10:00 AM', date: '2026-09-11' },
          { id: 'msg_102', from: 'team@developer.org', subject: 'Release notes v2.4 confirmed', date: '2026-09-10' }
        ]
      };
    case 'filesystem_read_file':
      return {
        status: 'SUCCESS',
        filepath: parameters.filepath,
        content: `{"status": "ok", "app": "demo-service", "version": "1.0.0", "healthy": true}`
      };
    case 'sql_query_runner':
      return {
        status: 'SUCCESS',
        queryExecuted: parameters.query,
        rows: [
          { metric_name: 'total_active_users', count: 14205 },
          { metric_name: 'average_latency_ms', count: 14 }
        ]
      };
    case 'exec_shell_command':
      return {
        status: 'SUCCESS',
        command: parameters.command,
        output: `up 14 days, 3:22, 2 users, load average: 0.12, 0.08, 0.05`
      };
    case 'slack_post_message':
      return {
        status: 'SUCCESS',
        channel: parameters.channel,
        sentTimestamp: new Date().toISOString(),
        messageDelivered: true
      };
    default:
      return { status: 'SUCCESS', message: 'Executed safely within sandbox boundary.' };
  }
}

/**
 * The Sentinel Interceptor Middleware
 */
export async function interceptAndInspect({
  toolName = 'gmail_search_emails',
  parameters = {},
  agentPrompt = '',
  firewallEnabled = true
}) {
  const eventId = 'sec_' + Math.random().toString(36).substring(2, 9);
  const timestamp = new Date().toISOString();

  // Retrieve tool metadata
  const allTools = getAllTools();
  const tool = allTools.find(t => t.name === toolName);

  // 1. Provenance Cryptographic Verification
  const provenance = verifyToolProvenance(toolName);

  // 2. Dynamic Semantic & Heuristic Threat Inspection
  const threatResult = inspectPayload({
    tool,
    toolName,
    parameters,
    prompt: agentPrompt
  });

  // Evaluate final defense decision
  let finalStatus = 'PASSED';
  let blockReason = null;
  let simulatedOutput = null;

  // Check if Provenance Failed
  if (!provenance.verified) {
    if (firewallEnabled) {
      finalStatus = 'BLOCKED';
      blockReason = provenance.status === 'UNREGISTERED_TOOL'
        ? `UNREGISTERED TOOL: Tool '${toolName}' is not registered in the MCP manifest authority!`
        : 'INTEGRITY FAILURE: Cryptographic SHA-256 hash mismatch! Tool binary has been tampered with or modified unauthorizedly.';
      threatResult.threatScore = 98;
      threatResult.blocked = true;
      threatResult.category = provenance.status === 'UNREGISTERED_TOOL'
        ? 'Unregistered Tool Execution Attempt'
        : 'Cryptographic Provenance Failure / Supply Chain Tampering';
      threatResult.triggers.unshift({
        vector: 'Provenance',
        name: provenance.status === 'UNREGISTERED_TOOL'
          ? `Unregistered Tool Blocked: '${toolName}'`
          : 'Cryptographic SHA-256 Signature Mismatch (Untrusted Binary)',
        severity: 'CRITICAL',
        impact: 98
      });
      simulatedOutput = {
        blockNotice: '🛑 SENTINEL INTERCEPT: Execution strictly blocked at Provenance Verification Gate.',
        reason: blockReason,
        expectedSha256: provenance.goldenHash,
        detectedSha256: provenance.actualHash,
        remedy: 'Re-authenticate tool manifest signature or rollback unauthorized code mutation.'
      };
    } else {
      // Firewall OFF: Tampered tool backdoor runs!
      finalStatus = 'COMPROMISED';
      simulatedOutput = {
        warning: '⚠️ FIREWALL DISABLED: Tampered tool executed without cryptographic verification!',
        backdoorDetails: provenance.tamperDetails,
        payloadExecution: simulateToolExecution(toolName, parameters, true)
      };
    }
  } else if (threatResult.threatScore > 50) {
    // Provenance valid, but Threat Engine triggered!
    if (firewallEnabled) {
      finalStatus = 'BLOCKED';
      blockReason = `THREAT SCORE THRESHOLD EXCEEDED (${threatResult.threatScore}/100): ${threatResult.category}`;
      simulatedOutput = {
        blockNotice: '🛡️ SENTINEL FIREWALL INTERCEPT: Malicious intent or schema boundary violation blocked before reaching MCP Server.',
        quarantineAction: 'Execution dropped. Zero outbound socket or tool transmission allowed.',
        category: threatResult.category,
        threatScore: threatResult.threatScore,
        violationSummary: threatResult.triggers.map(t => `[${t.vector}] ${t.name}`).join(' | '),
        sanitizedFeedback: 'Agent request was sanitized. No data was leaked.'
      };
    } else {
      // Firewall OFF: Malicious attack successfully breaches!
      finalStatus = 'COMPROMISED';
      simulatedOutput = simulateToolExecution(toolName, parameters, true);
    }
  } else {
    // Safe request!
    finalStatus = 'PASSED';
    simulatedOutput = await executeRealTool(toolName, parameters);
  }

  // Construct Telemetry Record
  const telemetryRecord = {
    id: eventId,
    timestamp,
    toolName,
    agentPrompt: agentPrompt.length > 80 ? agentPrompt.substring(0, 80) + '...' : agentPrompt,
    firewallEnabled,
    status: finalStatus,
    threatScore: threatResult.threatScore,
    category: threatResult.category,
    latencyMs: threatResult.inspectionLatencyMs,
    provenanceStatus: provenance.verified ? 'VERIFIED' : 'MISMATCH',
    provenanceHash: provenance.actualHash ? provenance.actualHash.substring(0, 16) + '...' : 'N/A',
    vectorBreakdown: threatResult.vectors,
    triggersCount: threatResult.triggers.length
  };

  // Prepend to telemetry stream (max 50 events)
  forensicTelemetryLog.unshift(telemetryRecord);
  if (forensicTelemetryLog.length > 50) forensicTelemetryLog.pop();

  return {
    eventId,
    timestamp,
    toolName,
    firewallEnabled,
    status: finalStatus,
    blockReason,
    provenance,
    threatEngine: threatResult,
    output: simulatedOutput,
    telemetryHistory: forensicTelemetryLog.slice(0, 10)
  };
}

export function getTelemetryHistory() {
  return forensicTelemetryLog;
}
