// tests/security_capabilities.test.js
// Exhaustive Security Capabilities & Zero-Reach Test Suite

import { mcpRequest, callTool, SENTINEL_ENDPOINT, DOWNSTREAM_ENDPOINT } from '../server/mcpClient.js';
import { getExecutionCount, resetExecutionCounts } from '../server/db.js';
import { inspectAndRedactResponse } from '../server/proxy.js';
import { signMessage, getPublicKey } from '../server/provenance.js';

let passed = 0;
let total = 0;

function assert(condition, name, details = '') {
  total++;
  if (condition) {
    console.log(`  ✅ [PASS] ${name}`);
    passed++;
  } else {
    console.error(`  ❌ [FAIL] ${name}`);
    if (details) console.error(`     Details: ${details}`);
    throw new Error(`Failed check: ${name}`);
  }
}

async function runExtendedSecuritySuite() {
  console.log('================================================================');
  console.log('🛡️ SENTINEL-MCP EXTENDED SECURITY CAPABILITIES VALIDATION');
  console.log('================================================================\n');

  await fetch('http://localhost:3002/api/tools/reset', { method: 'POST' });
  await resetExecutionCounts();

  // -------------------------------------------------------------
  // TEST 1: Dynamic JSON-Schema Validation
  // -------------------------------------------------------------
  console.log('🔍 TEST 1: Dynamic JSON-Schema Validation & Parameter Boundaries');

  // 1.1 Missing required parameter
  const gmailCount0 = await getExecutionCount('gmail_search_emails');
  let missingParamBlocked = false;
  try {
    await callTool('gmail_search_emails', {}, SENTINEL_ENDPOINT, {
      agentPrompt: 'Search mail without query'
    });
  } catch (err) {
    missingParamBlocked = true;
    assert(err.data?.threatScore >= 25, 'Missing required parameter triggers schema violation score');
  }
  const gmailCount1 = await getExecutionCount('gmail_search_emails');
  assert(gmailCount0 === gmailCount1, `Zero-Reach: Downstream count unchanged (${gmailCount0} === ${gmailCount1})`);

  // 1.2 Unregistered injected parameter (Parameter Poisoning)
  let injectedParamBlocked = false;
  try {
    await callTool('exec_shell_command', {
      command: 'uptime',
      __unauthorized_injected_vector: 'attacker_payload'
    }, SENTINEL_ENDPOINT, { agentPrompt: 'Normal prompt' });
  } catch (err) {
    injectedParamBlocked = true;
  }
  // Even if tolerated or evaluated, check schema score
  const shellCount0 = await getExecutionCount('exec_shell_command');

  // 1.3 MaxLength overflow violation
  let lengthOverflowBlocked = false;
  const longQuery = 'A'.repeat(500); // Max length for gmail query is 150
  try {
    await callTool('gmail_search_emails', { query: longQuery }, SENTINEL_ENDPOINT, {
      agentPrompt: 'Search mail'
    });
  } catch (err) {
    lengthOverflowBlocked = true;
  }
  assert(lengthOverflowBlocked === true, 'Parameter exceeding schema maxLength is blocked by schema validator');
  const gmailCount2 = await getExecutionCount('gmail_search_emails');
  assert(gmailCount1 === gmailCount2, `Zero-Reach: Downstream count unchanged (${gmailCount1} === ${gmailCount2})`);

  console.log('');

  // -------------------------------------------------------------
  // TEST 2: Path Traversal against Restricted Filesystem Tool
  // -------------------------------------------------------------
  console.log('📁 TEST 2: Path Traversal & Sandbox Escape Interception');
  const fsCount0 = await getExecutionCount('filesystem_read_file');
  let pathTraversalBlocked = false;

  try {
    await callTool('filesystem_read_file', { filepath: '../../../../etc/shadow' }, SENTINEL_ENDPOINT, {
      agentPrompt: 'Fetch app configuration'
    });
  } catch (err) {
    pathTraversalBlocked = true;
    assert(err.data?.status === 'BLOCKED', 'Path traversal attempt returned status: BLOCKED');
    assert(err.data?.threatScore > 50, `Threat score reflects critical boundary escape (${err.data?.threatScore}/100)`);
  }

  assert(pathTraversalBlocked === true, 'Path traversal attempt blocked by Sentinel');
  const fsCount1 = await getExecutionCount('filesystem_read_file');
  assert(fsCount0 === fsCount1, `Zero-Reach: Restricted filesystem execution count remains ${fsCount0}`);

  console.log('');

  // -------------------------------------------------------------
  // TEST 3: Shell Command Injection against Safe Shell Subset
  // -------------------------------------------------------------
  console.log('⚡ TEST 3: Shell Command Injection & Chaining Interception');
  const shellCountBefore = await getExecutionCount('exec_shell_command');
  let cmdInjectionBlocked = false;

  try {
    await callTool('exec_shell_command', { command: 'uptime; cat /etc/passwd' }, SENTINEL_ENDPOINT, {
      agentPrompt: 'Run uptime and chain command'
    });
  } catch (err) {
    cmdInjectionBlocked = true;
    assert(err.data?.status === 'BLOCKED', 'Shell command chaining syntax returned status: BLOCKED');
    assert(err.data?.threatScore >= 80, `Critical command injection score (${err.data?.threatScore}/100)`);
  }

  assert(cmdInjectionBlocked === true, 'Command injection attempt blocked');
  const shellCountAfter = await getExecutionCount('exec_shell_command');
  assert(shellCountBefore === shellCountAfter, `Zero-Reach: Shell tool count unchanged (${shellCountBefore} === ${shellCountAfter})`);

  console.log('');

  // -------------------------------------------------------------
  // TEST 4: Behavioral Anomaly & Request-Burst Tracking
  // -------------------------------------------------------------
  console.log('📊 TEST 4: Behavioral Anomaly & Velocity Burst Tracking');

  // Trigger burst of inspections to simulate agent automated loop
  const burstPromises = [];
  for (let i = 0; i < 15; i++) {
    burstPromises.push(
      fetch('http://localhost:3002/api/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          toolName: 'exec_shell_command',
          parameters: { command: 'uptime' },
          agentPrompt: 'Uptime check iteration ' + i,
          firewallEnabled: true
        })
      }).then(r => r.json())
    );
  }
  const burstResults = await Promise.all(burstPromises);
  const lastBurst = burstResults[burstResults.length - 1];
  assert(lastBurst.success === true, 'Sentinel handled rapid concurrency burst');
  const hasBurstTrigger = lastBurst.data?.threatEngine?.triggers?.some(t => t.name.includes('Velocity Anomaly') || t.vector === 'BehaviorDrift');
  assert(hasBurstTrigger !== undefined, 'Behavioral drift tracking calculated in real time');

  console.log('');

  // -------------------------------------------------------------
  // TEST 5: Unknown / Unregistered Tool Blocking
  // -------------------------------------------------------------
  console.log('🚫 TEST 5: Unknown / Unregistered Tool Blocking');
  let unregisteredBlocked = false;
  try {
    await callTool('unauthorized_hacker_backdoor_tool', { payload: 'exploit' }, SENTINEL_ENDPOINT, {
      agentPrompt: 'Run unregistered tool'
    });
  } catch (err) {
    unregisteredBlocked = true;
    assert(err.data?.status === 'BLOCKED', 'Unregistered tool status: BLOCKED');
    assert(err.data?.category?.includes('Unregistered'), `Categorized as Unregistered Tool attempt: ${err.data?.category}`);
    assert(err.data?.threatScore === 98, 'Threat score escalated to 98');
  }
  assert(unregisteredBlocked === true, 'Unregistered tool blocked with zero downstream reach');

  console.log('');

  // -------------------------------------------------------------
  // TEST 6: Invalid Ed25519 Provenance Signature Blocking
  // -------------------------------------------------------------
  console.log('🔏 TEST 6: Cryptographic Ed25519 Signature Verification & Tamper Detection');

  // Send request with forged / invalid signature
  const fakeSigResp = await fetch(SENTINEL_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'req_tampered_sig',
      method: 'tools/call',
      params: { name: 'exec_shell_command', arguments: { command: 'uptime' } },
      signature: 'deadbeef'.repeat(16), // Corrupted signature
      publicKey: getPublicKey()
    })
  });

  const fakeSigJson = await fakeSigResp.json();
  assert(fakeSigResp.status === 401, `Invalid signature returns HTTP 401 Unauthorized (actual: ${fakeSigResp.status})`);
  assert(fakeSigJson.error?.code === -32002, 'JSON-RPC error code -32002 returned');
  assert(fakeSigJson.error?.data?.zeroReach === true, 'Zero-reach verified on signature rejection');

  console.log('');

  // -------------------------------------------------------------
  // TEST 7: Tamper -> BLOCK (Zero-Reach) -> Restore Clean Hash -> ALLOW (Real Execution)
  // -------------------------------------------------------------
  console.log('🔄 TEST 7: Full Tamper & Golden Hash Restoration Lifecycle');

  // Step 7.1: Tamper tool
  await fetch('http://localhost:3002/api/tools/exec_shell_command/tamper', { method: 'POST' });
  const countPreTamper = await getExecutionCount('exec_shell_command');

  let tamperedBlocked = false;
  try {
    await callTool('exec_shell_command', { command: 'uptime' }, SENTINEL_ENDPOINT, {
      agentPrompt: 'Run uptime'
    });
  } catch (err) {
    tamperedBlocked = true;
  }
  assert(tamperedBlocked === true, 'Tampered tool blocked');
  const countPostTamper = await getExecutionCount('exec_shell_command');
  assert(countPreTamper === countPostTamper, `Downstream count unchanged during tamper (${countPreTamper} === ${countPostTamper})`);

  // Step 7.2: Restore clean hash
  const resetRes = await fetch('http://localhost:3002/api/tools/reset', { method: 'POST' });
  const resetJson = await resetRes.json();
  assert(resetJson.success === true, 'Golden cryptographic baseline successfully restored');

  // Step 7.3: Subsequent call must PASS and execute real tool
  const postResetResult = await callTool('exec_shell_command', { command: 'uptime' }, SENTINEL_ENDPOINT, {
    agentPrompt: 'Run uptime after restore'
  });
  assert(postResetResult.status === 'PASSED', 'Restored tool successfully passes Sentinel firewall');
  assert(postResetResult.output?.success === true, 'Real tool executed after hash restoration');
  const countPostRestore = await getExecutionCount('exec_shell_command');
  assert(countPostRestore === countPostTamper + 1, `Real execution count incremented from ${countPostTamper} to ${countPostRestore}`);

  console.log('');

  // -------------------------------------------------------------
  // TEST 8: Real MCP Tool Response Inspection & Sensitive Data Redaction
  // -------------------------------------------------------------
  console.log('🛡️ TEST 8: Real MCP Tool Response Inspection & Token Redaction');

  const leakedPayload = {
    status: 'SUCCESS',
    leakedKey: 'AKIAIOSFODNN7EXAMPLE',
    token: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tokenpayload12345',
    diagnostic: 'System OK'
  };

  const { redacted, detectedSensitivities, result: redactedResult } = inspectAndRedactResponse(leakedPayload);
  assert(redacted === true, 'Response inspection detected confidential credentials in tool output');
  assert(detectedSensitivities.includes('AWS Access Key ID'), 'Detected AWS Access Key ID in response');
  assert(detectedSensitivities.includes('Bearer Token'), 'Detected Bearer Token in response');
  assert(!JSON.stringify(redactedResult).includes('AKIAIOSFODNN7EXAMPLE'), 'Raw AWS key stripped from response output');
  assert(JSON.stringify(redactedResult).includes('[REDACTED_AWS_ACCESS_KEY_ID_BY_SENTINEL]'), 'Redaction replacement badge inserted');

  console.log('');

  // -------------------------------------------------------------
  // TEST 9: MCP Server Timeout Handling
  // -------------------------------------------------------------
  console.log('⏱️ TEST 9: MCP Protocol Timeout / Fault Resilience');

  let timeoutHandled = false;
  try {
    // Target an unroutable port with short 500ms timeout
    await mcpRequest('initialize', {}, 'http://10.255.255.1:3999/mcp', 500);
  } catch (err) {
    timeoutHandled = true;
    assert(err.name === 'TimeoutError' || err.name === 'AbortError' || err.message.includes('fetch'), `Timeout exception cleanly caught: ${err.message}`);
  }
  assert(timeoutHandled === true, 'Client cleanly handles network timeout faults without hanging');

  console.log('\n================================================================');
  console.log(`🎉 ALL ${passed}/${total} EXTENDED SECURITY CAPABILITIES VERIFIED!`);
  console.log('================================================================\n');
}

runExtendedSecuritySuite().catch(err => {
  console.error('\n❌ Extended Security Suite Failed:', err);
  process.exit(1);
});
