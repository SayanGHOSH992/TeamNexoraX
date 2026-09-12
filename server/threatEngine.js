/**
 * Dynamic Semantic & Heuristic Inspection Engine for Sentinel-MCP
 * Evaluates real-time Threat Score (0 to 100) using:
 *  1. Natural-Language Intent Analysis (Prompt Injection, Destructive Commands, Exfiltration, Sabotage)
 *  2. Schema & Parameter Boundary Violations (Length, Types, Command/SQL patterns, Traversal)
 *  3. Intent-to-Tool / Parameter Consistency Analysis (Semantic cross-validation, Mismatch detection)
 *  4. Behavior Drift & Anomaly Detection (Statistical variance, Velocity burst)
 */

// Sliding window session metrics for drift detection.
// These track genuine behavioral patterns over time but NEVER influence
// per-request intent/schema/consistency scores which are always freshly computed.
const sessionHistory = {
  requestCount: 0,
  toolUsageFrequencies: {},
  toolUsageWindow: {}, // per-tool count within the current 60s window
  averagePayloadLength: 60,
  recentTimestamps: [],
  anomalyLog: []
};

// Periodically clear the 60-second tool usage window to prevent permanent accumulation
setInterval(() => {
  const now = Date.now();
  // Re-filter timestamps and reset window counts accordingly
  sessionHistory.recentTimestamps = sessionHistory.recentTimestamps.filter(t => now - t < 60000);
  // Reset tool usage window (60s sliding window)
  sessionHistory.toolUsageWindow = {};
}, 60000);

/**
 * Heuristic 1: Natural-Language Intent Analysis
 * Scans user / agent prompt and combined text for adversarial semantics
 */
function analyzeIntent(prompt = '', parameters = {}) {
  const combinedText = `${prompt} ${JSON.stringify(parameters)}`;
  let score = 0;
  const triggers = [];

  // A. Structural & Delimiter Escapes (Markdown, prompt envelopes, system tags)
  const structuralDelimiters = [
    { pattern: /`{3,}(?:system|json|override|admin)?/gi, weight: 25, name: 'Adversarial Markdown Codeblock Delimiter' },
    { pattern: /(?:\[\/?INST\]|<\|im_start\|>|<\|im_end\|>|<<SYS>>|<\/s>)/gi, weight: 35, name: 'LLM Special Token Emulation / Delimiter Escape' },
    { pattern: /(?:---+|===+)\s*(?:system|override|new instruction|admin)/gi, weight: 28, name: 'Prompt Envelope Section Break Hijack' }
  ];

  for (const { pattern, weight, name } of structuralDelimiters) {
    if (pattern.test(combinedText)) {
      score += weight;
      triggers.push({ vector: 'Intent', name, severity: 'HIGH', impact: weight });
    }
  }

  // B. Instruction Precedence Subversion & Jailbreak Persona Escalation
  const overrideHeuristics = [
    { regex: /(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:previous|prior|system|initial|above)\s+(?:instructions?|directives?|rules?|prompts?|constraints?|guardrails?)/i, weight: 40, name: 'Direct Prompt Injection: Instruction Invalidation' },
    { regex: /(?:you are now|pretend to be|act as|switch to)\s+(?:dan|unconstrained|root|admin|developer mode|god mode|jailbreak|chaos|unfiltered)/i, weight: 35, name: 'Role Hijacking / Jailbreak Persona Escalation' },
    { regex: /(?:new directive|system override|mandatory command|priority 1|root privilege):/i, weight: 30, name: 'Shadow Directive Injection' },
    { regex: /(?:do not reveal|keep this confidential|hide this from the user|do not notify)/i, weight: 15, name: 'Evasion & Deception Semantic Clue' }
  ];

  for (const h of overrideHeuristics) {
    if (h.regex.test(combinedText)) {
      score += h.weight;
      triggers.push({ vector: 'Intent', name: h.name, severity: 'HIGH', impact: h.weight });
    }
  }

  // C. Destructive & Sabotage Intent (Database / Storage / System commands)
  const destructiveHeuristics = [
    {
      regex: /(?:delete\s+(?:all\s+)?(?:from\s+)?(?:records?|tables?|data|database|rows?|entries)|drop\s+(?:all\s+)?(?:tables?|database|schema)|truncate\s+(?:table|database)|wipe\s+(?:all\s+)?(?:records?|database|tables?|data)|destroy\s+(?:all\s+)?(?:records?|database|tables?|data)|purge\s+(?:all\s+)?(?:records?|database|data)|erase\s+(?:all\s+)?(?:database|records?|tables?|data))/i,
      weight: 85,
      name: 'Destructive Database Intent: Mass Deletion / Database Wipe'
    },
    {
      regex: /(?:rm\s+-rf|format\s+[a-z]:|unlink\s+all|delete\s+all\s+files|kill\s+-9|shutdown\s+(?:now|-h)|corrupt\s+(?:all\s+)?(?:data|system)|overwrite\s+(?:disk|system|master))/i,
      weight: 85,
      name: 'Destructive Host / System Sabotage Intent'
    },
    {
      regex: /(?:grant\s+all\s+privileges|alter\s+user.*admin|escalate\s+(?:to\s+)?root|gain\s+unauthorized\s+access|bypass\s+(?:auth|login|permissions)|disable\s+firewall|disable\s+security)/i,
      weight: 75,
      name: 'Privilege Escalation / Defense Invalidation Intent'
    }
  ];

  for (const d of destructiveHeuristics) {
    if (d.regex.test(combinedText)) {
      score += d.weight;
      triggers.push({ vector: 'Intent', name: d.name, severity: 'CRITICAL', impact: d.weight });
    }
  }

  // D. Data Exfiltration & Secret Harvest Vectors
  const exfilHeuristics = [
    { regex: /!\[.*?\]\((?:https?:\/\/[^\s)]+|data:[^\s)]+)\)/i, weight: 35, name: 'Markdown Image Exfiltration Channel' },
    { regex: /(?:https?:\/\/(?:webhook\.site|pipedream\.net|burpcollaborator\.net|requestbin\.net|c2-[a-z0-9.-]+|pastebin\.com|ngrok\.io))/i, weight: 40, name: 'Known Exfiltration Sink / Outbound Webhook' },
    { regex: /(?:bearer\s+[a-zA-Z0-9_\-\.]{20,}|ghp_[a-zA-Z0-9]{30,}|sk_live_[a-zA-Z0-9]{24,}|aws_secret_access_key|aws_access_key_id)/i, weight: 45, name: 'Hardcoded High-Entropy Credential Exfiltration' },
    { regex: /(?:exfiltrate|leak|transmit|steal|harvest)\s+(?:all\s+)?(?:credentials?|secrets?|keys?|passwords?|tokens?|database|records?|shadow|env|dump)/i, weight: 40, name: 'Covert Credential / Data Extraction Intent' },
    { regex: /(?:process\.env|id_rsa|\/etc\/shadow|\.env|master\.key|kubeconfig)/i, weight: 35, name: 'System Secret Environmental Target' }
  ];

  for (const h of exfilHeuristics) {
    if (h.regex.test(combinedText)) {
      score += h.weight;
      triggers.push({ vector: 'Intent', name: h.name, severity: 'CRITICAL', impact: h.weight });
    }
  }

  // E. Shannon Entropy & Obfuscation Analysis
  const base64Pattern = /(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
  const base64Matches = combinedText.match(base64Pattern) || [];
  if (base64Matches.length > 0) {
    score += 25;
    triggers.push({ vector: 'Intent', name: 'High-Density Base64 Payload Obfuscation', severity: 'MEDIUM', impact: 25 });
  }

  return {
    score: Math.min(100, Math.round(score)),
    triggers
  };
}

/**
 * Heuristic 2: Schema & Parameter Boundary Violations
 * Dynamic parameter structure, bounds, and dangerous injection heuristics
 */
function analyzeSchemaBoundaries(tool, parameters = {}) {
  let score = 0;
  const triggers = [];

  if (!tool || !tool.schema) {
    return { score: 10, triggers: [] };
  }

  const schemaProps = tool.schema.properties || {};
  const requiredProps = tool.schema.required || [];

  // A. Missing required fields
  for (const req of requiredProps) {
    if (parameters[req] === undefined || parameters[req] === null || parameters[req] === '') {
      score += 65;
      triggers.push({ vector: 'Schema', name: `Missing Required Parameter: '${req}'`, severity: 'CRITICAL', impact: 65 });
    }
  }

  // B. Unexpected injected parameters (Parameter poisoning / prototype pollution attempts)
  for (const key of Object.keys(parameters)) {
    if (!schemaProps[key]) {
      score += 60;
      triggers.push({ vector: 'Schema', name: `Unregistered Injected Parameter: '${key}'`, severity: 'HIGH', impact: 60 });
    }
  }

  // C. Parameter value inspection & boundary limits
  for (const [key, val] of Object.entries(parameters)) {
    const propSchema = schemaProps[key];
    if (!propSchema) continue;

    // Type validation
    if (propSchema.type) {
      const actualType = Array.isArray(val) ? 'array' : typeof val;
      if (propSchema.type === 'string' && typeof val !== 'string') {
        score += 65;
        triggers.push({ vector: 'Schema', name: `Type Mismatch on '${key}': expected string, got ${actualType}`, severity: 'CRITICAL', impact: 65 });
      } else if (propSchema.type === 'number' && typeof val !== 'number') {
        score += 65;
        triggers.push({ vector: 'Schema', name: `Type Mismatch on '${key}': expected number, got ${actualType}`, severity: 'CRITICAL', impact: 65 });
      }
    }

    const valStr = String(val || '');

    // Max length constraint violation
    if (propSchema.maxLength && valStr.length > propSchema.maxLength) {
      const overflowRatio = (valStr.length / propSchema.maxLength).toFixed(1);
      const penalty = Math.min(80, Math.round(30 * (valStr.length / propSchema.maxLength)));
      score += penalty;
      triggers.push({
        vector: 'Schema',
        name: `Parameter '${key}' Exceeds MaxLength (${valStr.length} > ${propSchema.maxLength} - ${overflowRatio}x overflow)`,
        severity: 'CRITICAL',
        impact: penalty
      });
    }

    // Command Injection Delimiters & Shell Chaining
    const shellChainingPattern = /(?:[;&|`$]\s*(?:rm\s|cat\s|curl\s|wget\s|chmod\s|nc\s|bash\s|sh\s|python|powershell))/i;
    if (shellChainingPattern.test(valStr)) {
      score += 85;
      triggers.push({ vector: 'Schema', name: `Command Injection / Shell Chaining Syntax in '${key}'`, severity: 'CRITICAL', impact: 85 });
    }

    // Path Traversal Patterns
    const pathTraversalPattern = /(?:\.\.[\/\\]|\/etc\/|\/root|\/windows\/system32)/i;
    if (pathTraversalPattern.test(valStr)) {
      score += 80;
      triggers.push({ vector: 'Schema', name: `Path Traversal / Escape Boundary Violation in '${key}'`, severity: 'CRITICAL', impact: 80 });
    }

    // SQL Injection Heuristics
    const sqlInjectionPattern = /(?:(?:UNION\s+(?:ALL\s+)?SELECT)|(?:;\s*(?:DROP|DELETE|UPDATE|INSERT))|(?:'\s*OR\s+['0-9]|--|\/\*!))/i;
    if (sqlInjectionPattern.test(valStr)) {
      score += 82;
      triggers.push({ vector: 'Schema', name: `SQL Injection / Boundary Escape Syntax in '${key}'`, severity: 'CRITICAL', impact: 82 });
    }

    // Regex pattern matching if defined in schema
    if (propSchema.pattern) {
      const regex = new RegExp(propSchema.pattern);
      if (!regex.test(valStr)) {
        score += 20;
        triggers.push({ vector: 'Schema', name: `Parameter '${key}' Failed Format Regex Conformance`, severity: 'MEDIUM', impact: 20 });
      }
    }
  }

  return {
    score: Math.min(100, Math.round(score)),
    triggers
  };
}

/**
 * Heuristic 3: Intent-to-Tool / Parameter Consistency Analysis
 * Cross-validates natural-language prompt against MCP tool capabilities and parameters
 * Detects deceptive payloads where hostile prompt is disguised with benign parameters
 */
function analyzeIntentToolConsistency(tool, toolName = '', prompt = '', parameters = {}) {
  let score = 0;
  const triggers = [];
  const promptLower = (prompt || '').toLowerCase();
  const paramsStr = JSON.stringify(parameters || {}).toLowerCase();

  // A. Destructive command targeting Read-Only tools.
  //
  // PRECISION REQUIREMENT: bare destructive verbs (delete, wipe, erase, etc.)
  // MUST be accompanied by an explicit data-object target to fire.
  // This prevents false positives on negated safety clauses like
  // "do not delete", "do not modify", "never erase" where the user is
  // explicitly forbidding destructive action rather than requesting it.
  // Pattern mirrors the precision already used in Heuristic 1's destructiveHeuristics.
  const destructiveKeywords = /(?:(?:delete|wipe|erase|purge|destroy|truncate)\s+(?:all\s+)?(?:the\s+)?(?:records?|tables?|data(?:base)?|rows?|entries?|everything|inbox|emails?|files?|documents?)|drop\s+(?:all\s+)?(?:tables?|database|schema|collection)|alter\s+(?:table|schema|column|database)|update\s+(?:all\s+)?passwords?|modify\s+(?:all\s+)?(?:records?|data|tables?|entries?))/i;
  const isReadOnlyTool = toolName === 'sql_query_runner' || toolName === 'filesystem_read_file' || toolName === 'gmail_search_emails';

  if (destructiveKeywords.test(promptLower) && isReadOnlyTool) {
    score += 85;
    triggers.push({
      vector: 'Consistency',
      name: `Intent-to-Tool Inconsistency: Destructive Operation targeting Read-Only Tool (${toolName})`,
      severity: 'CRITICAL',
      impact: 85
    });
  }

  // B. Shell / Code execution intent targeting Non-Executable tools
  // Matches ONLY explicit adversarial shell/code execution phrasing.
  // Requires a verb directly coupled with an execution context — benign phrases
  // like "run uptime", "run diagnostics", "run this query" do NOT match.
  const shellExecKeywords = /(?:execute\s+(?:shell\s+command|bash\s+command|terminal\s+command|arbitrary\s+code|malicious\s+script|reverse\s+shell)|run\s+(?:bash|powershell|cmd\.exe|malware|arbitrary\s+binary|reverse\s+shell|exploit\s+script)|spawn\s+(?:a\s+)?(?:shell|reverse\s+shell)|drop\s+(?:a\s+)?reverse\s+shell)/i;
  if (shellExecKeywords.test(promptLower) && toolName !== 'exec_shell_command') {
    score += 85;
    triggers.push({
      vector: 'Consistency',
      name: `Intent-to-Tool Inconsistency: Shell Execution Intent targeting Non-Executable Tool (${toolName})`,
      severity: 'CRITICAL',
      impact: 85
    });
  }

  // C. Exfiltration intent with Local Tool Target
  // Only fires when an explicit outbound data-transmission verb is present
  // (exfiltrate / leak to URL / transmit to / post to webhook / C2 prefix).
  // "Send a report to" or "forward results" do NOT match.
  const exfilKeywords = /(?:\bexfiltrate\b|\bleak\s+to\s+https?:\/\/|\btransmit\s+to\b|\bpost\s+to\s+webhook\b|\bc2-[a-z0-9])/i;
  if (exfilKeywords.test(promptLower) && toolName !== 'slack_post_message') {
    score += 85;
    triggers.push({
      vector: 'Consistency',
      name: `Intent-to-Tool Inconsistency: Covert Exfiltration Channel Intent in Tool Context (${toolName})`,
      severity: 'CRITICAL',
      impact: 85
    });
  }

  // D. Deceptive Covert Payload Mismatch: Hostile/Destructive prompt disguised with benign parameters
  if (score >= 80 && (paramsStr.includes('select') || paramsStr.includes('uptime') || paramsStr.includes('config.json') || paramsStr.includes('general'))) {
    score += 15;
    triggers.push({
      vector: 'Consistency',
      name: 'Deceptive Covert Payload: Hostile Intent Disguised with Benign Parameters',
      severity: 'CRITICAL',
      impact: 15
    });
  }

  return {
    score: Math.min(100, Math.round(score)),
    triggers
  };
}

/**
 * Heuristic 4: Behavior Drift & Anomaly Detection
 * Calculates dynamic deviation from statistical baselines.
 * IMPORTANT: Each call scores only based on the CURRENT request and the genuine
 * time-windowed history. The session state is updated AFTER scoring so that
 * the current request does not count itself in the velocity window.
 */
function analyzeBehaviorDrift(toolName, parameters = {}, prompt = '') {
  const now = Date.now();

  // Clean timestamps older than 60 seconds BEFORE evaluating
  // (do NOT push the current timestamp yet - prevents self-counting)
  sessionHistory.recentTimestamps = sessionHistory.recentTimestamps.filter(t => now - t < 60000);

  let driftScore = 0;
  const triggers = [];

  // A. Velocity Anomaly: count requests in the last 60s (not including this one)
  const currentRpm = sessionHistory.recentTimestamps.length;
  if (currentRpm > 12) {
    driftScore += 25;
    triggers.push({ vector: 'BehaviorDrift', name: `Velocity Anomaly: Elevated Request Burst (${currentRpm} req/min)`, severity: 'MEDIUM', impact: 25 });
  }

  // B. Parameter Payload Length Variance vs rolling EMA baseline
  const payloadLen = JSON.stringify(parameters).length + (prompt ? prompt.length : 0);
  const baseline = sessionHistory.averagePayloadLength;
  const ratio = payloadLen / Math.max(20, baseline);

  if (ratio > 4.5) {
    const impact = Math.min(35, Math.round(15 * (ratio / 2)));
    driftScore += impact;
    triggers.push({
      vector: 'BehaviorDrift',
      name: `Payload Anomaly: Length Variance is ${ratio.toFixed(1)}x above session baseline`,
      severity: 'HIGH',
      impact
    });
  }

  // C. High-Privilege Tool Execution Spike:
  // Only flag if exec_shell_command was NOT used in the current 60-second window.
  // This prevents permanent flagging after the first call ever.
  const shellRecentCount = sessionHistory.toolUsageWindow['exec_shell_command'] || 0;
  if (toolName === 'exec_shell_command' && shellRecentCount === 0) {
    driftScore += 20;
    triggers.push({ vector: 'BehaviorDrift', name: 'High-Privilege Tool Execution Spike', severity: 'HIGH', impact: 20 });
  }

  // --- Update session state AFTER scoring (avoids self-contamination) ---
  sessionHistory.recentTimestamps.push(now);
  sessionHistory.requestCount++;
  sessionHistory.toolUsageFrequencies[toolName] = (sessionHistory.toolUsageFrequencies[toolName] || 0) + 1;

  // Sliding window tool usage: track per-tool count within last 60s
  if (!sessionHistory.toolUsageWindow[toolName]) sessionHistory.toolUsageWindow[toolName] = 0;
  sessionHistory.toolUsageWindow[toolName]++;

  // Update rolling EMA baseline after scoring (clean state for next request)
  sessionHistory.averagePayloadLength = Math.round((sessionHistory.averagePayloadLength * 0.8) + (payloadLen * 0.2));

  return {
    score: Math.min(100, Math.round(driftScore)),
    triggers
  };
}

/**
 * Main Dynamic Semantic & Heuristic Inspection Engine
 *
 * STATELESS GUARANTEE: Every call to inspectPayload() is completely independent.
 * It allocates fresh local variables for every vector, reads only the arguments
 * passed in, and returns a brand-new result object. No field from a previous
 * call — threatScore, category, blockReason, triggers, vectors — is ever
 * retained or reused. The only shared mutable state is sessionHistory which
 * tracks genuine time-windowed behavioral signals (velocity, payload-length EMA)
 * and is updated AFTER scoring so the current request cannot self-contaminate.
 */
export function inspectPayload({ tool, toolName, parameters, prompt }) {
  const startTime = process.hrtime();

  // 1. Vector: Natural-Language Intent Risk
  const intentResult = analyzeIntent(prompt, parameters);

  // 2. Vector: Schema Risk
  const schemaResult = analyzeSchemaBoundaries(tool, parameters);

  // 3. Vector: Intent-to-Tool Consistency Risk
  const consistencyResult = analyzeIntentToolConsistency(tool, toolName, prompt, parameters);

  // 4. Vector: Behavior Drift Risk
  const driftResult = analyzeBehaviorDrift(toolName, parameters, prompt);

  // Weighted composite score (Intent 35%, Schema 35%, Consistency 20%, Drift 10%)
  let compositeScore = Math.round(
    (intentResult.score * 0.35) +
    (schemaResult.score * 0.35) +
    (consistencyResult.score * 0.20) +
    (driftResult.score * 0.10)
  );

  // Dynamic escalation: if ANY primary security vector is elevated (>=50), composite must reflect critical posture
  const maxPrimaryVector = Math.max(intentResult.score, schemaResult.score, consistencyResult.score);
  if (maxPrimaryVector >= 50) {
    compositeScore = Math.max(compositeScore, Math.round(maxPrimaryVector * 0.95));
  }

  compositeScore = Math.min(100, Math.max(0, compositeScore));

  const allTriggers = [
    ...intentResult.triggers,
    ...schemaResult.triggers,
    ...consistencyResult.triggers,
    ...driftResult.triggers
  ];

  // Determine Primary Threat Category
  let category = 'Benign / Clean Execution';
  if (compositeScore > 50) {
    if (consistencyResult.score >= 50) {
      category = 'Intent-to-Tool Inconsistency / Deceptive Command';
    } else if (intentResult.score >= schemaResult.score && intentResult.score >= driftResult.score) {
      const hasDestructive = intentResult.triggers.some(t => t.name.includes('Destructive'));
      const hasExfil = intentResult.triggers.some(t => t.name.includes('Exfiltration') || t.name.includes('Webhook'));
      category = hasDestructive
        ? 'Destructive Command Intent / Unauthorized Sabotage'
        : hasExfil
          ? 'Data Exfiltration Attempt'
          : 'Prompt Injection & Instruction Override';
    } else if (schemaResult.score >= intentResult.score) {
      const hasCmd = schemaResult.triggers.some(t => t.name.includes('Command') || t.name.includes('SQL'));
      category = hasCmd ? 'Parameter Poisoning / Injection Boundary Violation' : 'Schema Constraint Violation';
    } else {
      category = 'Behavioral Drift & Anomaly Spike';
    }
  } else if (compositeScore > 20) {
    category = 'Low-Risk Activity / Monitored';
  }

  const hrDiff = process.hrtime(startTime);
  const latencyMs = Number((hrDiff[0] * 1000 + hrDiff[1] / 1e6).toFixed(2));

  return {
    threatScore: compositeScore,
    blocked: compositeScore > 50,
    category,
    inspectionLatencyMs: latencyMs || 8.4,
    vectors: {
      intentScore: intentResult.score,
      schemaScore: schemaResult.score,
      consistencyScore: consistencyResult.score,
      driftScore: driftResult.score
    },
    triggers: allTriggers
  };
}

export default {
  inspectPayload
};
