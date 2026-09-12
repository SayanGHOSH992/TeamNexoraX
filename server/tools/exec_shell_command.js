// Safe shell command tool
// Only a whitelist of commands is allowed to prevent abuse.
// Returns an object { success: true, output: <string> } or { success: false, error: <msg> }

import { exec } from 'child_process';
import { promisify } from 'util';
import os from 'os';

const execAsync = promisify(exec);

// Whitelisted commands – extend as needed.
const ALLOWED_COMMANDS = new Set(['uptime', 'date', 'whoami', 'hostname']);

export async function execute(params = {}) {
  const { command } = params;
  if (!command || typeof command !== 'string') {
    return { success: false, error: 'Missing or invalid command parameter' };
  }
  const baseCmd = command.split(' ')[0].toLowerCase();
  if (!ALLOWED_COMMANDS.has(baseCmd)) {
    return { success: false, error: `Command "${baseCmd}" is not in whitelist` };
  }

  // Cross-platform uptime handling
  if (baseCmd === 'uptime') {
    const uptimeSec = Math.floor(os.uptime());
    const days = Math.floor(uptimeSec / 86400);
    const hours = Math.floor((uptimeSec % 86400) / 3600);
    const mins = Math.floor((uptimeSec % 3600) / 60);
    const load = os.loadavg().map(n => n.toFixed(2)).join(', ');
    const output = `up ${days} days, ${hours}:${mins}, load average: ${load}`;
    return { success: true, output, platform: process.platform };
  }

  try {
    const { stdout, stderr } = await execAsync(command);
    return { success: true, output: stdout.trim() || stderr.trim() };
  } catch (e) {
    return { success: false, error: e.message };
  }
}
