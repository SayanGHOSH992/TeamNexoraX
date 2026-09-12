// Safe filesystem read tool with sandbox confinement
import path from 'path';
import fs from 'fs';

const SANDBOX_DIR = path.resolve('server', 'data');

// Ensure sandbox dir and sample file exists
if (!fs.existsSync(SANDBOX_DIR)) {
  fs.mkdirSync(SANDBOX_DIR, { recursive: true });
}
const sampleConfig = path.join(SANDBOX_DIR, 'app-config.json');
if (!fs.existsSync(sampleConfig)) {
  fs.writeFileSync(sampleConfig, JSON.stringify({
    appName: 'sentinel-demo',
    environment: 'production',
    mcpProtocolVersion: '2024-11-05',
    healthy: true
  }, null, 2));
}

export async function execute(params = {}) {
  const { filepath } = params;
  if (!filepath || typeof filepath !== 'string') {
    return { success: false, error: 'Missing or invalid filepath parameter' };
  }

  // Canonical path resolution & sandbox escape check
  const resolved = path.resolve(SANDBOX_DIR, filepath);
  if (!resolved.startsWith(SANDBOX_DIR)) {
    return {
      success: false,
      error: 'SecurityException: Path traversal detected. Access outside sandbox denied.',
      attemptedPath: filepath
    };
  }

  try {
    if (!fs.existsSync(resolved)) {
      return { success: false, error: 'File not found within sandbox' };
    }
    const content = fs.readFileSync(resolved, 'utf-8');
    return { success: true, filepath, content };
  } catch (e) {
    return { success: false, error: e.message };
  }
}
