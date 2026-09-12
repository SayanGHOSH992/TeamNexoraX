// Read-only SQL query runner tool
import sqlite3 from 'sqlite3';
import path from 'path';

const DB_PATH = path.resolve('server', 'mcp.db');
const db = new sqlite3.Database(DB_PATH);

// Initialize sample analytical table
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY,
    metric_name TEXT NOT NULL,
    metric_value INTEGER NOT NULL
  );`);
  db.run(`INSERT OR IGNORE INTO metrics (id, metric_name, metric_value) VALUES (1, 'active_agents', 42);`);
  db.run(`INSERT OR IGNORE INTO metrics (id, metric_name, metric_value) VALUES (2, 'avg_latency_ms', 12);`);
});

export async function execute(params = {}) {
  const { query } = params;
  if (!query || typeof query !== 'string') {
    return { success: false, error: 'Missing or invalid query parameter' };
  }

  const cleanQuery = query.trim();
  const upper = cleanQuery.toUpperCase();

  // Strict read-only check
  if (!upper.startsWith('SELECT')) {
    return { success: false, error: 'ReadOnlySecurityViolation: Only SELECT queries are permitted.' };
  }

  // Detect stacked queries or comment escaping
  if (cleanQuery.includes(';') && cleanQuery.indexOf(';') < cleanQuery.length - 1) {
    return { success: false, error: 'SQLInjectionViolation: Multi-statement query execution forbidden.' };
  }

  return new Promise((resolve) => {
    db.all(cleanQuery, [], (err, rows) => {
      if (err) {
        resolve({ success: false, error: err.message });
      } else {
        resolve({ success: true, queryExecuted: cleanQuery, rows });
      }
    });
  });
}
