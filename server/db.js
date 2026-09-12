// server/db.js
import sqlite3 from 'sqlite3';
import path from 'path';

const DB_PATH = path.resolve('server', 'mcp.db');
const db = new sqlite3.Database(DB_PATH);

// Initialize table
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS executions (tool TEXT PRIMARY KEY, count INTEGER NOT NULL);`);
});

export function incrementExecution(toolName) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO executions (tool, count) VALUES (?, 1)
       ON CONFLICT(tool) DO UPDATE SET count = count + 1;`,
      [toolName],
      function (err) {
        if (err) reject(err);
        else resolve();
      }
    );
  });
}

export function getExecutionCount(toolName) {
  return new Promise((resolve, reject) => {
    db.get('SELECT count FROM executions WHERE tool = ?', [toolName], (err, row) => {
      if (err) reject(err);
      else resolve(row ? row.count : 0);
    });
  });
}

export function getAllTelemetry() {
  return new Promise((resolve, reject) => {
    db.all('SELECT tool, count FROM executions', [], (err, rows) => {
      if (err) reject(err);
      else resolve(rows || []);
    });
  });
}

export function resetExecutionCounts() {
  return new Promise((resolve, reject) => {
    db.run('DELETE FROM executions;', [], function (err) {
      if (err) reject(err);
      else resolve();
    });
  });
}

export default {
  incrementExecution,
  getExecutionCount,
  getAllTelemetry,
  resetExecutionCounts
};
