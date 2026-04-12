// ============================================================
// The Key Vault — Audit Log Service
// buildwhilebleeding.com
// ============================================================
import { ACCESS_LOG_TABLE, LOG_PAGE_SIZE } from "../constants.js";
// ----------------------------------------------------------
// Write a single access event to D1
// ----------------------------------------------------------
export async function logAccess(db, entry) {
    await db
        .prepare(`INSERT INTO ${ACCESS_LOG_TABLE} (caller_id, key_name, access_granted, reason, timestamp, ip)
       VALUES (?, ?, ?, ?, ?, ?)`)
        .bind(entry.caller_id, entry.key_name, entry.access_granted, entry.reason, entry.timestamp, entry.ip)
        .run();
}
// ----------------------------------------------------------
// Retrieve paginated audit log
// Optionally filtered by caller_id
// ----------------------------------------------------------
export async function getAccessLog(db, options = {}) {
    const page = Math.max(1, options.page ?? 1);
    const offset = (page - 1) * LOG_PAGE_SIZE;
    let query = `SELECT * FROM ${ACCESS_LOG_TABLE}`;
    const bindings = [];
    const conditions = [];
    if (options.caller_id) {
        conditions.push("caller_id = ?");
        bindings.push(options.caller_id);
    }
    if (options.key_name) {
        conditions.push("key_name = ?");
        bindings.push(options.key_name);
    }
    if (conditions.length > 0) {
        query += ` WHERE ${conditions.join(" AND ")}`;
    }
    query += ` ORDER BY timestamp DESC LIMIT ${LOG_PAGE_SIZE} OFFSET ${offset}`;
    let countQuery = `SELECT COUNT(*) as total FROM ${ACCESS_LOG_TABLE}`;
    if (conditions.length > 0) {
        countQuery += ` WHERE ${conditions.join(" AND ")}`;
    }
    let stmt = db.prepare(query);
    let countStmt = db.prepare(countQuery);
    for (const val of bindings) {
        stmt = stmt.bind(val);
        countStmt = countStmt.bind(val);
    }
    const [rows, countRow] = await Promise.all([
        stmt.all(),
        countStmt.first(),
    ]);
    return {
        entries: rows.results,
        total: countRow?.total ?? 0,
        page,
        per_page: LOG_PAGE_SIZE,
    };
}
// ----------------------------------------------------------
// Initialize the D1 table (run once on deploy)
// ----------------------------------------------------------
export async function initializeSchema(db) {
    await db.exec(`
    CREATE TABLE IF NOT EXISTS ${ACCESS_LOG_TABLE} (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      caller_id TEXT NOT NULL,
      key_name TEXT NOT NULL,
      access_granted INTEGER NOT NULL,
      reason TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      ip TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_caller ON ${ACCESS_LOG_TABLE}(caller_id);
    CREATE INDEX IF NOT EXISTS idx_key ON ${ACCESS_LOG_TABLE}(key_name);
    CREATE INDEX IF NOT EXISTS idx_ts ON ${ACCESS_LOG_TABLE}(timestamp);
  `);
}
//# sourceMappingURL=audit.js.map