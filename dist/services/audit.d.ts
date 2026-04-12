import type { AccessLogEntry, D1Database, AccessLogResult } from "../types.js";
export declare function logAccess(db: D1Database, entry: Omit<AccessLogEntry, "id">): Promise<void>;
export declare function getAccessLog(db: D1Database, options?: {
    page?: number;
    caller_id?: string;
    key_name?: string;
}): Promise<AccessLogResult>;
export declare function initializeSchema(db: D1Database): Promise<void>;
//# sourceMappingURL=audit.d.ts.map