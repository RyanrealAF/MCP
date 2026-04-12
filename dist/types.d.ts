export interface VaultClient {
    id: string;
    bearerToken: string;
    allowedKeys: string[];
    description: string;
    createdAt: string;
}
export interface AccessLogEntry {
    id?: number;
    caller_id: string;
    key_name: string;
    access_granted: 0 | 1;
    reason: string;
    timestamp: string;
    ip: string;
}
export interface VaultEnv {
    VAULT_ACL: KVNamespace;
    VAULT_LOG: D1Database;
    VAULT_ADMIN_TOKEN: string;
    [key: string]: unknown;
}
export interface GetSecretResult {
    value: string | null;
    access_granted: boolean;
    key_name: string;
    caller_id: string;
    reason: string;
}
export interface ListSecretsResult {
    caller_id: string;
    allowed_keys: string[];
    total: number;
}
export interface AccessLogResult {
    entries: AccessLogEntry[];
    total: number;
    page: number;
    per_page: number;
}
export interface ProvisionClientResult {
    client_id: string;
    bearer_token: string;
    allowed_keys: string[];
    message: string;
}
export interface RevokeClientResult {
    client_id: string;
    revoked: boolean;
    message: string;
}
export interface KVNamespace {
    get(key: string): Promise<string | null>;
    put(key: string, value: string): Promise<void>;
    delete(key: string): Promise<void>;
    list(options?: {
        prefix?: string;
    }): Promise<{
        keys: {
            name: string;
        }[];
    }>;
}
export interface D1Database {
    prepare(query: string): D1PreparedStatement;
    exec(query: string): Promise<void>;
}
export interface D1PreparedStatement {
    bind(...values: unknown[]): D1PreparedStatement;
    run(): Promise<{
        success: boolean;
    }>;
    all<T = Record<string, unknown>>(): Promise<{
        results: T[];
    }>;
    first<T = Record<string, unknown>>(): Promise<T | null>;
}
//# sourceMappingURL=types.d.ts.map