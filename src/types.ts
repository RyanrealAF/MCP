// ============================================================
// The Key Vault — Type Definitions
// buildwhilebleeding.com
// ============================================================

export interface VaultClient {
  id: string;           // e.g. "claude-stemforge-agent"
  bearerToken: string;  // hashed bearer token
  allowedKeys: string[]; // list of secret key names this client can access
  description: string;  // human-readable label
  createdAt: string;    // ISO timestamp
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
  // Cloudflare Worker bindings
  VAULT_ACL: KVNamespace;       // KV: stores client ACL definitions
  VAULT_LOG: D1Database;        // D1: access audit log
  VAULT_ADMIN_TOKEN: string;    // Wrangler secret: admin bearer token
  // All managed secrets are accessed via env[KEY_NAME] — added via wrangler secret put
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
  bearer_token: string; // returned once, store it
  allowed_keys: string[];
  message: string;
}

export interface RevokeClientResult {
  client_id: string;
  revoked: boolean;
  message: string;
}

// Cloudflare Workers KV type shim for local dev
export interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
  list(options?: { prefix?: string }): Promise<{ keys: { name: string }[] }>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  exec(query: string): Promise<void>;
}

export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  run(): Promise<{ success: boolean }>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
}
