import type { VaultClient, KVNamespace } from "../types.js";
export declare function hashToken(token: string): Promise<string>;
export declare function generateBearerToken(): string;
export declare function resolveCallerFromToken(bearerToken: string, kv: KVNamespace): Promise<VaultClient | null>;
export declare function getClientById(clientId: string, kv: KVNamespace): Promise<VaultClient | null>;
export declare function isAdminToken(bearerToken: string, adminToken: string): boolean;
export declare function extractBearerToken(authHeader: string | null): string | null;
export declare function callerCanAccessKey(client: VaultClient, keyName: string): boolean;
//# sourceMappingURL=auth.d.ts.map