// ============================================================
// The Key Vault — Auth Service
// buildwhilebleeding.com
// ============================================================

import type { VaultClient, VaultEnv, KVNamespace } from "../types.js";
import { ACL_PREFIX, ERR_UNAUTHORIZED, ERR_CLIENT_NOT_FOUND } from "../constants.js";

// ----------------------------------------------------------
// Token hashing using Web Crypto (available in CF Workers)
// ----------------------------------------------------------
export async function hashToken(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ----------------------------------------------------------
// Generate a cryptographically random bearer token
// ----------------------------------------------------------
export function generateBearerToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ----------------------------------------------------------
// Resolve caller_id from bearer token
// Returns null if no match found
// ----------------------------------------------------------
export async function resolveCallerFromToken(
  bearerToken: string,
  kv: KVNamespace
): Promise<VaultClient | null> {
  const tokenHash = await hashToken(bearerToken);

  // List all ACL keys and find matching token hash
  const list = await kv.list({ prefix: ACL_PREFIX });

  for (const key of list.keys) {
    const raw = await kv.get(key.name);
    if (!raw) continue;

    let client: VaultClient;
    try {
      client = JSON.parse(raw) as VaultClient;
    } catch {
      continue;
    }

    if (client.bearerToken === tokenHash) {
      return client;
    }
  }

  return null;
}

// ----------------------------------------------------------
// Load a specific client by ID
// ----------------------------------------------------------
export async function getClientById(
  clientId: string,
  kv: KVNamespace
): Promise<VaultClient | null> {
  const raw = await kv.get(`${ACL_PREFIX}${clientId}`);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as VaultClient;
  } catch {
    return null;
  }
}

// ----------------------------------------------------------
// Check if a bearer token is the admin token
// ----------------------------------------------------------
export function isAdminToken(bearerToken: string, adminToken: string): boolean {
  // Timing-safe compare via constant-length comparison
  if (bearerToken.length !== adminToken.length) return false;
  let diff = 0;
  for (let i = 0; i < bearerToken.length; i++) {
    diff |= bearerToken.charCodeAt(i) ^ adminToken.charCodeAt(i);
  }
  return diff === 0;
}

// ----------------------------------------------------------
// Extract bearer token from Authorization header
// ----------------------------------------------------------
export function extractBearerToken(authHeader: string | null): string | null {
  if (!authHeader) return null;
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return null;
  return parts[1] ?? null;
}

// ----------------------------------------------------------
// Validate caller has access to a specific key
// ----------------------------------------------------------
export function callerCanAccessKey(client: VaultClient, keyName: string): boolean {
  return client.allowedKeys.includes(keyName);
}
