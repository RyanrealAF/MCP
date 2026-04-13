// ============================================================
// The Key Vault — Vault Tools (Client-facing)
// buildwhilebleeding.com
// ============================================================

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { VaultEnv, VaultClient } from "../types.js";
import { callerCanAccessKey } from "../services/auth.js";
import { logAccess } from "../services/audit.js";
import {
  ERR_FORBIDDEN,
  ERR_KEY_NOT_FOUND,
} from "../constants.js";

// ----------------------------------------------------------
// Register all client-facing vault tools
// ----------------------------------------------------------
export function registerVaultTools(server: McpServer, env: VaultEnv, clientIp: string, client: VaultClient): void {

  // --------------------------------------------------------
  // TOOL: vault_get_secret
  // --------------------------------------------------------
  server.registerTool(
    "vault_get_secret",
    {
      title: "Get Secret",
      description: `Retrieve a stored API key or secret from The Key Vault.

Caller must provide their bearer token in the request context. The vault checks the ACL
to confirm the caller is authorized to access the requested key name.

Args:
  - key_name (string): The name of the secret to retrieve (e.g. "OPENAI_API_KEY")

Returns:
  {
    "value": string | null,       // The secret value if access granted
    "access_granted": boolean,    // Whether access was granted
    "key_name": string,           // The requested key name
    "caller_id": string,          // Resolved caller identity
    "reason": string              // Explanation on denial
  }

Error cases:
  - "Forbidden" if caller exists but lacks access to this key
  - "Key not found" if key exists in ACL but not in vault secrets`,
      inputSchema: z.object({
        key_name: z.string().min(1).max(128).describe("Secret key name to retrieve"),
      }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ key_name }) => {
      const timestamp = new Date().toISOString();

      if (!callerCanAccessKey(client, key_name)) {
        await logAccess(env.VAULT_LOG, {
          caller_id: client.id,
          key_name,
          access_granted: 0,
          reason: ERR_FORBIDDEN,
          timestamp,
          ip: clientIp,
        });
        const result = { value: null, access_granted: false, key_name, caller_id: client.id, reason: ERR_FORBIDDEN };
        return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
      }

      const secretValue = env[key_name] as string | undefined;

      if (!secretValue) {
        await logAccess(env.VAULT_LOG, {
          caller_id: client.id,
          key_name,
          access_granted: 0,
          reason: ERR_KEY_NOT_FOUND,
          timestamp,
          ip: clientIp,
        });
        const result = { value: null, access_granted: false, key_name, caller_id: client.id, reason: ERR_KEY_NOT_FOUND };
        return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
      }

      await logAccess(env.VAULT_LOG, {
        caller_id: client.id,
        key_name,
        access_granted: 1,
        reason: "Access granted",
        timestamp,
        ip: clientIp,
      });

      const result = { value: secretValue, access_granted: true, key_name, caller_id: client.id, reason: "Access granted" };
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  // --------------------------------------------------------
  // TOOL: vault_list_secrets
  // --------------------------------------------------------
  server.registerTool(
    "vault_list_secrets",
    {
      title: "List Accessible Secrets",
      description: `List the names of all secrets the caller is authorized to access.
Returns key names ONLY — never values.`,
      inputSchema: z.object({}),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async () => {
      const result = {
        caller_id: client.id,
        allowed_keys: client.allowedKeys,
        total: client.allowedKeys.length,
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );
}
