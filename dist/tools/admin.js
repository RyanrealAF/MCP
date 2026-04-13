// ============================================================
// The Key Vault — Admin Tools (Admin-only)
// buildwhilebleeding.com
// ============================================================
import { z } from "zod";
import { generateBearerToken, hashToken, getClientById, } from "../services/auth.js";
import { getAccessLog } from "../services/audit.js";
import { ACL_PREFIX, ERR_CLIENT_NOT_FOUND, } from "../constants.js";
// ----------------------------------------------------------
// Register all admin tools (require admin bearer token)
// ----------------------------------------------------------
export function registerAdminTools(server, env) {
    // --------------------------------------------------------
    // TOOL: vault_provision_client
    // --------------------------------------------------------
    server.registerTool("vault_provision_client", {
        title: "Provision Client",
        description: `Create a new vault client with a bearer token and ACL (admin only).

The generated bearer_token is returned ONCE and never stored in plaintext.
Store it immediately — it cannot be recovered after this call.

Args:
  - client_id (string): Unique ID for this client (e.g. "claude-stemforge-agent")
  - allowed_keys (string[]): List of secret key names this client may access
  - description (string): Human-readable label for this client

Returns:
  {
    "client_id": string,
    "bearer_token": string,   // STORE THIS — returned once only
    "allowed_keys": string[],
    "message": string
  }`,
        inputSchema: z.object({
            client_id: z.string().min(1).max(64).regex(/^[a-z0-9-]+$/).describe("Unique client ID (lowercase, hyphens only)"),
            allowed_keys: z.array(z.string().min(1)).min(1).describe("Secret key names this client can access"),
            description: z.string().min(1).max(256).describe("Human-readable label for this client"),
        }),
        annotations: {
            readOnlyHint: false,
            destructiveHint: false,
            idempotentHint: false,
            openWorldHint: false,
        },
    }, async ({ client_id, allowed_keys, description }) => {
        const bearerToken = generateBearerToken();
        const tokenHash = await hashToken(bearerToken);
        const client = {
            id: client_id,
            bearerToken: tokenHash,
            allowedKeys: allowed_keys,
            description,
            createdAt: new Date().toISOString(),
        };
        await env.VAULT_ACL.put(`${ACL_PREFIX}${client_id}`, JSON.stringify(client));
        const result = {
            client_id,
            bearer_token: bearerToken, // plaintext — returned once only
            allowed_keys,
            message: `Client '${client_id}' provisioned. Store the bearer_token immediately — it will not be recoverable.`,
        };
        return { content: [{ type: "text", text: JSON.stringify(result) }] };
    });
    // --------------------------------------------------------
    // TOOL: vault_revoke_client
    // --------------------------------------------------------
    server.registerTool("vault_revoke_client", {
        title: "Revoke Client",
        description: `Permanently revoke a client's access to the vault (admin only).
The client's ACL entry is deleted. Their bearer token immediately stops working.

Args:
  - client_id (string): ID of the client to revoke

Returns:
  {
    "client_id": string,
    "revoked": boolean,
    "message": string
  }`,
        inputSchema: z.object({
            client_id: z.string().min(1).describe("Client ID to revoke"),
        }),
        annotations: {
            readOnlyHint: false,
            destructiveHint: true,
            idempotentHint: true,
            openWorldHint: false,
        },
    }, async ({ client_id }) => {
        const client = await getClientById(client_id, env.VAULT_ACL);
        if (!client) {
            return { content: [{ type: "text", text: JSON.stringify({ error: ERR_CLIENT_NOT_FOUND, client_id }) }] };
        }
        await env.VAULT_ACL.delete(`${ACL_PREFIX}${client_id}`);
        const result = {
            client_id,
            revoked: true,
            message: `Client '${client_id}' has been revoked. All future requests with their token will be denied.`,
        };
        return { content: [{ type: "text", text: JSON.stringify(result) }] };
    });
    // --------------------------------------------------------
    // TOOL: vault_update_acl
    // --------------------------------------------------------
    server.registerTool("vault_update_acl", {
        title: "Update Client ACL",
        description: `Update the list of keys a client is allowed to access (admin only).
Replaces the existing allowed_keys list entirely.

Args:
  - client_id (string): Target client ID
  - allowed_keys (string[]): New complete list of allowed key names

Returns:
  {
    "client_id": string,
    "allowed_keys": string[],
    "message": string
  }`,
        inputSchema: z.object({
            client_id: z.string().min(1).describe("Target client ID"),
            allowed_keys: z.array(z.string().min(1)).min(0).describe("New complete ACL (replaces existing)"),
        }),
        annotations: {
            readOnlyHint: false,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: false,
        },
    }, async ({ client_id, allowed_keys }) => {
        const client = await getClientById(client_id, env.VAULT_ACL);
        if (!client) {
            return { content: [{ type: "text", text: JSON.stringify({ error: ERR_CLIENT_NOT_FOUND, client_id }) }] };
        }
        const updated = { ...client, allowedKeys: allowed_keys };
        await env.VAULT_ACL.put(`${ACL_PREFIX}${client_id}`, JSON.stringify(updated));
        const result = {
            client_id,
            allowed_keys,
            message: `ACL for '${client_id}' updated successfully.`,
        };
        return { content: [{ type: "text", text: JSON.stringify(result) }] };
    });
    // --------------------------------------------------------
    // TOOL: vault_list_clients
    // --------------------------------------------------------
    server.registerTool("vault_list_clients", {
        title: "List Vault Clients",
        description: `List all provisioned clients and their ACL metadata (admin only).
Never returns bearer tokens.`,
        inputSchema: z.object({}),
        annotations: {
            readOnlyHint: true,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: false,
        },
    }, async () => {
        const list = await env.VAULT_ACL.list({ prefix: ACL_PREFIX });
        const clients = await Promise.all(list.keys.map(async (k) => {
            const raw = await env.VAULT_ACL.get(k.name);
            if (!raw)
                return null;
            const c = JSON.parse(raw);
            return {
                id: c.id,
                allowed_keys: c.allowedKeys,
                description: c.description,
                createdAt: c.createdAt,
            };
        }));
        const filtered = clients.filter(Boolean);
        const result = { clients: filtered, total: filtered.length };
        return { content: [{ type: "text", text: JSON.stringify(result) }] };
    });
    // --------------------------------------------------------
    // TOOL: vault_access_log
    // --------------------------------------------------------
    server.registerTool("vault_access_log", {
        title: "View Access Log",
        description: `Retrieve paginated audit log of all vault access events (admin only).
Optionally filter by caller_id or key_name.

Args:
  - page (number): Page number (default: 1)
  - caller_id (string, optional): Filter by specific caller
  - key_name (string, optional): Filter by specific key name

Returns:
  {
    "entries": [{ "id", "caller_id", "key_name", "access_granted", "reason", "timestamp", "ip" }],
    "total": number,
    "page": number,
    "per_page": number
  }`,
        inputSchema: z.object({
            page: z.number().int().min(1).default(1).describe("Page number"),
            caller_id: z.string().optional().describe("Filter by caller ID"),
            key_name: z.string().optional().describe("Filter by key name"),
        }),
        annotations: {
            readOnlyHint: true,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: false,
        },
    }, async ({ page, caller_id, key_name }) => {
        const log = await getAccessLog(env.VAULT_LOG, { page, caller_id, key_name });
        return { content: [{ type: "text", text: JSON.stringify(log) }] };
    });
}
//# sourceMappingURL=admin.js.map