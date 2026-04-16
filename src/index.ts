// ============================================================
// The Key Vault — Cloudflare Worker Entry Point
// buildwhilebleeding.com
// ============================================================

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { VaultEnv } from "./types.js";
import { registerVaultTools } from "./tools/vault.js";
import { registerAdminTools } from "./tools/admin.js";
import { initializeSchema } from "./services/audit.js";
import { VAULT_NAME, VAULT_VERSION } from "./constants.js";
import { resolveCallerFromToken, extractBearerToken } from "./services/auth.js";

// ----------------------------------------------------------
// Cloudflare Worker fetch handler
// ----------------------------------------------------------
export default {
  async fetch(request: Request, env: VaultEnv): Promise<Response> {
    const url = new URL(request.url);
    const clientIp = request.headers.get("CF-Connecting-IP") ?? "unknown";

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });
    }

    // Health check
    if (url.pathname === "/health" && request.method === "GET") {
      return Response.json({
        status: "ok",
        service: VAULT_NAME,
        version: VAULT_VERSION,
      });
    }

    // DB init endpoint (run once after deploy)
    if (url.pathname === "/init" && request.method === "POST") {
      const authHeader = request.headers.get("Authorization");
      const token = authHeader?.split(" ")[1];
      if (token !== (env.VAULT_ADMIN_TOKEN as string)) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      }
      await initializeSchema(env.VAULT_LOG);
      return Response.json({ message: "Schema initialized successfully." });
    }

    // MCP endpoint
    if (url.pathname === "/mcp" && request.method === "POST") {
      const authHeader = request.headers.get("Authorization");
      const bearerToken = extractBearerToken(authHeader);

      if (!bearerToken) {
        return Response.json({ error: "Unauthorized: Missing bearer token" }, { status: 401 });
      }

      const client = await resolveCallerFromToken(bearerToken, env.VAULT_ACL);
      const isAdmin = bearerToken === env.VAULT_ADMIN_TOKEN;

      if (!client && !isAdmin) {
        return Response.json({ error: "Unauthorized: Invalid bearer token" }, { status: 401 });
      }

      const server = new McpServer({
        name: "the-key-vault-mcp",
        version: VAULT_VERSION,
      });

      // Register tools — client IP threaded through for audit logging
      if (client) {
        registerVaultTools(server, env, clientIp, client);
      }
      if (isAdmin) {
        registerAdminTools(server, env);
      }

      const body = await request.json();

      // Manual tool execution for Cloudflare Workers
      // We need to wait for the response to be sent back through the transport
      let mcpResponse: any = null;
      let resolveResponse: (value: any) => void;
      const responsePromise = new Promise(resolve => {
        resolveResponse = resolve;
      });

      const transport = {
        async start() {},
        async close() {},
        async send(message: any) {
          mcpResponse = message;
          resolveResponse(message);
        },
        onmessage: null as any,
        onerror: null as any,
        onclose: null as any,
      };

      await server.connect(transport as any);

      // The onmessage handler is actually attached to the underlying server's transport
      const internalServer = (server as any).server;
      if (internalServer && internalServer.transport && typeof internalServer.transport.onmessage === 'function') {
         await internalServer.transport.onmessage(body);
      }

      // Wait for the response (with a timeout just in case)
      const timeoutPromise = new Promise(resolve => setTimeout(() => resolve({ error: { code: -32603, message: "Internal error: timeout" } }), 5000));
      const finalResponse = await Promise.race([responsePromise, timeoutPromise]);

      return new Response(JSON.stringify(finalResponse), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    return Response.json(
      { error: "Not found", endpoints: ["/mcp", "/health", "/init"] },
      { status: 404 }
    );
  },
};
