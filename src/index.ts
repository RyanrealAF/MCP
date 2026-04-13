// ============================================================
// The Key Vault — Cloudflare Worker Entry Point
// buildwhilebleeding.com
// ============================================================

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
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


      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });

      const body = await request.json();

      // Build a minimal Express-like req/res shim for CF Workers
      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();
      const encoder = new TextEncoder();

      const fakeRes = {
        statusCode: 200,
        headers: {} as Record<string, string>,
        setHeader(name: string, value: string) { this.headers[name] = value; },
        getHeader(name: string) { return this.headers[name]; },
        writeHead(status: number) { this.statusCode = status; },
        write(chunk: string | Uint8Array) {
          writer.write(typeof chunk === "string" ? encoder.encode(chunk) : chunk);
        },
        end(chunk?: string | Uint8Array) {
          if (chunk) this.write(chunk);
          writer.close();
        },
        on() { return this; },
      };

      // Use the JSON response mode — simpler for CF Workers
      let responseBody: unknown;
      let responseStatus = 200;

      try {
        await server.connect(transport);
        const result = await transport.handleRequest(
          { body, headers: Object.fromEntries(request.headers.entries()), method: "POST" } as never,
          fakeRes as never,
          body
        );
        void result;
      } catch (err) {
        responseStatus = 500;
        responseBody = { error: "Internal server error" };
      }

      // Collect response from stream
      const responseText = await new Response(readable).text();

      return new Response(responseText || JSON.stringify(responseBody ?? {}), {
        status: responseStatus,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          ...fakeRes.headers,
        },
      });
    }

    return Response.json(
      { error: "Not found", endpoints: ["/mcp", "/health", "/init"] },
      { status: 404 }
    );
  },
};
