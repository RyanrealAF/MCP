#!/usr/bin/env node
// ============================================================
// The Key Vault — Local Provision Script
// Run: node scripts/provision.js
// Use this to test provisioning via the deployed Worker
// ============================================================

const VAULT_URL = process.env.VAULT_URL ?? "https://the-key-vault.YOUR_SUBDOMAIN.workers.dev";
const ADMIN_TOKEN = process.env.VAULT_ADMIN_TOKEN;

if (!ADMIN_TOKEN) {
  console.error("Error: VAULT_ADMIN_TOKEN environment variable is required.");
  console.error("Usage: VAULT_ADMIN_TOKEN=your_token VAULT_URL=https://... node scripts/provision.js");
  process.exit(1);
}

async function callTool(toolName, input) {
  const res = await fetch(`${VAULT_URL}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${ADMIN_TOKEN}`
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: toolName, arguments: input },
    }),
  });
  const data = await res.json();
  if (data.error) throw new Error(JSON.stringify(data.error));
  const text = data.result?.content?.[0]?.text;
  if (!text) {
    throw new Error(`Empty response from tool ${toolName}. Full response: ${JSON.stringify(data)}`);
  }
  return JSON.parse(text);
}

async function main() {
  console.log("=== The Key Vault — Provision Script ===\n");

  // 1. Initialize DB schema
  console.log("1. Initializing database schema...");
  const initRes = await fetch(`${VAULT_URL}/init`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
  });
  const initData = await initRes.json();
  console.log("   ", initData.message ?? initData.error);

  // 2. Provision a test client
  console.log("\n2. Provisioning test client: claude-test-agent...");
  const client = await callTool("vault_provision_client", {
    client_id: "claude-test-agent",
    allowed_keys: ["OPENAI_API_KEY", "HUGGINGFACE_TOKEN"],
    description: "Test agent for local development",
  });
  console.log("   Client ID:    ", client.client_id);
  console.log("   Bearer Token: ", client.bearer_token);
  console.log("   Allowed Keys: ", client.allowed_keys.join(", "));
  console.log("\n   ⚠️  Store the bearer token — it will not be shown again.");

  // 3. List all clients
  console.log("\n3. Listing all clients...");
  const list = await callTool("vault_list_clients", {});
  console.log(`   Total clients: ${list.total}`);
  list.clients.forEach((c) => {
    console.log(`   - ${c.id}: [${c.allowed_keys.join(", ")}]`);
  });

  console.log("\n✅ Done.");
}

main().catch((err) => {
  console.error("Fatal:", err.message);
  process.exit(1);
});
