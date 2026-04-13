p# The Key Vault
**Centralized API Key Vault via MCP — by buildwhilebleeding.com**

A zero-trust credential broker running on Cloudflare Workers free tier. Any MCP-compatible AI client can retrieve secrets via authenticated tool calls. Keys live in Cloudflare Workers Secrets (encrypted at rest). Every access is logged to D1.

---

## Architecture

```
AI Client (Claude / GPT / etc.)
        │
        ▼  POST /mcp  (MCP JSON-RPC)
[ Cloudflare Worker — The Key Vault ]
        │
        ├── Auth: Bearer token → resolve caller_id from KV ACL
        ├── ACL check: caller_id → allowed_keys[]
        ├── Secret fetch: env[KEY_NAME] (Workers Secrets)
        └── Audit: D1 access log (caller, key, granted/denied, timestamp, IP)
```

---

## Tools Exposed

### Client Tools
| Tool | Description |
|---|---|
| `vault_get_secret` | Retrieve a secret by name (ACL-gated) |
| `vault_list_secrets` | List key names the caller can access (values never returned) |

### Admin Tools (require `VAULT_ADMIN_TOKEN`)
| Tool | Description |
|---|---|
| `vault_provision_client` | Create a new client + bearer token + ACL |
| `vault_revoke_client` | Permanently revoke a client's access |
| `vault_update_acl` | Update which keys a client can access |
| `vault_list_clients` | List all provisioned clients |
| `vault_access_log` | View paginated audit log (filterable by caller/key) |

---

## Deploy

### 1. Prerequisites
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) installed and authenticated
- Cloudflare account (free tier works)

### 2. Create Infrastructure

```bash
# Create KV namespace for ACL
wrangler kv namespace create "VAULT_ACL"
# → Copy the id into wrangler.toml → kv_namespaces[0].id

# Create D1 database for audit log
wrangler d1 create the-key-vault-log
# → Copy the database_id into wrangler.toml → d1_databases[0].database_id
```

### 3. Set Secrets

```bash
# Admin token — generate a strong random value and store it yourself
wrangler secret put VAULT_ADMIN_TOKEN

# Add every API key you want managed by the vault
wrangler secret put OPENAI_API_KEY
wrangler secret put HUGGINGFACE_TOKEN
wrangler secret put CLOUDFLARE_API_TOKEN
# ... add as many as needed
```

### 4. Deploy

```bash
npm install
npm run build
wrangler deploy
```

### 5. Initialize the Database

```bash
curl -X POST https://the-key-vault.YOUR_SUBDOMAIN.workers.dev/init \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### 6. Provision Your First Client

```bash
VAULT_ADMIN_TOKEN=your_token \
VAULT_URL=https://the-key-vault.YOUR_SUBDOMAIN.workers.dev \
node scripts/provision.js
```

Or call `vault_provision_client` directly via MCP:
```json
{
  "admin_token": "YOUR_ADMIN_TOKEN",
  "client_id": "claude-stemforge-agent",
  "allowed_keys": ["HUGGINGFACE_TOKEN", "CLOUDFLARE_API_TOKEN"],
  "description": "StemForge audio pipeline agent"
}
```

**Save the returned `bearer_token` immediately — it's only shown once.**

---

## Connect to Claude.ai

1. Go to **Settings → Connectors → Add MCP Server**
2. URL: `https://the-key-vault.YOUR_SUBDOMAIN.workers.dev/mcp`
3. The vault tools will appear in Claude's tool list

---

## Adding a New Secret (Rotation)

```bash
# Update the value in Workers Secrets
wrangler secret put OPENAI_API_KEY
# → Enter new value
# → Redeploy
wrangler deploy
```

No client reconfiguration needed — they call `vault_get_secret` by name, not by value.

---

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/mcp` | POST | MCP JSON-RPC tool interface |
| `/health` | GET | Health check |
| `/init` | POST | Initialize D1 schema (admin token required) |

---

## Security Model

- Bearer tokens are hashed with SHA-256 before storage — the plaintext is never persisted
- Secrets never appear in logs or error messages — only key names are logged
- Every access attempt (granted or denied) is written to D1
- ACL is enforced per-request, per-key — no wildcard access
- Admin operations require a separate admin token, never exposed to clients
