// ============================================================
// The Key Vault — Constants
// buildwhilebleeding.com
// ============================================================
export const VAULT_NAME = "The Key Vault";
export const VAULT_VERSION = "1.0.0";
// KV key prefix for client ACL records
export const ACL_PREFIX = "acl:";
// D1 table name
export const ACCESS_LOG_TABLE = "vault_access_log";
// Max log entries to return per page
export const LOG_PAGE_SIZE = 50;
// Errors
export const ERR_UNAUTHORIZED = "Unauthorized: invalid or missing bearer token";
export const ERR_FORBIDDEN = "Forbidden: caller does not have access to this key";
export const ERR_KEY_NOT_FOUND = "Key not found in vault";
export const ERR_CLIENT_NOT_FOUND = "Client ID not found in ACL";
export const ERR_ADMIN_ONLY = "This operation requires admin privileges";
export const ERR_MISSING_FIELDS = "Missing required fields";
//# sourceMappingURL=constants.js.map