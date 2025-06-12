-- JWT Blocklist Table
CREATE TABLE jwt_blocklist (
    jti TEXT PRIMARY KEY,         -- JWT ID
    user_id TEXT,                 -- User ID associated with the token (for auditing/context)
    expires_at DATETIME NOT NULL  -- Token's original expiry time, also when this blocklist entry can be purged
);

CREATE INDEX IF NOT EXISTS idx_jwt_blocklist_expires_at ON jwt_blocklist (expires_at);
COMMIT;
