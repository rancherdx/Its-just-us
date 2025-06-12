CREATE TABLE user_ms_graph_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL UNIQUE, -- App's internal user ID
    ms_graph_user_id TEXT,      -- Microsoft Graph User ID (from /me endpoint)
    access_token_encrypted TEXT NOT NULL,
    refresh_token_encrypted TEXT NOT NULL,
    token_expiry_timestamp_ms INTEGER NOT NULL, -- UTC milliseconds since epoch
    scopes TEXT, -- Space-separated list of granted scopes
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_ms_graph_tokens_user_id ON user_ms_graph_tokens (user_id);
COMMIT;
