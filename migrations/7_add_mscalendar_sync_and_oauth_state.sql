-- Add fields to users table for MS Graph Calendar Sync and User ID
ALTER TABLE users ADD COLUMN microsoft_user_id TEXT; -- Stores the user's actual MS Graph User ID
ALTER TABLE users ADD COLUMN synced_ms_calendar_id TEXT; -- Stores the ID of the MS Calendar they chose to sync

-- Optional: Add an index if you query by microsoft_user_id often
CREATE INDEX IF NOT EXISTS idx_users_microsoft_user_id ON users (microsoft_user_id);

-- OAuth State Table (for CSRF protection and user association during OAuth flow)
CREATE TABLE oauth_state (
    state TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at DATETIME NOT NULL -- Store as ISO8601 string or UNIX timestamp
);
CREATE INDEX IF NOT EXISTS idx_oauth_state_expires_at ON oauth_state (expires_at);

COMMIT;
