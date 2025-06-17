CREATE TABLE child_activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    child_user_id TEXT NOT NULL,
    event_type TEXT NOT NULL DEFAULT 'heartbeat_active', -- e.g., 'heartbeat_active', 'app_foreground', 'app_background', 'feature_A_start', 'feature_A_end'
    client_event_timestamp DATETIME, -- Timestamp from the client, if provided (UTC ISO8601)
    server_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, -- Timestamp when server logged it (UTC)
    event_details_json TEXT, -- Optional JSON blob for more specific event data
    FOREIGN KEY (child_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_child_activity_logs_child_user_id_timestamp ON child_activity_logs (child_user_id, server_timestamp DESC);
COMMIT;
