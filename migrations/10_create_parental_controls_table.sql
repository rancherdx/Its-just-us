CREATE TABLE parental_control_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    child_user_id TEXT NOT NULL UNIQUE, -- The user ID of the child
    settings_json TEXT NOT NULL, -- Stores settings like DND times, screen time limits
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (child_user_id) REFERENCES users(id) ON DELETE CASCADE
);
COMMIT;
