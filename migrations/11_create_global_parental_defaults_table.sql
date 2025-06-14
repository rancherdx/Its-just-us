CREATE TABLE global_parental_control_defaults (
    id INTEGER PRIMARY KEY CHECK (id = 1), -- Ensures only one row
    settings_json TEXT NOT NULL,           -- Stores the JSON blob of default settings
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_by_super_admin_id TEXT NOT NULL, -- User ID of the super_admin who last updated
    FOREIGN KEY (updated_by_super_admin_id) REFERENCES users(id) ON DELETE RESTRICT -- Prevent deletion of user if they set this
);

-- Seed with an initial empty/default state if desired, or leave for first PUT by admin
-- Example initial seed (optional, admin can set it via API):
-- INSERT OR IGNORE INTO global_parental_control_defaults (id, settings_json, updated_by_super_admin_id)
-- VALUES (1, '{}', 'system_init_placeholder_user_id');
-- (Requires a placeholder user_id or a known super_admin ID if seeding)

COMMIT;
