CREATE TABLE user_public_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    public_key_pem TEXT NOT NULL, -- Stores the public key in PEM format
    key_type TEXT NOT NULL DEFAULT 'e2ee_messaging', -- e.g., 'e2ee_messaging', 'pgp_signing'
    key_identifier TEXT, -- Optional: A user-friendly name or fingerprint for the key
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME, -- Optional: If keys have an expiry
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    -- A user might have multiple keys, but perhaps only one active key of a certain type.
    -- Or, a user might have one primary key for E2EE.
    -- For simplicity, this schema allows multiple keys per user. A unique constraint
    -- could be (user_id, key_type, is_active) if only one active key per type is allowed,
    -- but that requires careful management by the application.
    -- Let's start without it; the app can enforce "only one active e2ee_messaging key".
    -- A unique constraint on (user_id, public_key_pem) might be useful to prevent duplicates.
    UNIQUE (user_id, public_key_pem)
);

CREATE INDEX IF NOT EXISTS idx_user_public_keys_user_id_key_type_active ON user_public_keys (user_id, key_type, is_active);

COMMIT;
