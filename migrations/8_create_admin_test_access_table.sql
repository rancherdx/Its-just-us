CREATE TABLE admin_test_access (
    id INTEGER PRIMARY KEY CHECK (id = 1), -- Ensures only one row for a single system PIN
    pin_hash TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Note to admin: After migration, manually insert the hashed PIN.
-- Example:
-- INSERT INTO admin_test_access (id, pin_hash, updated_at)
-- VALUES (1, 'YOUR_SHA256_HASHED_PIN_HERE', datetime('now'));
COMMIT;
