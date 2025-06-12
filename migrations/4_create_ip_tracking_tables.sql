-- User Known IPs Table
CREATE TABLE user_known_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    is_trusted BOOLEAN DEFAULT 0, -- Admin/user can mark an IP as trusted
    notes TEXT,                   -- Optional notes, e.g., "Home Wi-Fi"
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_user_known_ips_user_id_last_seen ON user_known_ips (user_id, last_seen_at DESC);

-- Failed Login Attempts Table
CREATE TABLE failed_login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempted_identifier TEXT NOT NULL, -- Email or username used for login attempt
    ip_address TEXT NOT NULL,
    user_agent TEXT, -- Store User-Agent for more context
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- No FK for attempted_identifier as it might not match a real user
    -- but can be correlated with users.email or users.name if needed.
    is_suspicious BOOLEAN DEFAULT 0 -- Can be flagged by other processes later
);
CREATE INDEX IF NOT EXISTS idx_failed_login_attempts_ip_address ON failed_login_attempts (ip_address, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_failed_login_attempts_identifier ON failed_login_attempts (attempted_identifier, attempted_at DESC);

COMMIT;
