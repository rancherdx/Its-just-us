PRAGMA foreign_keys = ON;

-- From migrations/0_initial_schema.sql
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))), -- Using UUID for new users
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT, -- Nullable for OAuth users
    profile_picture TEXT,
    status TEXT, -- e.g., 'online', 'offline', 'away'
    last_seen_at DATETIME,
    bio TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

DROP TABLE IF EXISTS password_reset_tokens;
CREATE TABLE password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
);

DROP TABLE IF EXISTS posts;
CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    title TEXT,
    content TEXT,
    media_url TEXT,
    media_type TEXT,
    visibility TEXT DEFAULT 'public',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

DROP TABLE IF EXISTS events;
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    all_day BOOLEAN DEFAULT 0,
    location TEXT,
    visibility TEXT DEFAULT 'private',
    recurrence_rule TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

DROP TABLE IF EXISTS conversations;
CREATE TABLE conversations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    title TEXT,
    created_by_user_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_message_at DATETIME,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

DROP TABLE IF EXISTS conversation_participants;
CREATE TABLE conversation_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_read_at DATETIME,
    is_admin BOOLEAN DEFAULT 0,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (conversation_id, user_id)
);

DROP TABLE IF EXISTS messages;
CREATE TABLE messages (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    conversation_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    content TEXT NOT NULL,
    message_type TEXT DEFAULT 'text',
    media_url TEXT,
    reactions_json TEXT,
    parent_message_id TEXT,
    is_edited BOOLEAN DEFAULT 0,
    is_deleted BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_message_id) REFERENCES messages(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_conversation_created_at ON messages (conversation_id, created_at DESC);

DROP TABLE IF EXISTS video_calls;
CREATE TABLE video_calls (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    room_name TEXT NOT NULL UNIQUE,
    created_by_user_id TEXT NOT NULL,
    title TEXT,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME,
    status TEXT NOT NULL,
    max_participants INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);

DROP TABLE IF EXISTS call_participants;
CREATE TABLE call_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    call_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    left_at DATETIME,
    status TEXT,
    is_muted BOOLEAN DEFAULT 0,
    is_video_enabled BOOLEAN DEFAULT 0,
    FOREIGN KEY (call_id) REFERENCES video_calls(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (call_id, user_id)
);

DROP TABLE IF EXISTS third_party_integrations;
CREATE TABLE third_party_integrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT NOT NULL UNIQUE,
    friendly_name TEXT,
    description TEXT,
    api_key_encrypted TEXT,
    client_id_encrypted TEXT,
    client_secret_encrypted TEXT,
    tenant_id_encrypted TEXT,
    other_config_encrypted TEXT,
    is_enabled BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS audit_logs;
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details_json TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

DROP TABLE IF EXISTS seasonal_themes;
CREATE TABLE seasonal_themes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    start_date DATE,
    end_date DATE,
    theme_config_json TEXT,
    is_active BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- From migrations/1_add_cf_calls_fields_to_video_calls.sql
ALTER TABLE video_calls ADD COLUMN cf_calls_app_id TEXT;
ALTER TABLE video_calls ADD COLUMN cf_calls_session_id TEXT;
ALTER TABLE video_calls ADD COLUMN cf_calls_data TEXT;

-- From migrations/2_create_push_subscriptions_table.sql
DROP TABLE IF EXISTS push_subscriptions;
CREATE TABLE push_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    keys_p256dh TEXT NOT NULL,
    keys_auth TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id, endpoint)
);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user_id ON push_subscriptions (user_id);

-- From migrations/3_create_jwt_blocklist_table.sql
DROP TABLE IF EXISTS jwt_blocklist;
CREATE TABLE jwt_blocklist (
    jti TEXT PRIMARY KEY,
    user_id TEXT,
    expires_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jwt_blocklist_expires_at ON jwt_blocklist (expires_at);

-- From migrations/4_create_ip_tracking_tables.sql
DROP TABLE IF EXISTS user_known_ips;
CREATE TABLE user_known_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    is_trusted BOOLEAN DEFAULT 0,
    notes TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_user_known_ips_user_id_last_seen ON user_known_ips (user_id, last_seen_at DESC);

DROP TABLE IF EXISTS failed_login_attempts;
CREATE TABLE failed_login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempted_identifier TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_suspicious BOOLEAN DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_failed_login_attempts_ip_address ON failed_login_attempts (ip_address, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_failed_login_attempts_identifier ON failed_login_attempts (attempted_identifier, attempted_at DESC);

-- From migrations/5_create_email_templates_table.sql
DROP TABLE IF EXISTS email_templates;
CREATE TABLE email_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_name TEXT NOT NULL UNIQUE,
    subject_template TEXT NOT NULL,
    body_html_template TEXT NOT NULL,
    default_sender_name TEXT,
    default_sender_email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_email_templates_template_name ON email_templates (template_name);

-- From migrations/6_create_user_ms_graph_tokens_table.sql
DROP TABLE IF EXISTS user_ms_graph_tokens;
CREATE TABLE user_ms_graph_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL UNIQUE,
    ms_graph_user_id TEXT,
    access_token_encrypted TEXT NOT NULL,
    refresh_token_encrypted TEXT NOT NULL,
    token_expiry_timestamp_ms INTEGER NOT NULL,
    scopes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_ms_graph_tokens_user_id ON user_ms_graph_tokens (user_id);

-- From migrations/7_add_mscalendar_sync_and_oauth_state.sql
ALTER TABLE users ADD COLUMN microsoft_user_id TEXT;
ALTER TABLE users ADD COLUMN synced_ms_calendar_id TEXT;
CREATE INDEX IF NOT EXISTS idx_users_microsoft_user_id ON users (microsoft_user_id);

DROP TABLE IF EXISTS oauth_state;
CREATE TABLE oauth_state (
    state TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_state_expires_at ON oauth_state (expires_at);

-- Final COMMIT (optional for schema definition script but good practice)
COMMIT;
