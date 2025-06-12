-- Push Subscriptions Table
CREATE TABLE push_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    endpoint TEXT NOT NULL, -- From the PushSubscription object
    keys_p256dh TEXT NOT NULL, -- From PushSubscription.keys.p256dh
    keys_auth TEXT NOT NULL,   -- From PushSubscription.keys.auth
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id, endpoint) -- A user should not have duplicate subscriptions for the same endpoint
);

CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user_id ON push_subscriptions (user_id);
COMMIT;
