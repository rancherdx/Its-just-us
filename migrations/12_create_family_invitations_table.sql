CREATE TABLE family_invitations (
    id TEXT PRIMARY KEY, -- UUID, generated by application
    family_id TEXT NOT NULL,
    invited_email TEXT NOT NULL,
    invited_by_user_id TEXT NOT NULL,
    role_to_assign TEXT NOT NULL, -- e.g., 'parent', 'child'
    status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'accepted', 'declined', 'expired'
    token TEXT NOT NULL UNIQUE, -- Secure random token for the invite link
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (family_id) REFERENCES families(id) ON DELETE CASCADE,
    FOREIGN KEY (invited_by_user_id) REFERENCES users(id) ON DELETE CASCADE
    -- Note: invited_email is not a FK as the user may not exist yet.
);

CREATE INDEX IF NOT EXISTS idx_family_invitations_family_id_status ON family_invitations (family_id, status);
CREATE INDEX IF NOT EXISTS idx_family_invitations_invited_email ON family_invitations (invited_email);
CREATE INDEX IF NOT EXISTS idx_family_invitations_expires_at ON family_invitations (expires_at);

COMMIT;
