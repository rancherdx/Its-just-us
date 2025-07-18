-- Add RBAC related columns to the 'users' table
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';
ALTER TABLE users ADD COLUMN family_id TEXT; -- Nullable, will store UUID string
ALTER TABLE users ADD COLUMN date_of_birth DATE; -- Nullable

-- Create an index on the new family_id column in users table
CREATE INDEX IF NOT EXISTS idx_users_family_id ON users (family_id);
-- Optionally, create an index on the role if queried often
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);

-- Create the 'families' table
CREATE TABLE families (
    id TEXT PRIMARY KEY, -- UUID, generated by application
    family_name TEXT,    -- Optional name for the family
    created_by_user_id TEXT NOT NULL, -- User ID of the family creator/initial admin
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Optional: Index on families.created_by_user_id
CREATE INDEX IF NOT EXISTS idx_families_created_by_user_id ON families (created_by_user_id);

COMMIT;
