-- Add Cloudflare Calls related fields to video_calls table
ALTER TABLE video_calls ADD COLUMN cf_calls_app_id TEXT;
ALTER TABLE video_calls ADD COLUMN cf_calls_session_id TEXT;
ALTER TABLE video_calls ADD COLUMN cf_calls_data TEXT; -- Store as JSON string

-- It's good practice to update the updated_at timestamp for existing rows if applicable,
-- but for new columns, it's often not necessary unless a default value implies a change.
-- For SQLite, multiple ALTER TABLE ADD COLUMN statements are fine.
COMMIT;
