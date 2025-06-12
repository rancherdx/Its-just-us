CREATE TABLE email_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_name TEXT NOT NULL UNIQUE, -- e.g., 'welcome_email', 'password_reset'
    subject_template TEXT NOT NULL,
    body_html_template TEXT NOT NULL,
    default_sender_name TEXT,
    default_sender_email TEXT, -- If template should override default MS Graph sender
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_email_templates_template_name ON email_templates (template_name);
COMMIT;
