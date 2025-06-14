-- Seed data for the It's Just Us application

-- Seasonal Themes
INSERT OR IGNORE INTO seasonal_themes (name, description, start_date, end_date, theme_config_json, is_active) VALUES
('Juneteenth', 'Theme celebrating Juneteenth - Freedom Day.', '2024-06-19', '2024-06-19', '{ "primaryColor": "#AA0000", "secondaryColor": "#006A35", "accentColor": "#000000", "textColor": "#FFFFFF", "fontFamily": "Georgia, serif", "bannerImageUrl": "/assets/themes/juneteenth/banner.jpg", "loadingScreen": {"backgroundColor": "#000000", "text": "Celebrating Freedom...", "icon": "/assets/themes/juneteenth/icon.png"} }', 0),
('FathersDay', 'Theme celebrating Father''s Day.', '2024-06-16', '2024-06-16', '{ "primaryColor": "#1034A6", "secondaryColor": "#B0C4DE", "accentColor": "#708090", "textColor": "#333333", "fontFamily": "Verdana, sans-serif", "bannerImageUrl": "/assets/themes/fathersday/banner.jpg", "loadingScreen": {"backgroundColor": "#B0C4DE", "text": "Happy Father''''s Day!", "icon": "/assets/themes/fathersday/icon.png"} }', 0),
('Christmas', 'Christmas Holiday Theme', NULL, NULL, '{ "primaryColor": "#D1403F", "secondaryColor": "#1B5E20", "accentColor": "#FDD835", "textColor": "#FFFFFF", "fontFamily": "''Merry Christmas'', cursive", "bannerImageUrl": "/assets/themes/christmas/banner.jpg", "status": "upcoming_configuration" }', 0),
('NewYears', 'New Year''s Celebration Theme', NULL, NULL, '{ "primaryColor": "#FFD700", "secondaryColor": "#000000", "accentColor": "#C0C0C0", "textColor": "#FFFFFF", "fontFamily": "Arial, sans-serif", "bannerImageUrl": "/assets/themes/newyears/banner.jpg", "status": "upcoming_configuration" }', 0),
('IndependenceDayUS', 'US Independence Day Theme', NULL, NULL, '{ "primaryColor": "#BF0A30", "secondaryColor": "#FFFFFF", "accentColor": "#002868", "textColor": "#000000", "fontFamily": "Georgia, serif", "bannerImageUrl": "/assets/themes/independence_day/banner.jpg", "status": "upcoming_configuration" }', 0),
('ThanksgivingUS', 'US Thanksgiving Theme', NULL, NULL, '{ "primaryColor": "#A0522D", "secondaryColor": "#FF8C00", "accentColor": "#8B4513", "textColor": "#FFFFFF", "fontFamily": "Georgia, serif", "bannerImageUrl": "/assets/themes/thanksgiving/banner.jpg", "status": "upcoming_configuration" }', 0),
('Halloween', 'Halloween Spooky Theme', NULL, NULL, '{ "primaryColor": "#FF6600", "secondaryColor": "#000000", "accentColor": "#580073", "textColor": "#FFFFFF", "fontFamily": "''Creepster'', cursive", "bannerImageUrl": "/assets/themes/halloween/banner.jpg", "status": "upcoming_configuration" }', 0),
('MLKDay', 'Martin Luther King Jr. Day Theme', NULL, NULL, '{ "primaryColor": "#000000", "secondaryColor": "#BDBDBD", "accentColor": "#D4AF37", "textColor": "#FFFFFF", "fontFamily": "Georgia, serif", "bannerImageUrl": "/assets/themes/mlkday/banner.jpg", "status": "upcoming_configuration" }', 0);

-- Email Templates
INSERT OR IGNORE INTO email_templates (template_name, subject_template, body_html_template, default_sender_name, default_sender_email) VALUES
('welcome_email', 'Welcome to {{appName}}, {{name}}!', '<html><body><h1>Hi {{name}},</h1><p>Thanks for joining {{appName}}. We are excited to have you!</p><p>Regards,<br/>The {{appName}} Team</p></body></html>', NULL, NULL),
('password_reset_email', 'Password Reset Request for {{appName}}', '<html><body><p>Hi {{name}},</p><p>You requested a password reset for your account with {{appName}}.</p><p>Please click this link to reset your password: <a href="{{resetLink}}">{{resetLink}}</a></p><p>This link is valid for {{expiryMinutes}} minutes.</p><p>If you did not request this, please ignore this email.</p><p>Regards,<br/>The {{appName}} Team</p></body></html>', NULL, NULL),
('password_changed_confirmation', 'Your Password for {{appName}} Has Been Changed', '<html><body><p>Hi {{name}},</p><p>This email confirms that your password for your {{appName}} account was successfully changed.</p><p>If you did not make this change, please contact our support team immediately.</p><p>Regards,<br/>The {{appName}} Team</p></body></html>', NULL, NULL);

-- Third-Party Integrations (Placeholders - Requires manual encryption and actual values for production)
-- Note: For encrypted fields, the value 'PLACEHOLDER_ENCRYPTED_...' should be replaced with actual encrypted data.
-- For this seed, we are inserting NULL or placeholder text as direct encryption isn't feasible here.
-- The application should have a secure way to populate these, possibly via an admin UI that handles encryption.

INSERT OR IGNORE INTO third_party_integrations (service_name, friendly_name, description, is_enabled, api_key_encrypted, client_id_encrypted, client_secret_encrypted, tenant_id_encrypted, other_config_encrypted) VALUES
('MicrosoftGraphDelegated', 'Microsoft Graph (User OAuth)', 'For user calendar sync and other user-delegated MS Graph features. Requires Client ID, Client Secret, Tenant ID.', 0, NULL, 'PLACEHOLDER_MS_DELEGATED_CLIENT_ID', 'PLACEHOLDER_MS_DELEGATED_CLIENT_SECRET', 'PLACEHOLDER_MS_DELEGATED_TENANT_ID (or common)'),
('MicrosoftGraphAppOnlyEmail', 'Microsoft Graph (App-Only Email)', 'For sending application emails (welcome, password reset etc.). Requires Client ID, Client Secret, Tenant ID, Sending User ID.', 1, NULL, 'PLACEHOLDER_MS_APPEMAIL_CLIENT_ID', 'PLACEHOLDER_MS_APPEMAIL_CLIENT_SECRET', 'PLACEHOLDER_MS_APPEMAIL_TENANT_ID', 'PLACEHOLDER_CONFIG_WITH_SENDING_USER_ID'),
('CloudflareCalls', 'Cloudflare Calls (Video)', 'For video call infrastructure. Requires App ID and API Token.', 0, 'PLACEHOLDER_CF_CALLS_API_TOKEN', 'PLACEHOLDER_CF_CALLS_APP_ID', NULL, NULL, NULL),
('VAPIDPushKeys', 'Web Push VAPID Keys', 'VAPID Public and Private keys for Web Push Notifications.', 1, 'PLACEHOLDER_VAPID_PUBLIC_KEY', NULL, 'PLACEHOLDER_VAPID_PRIVATE_KEY', NULL, NULL);

COMMIT;
