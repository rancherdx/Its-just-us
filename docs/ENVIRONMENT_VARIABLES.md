# Backend Environment Variables & Secrets Configuration

This document outlines the necessary environment variables, Cloudflare service bindings (D1, KV, R2, Durable Objects), and secrets required for the proper functioning of the 'It's Just Us' backend application running on Cloudflare Workers.

## 1. Cloudflare Service Bindings (configured in `wrangler.toml`)

These bindings link your Worker to various Cloudflare services. You typically configure these in your `wrangler.toml` file. The `id` or `bucket_name` values will be specific to your Cloudflare account after you create these resources.

### 1.1. D1 Databases

*   **`D1_DB`**
    *   **Binding Name:** `D1_DB`
    *   **Description:** The main application database storing user data, messages, conversations, themes, etc.
    *   **Example `wrangler.toml` entry:**
        ```toml
        [[d1_databases]]
        binding = "D1_DB"
        database_name = "its-just-us"
        database_id = "your_d1_database_id_here" # Replace with your actual D1 DB ID
        migrations = true
        ```

### 1.2. KV Namespaces

*   **`RATE_LIMIT_KV`**
    *   **Binding Name:** `RATE_LIMIT_KV`
    *   **Description:** Used to store IP addresses and request timestamps for implementing rate limiting on certain API endpoints (e.g., login, register).
    *   **Example `wrangler.toml` entry:**
        ```toml
        [[kv_namespaces]]
        binding = "RATE_LIMIT_KV"
        id = "your_kv_namespace_id_for_rate_limiting" # Replace with your actual KV Namespace ID
        # preview_id = "your_preview_kv_namespace_id" # Optional: for development
        ```

### 1.3. R2 Buckets

*   **`USER_MEDIA_BUCKET`**
    *   **Binding Name:** `USER_MEDIA_BUCKET`
    *   **Description:** For storing user-uploaded media files (e.g., profile pictures, post images/videos).
    *   **Example `wrangler.toml` entry:**
        ```toml
        [[r2_buckets]]
        binding = "USER_MEDIA_BUCKET"
        bucket_name = "your-user-media-bucket-name" # Replace
        # preview_bucket_name = "your-preview-user-media-bucket-name" # Optional
        ```
*   **`LIVESTREAMS_BUCKET`**
    *   **Binding Name:** `LIVESTREAMS_BUCKET`
    *   **Description:** For storing livestreaming data or recordings.
    *   **Example `wrangler.toml` entry:**
        ```toml
        [[r2_buckets]]
        binding = "LIVESTREAMS_BUCKET"
        bucket_name = "your-livestreams-bucket-name" # Replace
        ```
*   **`CONTENT_STORAGE_BUCKET`**
    *   **Binding Name:** `CONTENT_STORAGE_BUCKET`
    *   **Description:** For general application content storage (e.g., theme assets if not served from elsewhere, larger static files).
    *   **Example `wrangler.toml` entry:**
        ```toml
        [[r2_buckets]]
        binding = "CONTENT_STORAGE_BUCKET"
        bucket_name = "your-content-storage-bucket-name" # Replace
        ```

### 1.4. Durable Object Bindings

These bindings link to your Durable Object classes defined in `src/index.js`.

*   **`MY_DURABLE_OBJECT`** (If still in use)
    *   **Binding Name:** `MY_DURABLE_OBJECT`
    *   **Class Name:** `MyDurableObject`
    *   **Description:** Placeholder or example Durable Object. Review if this is actively used or can be removed.
*   **`CONVERSATION_DO`**
    *   **Binding Name:** `CONVERSATION_DO`
    *   **Class Name:** `ConversationDurableObject`
    *   **Description:** Manages real-time messaging state and WebSocket connections for individual conversations.
*   **`VIDEO_CALL_SIGNALING_DO`**
    *   **Binding Name:** `VIDEO_CALL_SIGNALING_DO`
    *   **Class Name:** `VideoCallSignalingDO`
    *   **Description:** Manages WebRTC signaling and WebSocket connections for video call rooms.

*Example `wrangler.toml` Durable Objects section:*
```toml
[durable_objects]
bindings = [
  { name = "MY_DURABLE_OBJECT", class_name = "MyDurableObject" },
  { name = "CONVERSATION_DO", class_name = "ConversationDurableObject" },
  { name = "VIDEO_CALL_SIGNALING_DO", class_name = "VideoCallSignalingDO" }
]
```

## 2. Secrets (Managed via Wrangler CLI)

These are sensitive values that should be set using `npx wrangler secret put <SECRET_NAME>`. **Never commit these directly into your code or `wrangler.toml`.**

*   **`JWT_SECRET`**
    *   **Description:** A strong, random string used as the secret key for signing and verifying JSON Web Tokens (JWTs) for user authentication.
    *   **How to Generate:** Use a cryptographically secure random string generator (at least 32 characters long, ideally 64).
*   **`ENCRYPTION_KEY`**
    *   **Description:** A Base64 encoded 256-bit (32-byte) key used for AES-GCM encryption and decryption of sensitive data stored in the database (e.g., third-party API keys, Microsoft Graph user tokens).
    *   **How to Generate:** Generate 32 random bytes and then Base64 encode them. Example using Node.js: `require('crypto').randomBytes(32).toString('base64')`
*   **`VAPID_PUBLIC_KEY`**
    *   **Description:** The public VAPID key for enabling Web Push Notifications. This key is sent to client browsers.
    *   **How to Generate:** Use a web-push library (e.g., `web-push`) to generate VAPID key pairs.
*   **`VAPID_PRIVATE_KEY`**
    *   **Description:** The private VAPID key for signing Web Push Notifications. Keep this secret.
    *   **How to Generate:** Generated along with the public key using a web-push library.
*   **Microsoft Graph App-Only (for sending emails via `third_party_integrations` service `MicrosoftGraphAppOnlyEmail`):**
    *   `MS_GRAPH_APP_CLIENT_ID`: The Application (client) ID from your Azure App Registration for app-only email sending.
    *   `MS_GRAPH_APP_CLIENT_SECRET`: The Client Secret from your Azure App Registration for app-only email sending.
    *   `MS_GRAPH_APP_TENANT_ID`: The Directory (tenant) ID from your Azure App Registration.
    *   `MS_GRAPH_SENDING_USER_ID`: The User ID or User Principal Name (UPN) of the mailbox that the app-only registration has permission to send email from (e.g., `notifications@yourdomain.com`).
*   **Microsoft Graph Delegated (for user calendar access via `third_party_integrations` service `MicrosoftGraphDelegated`):**
    *   `MS_GRAPH_DELEGATED_CLIENT_ID`: The Application (client) ID from your Azure App Registration configured for delegated user permissions.
    *   `MS_GRAPH_DELEGATED_CLIENT_SECRET`: The Client Secret for this delegated app registration.
    *   `MS_GRAPH_DELEGATED_TENANT_ID`: The Directory (tenant) ID (often 'common' for multi-tenant personal/work accounts, or your specific Azure tenant ID).
*   **Facebook OAuth (if `Facebook` service in `third_party_integrations` is used):**
    *   `FACEBOOK_CLIENT_ID`: Your Facebook App ID.
    *   `FACEBOOK_CLIENT_SECRET`: Your Facebook App Secret.
*   **`ADMIN_TEST_PIN_HASH`** (For Admin Testing Page - if implemented as a secret)
    *   **Description:** A securely hashed (e.g., using Argon2, bcrypt, or SHA-256 if simpler hashing is acceptable for this internal tool) version of the 6-digit PIN required to access special features on the Admin Testing Page. The worker will hash the input PIN and compare it to this stored hash.
    *   **How to Generate:** Choose a PIN, hash it using a secure hashing function, and store the resulting hash string.

## 3. Notes on `third_party_integrations` Table

Several of the secrets listed above (especially Microsoft Graph and Facebook credentials) are used to populate the encrypted fields in the `third_party_integrations` D1 table via the Admin UI or a setup script. The actual secret values are set in the Worker environment using `wrangler secret put`, and then an administrator would enter these into the application via the `/api/admin/integrations` endpoint, where they get encrypted before database storage.

The placeholder seed data for `third_party_integrations` in `docs/master_seed_data.sql` references fields like `PLACEHOLDER_ENCRYPTED_MS_DELEGATED_CLIENT_ID`. This indicates that the *actual values* for these (e.g., the MS Delegated Client ID itself) should first be set as environment secrets (e.g., `MS_GRAPH_DELEGATED_CLIENT_ID`), and then the admin setup process would use these environment secrets, encrypt them, and store the encrypted versions in the D1 table. Alternatively, for direct setup, an admin could type the raw secrets into an admin UI form, and the backend encrypts them on save. The environment secrets are primarily for the Worker to *access* these services (e.g., for token exchange in OAuth flows).

Ensure that the `is_enabled` flag in `third_party_integrations` is set to `1` for services you intend to use.
```
