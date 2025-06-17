# Manual Implementation Notes for Backend Features

This document provides detailed instructions for manually implementing backend features that could not be reliably applied by the AI agent due to tooling issues, primarily with modifications to the `src/index.js` file. All JavaScript code snippets are intended for `src/index.js` unless otherwise specified.

## 1. Rate Limiting (IP-Based for Login & Registration)

**Objective:** Protect `/auth/login` and `/auth/register` endpoints from brute-force attacks by limiting the number of attempts per IP address.

**Files to Modify:**
*   `wrangler.toml`
*   `src/index.js`

**Steps:**

**A. Configure KV Namespace in `wrangler.toml`:**
   Ensure the following KV namespace binding exists. Create the namespace in your Cloudflare dashboard and replace the placeholder `id`.
   ```toml
   [[kv_namespaces]]
   binding = "RATE_LIMIT_KV"
   id = "your_kv_namespace_id_for_rate_limiting" # <-- REPLACE THIS
   # preview_id = "your_preview_kv_id" # Optional: for wrangler dev previews
   ```

**B. Add `checkRateLimit` Helper Function to `src/index.js`:**
   Place this function at the module level, near other helper functions.
   ```javascript
   async function checkRateLimit(env, key, limit, windowSeconds) {
     if (!env.RATE_LIMIT_KV) {
       console.warn("RATE_LIMIT_KV namespace not bound. Rate limiting disabled for key:", key);
       return { allowed: true, remaining: limit }; // Fail open if KV is not configured
     }

     const now = Date.now(); // Milliseconds
     const windowMillis = windowSeconds * 1000;

     let attempts = [];
     try {
       const storedAttemptsJson = await env.RATE_LIMIT_KV.get(key, { type: "json" });
       if (storedAttemptsJson && Array.isArray(storedAttemptsJson)) {
         attempts = storedAttemptsJson;
       }
     } catch (e) {
       console.error(`Error reading from RATE_LIMIT_KV for key ${key}:`, e.message);
       return { allowed: true, remaining: limit }; // Fail open on KV read error
     }

     const validAttempts = attempts.filter(timestamp => (now - timestamp) < windowMillis);
     const newRemaining = limit - validAttempts.length - 1;

     if (validAttempts.length >= limit) {
       return { allowed: false, remaining: 0 }; // Rate limited
     }

     validAttempts.push(now);
     try {
       await env.RATE_LIMIT_KV.put(key, JSON.stringify(validAttempts), {
         expirationTtl: windowSeconds
       });
     } catch (e) {
       console.error(`Error writing to RATE_LIMIT_KV for key ${key}:`, e.message);
     }
     return { allowed: true, remaining: Math.max(0, newRemaining) };
   }
   ```

**C. Integrate into `/auth/login` Endpoint in `src/index.js`:**
   At the beginning of the `/auth/login` route handler:
   ```javascript
   // Rate Limiting for /auth/login
   const ipAddressLogin = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || "unknown_ip_login";
   const loginRateLimitKey = `login_ip_${ipAddressLogin}`;
   // Example: 10 login attempts per IP per 5 minutes (300 seconds)
   const { allowed: allowedLogin, remaining: remainingLoginAttempts } = await checkRateLimit(env, loginRateLimitKey, 10, 300);

   if (!allowedLogin) {
     return errorResponse("Too many login attempts. Please try again later.", 429);
   }
   // ... rest of the login logic ...
   ```

**D. Integrate into `/auth/register` Endpoint in `src/index.js`:**
   At the beginning of the `/auth/register` route handler:
   ```javascript
   // Rate Limiting for /auth/register
   const ipAddressRegister = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || "unknown_ip_register";
   const registerRateLimitKey = `register_ip_${ipAddressRegister}`;
   // Example: 5 registration attempts per IP per hour (3600 seconds)
   const { allowed: allowedRegister, remaining: remainingRegisterAttempts } = await checkRateLimit(env, registerRateLimitKey, 5, 3600);

   if (!allowedRegister) {
     return errorResponse("Too many registration attempts from this IP. Please try again later.", 429);
   }
   // ... rest of the registration logic ...
   ```

## 2. Enhanced Audit Logging (Specific Events)

**Objective:** Add more detailed audit logs for specific critical actions. The `logAuditEvent` helper function is assumed to be present in `src/index.js`.

**Modify `logAuditEvent` in `src/index.js` to handle potentially null `request` object (for calls from Durable Objects):**
Locate the `logAuditEvent` function and ensure it can gracefully handle `request` being null:
   ```javascript
   // Ensure this is the version of logAuditEvent in src/index.js
   async function logAuditEvent(env, request, action, userId, targetType, targetId, outcome = "success", logDetails = {}) {
     try {
       // Use optional chaining for request properties
       const ipAddress = request?.headers?.get('CF-Connecting-IP') || request?.headers?.get('X-Forwarded-For') || "N/A_DO_Event";
       const userAgent = request?.headers?.get('User-Agent') || "N/A_DO_Event";
       const eventUserId = userId === undefined ? null : userId; // Ensure userId can be null
       const detailsToLog = { outcome, ...logDetails };
       // Remove undefined properties from details to avoid issues with D1 undefined binding
       Object.keys(detailsToLog).forEach(key => detailsToLog[key] === undefined && delete detailsToLog[key]);


       await env.D1_DB.prepare(
         "INSERT INTO audit_logs (user_id, action, target_type, target_id, ip_address, user_agent, details_json) VALUES (?, ?, ?, ?, ?, ?, ?)"
       ).bind(eventUserId, action, targetType, targetId, ipAddress, userAgent, JSON.stringify(detailsToLog)).run();
     } catch (dbError) {
       console.error(`Failed to log audit event ${action} for user ${userId}:`, dbError.message, dbError.cause ? dbError.cause.message : '');
     }
   }
   ```

**Add Specific Audit Log Calls:**

**A. `/auth/register` (Successful Registration) in `src/index.js`:**
   Within the `/auth/register` handler, after the user and family records are successfully created in D1 and *before* `signToken` for the new user:
   ```javascript
   // Assuming 'newUserId', 'userRole', 'familyId' are available from the user creation step.
   ctx.waitUntil(logAuditEvent(env, request, 'register_success', newUserId, 'user', newUserId, 'success', { role: userRole, familyId: familyId }));
   ```

**B. `POST /api/conversations` (Create Conversation) in `src/index.js`:**
   Within the `POST /api/conversations` handler, after the conversation and participant records are successfully created in D1:
   ```javascript
   // Assuming 'newConversation.id', 'user.userId' (creator), 'requestData.title', 'requestData.participantIds' are available.
   ctx.waitUntil(logAuditEvent(env, request, 'create_conversation', user.userId, 'conversation', newConversation.id, 'success', { title: requestData.title, participantIds: requestData.participantIds }));
   ```

**C. `ConversationDurableObject` - `webSocketMessage` and `broadcast` methods (in `src/index.js`):**
   The audit logging for DND suppression within these methods was already successfully added in a previous step. Ensure those calls use the updated `logAuditEvent` that handles `request` being `null`.
   Example from previous successful step (ensure `logAuditEvent` is called directly, not `this.env.logAuditEvent` unless it was explicitly bound):
   ```javascript
   // Inside ConversationDurableObject's broadcast method, for DND suppression:
   // const auditDetailsBroadcast = { ... };
   // this.state.waitUntil(logAuditEvent(this.env, null /* request */, 'dnd_suppress_websocket_broadcast', null /* acting_user_id (system) */, 'message_broadcast_to_child', recipientUserId, 'success', auditDetailsBroadcast));

   // Inside ConversationDurableObject's webSocketMessage method, for DND push suppression:
   // const auditDetailsPushWs = { ... };
   // this.state.waitUntil(logAuditEvent(this.env, null /* request */, 'dnd_suppress_push_from_ws', null /* acting_user_id (system) */, 'push_notification_to_child', recipientUserId_push, 'success', auditDetailsPushWs));
   ```

## 3. API Response Caching (Using Cache API)

**Objective:** Implement caching for frequently accessed GET endpoints to improve performance and reduce D1 load.

**Files to Modify:** `src/index.js`

**Steps:**

**A. Cache `GET /api/me/calendars` (Example: 1 hour cache):**
   Wrap the existing logic in the `GET /api/me/calendars` route handler:
   ```javascript
   // Inside the main fetch handler, for the route matching GET /api/me/calendars
   if (url.pathname === "/api/me/calendars" && request.method === "GET") {
     if (!user) return errorResponse("Unauthorized", 401);

     const cacheUrl = new URL(request.url);
     cacheUrl.pathname = `/cache/user/${user.userId}/me/calendars`;
     const cacheKeyRequest = new Request(cacheUrl.toString(), { method: 'GET' });

     const cache = caches.default;
     let response = await cache.match(cacheKeyRequest);

     if (response) {
       const newHeaders = new Headers(response.headers);
       newHeaders.set("X-Cache-Status", "HIT_MANUAL_CALENDARS");
       return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
     }

     // --- START ORIGINAL LOGIC for /api/me/calendars ---
     // This is where your actual code to fetch calendars and create a Response object goes.
     // For example:
     // response = await (async () => {
     //   try {
     //     const accessToken = await env.getValidMsGraphUserAccessToken(user.userId, env);
     //     const graphResponse = await fetch("https://graph.microsoft.com/v1.0/me/calendars", { headers: { Authorization: `Bearer ${accessToken}` } });
     //     if (!graphResponse.ok) { const errTxt = await graphResponse.text(); throw new Error(`MS Graph calendars error: ${graphResponse.status} ${errTxt}`); }
     //     const calendarData = await graphResponse.json();
     //     return jsonResponse(calendarData.value); // Assuming jsonResponse creates a new Response
     //   } catch (e) { console.error("Error fetching MS Calendars:", e.message); return errorResponse("Failed to fetch calendars", 500); }
     // })();
     // --- END ORIGINAL LOGIC for /api/me/calendars ---

     if (response && response.ok) {
       const responseToCache = response.clone();
       responseToCache.headers.set('Cache-Control', 'public, max-age=3600'); // 1 hour
       responseToCache.headers.set('X-Cache-Timestamp', new Date().toISOString());
       ctx.waitUntil(cache.put(cacheKeyRequest, responseToCache));
     }
     return response;
   }
   ```

**B. Cache `GET /api/conversations` (Example: 2 minute cache):**
   Wrap the existing logic in the `GET /api/conversations` route handler similarly:
   ```javascript
   // Inside the main fetch handler, for the route matching GET /api/conversations
   if (url.pathname === "/api/conversations" && request.method === "GET") {
     if (!user) return errorResponse("Unauthorized", 401);

     const cacheUrl = new URL(request.url);
     cacheUrl.pathname = `/cache/user/${user.userId}/conversations${cacheUrl.search}`;
     const cacheKeyRequest = new Request(cacheUrl.toString(), { method: 'GET' });

     const cache = caches.default;
     let response = await cache.match(cacheKeyRequest);

     if (response) {
       const newHeaders = new Headers(response.headers);
       newHeaders.set("X-Cache-Status", "HIT_MANUAL_CONVERSATIONS");
       return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
     }

     // --- START ORIGINAL LOGIC for /api/conversations ---
     // This is where your actual code to fetch conversations and create a Response object goes.
     // For example:
     // response = await (async () => {
     //   // ... your logic to query D1 for conversations, fetch participants, last message ...
     //   // const conversations = await ... ;
     //   // return jsonResponse(conversations); // Assuming jsonResponse creates a new Response
     // })();
     // --- END ORIGINAL LOGIC for /api/conversations ---


     if (response && response.ok) {
       const responseToCache = response.clone();
       responseToCache.headers.set('Cache-Control', 'public, max-age=120'); // 2 minutes
       responseToCache.headers.set('X-Cache-Timestamp', new Date().toISOString());
       ctx.waitUntil(cache.put(cacheKeyRequest, responseToCache));
     }
     return response;
   }
   ```
   *(Important: You need to replace the commented out "START ORIGINAL LOGIC" / "END ORIGINAL LOGIC" sections with your actual, current JavaScript logic that generates the `Response` object for those routes. The caching logic wraps around your existing code.)*

## 4. Admin Test Harness - DB Initialization from R2

**Objective:** Modify `/api/admin/test-harness/db/initialize` to fetch SQL from an R2 object.

**Files to Modify:** `src/index.js`

**Steps:**
Replace the current logic of the `/api/admin/test-harness/db/initialize` endpoint (which uses a hardcoded SQL sample) with the R2 fetching logic. (The full code for this was provided in a previous subtask definition when it was first attempted).
   ```javascript
   // In src/index.js, find the handler for:
   // if (pathname === "/api/admin/test-harness/db/initialize" && method === "POST")
   // Replace its entire block with:
   if (pathname === "/api/admin/test-harness/db/initialize" && method === "POST") {
     if (!user || !requireRole(user, ['super_admin'])) {
         ctx.waitUntil(logAuditEvent(env, request, 'test_harness_access_denied', user?.userId || 'unknown', 'db_initialize_r2', 'attempt', 'failure', {reason: 'Insufficient role'}));
         return errorResponse("Forbidden: Insufficient privileges.", 403);
     }

     let requestData;
     try {
       requestData = await request.json();
     } catch (e) {
       return errorResponse("Invalid JSON request body.", 400);
     }

     const { r2ObjectKey } = requestData;
     if (!r2ObjectKey || typeof r2ObjectKey !== 'string' || r2ObjectKey.trim() === "") {
       return errorResponse("Request body must include 'r2ObjectKey' (string) specifying the SQL script path in R2.", 400);
     }

     if (!env.CONTENT_STORAGE_BUCKET) {
       console.error("CONTENT_STORAGE_BUCKET R2 binding not configured for DB initialization from R2.");
       ctx.waitUntil(logAuditEvent(env, request, 'db_initialize_r2_config_error', user.userId, 'database_script', r2ObjectKey, 'failure', {error: "R2 not configured"}));
       return errorResponse("R2 storage for SQL scripts is not configured on the server.", 500);
     }

     try {
       console.log(`Attempting to fetch R2 object: ${r2ObjectKey}`);
       const r2Object = await env.CONTENT_STORAGE_BUCKET.get(r2ObjectKey);

       if (r2Object === null) {
         ctx.waitUntil(logAuditEvent(env, request, 'db_initialize_r2_not_found', user.userId, 'database_script', r2ObjectKey, 'failure'));
         return errorResponse(`SQL script not found in R2 at key: ${r2ObjectKey}`, 404);
       }

       const sqlContent = await r2Object.text();
       if (!sqlContent || sqlContent.trim() === "") {
         ctx.waitUntil(logAuditEvent(env, request, 'db_initialize_r2_empty_script', user.userId, 'database_script', r2ObjectKey, 'failure'));
         return errorResponse(`SQL script at key ${r2ObjectKey} is empty.`, 400);
       }

       console.log(`Executing SQL script from R2: ${r2ObjectKey} (length: ${sqlContent.length})`);
       const dbResult = await env.D1_DB.exec(sqlContent);

       ctx.waitUntil(logAuditEvent(env, request, 'db_initialize_from_r2_executed', user.userId, 'database_script', r2ObjectKey, 'success', { statements_run: dbResult.count, duration_ms: dbResult.duration }));
       return jsonResponse({
         message: `Database initialization script '${r2ObjectKey}' executed. Statements processed: ${dbResult.count || 'unknown'}.`,
         statements_run: dbResult.count,
         duration_ms: dbResult.duration
       });

     } catch (error) {
       console.error(`Failed to initialize database from R2 script ${r2ObjectKey}:`, error.message, error.cause);
       ctx.waitUntil(logAuditEvent(env, request, 'db_initialize_from_r2_exception', user.userId, 'database_script', r2ObjectKey, 'failure', { error: error.message }));
       return errorResponse(`An unexpected error occurred while processing script '${r2ObjectKey}'. Check worker logs.`, 500);
     }
   }
   ```

## 5. Admin Test Harness - Test Token Validation Logic

**Objective:** Enhance `verifyToken` (or `getUser`) to add special validation for JWTs containing `isTestToken: true`.

**Files to Modify:** `src/index.js`

**Steps:**
Modify the `getUser` function. After `verifyToken` successfully returns the payload:
   ```javascript
   // Inside getUser, after 'const payload = await verifyToken(token, env.JWT_SECRET, env);'
   if (payload && payload.isTestToken === true) {
     const currentPathname = new URL(request.url).pathname;
     // Define allowed paths for test tokens or other validation logic
     const isTestHarnessPath = currentPathname.startsWith('/api/admin/test-harness/');
     const isGeneralApiUserPath = currentPathname.startsWith('/api/users/') || currentPathname.startsWith('/api/me/'); // Example: allow for some user data fetching

     if (!isTestHarnessPath && !isGeneralApiUserPath /* Add other conditions if needed */) {
       console.warn(`Test token for user ${payload.userId} used on restricted path: ${currentPathname}. Invalidating.`);
       // It's important that logAuditEvent is defined and accessible globally or via env.
       if (typeof logAuditEvent === 'function') {
           ctx.waitUntil(logAuditEvent(env, request, 'test_token_abuse_attempt', payload.userId, 'auth_token_usage', payload.jti, 'failure', { path: currentPathname }));
       } else {
           console.warn("logAuditEvent not available for test_token_abuse_attempt.");
       }
       return null; // Invalidate session by returning null user
     }
   }
   // return payload; // This is the original return if all checks pass
   ```
   *(Ensure `ctx` is available in `getUser`'s scope if `waitUntil` is used there, or log synchronously if not critical path).*

This provides a starting point for manual implementation of these features. Remember to test thoroughly after applying these changes.

## 6. Family Invitation System

**Objective:** Allow family admins or parents to invite new or existing users to their family. Invitations are sent via email with a unique token.

**Files to Modify:**
*   `src/index.js`
*   `migrations/<new_migration_file.sql>` (for `family_invitations` table)
*   Potentially `email_templates` table in D1 (for `family_invitation_email`)

**A. Database Schema (migrations/X_add_family_invitations_table.sql):**
   ```sql
   -- Add to a new migration file and apply
   DROP TABLE IF EXISTS family_invitations;
   CREATE TABLE family_invitations (
       id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))), -- UUID
       family_id TEXT NOT NULL,
       invited_by_user_id TEXT NOT NULL,
       email TEXT NOT NULL, -- Email of the invitee
       role_to_assign TEXT NOT NULL DEFAULT 'member', -- e.g., 'parent', 'child', 'member'
       token_hash TEXT NOT NULL UNIQUE, -- Secure token for the invitation link
       status TEXT NOT NULL DEFAULT 'pending', -- e.g., 'pending', 'accepted', 'declined', 'expired', 'cancelled'
       expires_at DATETIME NOT NULL,
       accepted_by_user_id TEXT, -- Who accepted it, if applicable
       created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
       updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
       FOREIGN KEY (family_id) REFERENCES families(id) ON DELETE CASCADE,
       FOREIGN KEY (invited_by_user_id) REFERENCES users(id) ON DELETE CASCADE,
       FOREIGN KEY (accepted_by_user_id) REFERENCES users(id) ON DELETE SET NULL
   );
   CREATE INDEX IF NOT EXISTS idx_family_invitations_family_email_status ON family_invitations (family_id, email, status);
   CREATE INDEX IF NOT EXISTS idx_family_invitations_token_hash ON family_invitations (token_hash);

   -- Optional: Add a trigger to update `updated_at`
    CREATE TRIGGER IF NOT EXISTS trg_family_invitations_updated_at
    AFTER UPDATE ON family_invitations
    FOR EACH ROW
    BEGIN
        UPDATE family_invitations SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
    END;
   ```

**B. Helper Function `generateSecureToken` in `src/index.js`:**
   (Ensure this is present from previous notes or add it if missing)
   ```javascript
   function generateSecureToken(length = 32) { // 32 bytes = 64 hex chars
     const buffer = new Uint8Array(length);
     crypto.getRandomValues(buffer);
     return Array.from(buffer, byte => byte.toString(16).padStart(2, '0')).join('');
   }
   ```

**C. Email Template `family_invitation_email`:**
   Ensure an email template named `family_invitation_email` exists in your `email_templates` table. It should accept variables like `{{inviter_name}}`, `{{family_name}}`, `{{invitee_name}}`, `{{role_to_assign}}`, and `{{accept_link}}`.

**D. API Endpoint Implementations in `src/index.js`:**

   **1. `POST /api/me/family/invitations` (Send Invitation):**
      ```javascript
      // Add to the main fetch handler's routing logic
      if (pathname === "/api/me/family/invitations" && method === "POST") {
          if (!user) return errorResponse("Unauthorized", 401);
          if (!requireRole(user, ['family_admin', 'parent'])) {
              return errorResponse("Forbidden: Insufficient role. Only family admins or parents can send invitations.", 403);
          }

          try {
              const { email: inviteeEmail, role: inviteeRole = 'member' } = await request.json(); // Default role to 'member'
              if (!inviteeEmail || typeof inviteeEmail !== 'string' || !['parent', 'child', 'member'].includes(inviteeRole)) {
                  return errorResponse("Valid invitee email and role ('parent', 'child', 'member') are required.", 400);
              }
              if (inviteeEmail.toLowerCase() === user.email?.toLowerCase()) {
                  return errorResponse("You cannot invite yourself to your family.", 400);
              }

              const inviterFamilyId = user.familyId;
              if (!inviterFamilyId) {
                  return errorResponse("Inviter must belong to a family to send invitations.", 400);
              }

              const existingInviteeUser = await env.D1_DB.prepare("SELECT id, family_id, name FROM users WHERE email = ?").bind(inviteeEmail).first();
              if (existingInviteeUser && existingInviteeUser.family_id === inviterFamilyId) {
                  return errorResponse("This user is already a member of your family.", 400);
              }
              if (existingInviteeUser && existingInviteeUser.family_id) {
                  return errorResponse("This user is already part of another family.", 400); // Cannot invite someone already in any family
              }

              // Check for existing pending invitation to the same family
              const existingPendingInvitation = await env.D1_DB.prepare(
                  "SELECT id FROM family_invitations WHERE family_id = ? AND email = ? AND status = 'pending' AND expires_at > datetime('now')"
              ).bind(inviterFamilyId, inviteeEmail).first();
              if (existingPendingInvitation) {
                  return errorResponse("An active invitation already exists for this email address to your family.", 400);
              }

              const invitationToken = generateSecureToken(32); // Generates a 64-character hex string
              const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // Invitation valid for 7 days
              const invitationId = crypto.randomUUID();

              // In a real scenario, you'd hash the token if you plan to query by it directly for acceptance.
              // For simplicity in link generation, we might store it directly OR store a hash and look up by hash.
              // Storing token directly for now, assuming lookup by this token for accept/decline.
              await env.D1_DB.prepare(
                  "INSERT INTO family_invitations (id, family_id, invited_by_user_id, email, role_to_assign, token_hash, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)"
              ).bind(invitationId, inviterFamilyId, user.userId, inviteeEmail, inviteeRole, invitationToken, expiresAt.toISOString().slice(0, 19).replace('T', ' ')).run();

              const inviterName = user.name || user.email || "A family member";
              const familyInfo = await env.D1_DB.prepare("SELECT family_name FROM families WHERE id = ?").bind(inviterFamilyId).first();
              const familyName = familyInfo?.family_name || "their family";

              const frontendBaseUrl = env.FRONTEND_URL || 'https://your-frontend-app.com'; // Set in Wrangler or env
              const acceptLink = `${frontendBaseUrl}/join-family?token=${invitationToken}`;

              const emailContent = await getProcessedEmailTemplate(env, 'family_invitation_email', {
                  inviter_name: inviterName,
                  family_name: familyName,
                  invitee_name: existingInviteeUser?.name || inviteeEmail, // Use existing user's name if available
                  role_to_assign: inviteeRole,
                  accept_link: acceptLink,
              });

              ctx.waitUntil(sendEmail(env, inviteeEmail, emailContent.subject, emailContent.body));
              ctx.waitUntil(logAuditEvent(env, request, 'family_invitation_sent', user.userId, 'family_invitation', invitationId, 'success',
                { familyId: inviterFamilyId, inviteeEmail, roleAssigned: inviteeRole }
              ));

              return jsonResponse({ message: "Family invitation sent successfully.", invitationId: invitationId }, 201);
          } catch (e) {
              console.error("Error sending family invitation:", e.message, e.stack);
              // Consider more specific error logging for D1 errors vs email errors
              return errorResponse("Failed to send family invitation. Please try again later.", 500);
          }
      }
      ```

   **2. `GET /api/invitations/:token/details` (Get Invitation Details - Public):**
      ```javascript
      // Add to main fetch handler
      const inviteDetailsMatch = pathname.match(/^\/api\/invitations\/([a-zA-Z0-9-]+)\/details$/i);
      if (inviteDetailsMatch && method === "GET") {
          const token = inviteDetailsMatch[1];
          // No user authentication needed for this specific endpoint to view details.
          // Query by the token_hash (assuming it's stored directly, not hashed, for this example)
          const invitation = await env.D1_DB.prepare(
              "SELECT fi.email, fi.role_to_assign, fi.status, fi.expires_at, f.family_name, u.name as inviter_name FROM family_invitations fi JOIN families f ON fi.family_id = f.id JOIN users u ON fi.invited_by_user_id = u.id WHERE fi.token_hash = ? AND fi.status = 'pending' AND fi.expires_at > datetime('now')"
          ).bind(token).first();

          if (!invitation) {
              return errorResponse("Invitation not found, already used, or expired.", 404);
          }
          // Do not expose sensitive parts of the token or full user details of inviter.
          return jsonResponse({
              inviteeEmail: invitation.email, // Email the invite was sent to
              roleToAssign: invitation.role_to_assign,
              familyName: invitation.family_name,
              inviterName: invitation.inviter_name, // Or a generic "A member of [Family Name]"
              expiresAt: invitation.expires_at
          });
      }
      ```

   **3. `POST /api/invitations/:token/accept` (Accept Invitation - Requires Logged-in User):**
      ```javascript
      // Add to main fetch handler
      const inviteAcceptMatch = pathname.match(/^\/api\/invitations\/([a-zA-Z0-9-]+)\/accept$/i);
      if (inviteAcceptMatch && method === "POST") {
          if (!user) return errorResponse("Unauthorized: You must be logged in to accept an invitation.", 401);

          const token = inviteAcceptMatch[1];
          const inviteeUserId = user.userId; // User accepting the invitation

          // Retrieve invitation; ensure it's for the logged-in user's email
          const invitation = await env.D1_DB.prepare(
              "SELECT id, family_id, email, role_to_assign FROM family_invitations WHERE token_hash = ? AND status = 'pending' AND expires_at > datetime('now')"
          ).bind(token).first();

          if (!invitation) return errorResponse("Invitation not found, already used, or expired.", 404);
          if (user.email.toLowerCase() !== invitation.email.toLowerCase()) {
              return errorResponse("This invitation is intended for a different email address.", 403);
          }
          if (user.familyId) { // Check if user is already in a family
              return errorResponse("You are already part of a family. To join a new family, you must first leave your current one.", 400);
          }

          // Perform transaction: Update user's family_id and role, and update invitation status
          const batchOperations = [
              env.D1_DB.prepare("UPDATE users SET family_id = ?, role = ?, updated_at = datetime('now') WHERE id = ?")
                  .bind(invitation.family_id, invitation.role_to_assign, inviteeUserId),
              env.D1_DB.prepare("UPDATE family_invitations SET status = 'accepted', accepted_by_user_id = ?, updated_at = datetime('now') WHERE id = ?")
                  .bind(inviteeUserId, invitation.id)
          ];
          await env.D1_DB.batch(batchOperations);

          ctx.waitUntil(logAuditEvent(env, request, 'family_invitation_accepted', inviteeUserId, 'family_invitation', invitation.id, 'success',
            { familyId: invitation.family_id, assignedRole: invitation.role_to_assign }
          ));
          return jsonResponse({ message: "Invitation accepted successfully! Welcome to the family." });
      }
      ```

   **4. `POST /api/invitations/:token/decline` (Decline Invitation - Public or Logged-in User):**
      ```javascript
      // Add to main fetch handler
      const inviteDeclineMatch = pathname.match(/^\/api\/invitations\/([a-zA-Z0-9-]+)\/decline$/i);
      if (inviteDeclineMatch && method === "POST") {
          const token = inviteDeclineMatch[1];
          let declinedByUserId = user?.userId; // Optional: if user is logged in

          const invitation = await env.D1_DB.prepare(
              "SELECT id, email FROM family_invitations WHERE token_hash = ? AND status = 'pending' AND expires_at > datetime('now')"
          ).bind(token).first();

          if (!invitation) return errorResponse("Invitation not found, already used, or expired.", 404);

          // If a user is logged in, they can only decline an invitation addressed to their email.
          if (user && user.email.toLowerCase() !== invitation.email.toLowerCase()) {
              return errorResponse("You cannot decline an invitation not addressed to your email.", 403);
          }

          await env.D1_DB.prepare("UPDATE family_invitations SET status = 'declined', accepted_by_user_id = ?, updated_at = datetime('now') WHERE id = ?")
              .bind(declinedByUserId, invitation.id).run(); // Store who declined if logged in

          ctx.waitUntil(logAuditEvent(env, request, 'family_invitation_declined', declinedByUserId || 'anonymous_via_token', 'family_invitation', invitation.id, 'success', { inviteeEmail: invitation.email }));
          return jsonResponse({ message: "Invitation declined." });
      }
      ```

   **5. `GET /api/me/family/invitations` (List Sent Invitations - Admin/Parent):**
      ```javascript
      // Add to main fetch handler
      if (pathname === "/api/me/family/invitations" && method === "GET") {
          if (!user) return errorResponse("Unauthorized", 401);
          if (!requireRole(user, ['family_admin', 'parent'])) {
              return errorResponse("Forbidden: Insufficient role.", 403);
          }
          if (!user.familyId) return errorResponse("You are not part of a family to view its invitations.", 400);

          // Fetches invitations sent by the current user for their family
          const invitations = await env.D1_DB.prepare(
              "SELECT id, email, role_to_assign, status, created_at, expires_at FROM family_invitations WHERE family_id = ? AND invited_by_user_id = ? ORDER BY created_at DESC"
          ).bind(user.familyId, user.userId).all();

          return jsonResponse(invitations.results || []);
      }
      ```

   **6. `DELETE /api/me/family/invitations/:invitationId` (Cancel Sent Invitation - Admin/Parent):**
      ```javascript
      // Add to main fetch handler
      const cancelInviteMatch = pathname.match(/^\/api\/me\/family\/invitations\/([a-zA-Z0-9-]+)$/i);
      if (cancelInviteMatch && method === "DELETE") {
          if (!user) return errorResponse("Unauthorized", 401);
          if (!requireRole(user, ['family_admin', 'parent'])) {
              return errorResponse("Forbidden: Insufficient role.", 403);
          }
          if (!user.familyId) return errorResponse("You are not part of a family.", 400);

          const invitationIdToCancel = cancelInviteMatch[1];
          // Ensure the invitation being cancelled was sent by this user for their family and is still pending
          const result = await env.D1_DB.prepare(
              "UPDATE family_invitations SET status = 'cancelled', updated_at = datetime('now') WHERE id = ? AND invited_by_user_id = ? AND family_id = ? AND status = 'pending'"
          ).bind(invitationIdToCancel, user.userId, user.familyId).run();

          if (result.changes === 0) {
              // Could be due to not found, already processed, or not authorized if check was broader
              return errorResponse("Invitation not found, already processed, or you're not authorized to cancel it.", 404);
          }
          ctx.waitUntil(logAuditEvent(env, request, 'family_invitation_cancelled', user.userId, 'family_invitation', invitationIdToCancel, 'success'));
          return jsonResponse({ message: "Invitation successfully cancelled." });
      }
      ```

**E. Integration into `fetch` handler's main router:**
   The above snippets should be placed within the main `if/else if` block of the `fetch` handler in `src/index.js`, similar to other route definitions. Pay attention to the order, especially for routes with parameters. Public routes like `/api/invitations/:token/details` might need to be defined *before* the general auth check if they are truly public.

**F. Public API Path Adjustments:**
   Ensure `/api/invitations/:token/details` and `/api/invitations/:token/decline` are added to `PUBLIC_API_PATHS` array or equivalent logic if they are intended to be accessible without prior user login. `/api/invitations/:token/accept` should *not* be public as it requires a logged-in user session.

## 7. Public Key Management API

**Objective:** Allow users to submit their public keys (e.g., for end-to-end encryption negotiations) and allow other users to retrieve these keys.

**Files to Modify:**
*   `src/index.js`
*   `migrations/<new_migration_file.sql>` (for `user_public_keys` table)

**A. Database Schema (migrations/Y_add_user_public_keys_table.sql):**
   ```sql
   -- Add to a new migration file and apply
   DROP TABLE IF EXISTS user_public_keys;
   CREATE TABLE user_public_keys (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       user_id TEXT NOT NULL,
       public_key_pem TEXT NOT NULL,
       key_type TEXT NOT NULL DEFAULT 'e2ee_comm', -- e.g., 'e2ee_comm', 'pgp_email'
       device_name TEXT, -- Optional, user-provided name for the key/device
       is_active BOOLEAN DEFAULT 1, -- 1 for true, 0 for false
       created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
       last_used_at DATETIME, -- Optional: can be updated when key is used for encryption/signing
       expires_at DATETIME, -- Optional: if keys have a defined expiry
       FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
       UNIQUE (user_id, public_key_pem) -- Prevent duplicate keys for the same user
   );
   CREATE INDEX IF NOT EXISTS idx_user_public_keys_user_type_active ON user_public_keys (user_id, key_type, is_active, created_at DESC);
   ```

**B. API Endpoint Implementations in `src/index.js`:**

   **1. `POST /api/me/public-keys` (Submit/Register a Public Key):**
      ```javascript
      // Add to the main fetch handler's routing logic
      if (pathname === "/api/me/public-keys" && method === "POST") {
          if (!user) return errorResponse("Unauthorized", 401);

          try {
              const {
                  publicKeyPem, // Required: The public key in PEM format
                  keyType = 'e2ee_comm', // Optional: Type of key, defaults to 'e2ee_comm'
                  deviceName, // Optional: User-friendly name for the device/key
                  isActive = true, // Optional: Set this key as active for its type, defaults to true
                  expiresAt // Optional: ISO string for when the key expires
              } = await request.json();

              if (!publicKeyPem || typeof publicKeyPem !== 'string') {
                  return errorResponse("publicKeyPem (string) is required.", 400);
              }
              if (typeof keyType !== 'string') {
                  return errorResponse("keyType must be a string.", 400);
              }
              // Basic PEM format check (very rudimentary)
              if (!publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----') || !publicKeyPem.endsWith('-----END PUBLIC KEY-----')) {
                  return errorResponse("publicKeyPem does not appear to be in valid PEM format.", 400);
              }

              let expiresAtISO = null;
              if (expiresAt) {
                  try {
                      expiresAtISO = new Date(expiresAt).toISOString();
                  } catch (e) {
                      return errorResponse("Invalid date format for expiresAt. Please use ISO 8601 format.", 400);
                  }
              }

              // If this key is being set to active, deactivate other keys of the same type for this user
              if (isActive) {
                  await env.D1_DB.prepare(
                      "UPDATE user_public_keys SET is_active = 0 WHERE user_id = ? AND key_type = ? AND is_active = 1"
                  ).bind(user.userId, keyType).run();
              }

              const insertResult = await env.D1_DB.prepare(
                  "INSERT INTO user_public_keys (user_id, public_key_pem, key_type, device_name, is_active, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
              ).bind(user.userId, publicKeyPem, keyType, deviceName || null, isActive ? 1 : 0, expiresAtISO)
               .run();

              const newKeyId = insertResult.meta?.last_row_id; // D1 specific way to get last insert ID

              ctx.waitUntil(logAuditEvent(env, request, 'public_key_added', user.userId, 'user_public_key', newKeyId ? String(newKeyId) : 'unknown', 'success',
                { keyType, deviceName: deviceName || 'N/A', isActive }
              ));

              return jsonResponse({
                  message: "Public key registered successfully.",
                  keyId: newKeyId, // This might not be available or reliable across all D1 versions/setups
                  publicKeyPem,
                  keyType,
                  deviceName,
                  isActive
              }, 201);

          } catch (e) {
              if (e.message && e.message.toLowerCase().includes('unique constraint failed')) {
                  console.warn(`User ${user.userId} attempted to add a duplicate public key.`);
                  return errorResponse("This public key has already been registered for your account.", 409); // Conflict
              }
              console.error("Error registering public key:", e.message, e.stack);
              return errorResponse("Failed to register public key.", 500);
          }
      }
      ```

   **2. `GET /api/users/:targetUserId/public-key` (Get Active Public Key for a User):**
      ```javascript
      // Add to main fetch handler, ensure param matching is robust
      const userPublicKeyMatch = pathname.match(/^\/api\/users\/([a-zA-Z0-9-]+)\/public-key$/i);
      if (userPublicKeyMatch && method === "GET") {
          if (!user) return errorResponse("Unauthorized", 401); // Requesting user must be logged in

          const targetUserIdToFetch = userPublicKeyMatch[1];
          const keyTypeQuery = url.searchParams.get('type') || 'e2ee_comm'; // Default to 'e2ee_comm'

          // Basic validation for targetUserIdToFetch if needed (e.g., UUID format)
          // For simplicity, directly using it.

          // Fetch the most recent, active key of the specified type for the target user
          const publicKeyRecord = await env.D1_DB.prepare(
              "SELECT id, public_key_pem, key_type, device_name, created_at, expires_at FROM user_public_keys WHERE user_id = ? AND key_type = ? AND is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now')) ORDER BY created_at DESC LIMIT 1"
          ).bind(targetUserIdToFetch, keyTypeQuery).first();

          if (!publicKeyRecord) {
              return errorResponse(`No active public key of type '${keyTypeQuery}' found for the specified user.`, 404);
          }

          // Consider audit logging this access if sensitive/important
          // ctx.waitUntil(logAuditEvent(env, request, 'public_key_retrieved', user.userId, 'user_public_key_access', publicKeyRecord.id, 'success', { targetUserId: targetUserIdToFetch, keyType: keyTypeQuery }));

          return jsonResponse({
              userId: targetUserIdToFetch,
              keyId: publicKeyRecord.id,
              publicKeyPem: publicKeyRecord.public_key_pem,
              keyType: publicKeyRecord.key_type,
              deviceName: publicKeyRecord.device_name,
              createdAt: publicKeyRecord.created_at,
              expiresAt: publicKeyRecord.expires_at
          });
      }
      ```

**C. Integration into `fetch` handler's main router:**
   Place these route handlers within the main `if/else if` block in `src/index.js`. The `/api/users/:targetUserId/public-key` route with a parameter should generally be placed after more static routes to avoid premature matching, or use more precise regex matching if necessary.

**D. Security Considerations:**
*   **PEM Validation:** The example includes a very basic PEM format check. For production, a more robust validation library or method should be used to ensure the key is well-formed and of an expected type (e.g., RSA, EC).
*   **Key Usage:** The `last_used_at` field is optional but can be useful for key rotation policies or identifying stale keys.
*   **Authorization for Retrieval:** The `GET /api/users/:targetUserId/public-key` endpoint currently allows any authenticated user to fetch any other user's public key. Depending on application requirements, you might want to restrict this (e.g., only users within the same family, or only if there's an active conversation).
