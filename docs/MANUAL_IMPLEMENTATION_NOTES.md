# Manual Implementation Notes for Backend Features

This document provides detailed instructions for manually implementing backend features that could not be reliably applied by the AI agent due to tooling issues, primarily with modifications to the `src/index.js` file.

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
       // Fetch existing attempts. Note: D1 returns values directly, KV returns { value, metadata }
       // Assuming this was intended for KV, 'json' type is correct.
       const storedAttemptsJson = await env.RATE_LIMIT_KV.get(key, { type: "json" });
       if (storedAttemptsJson && Array.isArray(storedAttemptsJson)) {
         attempts = storedAttemptsJson;
       }
     } catch (e) {
       console.error(`Error reading from RATE_LIMIT_KV for key ${key}:`, e.message);
       return { allowed: true, remaining: limit }; // Fail open on KV read error
     }

     // Filter out attempts older than the current window
     const validAttempts = attempts.filter(timestamp => (now - timestamp) < windowMillis);
     const newRemaining = limit - validAttempts.length - 1; // -1 for the current attempt being processed

     if (validAttempts.length >= limit) {
       return { allowed: false, remaining: 0 }; // Rate limited
     }

     // Add current attempt timestamp and store back in KV with a TTL equal to the window duration
     validAttempts.push(now);
     try {
       await env.RATE_LIMIT_KV.put(key, JSON.stringify(validAttempts), {
         expirationTtl: windowSeconds // TTL in seconds
       });
     } catch (e) {
       console.error(`Error writing to RATE_LIMIT_KV for key ${key}:`, e.message);
       // If KV write fails, we might still allow the request (fail open) or deny it.
       // For now, this implementation still considers the check passed if write fails but count was okay.
     }
     return { allowed: true, remaining: Math.max(0, newRemaining) }; // Not rate limited
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

   // Optional: Add X-RateLimit headers to all responses from this endpoint
   // This requires capturing the eventual response object to add these headers.
   // For simplicity here, we only act if rate limited.
   // A more advanced setup would involve a function to add these headers to any response being returned.

   if (!allowedLogin) {
     // Consider logging this specific rate limit event if desired
     // await logAuditEvent(env, request, 'rate_limit_exceeded', null, 'login_attempt', ipAddressLogin, 'failure');
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
     // await logAuditEvent(env, request, 'rate_limit_exceeded', null, 'register_attempt', ipAddressRegister, 'failure');
     return errorResponse("Too many registration attempts from this IP. Please try again later.", 429);
   }
   // ... rest of the registration logic ...
   ```

## 2. Enhanced Audit Logging

**Objective:** Add more detailed audit logs for specific critical actions. The `logAuditEvent` helper function is assumed to be present and functional in `src/index.js`.

**Files to Modify:**
*   `src/index.js` (including `ConversationDurableObject` class definition if it's in the same file)

**Steps:**

**A. `/auth/register` (Successful Registration):**
   Within the `/auth/register` handler, after the user and family records are successfully created in D1 and *before* `signToken` is called for the new user:
   ```javascript
   // Assuming 'newUserId' is the ID of the user just created
   // and 'userRole' and 'familyId' are the role and family ID assigned.
   ctx.waitUntil(logAuditEvent(env, request, 'register_success', newUserId, 'user', newUserId, 'success', { role: userRole, familyId: familyId }));
   ```

**B. `POST /api/conversations` (Create Conversation):**
   Within the `POST /api/conversations` handler, after the conversation and participant records are successfully created in D1:
   ```javascript
   // Assuming 'newConversation.id' is the ID of the conversation just created,
   // 'user.userId' is the creator, and 'requestData' contains title/participants.
   ctx.waitUntil(logAuditEvent(env, request, 'create_conversation', user.userId, 'conversation', newConversation.id, 'success', { title: requestData.title, participantIds: requestData.participantIds }));
   ```

**C. `ConversationDurableObject` - `webSocketMessage` Method (Message via WebSocket):**
   Within the `webSocketMessage` method of `ConversationDurableObject`, after a message sent via WebSocket is successfully persisted to D1:
   ```javascript
   // Assuming 'persistedMessage' is the object of the message saved to D1,
   // 'senderId' is ws.sessionInfo.userId, and 'this.conversationId' is available.
   // Note: 'request' object for IP/User-Agent is not directly available here.
   // The logAuditEvent function should gracefully handle a null 'request' argument.

   // Ensure logAuditEvent is defined or accessible, e.g., this.env.logAuditEvent if attached to env, or define it within DO.
   // Assuming logAuditEvent can be called:
   if (typeof this.env.logAuditEvent === 'function') { // Or however it's made accessible
        this.state.waitUntil(this.env.logAuditEvent(this.env, null, 'send_message_ws', senderId, 'message', persistedMessage.id, 'success', { conversationId: this.conversationId, clientType: 'websocket' }));
   } else if (typeof logAuditEvent === 'function') { // If it's a global in the worker scope (less likely for DOs unless specifically passed)
        this.state.waitUntil(logAuditEvent(this.env, null, 'send_message_ws', senderId, 'message', persistedMessage.id, 'success', { conversationId: this.conversationId, clientType: 'websocket' }));
   } else {
        console.warn("logAuditEvent not available in ConversationDurableObject for send_message_ws");
   }
   ```
   *Self-correction: `logAuditEvent` needs `env` as its first parameter. If calling from DO, it would be `this.env`. The `request` object for IP/User-Agent is indeed not available. The `logAuditEvent` function should be modified to handle `request` being potentially `null` or undefined, and skip IP/User-Agent logging in such cases.*

   **Modify `logAuditEvent` to handle null `request`:**
   ```javascript
   // In src/index.js, update logAuditEvent:
   async function logAuditEvent(env, request, action, userId, targetType, targetId, outcome = "success", logDetails = {}) {
     try {
       const ipAddress = request?.headers?.get('CF-Connecting-IP') || request?.headers?.get('X-Forwarded-For') || "unknown";
       const userAgent = request?.headers?.get('User-Agent') || "unknown";
       // ... rest of the function ...
     } // ... catch ...
   }
   ```

## 3. API Response Caching (Using Cache API)

**Objective:** Implement caching for frequently accessed GET endpoints to improve performance and reduce D1 load.

**Files to Modify:**
*   `src/index.js`

**Steps:**

**A. Cache `GET /api/me/calendars` (Example: 1 hour cache):**
   Wrap the existing logic in the `GET /api/me/calendars` route handler:
   ```javascript
   // Inside the main fetch handler, for the route matching GET /api/me/calendars
   if (url.pathname === "/api/me/calendars" && request.method === "GET") {
     if (!user) return errorResponse("Unauthorized", 401); // Assuming 'user' is from getUser()

     // Construct a unique cache key. Using a path prefix like /cache/ helps avoid collision.
     const cacheUrl = new URL(request.url);
     cacheUrl.pathname = `/cache/user/${user.userId}/me/calendars`;
     const cacheKeyRequest = new Request(cacheUrl.toString(), { method: 'GET' });

     const cache = caches.default;
     let response = await cache.match(cacheKeyRequest);

     if (response) {
       // Optional: Add a header to indicate cache hit for debugging
       const newHeaders = new Headers(response.headers);
       newHeaders.set("X-Cache-Status", "HIT");
       return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
     }

     // Original logic to fetch calendars (ensure this results in a 'response' variable):
     // try { ... actual MS Graph fetch and jsonResponse(calendarData.value) call ... }
     // Let's assume 'originalCalendarFetchLogic' is a function that returns the Response object
     response = await originalCalendarFetchLogic(request, env, user, ctx); // Pass ctx if original logic uses it

     if (response.ok) { // Only cache successful responses (2xx status)
       const responseToCache = response.clone();
       responseToCache.headers.set('Cache-Control', 'public, max-age=3600'); // 1 hour
       responseToCache.headers.set('X-Cache-Timestamp', new Date().toISOString()); // For debugging or custom reval
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
     // Include search parameters in cache key if they affect the response (e.g., pagination)
     cacheUrl.pathname = `/cache/user/${user.userId}/conversations${cacheUrl.search}`;
     const cacheKeyRequest = new Request(cacheUrl.toString(), { method: 'GET' });

     const cache = caches.default;
     let response = await cache.match(cacheKeyRequest);

     if (response) {
       const newHeaders = new Headers(response.headers);
       newHeaders.set("X-Cache-Status", "HIT");
       return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
     }

     // Original logic to fetch conversations...
     // Let's assume 'originalConversationsFetchLogic' returns the Response
     response = await originalConversationsFetchLogic(request, env, user, ctx);

     if (response.ok) {
       const responseToCache = response.clone();
       responseToCache.headers.set('Cache-Control', 'public, max-age=120'); // 2 minutes
       responseToCache.headers.set('X-Cache-Timestamp', new Date().toISOString());
       ctx.waitUntil(cache.put(cacheKeyRequest, responseToCache));
     }
     return response;
   }
   ```
   *(Note: You would need to refactor your existing route logic for `/api/me/calendars` and `/api/conversations` into functions like `originalCalendarFetchLogic` and `originalConversationsFetchLogic` that the caching wrapper can call.)*

---

This document should be kept updated if further `src/index.js` modifications by the AI agent fail.
