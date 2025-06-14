class MyDurableObject {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    return new Response("Hello from Durable Object!");
  }
}

// MS Graph User Token Helper
async function getValidMsGraphUserAccessToken(userId, env) {
  const tokenRow = await env.D1_DB.prepare(
    "SELECT access_token_encrypted, refresh_token_encrypted, token_expiry_timestamp_ms, scopes, ms_graph_user_id FROM user_ms_graph_tokens WHERE user_id = ?"
  ).bind(userId).first();

  if (!tokenRow) {
    throw new Error("Microsoft Graph account not linked for this user.");
  }

  let accessToken = await decrypt(tokenRow.access_token_encrypted, env);
  const refreshToken = await decrypt(tokenRow.refresh_token_encrypted, env);
  const now = Date.now();

  if (now >= tokenRow.token_expiry_timestamp_ms) {
    console.log(`MS Graph token expired for user ${userId}, refreshing...`);
    const msGraphAppCreds = await env.D1_DB.prepare(
      "SELECT client_id, client_secret_encrypted FROM third_party_integrations WHERE service_name = 'MicrosoftGraphDelegated' AND is_enabled = 1"
    ).first();

    if (!msGraphAppCreds) {
      throw new Error("MicrosoftGraphDelegated service configuration not found or not enabled.");
    }
    const clientId = msGraphAppCreds.client_id; // Assuming client_id is not encrypted
    const clientSecret = await decrypt(msGraphAppCreds.client_secret_encrypted, env);

    // Use 'common' tenant for multi-tenant apps, or specific if single-tenant
    const tokenUrl = `https://login.microsoftonline.com/common/oauth2/v2.0/token`;
    const params = new URLSearchParams();
    params.append('client_id', clientId);
    params.append('scope', tokenRow.scopes || 'openid profile email offline_access Calendars.ReadWrite User.Read'); // Fallback scopes
    params.append('refresh_token', refreshToken);
    params.append('grant_type', 'refresh_token');
    params.append('client_secret', clientSecret);

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    if (!response.ok) {
      const errorData = await response.text();
      console.error("MS Graph token refresh failed:", errorData);
      throw new Error(`Failed to refresh MS Graph token: ${response.status} - ${errorData}`);
    }

    const newTokens = await response.json();
    accessToken = newTokens.access_token;
    const newRefreshToken = newTokens.refresh_token || refreshToken; // MS might not always return a new refresh token
    const newExpiryTimestampMs = Date.now() + (newTokens.expires_in * 1000);
    const newScopes = newTokens.scope || tokenRow.scopes; // Keep old scopes if new ones aren't returned

    const newAccessTokenEnc = await encrypt(accessToken, env);
    const newRefreshTokenEnc = await encrypt(newRefreshToken, env);
    const updateTimestamp = new Date().toISOString();

    await env.D1_DB.prepare(
      "UPDATE user_ms_graph_tokens SET access_token_encrypted = ?, refresh_token_encrypted = ?, token_expiry_timestamp_ms = ?, scopes = ?, updated_at = ? WHERE user_id = ?"
    ).bind(newAccessTokenEnc, newRefreshTokenEnc, newExpiryTimestampMs, newScopes, updateTimestamp, userId).run();

    console.log(`MS Graph token refreshed and updated for user ${userId}.`);
  }
  return accessToken;
}


// Email Template Helper
async function getProcessedEmailTemplate(templateName, data, env) {
  const templateRow = await env.D1_DB.prepare(
    "SELECT subject_template, body_html_template, default_sender_name, default_sender_email FROM email_templates WHERE template_name = ?"
  ).bind(templateName).first();

  if (!templateRow) {
    console.error(`Email template "${templateName}" not found.`);
    // Fallback to a very basic plaintext representation or throw error
    // For now, let's return null or throw to indicate missing template explicitly
    throw new Error(`Email template "${templateName}" not found.`);
  }

  let subject = templateRow.subject_template;
  let bodyHtml = templateRow.body_html_template;

  for (const key in data) {
    const regex = new RegExp(`{{\\s*${key}\\s*}}`, 'g'); // Matches {{ key }}
    subject = subject.replace(regex, data[key]);
    bodyHtml = bodyHtml.replace(regex, data[key]);
  }

  return {
    subject,
    bodyHtml,
    // These can be used by the sendEmail function if it's enhanced to support them
    // defaultSenderName: templateRow.default_sender_name,
    // defaultSenderEmail: templateRow.default_sender_email
  };
}


// Audit Log Helper
async function logAuditEvent(env, request, action, userId, targetType, targetId, outcome = "success", logDetails = {}) {
  try {
    const ipAddress = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || "unknown";
    const userAgent = request.headers.get('User-Agent') || "unknown";
    // Ensure logDetails is an object before spreading
    const detailsToStore = typeof logDetails === 'object' && logDetails !== null ? logDetails : {};
    const fullDetails = JSON.stringify({ outcome, ...detailsToStore });

    await env.D1_DB.prepare(
      "INSERT INTO audit_logs (user_id, action, target_type, target_id, ip_address, user_agent, details_json) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(userId, action, targetType, targetId, ipAddress, userAgent, fullDetails).run();
  } catch (dbError) {
    console.error(`Failed to log audit event ${action} for user ${userId}:`, dbError.message, dbError.cause);
  }
}


async function sendPushNotification(subscription, payloadString, env) {
  // IMPORTANT: Full VAPID header generation is complex and typically uses a library.
  // This is a simplified placeholder to show the flow.
  // A proper implementation would involve JWT creation and ES256 signing.

  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY) {
    console.error("VAPID keys not configured. Cannot send push notification.");
    return false;
  }

  // const pushServiceOrigin = new URL(subscription.endpoint).origin; // Not used in simulation

  // Simplified VAPID headers (conceptual)
  // Real headers include 'Authorization: VAPID t=<jwt>, k=<public_key_base64url>'
  // and 'Encryption: salt=<salt_bytes_base64url>'
  // and 'Crypto-Key: dh=<public_key_bytes_base64url>;p256ecdsa=<public_key_bytes_base64url>'
  // The body itself also needs to be encrypted using Web Push Encryption.

  console.log(`Simulating push notification to: ${subscription.endpoint}`);
  console.log(`Payload: ${payloadString}`);
  console.log(`(Would use VAPID keys here and encrypt payload for real push)`);

  try {
    // const response = await fetch(subscription.endpoint, {
    //   method: "POST",
    //   headers: {
    //     // ... complex VAPID and encryption headers ...
    //     'Content-Type': 'application/octet-stream', // If encrypted
    //     'TTL': '86400' // Time to live in seconds
    //   },
    //   body: encryptedPayload // Encrypted payload
    // });

    // Simulate response handling
    // if (response.status === 410 || response.status === 404) { // Gone or Not Found - subscription expired or invalid
    //   console.log(`Subscription ${subscription.endpoint} is gone/invalid. Deleting.`);
    //   // Ensure subscription.user_id is available if this logic is enabled
    //   // await env.D1_DB.prepare("DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?")
    //   //   .bind(subscription.user_id, subscription.endpoint)
    //   //   .run();
    //   return false;
    // }
    // if (!response.ok) {
    //   console.error(`Push service error for ${subscription.endpoint}: ${response.status}`);
    //   return false;
    // }
    // console.log(`Push notification sent successfully to ${subscription.endpoint}`);
    return true; // Simulated success
  } catch (error) {
    console.error(`Error sending push notification to ${subscription.endpoint}:`, error);
    return false;
  }
}

export class VideoCallSignalingDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.videoCallId = state.id.toString();
    this.participants = new Map(); // userId -> WebSocket
    this.userIdToSessionId = new Map(); // userId -> sessionId
    this.sessions = new Map(); // sessionId -> WebSocket
    // console.log(`VideoCallSignalingDO created for call: ${this.videoCallId}`);
  }

  generateSessionId() {
    return crypto.randomUUID();
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.headers.get("Upgrade") === "websocket") {
      const userId = request.headers.get("X-User-Id");
      if (!userId) {
        return errorResponse("X-User-Id header is required for WebSocket connection.", 400);
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      await this.state.acceptWebSocket(server);

      const sessionId = this.generateSessionId();
      server.sessionInfo = { userId, sessionId, videoCallId: this.videoCallId };

      // If user already has a session, clean it up before starting a new one.
      if (this.userIdToSessionId.has(userId)) {
          const oldSessionId = this.userIdToSessionId.get(userId);
          const oldWs = this.sessions.get(oldSessionId);
          if (oldWs) {
              // console.log(`User ${userId} reconnecting, closing old WebSocket session ${oldSessionId}`);
              oldWs.close(1000, "Reconnecting with new session");
              this.sessions.delete(oldSessionId);
          }
      }

      this.sessions.set(sessionId, server);
      this.participants.set(userId, server);
      this.userIdToSessionId.set(userId, sessionId);

      // console.log(`User ${userId} (Session: ${sessionId}) connected to VideoCallSignalingDO: ${this.videoCallId}. Total sessions: ${this.sessions.size}`);

      // Notify other participants
      const joinNotification = JSON.stringify({ type: "user-joined", userId: userId, videoCallId: this.videoCallId });
      this.broadcast(joinNotification, sessionId);

      return new Response(null, { status: 101, webSocket: client });
    }
    return errorResponse("Expected WebSocket upgrade request.", 400);
  }

  async webSocketMessage(ws, message) {
    const senderUserId = ws.sessionInfo.userId;
    // console.log(`Message from ${senderUserId} in ${this.videoCallId}: ${message}`);

    let parsedMessage;
    try {
        parsedMessage = JSON.parse(message);
    } catch (e) {
        console.error(`Failed to parse message from ${senderUserId}: ${message}`);
        ws.send(JSON.stringify({type: "error", payload: {message: "Invalid JSON message format."}}));
        return;
    }

    const targetUserId = parsedMessage.targetUserId;

    if (targetUserId) {
      const targetWs = this.participants.get(targetUserId);
      if (targetWs && targetWs.readyState === WebSocket.READY_STATE_OPEN) {
        // console.log(`Forwarding message from ${senderUserId} to ${targetUserId}`);
        // Add senderId to the message if not already present, so target knows who it's from
        if (!parsedMessage.senderUserId) {
            parsedMessage.senderUserId = senderUserId;
        }
        targetWs.send(JSON.stringify(parsedMessage));
      } else {
        // console.warn(`Target user ${targetUserId} not found or WebSocket not open for message from ${senderUserId}.`);
        // Optionally notify sender that target is not available
         ws.send(JSON.stringify({type: "error", payload: {message: `User ${targetUserId} is not available.`}}));
      }
    } else {
      // Broadcast to all OTHER participants if no specific target
      // console.log(`Broadcasting message from ${senderUserId} to others in ${this.videoCallId}`);
       if (!parsedMessage.senderUserId) {
            parsedMessage.senderUserId = senderUserId;
        }
      this.participants.forEach((participantWs, userId) => {
        if (userId !== senderUserId && participantWs.readyState === WebSocket.READY_STATE_OPEN) {
          try {
            participantWs.send(JSON.stringify(parsedMessage));
          } catch (e) {
            console.error(`Error broadcasting to ${userId}: ${e.message}`);
          }
        }
      });
    }
  }

  async webSocketClose(ws, code, reason, wasClean) {
    const { userId, sessionId, videoCallId } = ws.sessionInfo;
    // console.log(`WebSocket closed for user ${userId} (Session: ${sessionId}) in call ${videoCallId}. Code: ${code}, Reason: ${reason}, Clean: ${wasClean}.`);

    this.sessions.delete(sessionId);
    // Only delete from participants map if this specific session was the one mapped
    if (this.userIdToSessionId.get(userId) === sessionId) {
        this.participants.delete(userId);
        this.userIdToSessionId.delete(userId);
        // Notify other participants
        const leftNotification = JSON.stringify({ type: "user-left", userId: userId, videoCallId: this.videoCallId });
        this.broadcast(leftNotification, sessionId); // Exclude the leaving session from this broadcast
    }
    // console.log(`User ${userId} removed. Participants remaining: ${this.participants.size}, Sessions: ${this.sessions.size}`);
  }

  async webSocketError(ws, error) {
    const { userId, sessionId, videoCallId } = ws.sessionInfo || { userId: 'unknown', sessionId: 'unknown', videoCallId: this.videoCallId };
    console.error(`WebSocket error for user ${userId} (Session: ${sessionId}) in call ${videoCallId}: ${error.message}`, error.stack);
    // Trigger cleanup, ensuring it's safe even if ws.sessionInfo is partially lost
    if (ws.sessionInfo) {
        await this.webSocketClose(ws, 1011, "WebSocket error", false);
    }
  }

  broadcast(messageString, excludeSessionId) {
    // console.log(`Broadcasting in DO ${this.videoCallId} (excluding ${excludeSessionId}): ${messageString}`);
    this.sessions.forEach((sessionWs) => {
      if (sessionWs.sessionInfo.sessionId !== excludeSessionId && sessionWs.readyState === WebSocket.READY_STATE_OPEN) {
        try {
          sessionWs.send(messageString);
        } catch (e) {
          console.error(`Error sending to session ${sessionWs.sessionInfo.sessionId}: ${e.message}`);
        }
      }
    });
  }
}

export class ConversationDurableObject {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Map(); // Map unique ID to WebSocket object
    this.conversationId = state.id.toString(); // DO is named with conversationId
    // Initialize D1 access if needed within other methods if env.D1_DB is correctly passed
    this.D1_DB = env.D1_DB;
  }

  // Helper to generate a unique ID for sessions
  generateSessionId() {
    return crypto.randomUUID();
  }

  async fetch(request) {
    const url = new URL(request.url);

    // Handle WebSocket upgrade requests
    if (request.headers.get("Upgrade") === "websocket") {
      if (!request.headers.get("X-User-Id")) {
        return new Response("User ID required for WebSocket connection", { status: 400 });
      }
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);

      await this.state.acceptWebSocket(server);
      const sessionId = this.generateSessionId();
      server.sessionInfo = {
        userId: request.headers.get("X-User-Id"), // Get senderId from header
        sessionId: sessionId
      };
      this.sessions.set(sessionId, server);

      return new Response(null, { status: 101, webSocket: client });
    }

    // Handle internal broadcast triggers from the main worker
    // Example path: /internal/do/:conversationId/broadcast (though path on DO itself is just /broadcast-message)
    if (url.pathname === "/broadcast-message" && request.method === "POST") {
      try {
        const message = await request.json();
        // Assuming message is already fully formed (including sender details if fetched by main worker)
        this.broadcast(JSON.stringify(message), null); // null senderWs as it's from API
        return new Response("Message broadcasted", { status: 200 });
      } catch (error) {
        console.error("DO Broadcast Error:", error);
        return new Response("Error broadcasting message: " + error.message, { status: 500 });
      }
    }

    return new Response("Not found in DO", { status: 404 });
  }

  async webSocketMessage(ws, message) {
    try {
      const parsedMessage = JSON.parse(message);
      const senderId = ws.sessionInfo.userId;
      const conversationId = this.conversationId;
      const now = new Date().toISOString();

      // Basic validation
      if (!parsedMessage.content || parsedMessage.content.trim() === "") {
        ws.send(JSON.stringify({ error: "Message content cannot be empty."}));
        return;
      }

      const messageId = crypto.randomUUID();

      const persistedMessage = {
        id: messageId,
        conversation_id: conversationId,
        sender_id: senderId,
        content: parsedMessage.content,
        message_type: parsedMessage.message_type || 'text',
        media_url: parsedMessage.media_url || null,
        reactions_json: null, // Default or handle later
        parent_message_id: null, // Default or handle later
        is_edited: 0,
        is_deleted: 0,
        created_at: now,
        updated_at: now,
        // You might want to fetch sender's name/profile_picture here or expect it from client
        // For simplicity, client can use sender_id to look up user details
        sender: { id: senderId } // Minimal sender info for broadcast
      };

      // Persist to D1 - Ensure D1_DB is available (passed in env)
      const msgInsertResult = await this.D1_DB.prepare(
        "INSERT INTO messages (id, conversation_id, sender_id, content, message_type, media_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
      ).bind(
        persistedMessage.id,
        persistedMessage.conversation_id,
        persistedMessage.sender_id,
        persistedMessage.content,
        persistedMessage.message_type,
        persistedMessage.media_url,
        persistedMessage.created_at,
        persistedMessage.updated_at
      ).run();

      // Update conversation's last_message_at and updated_at
      const convUpdateResult = await this.D1_DB.prepare(
        "UPDATE conversations SET last_message_at = ?, updated_at = ? WHERE id = ?"
      ).bind(now, now, conversationId).run();

      this.broadcast(JSON.stringify(persistedMessage), ws);

      // After broadcasting, send push notifications (non-blocking in DO context)
      if (msgInsertResult.success && convUpdateResult.success) {
        this.state.waitUntil((async () => {
          try {
            const participantsResult = await this.D1_DB.prepare(
              "SELECT user_id FROM conversation_participants WHERE conversation_id = ? AND user_id != ?"
            ).bind(conversationId, senderId).all();

            if (participantsResult.results && participantsResult.results.length > 0) {
              // Attempt to get sender's name for a richer notification
              let senderName = "Someone"; // Default sender name
              try {
                const senderInfo = await this.D1_DB.prepare("SELECT name FROM users WHERE id = ?").bind(senderId).first();
                if (senderInfo && senderInfo.name) {
                  senderName = senderInfo.name;
                }
              } catch (nameError) {
                console.error(`DO: Error fetching sender name for push notification (senderId: ${senderId}): ${nameError.message}`);
              }

              for (const participant of participantsResult.results) {
                const subscriptionsResult = await this.D1_DB.prepare(
                  "SELECT endpoint, keys_p256dh, keys_auth, user_id FROM push_subscriptions WHERE user_id = ?"
                ).bind(participant.user_id).all();

                if (subscriptionsResult.results) {
                  for (const sub of subscriptionsResult.results) {
                    const payload = JSON.stringify({
                      title: "New Message",
                      body: `${senderName}: ${persistedMessage.content.substring(0, 50)}${persistedMessage.content.length > 50 ? '...' : ''}`,
                      data: { conversationId: conversationId, messageId: persistedMessage.id }
                    });
                    // Not using ctx.waitUntil here as this.state.waitUntil is the DO equivalent
                    await sendPushNotification(sub, payload, this.env);
                  }
                }
              }
            }
          } catch (pushError) {
            console.error(`DO Push Notification Error (ConvID: ${this.conversationId}): ${pushError.message}`, pushError.stack);
          }
        })());
      }

    } catch (error) {
      console.error(`DO WebSocketMessage Error (ConvID: ${this.conversationId}, UserID: ${ws.sessionInfo?.userId}): ${error.message}`, error.stack);
      try {
        ws.send(JSON.stringify({ error: "Failed to process message: " + error.message }));
      } catch (sendError) {
        console.error("DO Error sending error to WebSocket:", sendError);
      }
    }
  }

  async webSocketClose(ws, code, reason, wasClean) {
    console.log(`WebSocket closed (ConvID: ${this.conversationId}, UserID: ${ws.sessionInfo?.userId}, SessionID: ${ws.sessionInfo?.sessionId}) code: ${code}, reason: ${reason}, wasClean: ${wasClean}`);
    if (ws.sessionInfo) {
      this.sessions.delete(ws.sessionInfo.sessionId);
    }
  }

  async webSocketError(ws, error) {
    console.error(`WebSocket Error (ConvID: ${this.conversationId}, UserID: ${ws.sessionInfo?.userId}, SessionID: ${ws.sessionInfo?.sessionId}): ${error.message}`, error.stack);
    if (ws.sessionInfo) {
      this.sessions.delete(ws.sessionInfo.sessionId);
    }
  }

  broadcast(messageString, senderWs) {
    // console.log(`Broadcasting from DO (ConvID: ${this.conversationId}): ${messageString}`);
    this.sessions.forEach((socket, sessionId) => {
      // Cloudflare Workers DO WebSockets don't have a senderWs === socket comparison that works directly with the object reference from webSocketMessage
      // If senderWs is provided, we assume its sessionInfo.sessionId matches the key in this.sessions
      if (senderWs && senderWs.sessionInfo && senderWs.sessionInfo.sessionId === sessionId) {
         // Don't send back to the original sender of this specific message if it came from a WebSocket.
         // If senderWs is null (e.g. broadcast from API), send to all.
         return;
      }
      if (socket.readyState === WebSocket.READY_STATE_OPEN) { // Native WebSocket constant
        try {
          socket.send(messageString);
        } catch (e) {
          console.error(`Broadcast send error to session ${sessionId} in ConvID ${this.conversationId}: ${e.message}`);
          // Optionally remove unresponsive/erroring sessions
          // this.sessions.delete(sessionId);
        }
      } else {
        // Optional: Clean up sessions that are not open
        // console.log(`Session ${sessionId} in ConvID ${this.conversationId} not open, removing.`);
        // this.sessions.delete(sessionId);
      }
    });
  }
}

// Encryption Helper Functions
async function getKey(env) {
  if (!env.ENCRYPTION_KEY) {
    throw new Error("ENCRYPTION_KEY environment variable is not set.");
  }
  const keyData = Uint8Array.from(atob(env.ENCRYPTION_KEY), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(text, env) {
  if (text === null || typeof text === 'undefined') return null;
  try {
    const key = await getKey(env);
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
    const encodedText = new TextEncoder().encode(text);

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encodedText
    );

    const iv_b64 = btoa(String.fromCharCode(...iv));
    const ciphertext_b64 = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
    return `${iv_b64}:${ciphertext_b64}`;
  } catch (error) {
    console.error("Encryption failed:", error);
    throw new Error("Encryption process failed.");
  }
}

async function decrypt(encryptedText, env) {
  if (encryptedText === null || typeof encryptedText === 'undefined') return null;
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 2) throw new Error("Invalid encrypted format.");

    const iv = Uint8Array.from(atob(parts[0]), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(parts[1]), c => c.charCodeAt(0));
    const key = await getKey(env);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error("Decryption failed:", error);
    // It's often better not to leak specifics of decryption errors to clients
    // For admin panel, more detail might be acceptable, but for now, generic.
    throw new Error("Decryption process failed or data is corrupt.");
  }
}

// Response Helper Functions
function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function errorResponse(message, status = 400) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// JWT Helper Functions
async function signToken(rawPayload, secret) { // Renamed payload to rawPayload to avoid confusion
  const header = { alg: "HS256", typ: "JWT" };
  // Add jti and ensure exp is set (e.g., 1 hour from now)
  const payload = {
    ...rawPayload,
    jti: crypto.randomUUID(),
    exp: rawPayload.exp || Math.floor(Date.now() / 1000) + (60 * 60) // Default 1 hour
  };
  const encodedHeader = btoa(JSON.stringify(header)).replace(/=+$/, "");
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/=+$/, "");
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(signatureInput)
  );
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=+$/, "");
  
  return `${signatureInput}.${encodedSignature}`;
}

async function verifyToken(token, secret, env) { // Added env for D1 access
  try {
    const [header, payloadB64, signatureB64] = token.split(".");
    if (!header || !payloadB64 || !signatureB64) {
      console.log("Token structure invalid");
      return null;
    }

    const signatureInput = `${header}.${payloadB64}`;
    const decodedPayload = JSON.parse(atob(payloadB64));

    // Check blocklist first
    if (decodedPayload.jti) {
      const blocklisted = await env.D1_DB.prepare("SELECT 1 FROM jwt_blocklist WHERE jti = ?").bind(decodedPayload.jti).first();
      if (blocklisted) {
        console.log(`Token JTI ${decodedPayload.jti} is blocklisted.`);
        return null;
      }
    }

    // Check expiration
    if (decodedPayload.exp && Math.floor(Date.now() / 1000) > decodedPayload.exp) {
      console.log(`Token expired at ${new Date(decodedPayload.exp * 1000)}`);
      // Optionally, clean up this specific JTI if it's also in blocklist due to logout (though it's expired anyway)
      // await env.D1_DB.prepare("DELETE FROM jwt_blocklist WHERE jti = ?").bind(decodedPayload.jti).run();
      return null;
    }

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const signature = Uint8Array.from(atob(signatureB64.replace(/_/g, '/').replace(/-/g, '+')), c => c.charCodeAt(0));

    const isValid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      encoder.encode(signatureInput)
    );

    if (!isValid) {
      console.log("Token signature invalid");
      return null;
    }
    return decodedPayload;
  } catch (error) {
    console.error("Error verifying token:", error);
    return null;
  }
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hashPin(pin) {
  if (typeof pin !== 'string' || pin.length === 0) {
    throw new Error('PIN must be a non-empty string.');
  }
  const encoder = new TextEncoder();
  const data = encoder.encode(pin);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join('');
}

async function getUser(request, env) { // env already passed
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.split(" ")[1];
  // Pass env to verifyToken
  return await verifyToken(token, env.JWT_SECRET, env);
}

// RBAC Helper Function
function requireRole(user, allowedRoles) {
  if (!user || !user.role) {
    return false; // No user or no role property on user object
  }
  if (!Array.isArray(allowedRoles)) {
    console.error("requireRole: allowedRoles must be an array.");
    return false;
  }
  return allowedRoles.includes(user.role);
}

import { sendEmail } from './services/microsoftGraphService.ts';

const redirectUri = "https://its-just-us.your-account.workers.dev/auth/facebook/callback";

// PUBLIC_ROUTES is replaced by the new auth gate logic below

export default {
  async fetch(request, env, ctx) { // Added ctx for waitUntil if needed later
    const url = new URL(request.url);
    const user = await getUser(request, env);

    // --- Start of new/refined auth gate logic ---
    const pathname = url.pathname;
    const method = request.method;

    const isApiRoute = pathname.startsWith('/api/');
    // const isAuthRoute = pathname.startsWith('/auth/'); // Auth routes have their own specific handling.

    let isPublicApiRoute = false;
    if (isApiRoute) {
        const PUBLIC_API_PATHS = [ // List specific API paths that DON'T need a user session
            "/api/auth/request-password-reset",
            "/api/auth/reset-password",
            "/api/test-email", // Assuming this was intended to be public for testing MS Graph
            // Add any other public GET API endpoints if necessary (e.g., fetching public config)
        ];
        // Exact match for specific public API routes
        if (PUBLIC_API_PATHS.includes(pathname)) {
            isPublicApiRoute = true;
        }
        // Allow OPTIONS requests for CORS preflight on all API routes
        if (method === "OPTIONS") {
           isPublicApiRoute = true;
        }
    }

    // Determine if the current request is for a known, explicitly unprotected frontend path.
    // These are paths that the frontend router handles, and the backend should not interfere.
    // This list is for documentation/clarity; static asset serving handles these.
    const KNOWN_FRONTEND_PUBLIC_PATHS = [
       "/", // Homepage
       "/privacy-policy",
       "/support",
       "/user-data",
       "/refund"
    ];

    let isKnownPublicFrontendPath = false;
    for (const publicPath of KNOWN_FRONTEND_PUBLIC_PATHS) {
       if (pathname === publicPath || (publicPath !== "/" && pathname.startsWith(publicPath + "/"))) {
           isKnownPublicFrontendPath = true;
           break;
       }
    }
    if (pathname === "/") isKnownPublicFrontendPath = true;


    // Apply authentication check:
    // If the user is not authenticated AND
    // the route is an API route AND
    // it's not an explicitly public API route,
    // THEN return Unauthorized.
    // Non-API routes (isApiRoute = false) will bypass this check.
    // Auth routes (pathname.startsWith('/auth/')) are handled by their specific logic later.
    if (!user && isApiRoute && !isPublicApiRoute && !pathname.startsWith('/auth/')) {
        return errorResponse("Unauthorized", 401);
    }

    // If an OPTIONS request made it here (not caught by isPublicApiRoute if more specific handling is desired)
    // handle it generally.
    if (method === 'OPTIONS') {
       return new Response(null, { headers: {
           'Access-Control-Allow-Origin': '*', // Adjust for your domain in production
           'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
           'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-User-Id',
       }});
    }
    // --- End of new/refined auth gate logic ---

    // Super Admin Role Check for /api/admin/* routes
    // This block is placed after the general authentication gate and before specific admin route handlers.
    if (pathname.startsWith('/api/admin/')) {
      // Ensure user is authenticated first (guaranteed if the main auth gate is effective)
      if (!user) {
        // This check is somewhat redundant due to the main auth gate but provides clear, explicit protection.
        return errorResponse("Unauthorized: Admin authentication required.", 401);
      }

      if (!requireRole(user, ['super_admin'])) {
        // Log the unauthorized access attempt
        if (typeof logAuditEvent === 'function') { // Check if logAuditEvent is available
           ctx.waitUntil(logAuditEvent(env, request, 'admin_access_denied', user.userId, 'admin_route_access', pathname, 'failure', { attemptedRole: user.role || 'unknown' }));
        } else {
           console.warn("logAuditEvent function not available for admin_access_denied event.");
        }
        return errorResponse("Forbidden: You do not have sufficient privileges to access this resource.", 403);
      }
      // If execution reaches here, user is authenticated AND is a super_admin.
    }

    // API Endpoint: Get Family Members
    if (pathname === "/api/me/family/members" && method === "GET") {
      if (!user) {
        // This check is technically redundant if the main auth gate correctly protects all /api/ routes not explicitly public.
        // However, it's good for clarity on routes that absolutely need a user.
        return errorResponse("Unauthorized: Authentication required.", 401);
      }

      const { userId, role, family_id: userFamilyId } = user;

      // Authorization: Only family_admin or super_admin can list family members.
      if (!requireRole(user, ['family_admin', 'super_admin'])) {
        if (typeof logAuditEvent === 'function') {
          ctx.waitUntil(logAuditEvent(env, request, 'family_members_access_denied', userId, 'family_members_list', userFamilyId || 'N/A', 'failure', { reason: 'Insufficient role' }));
        }
        return errorResponse("Forbidden: You do not have permission to view family members.", 403);
      }

      if (!userFamilyId) {
        // This case should be rare for a family_admin due to registration logic.
        // For a super_admin, they might not be part of a family, or they might need a different way to specify which family to view.
        // For this endpoint (/api/me/family/members), it implies "my current family".
        return jsonResponse({ message: "User is not associated with a family." }, 404);
      }

      try {
        const { results: familyMembers } = await env.D1_DB.prepare(
          "SELECT id, name, email, role, date_of_birth, profile_picture, created_at, last_seen_at FROM users WHERE family_id = ?"
        ).bind(userFamilyId).all();

        return jsonResponse(familyMembers || []);
      } catch (e) {
        console.error(`Error fetching family members for family_id ${userFamilyId}:`, e);
        return errorResponse("Failed to fetch family members: " + e.message, 500);
      }
    }

    if (url.pathname === "/test") {
      try {
        // Example: Test if users table exists and has data (optional)
        const { results } = await env.D1_DB.prepare(`SELECT * FROM users LIMIT 1`).all();
        return jsonResponse({ message: "Test route. Migrations should handle schema. Found users:", results });
      } catch (error) {
        console.error("Error in /test route:", error.message, error.cause);
        return errorResponse(`Error: ${error.message} - Check worker logs for cause. Ensure migrations have been applied.`, 500);
      }
    }

    // Video Call Management API Endpoints
    // POST /api/video/calls - Create a new video call
    if (url.pathname === "/api/video/calls" && request.method === "POST") {
      if (!user) return errorResponse("Unauthorized", 401);
      try {
        const body = await request.json().catch(() => ({}));
        const { title, max_participants } = body;
        const creatorId = user.userId;

        const callId = crypto.randomUUID();
        const roomName = crypto.randomUUID();
        const now = new Date().toISOString();
        const callStatus = 'pending';

        // Initial insert into video_calls
        await env.D1_DB.prepare(
          "INSERT INTO video_calls (id, room_name, created_by_user_id, title, start_time, status, max_participants, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ).bind(callId, roomName, creatorId, title || `Call by ${user.name || creatorId}`, now, callStatus, max_participants || null, now, now).run();

        // Add creator as participant
        await env.D1_DB.prepare(
          "INSERT INTO call_participants (call_id, user_id, status) VALUES (?, ?, ?)"
        ).bind(callId, creatorId, 'host').run();

        // Fetch Cloudflare Calls Credentials
        const cfCallsIntegration = await env.D1_DB.prepare(
            "SELECT client_id_encrypted, api_key_encrypted FROM third_party_integrations WHERE service_name = 'CloudflareCalls' AND is_enabled = 1"
        ).first();

        if (!cfCallsIntegration) {
            // Potentially delete the local video_calls record or mark it as failed
            // For now, let it exist but client won't get CF details
            console.warn(`Cloudflare Calls integration not configured or disabled for call ${callId}.`);
        }

        let decryptedAppId = null;
        let decryptedApiToken = null;
        let cfSessionData = null;
        let clientTokenForUser = null;

        if (cfCallsIntegration) {
            try {
                decryptedAppId = await decrypt(cfCallsIntegration.client_id_encrypted, env); // Assuming client_id stores App ID
                decryptedApiToken = await decrypt(cfCallsIntegration.api_key_encrypted, env); // Assuming api_key stores API Token
            } catch (decryptionError) {
                console.error("Failed to decrypt Cloudflare Calls credentials:", decryptionError);
                // Proceed without CF Calls integration if decryption fails
            }
        }

        if (decryptedAppId && decryptedApiToken) {
            try {
                // For this subtask, we simulate a successful Cloudflare Calls API response:
                cfSessionData = {
                    id: `sim_cf_sess_${crypto.randomUUID()}`, // Simulated session ID from CF
                    // Example structure, might include a specific token for clients to join this session
                    // This token is often different from the API token used for server-to-server auth.
                    // Let's assume CF returns a "sessionJoinToken" or similar for clients.
                    // For the purpose of this task, we'll call it 'token_for_client' to match the prompt
                    token_for_client: `sim_client_token_for_call_${callId}_${crypto.randomUUID()}`
                };
                console.log("Simulated Cloudflare Calls session creation:", cfSessionData);

                // Update video_calls record with CF Calls info
                await env.D1_DB.prepare(
                    "UPDATE video_calls SET cf_calls_app_id = ?, cf_calls_session_id = ?, cf_calls_data = ?, updated_at = ? WHERE id = ?"
                ).bind(decryptedAppId, cfSessionData.id, JSON.stringify(cfSessionData), new Date().toISOString(), callId).run();

                clientTokenForUser = cfSessionData.token_for_client;

            } catch (error) {
                console.error("Failed to create/process Cloudflare Calls session:", error);
                // Potentially delete the local video_calls record or mark it as failed if CF Calls session is critical
                // For now, we proceed, and the call will lack CF session data. Client should handle this.
            }
        }

        const newCall = {
          id: callId,
          room_name: roomName,
          created_by_user_id: creatorId,
          title: title || `Call by ${user.name || creatorId}`,
          start_time: now,
          status: callStatus,
          max_participants: max_participants || null,
          created_at: now,
          participants: [{ user_id: creatorId, status: 'host' }],
          cf_calls_session_id: cfSessionData ? cfSessionData.id : null,
          cf_client_token: clientTokenForUser // Token for the client to join this specific CF Call session
        };
        return jsonResponse(newCall, 201);

      } catch (e) {
        console.error("Error creating video call:", e);
        if (e.message.includes("ENCRYPTION_KEY")) return errorResponse(e.message, 500);
        return errorResponse("Failed to create video call: " + e.message, 500);
      }
    }

    // GET /api/video/calls - List video calls for the user
    if (url.pathname === "/api/video/calls" && request.method === "GET") {
      if (!user) return errorResponse("Unauthorized", 401);
      try {
        const userId = user.userId;
        const { results } = await env.D1_DB.prepare(
          `SELECT DISTINCT vc.id, vc.room_name, vc.title, vc.start_time, vc.status, vc.created_by_user_id,
                          vc.max_participants, vc.cf_calls_session_id, vc.cf_calls_data,
                  (SELECT COUNT(*) FROM call_participants cp_count WHERE cp_count.call_id = vc.id AND cp_count.left_at IS NULL) as current_participant_count
           FROM video_calls vc
           LEFT JOIN call_participants cp ON vc.id = cp.call_id
           WHERE vc.created_by_user_id = ? OR cp.user_id = ?
           ORDER BY vc.start_time DESC`
        ).bind(userId, userId).all();

        const callsWithClientTokens = results.map(call => {
            let clientToken = null;
            if (call.cf_calls_data) {
                try {
                    const cfData = JSON.parse(call.cf_calls_data);
                    clientToken = cfData.token_for_client || null; // Extract the client token
                } catch (parseError) {
                    console.error(`Error parsing cf_calls_data for call ${call.id}:`, parseError);
                }
            }
            // Return cf_calls_session_id and the extracted client token.
            // Avoid returning the entire cf_calls_data to the client list.
            return {
                ...call,
                cf_client_token: clientToken,
                cf_calls_data: undefined // Remove the raw cf_calls_data
            };
        });
        return jsonResponse(callsWithClientTokens);
      } catch (e) {
        console.error("Error fetching video calls:", e);
        return errorResponse("Failed to fetch video calls: " + e.message, 500);
      }
    }

    // Regex for /api/video/calls/:callId/(join|leave|signal)
    // Signal path is new, join/leave are existing HTTP POST paths
    const videoCallPathMatch = url.pathname.match(/^\/api\/video\/calls\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\/(join|leave|signal)$/i);

    if (videoCallPathMatch) {
      if (!user) return errorResponse("Unauthorized", 401);
      const callId = videoCallPathMatch[1];
      const action = videoCallPathMatch[2];
      const userId = user.userId;
      const now = new Date().toISOString();

      // Check if call exists (for join/leave, not strictly necessary for signal but good for consistency if we had other non-WS signal interactions)
      const callForHttpActions = (action === "join" || action === "leave")
          ? await env.D1_DB.prepare("SELECT id, status, max_participants FROM video_calls WHERE id = ?").bind(callId).first()
          : null;

      if ((action === "join" || action === "leave") && !callForHttpActions) {
        return errorResponse("Video call not found.", 404);
      }

      // WebSocket Signaling Route
      if (action === "signal" && request.method === "GET") {
        try {
            const doId = env.VIDEO_CALL_SIGNALING_DO.idFromString(callId);
            const stub = env.VIDEO_CALL_SIGNALING_DO.get(doId);
            const doRequest = new Request(request.url, request);
            doRequest.headers.set("X-User-Id", userId);
            return stub.fetch(doRequest);
        } catch (e) {
            console.error("Error forwarding WebSocket signaling request to DO:", e);
            return errorResponse("Failed to establish signaling connection: " + e.message, 500);
        }
      }


      if (action === "join") {
        // Use callForHttpActions, which is already fetched for join/leave
        if (callForHttpActions.status === 'completed' || callForHttpActions.status === 'failed') {
          return errorResponse("Cannot join a call that has already ended.", 400);
        }

        // Check max participants
        if (callForHttpActions.max_participants) {
          const { count } = await env.D1_DB.prepare(
            "SELECT COUNT(*) as count FROM call_participants WHERE call_id = ? AND left_at IS NULL"
          ).bind(callId).first();
          if (count >= callForHttpActions.max_participants) {
            return errorResponse("Call is full.", 403);
          }
        }
        if (call.status === 'completed' || call.status === 'failed') {
          return errorResponse("Cannot join a call that has already ended.", 400);
        }

        // Check max participants
        if (call.max_participants) {
          const { count } = await env.D1_DB.prepare(
            "SELECT COUNT(*) as count FROM call_participants WHERE call_id = ? AND left_at IS NULL"
          ).bind(callId).first();
          if (count >= call.max_participants) {
            return errorResponse("Call is full.", 403);
          }
        }

        // Add or update participant entry
        // Using INSERT OR REPLACE like behavior, or separate INSERT and UPDATE
        await env.D1_DB.prepare(
          "INSERT INTO call_participants (call_id, user_id, status, joined_at, left_at) VALUES (?, ?, ?, ?, NULL) ON CONFLICT(call_id, user_id) DO UPDATE SET status = ?, joined_at = ?, left_at = NULL"
        ).bind(callId, userId, 'connected', now, 'reconnected', now).run();

        // Optionally, update call status if it was 'pending'
        if (call.status === 'pending') {
            await env.D1_DB.prepare("UPDATE video_calls SET status = 'active', updated_at = ? WHERE id = ?").bind(now, callId).run();
        }

        return jsonResponse({ message: "Successfully joined the call." });

      } else if (action === "leave") {
        await env.D1_DB.prepare(
          "UPDATE call_participants SET status = ?, left_at = ? WHERE call_id = ? AND user_id = ?"
        ).bind('left', now, callId, userId).run();

        // Optional: Check if all participants left to update main call status (more complex logic for later)
        // For example, if the host leaves, or if current_participant_count becomes 0.
        // const { results: remainingParticipants } = await env.D1_DB.prepare("SELECT user_id FROM call_participants WHERE call_id = ? AND left_at IS NULL").bind(callId).all();
        // if (remainingParticipants.length === 0) {
        //    await env.D1_DB.prepare("UPDATE video_calls SET status = 'completed', end_time = ?, updated_at = ? WHERE id = ?").bind(now, now, callId).run();
        // }

        return jsonResponse({ message: "Successfully left the call." });
      }
    }

    // API Route: Request Password Reset
    if (request.method === "POST" && url.pathname === "/api/auth/request-password-reset") {
      try {
        const { email } = await request.json();
        if (!email) {
          return new Response(JSON.stringify({ message: "Email is required." }), { status: 400, headers: { "Content-Type": "application/json" } });
        }

        // Check if user exists
        const user = await env.D1_DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
        // Important: To prevent user enumeration attacks, always return a generic success message,
        // regardless of whether the email address is registered in the system.
        if (!user) {
          console.log(`Password reset requested for non-existent email (or existing, no indication given to client): ${email}`);
          return new Response(JSON.stringify({ message: "If your email is registered, you will receive a password reset link." }), { status: 200, headers: { "Content-Type": "application/json" } });
        }

        // Generate a cryptographically secure random token for the password reset link.
        const plainToken = crypto.randomUUID();
        // Hash the plain token before storing it in the database for security.
        const hashedToken = await hashPassword(plainToken);

        const expiryMinutes = 60; // Token will be valid for 60 minutes.
        const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000).toISOString();

        // Store the hashed token, the user's email, and the token's expiration time in the database.
        await env.D1_DB.prepare(
          "INSERT INTO password_reset_tokens (email, token_hash, expires_at) VALUES (?, ?, ?)"
        ).bind(email, hashedToken, expiresAt).run();

        // Prepare and send the password reset email.
        const frontendBaseUrl = env.FRONTEND_URL || "http://localhost:3000";
        const resetLink = `${frontendBaseUrl}/reset-password?token=${plainToken}`;

        try {
          const { subject, bodyHtml } = await getProcessedEmailTemplate(
            'password_reset_email',
            {
              // Assuming the user object from D1 might have a name, if not, email is used.
              // The 'user' variable here is from the D1 query: const user = await env.D1_DB.prepare("SELECT id, name FROM users WHERE email = ?").bind(email).first();
              // If 'user.name' is not guaranteed, a fallback is needed.
              name: user.name || email, // Use user.name if available, otherwise email as name
              resetLink: resetLink,
              expiryMinutes: expiryMinutes,
              appName: "It's Just Us" // Example app name
            },
            env
          );

          // Non-blocking email send
          sendEmail(env, { to: email, subject, htmlBody: bodyHtml })
            .then(success => console.log(success ? `Password reset email dispatched to ${email}.` : `Failed to dispatch password reset email to ${email}.`))
            .catch(err => console.error(`Error sending password reset email to ${email}:`, err));

          return jsonResponse({ message: "If your email is registered, you will receive a password reset link." });

        } catch (templateError) {
            console.error("Error processing password reset email template:", templateError);
            // Fallback to a simple email if template fails, or return an error
            // For now, just log and the generic success message is returned
            // but ideally, this failure should be handled more robustly.
             return errorResponse("Error processing email template. Please contact support.", 500);
        }

      } catch (error) {
        console.error("Error in /api/auth/request-password-reset:", error);
        return new Response(JSON.stringify({ message: "An error occurred. Please try again." }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }

    // API Route: Reset Password
    if (request.method === "POST" && url.pathname === "/api/auth/reset-password") {
      try {
        const { token, newPassword } = await request.json();
        if (!token || !newPassword) {
          return new Response(JSON.stringify({ message: "Token and new password are required." }), { status: 400, headers: { "Content-Type": "application/json" } });
        }

        // Hash the plain token received from the client to compare with the stored hashed token.
        const hashedToken = await hashPassword(token);

        // Attempt to find the token in the database.
        const tokenEntry = await env.D1_DB.prepare(
          "SELECT email, expires_at FROM password_reset_tokens WHERE token_hash = ?"
        ).bind(hashedToken).first();

        // If no token entry is found, the token is invalid or has already been used.
        if (!tokenEntry) {
          return new Response(JSON.stringify({ message: "Invalid or expired reset token." }), { status: 400, headers: { "Content-Type": "application/json" } });
        }

        // Check if the token has expired.
        if (new Date(tokenEntry.expires_at) < new Date()) {
          // Delete the expired token from the database to prevent reuse.
          await env.D1_DB.prepare("DELETE FROM password_reset_tokens WHERE token_hash = ?").bind(hashedToken).run();
          return new Response(JSON.stringify({ message: "Reset token has expired." }), { status: 400, headers: { "Content-Type": "application/json" } });
        }

        const userEmail = tokenEntry.email;
        // Hash the new password before updating it in the users table.
        const hashedNewPassword = await hashPassword(newPassword);

        // Update the user's password in the main users table.
        const updateResult = await env.D1_DB.prepare(
          "UPDATE users SET password_hash = ? WHERE email = ?"
        ).bind(hashedNewPassword, userEmail).run();

        // Check if the update was successful.
        if (updateResult.meta.changes === 0) {
             console.error(`Failed to update password for email: ${userEmail}. User might not exist or email changed.`);
             // This case should ideally not happen if token validation is robust and user exists.
             return new Response(JSON.stringify({ message: "Failed to update password. User not found." }), { status: 404, headers: { "Content-Type": "application/json" } });
        }

        // After successfully updating the password, delete the used token from the database.
        await env.D1_DB.prepare("DELETE FROM password_reset_tokens WHERE token_hash = ?").bind(hashedToken).run();

        // Send a confirmation email to the user that their password has been changed.
        try {
            // Need user's name for the template. The user was updated, but we might not have their name here.
            // For simplicity, we'll just use the email if name isn't readily available.
            // A better approach might be to fetch the user record again if name is strictly needed.
            const { subject, bodyHtml } = await getProcessedEmailTemplate(
                'password_changed_confirmation',
                { name: userEmail, appName: "It's Just Us" }, // Assuming 'name' is desired; userEmail as fallback.
                env
            );

            sendEmail(env, { to: userEmail, subject, htmlBody: bodyHtml })
              .then(success => console.log(success ? `Password change confirmation email dispatched to ${userEmail}.` : `Failed to dispatch password change confirmation to ${userEmail}.`))
              .catch(err => console.error(`Error sending password change confirmation to ${userEmail}:`, err));

        } catch (templateError) {
            console.error("Error processing password changed confirmation email template:", templateError);
            // Email sending is best-effort here, so don't fail the whole request.
        }

        return jsonResponse({ message: "Password reset successfully." });

      } catch (error) {
        console.error("Error in /api/auth/reset-password:", error);
        return new Response(JSON.stringify({ message: "An error occurred. Please try again." }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }

    // Facebook OAuth redirect
    if (url.pathname === "/auth/facebook") {
      const authUrl = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${env.FACEBOOK_CLIENT_ID}&redirect_uri=${redirectUri}&scope=email`;
      return Response.redirect(authUrl, 302);
    }

    // Facebook OAuth callback
    if (url.pathname === "/auth/facebook/callback") {
      const code = url.searchParams.get("code");
      if (!code) return new Response("No code provided", { status: 400 });

      const tokenResponse = await fetch("https://graph.facebook.com/v19.0/oauth/access_token", {
        method: "POST",
        body: new URLSearchParams({
          client_id: env.FACEBOOK_CLIENT_ID,
          client_secret: env.FACEBOOK_CLIENT_SECRET,
          redirect_uri: redirectUri,
          code,
        }),
      });
      const { access_token } = await tokenResponse.json();

      const userResponse = await fetch(`https://graph.facebook.com/me?fields=id,name,email,picture&access_token=${access_token}`);
      const userData = await userResponse.json();

      const { id: fbId, name, email, picture } = userData;
      const profilePicture = picture.data.url;  // Facebook profile photo URL

      await env.D1_DB.prepare(
        "INSERT OR REPLACE INTO users (id, name, email, profile_picture, password_hash) VALUES (?, ?, ?, ?, ?)"
      ).bind(fbId, name, email, profilePicture, "facebook-oauth").run();

      const token = await signToken({ userId: fbId, email, exp: Math.floor(Date.now() / 1000) + 3600 }, env.JWT_SECRET);
      return new Response(JSON.stringify({ token, profilePicture }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Facebook SDK token verification
    if (request.method === "POST" && url.pathname === "/auth/facebook/token") {
      const { accessToken } = await request.json();
      if (!accessToken) return new Response("No token provided", { status: 400 });

      const debugResponse = await fetch(
        `https://graph.facebook.com/debug_token?input_token=${accessToken}&access_token=${env.FACEBOOK_CLIENT_ID}|${env.FACEBOOK_CLIENT_SECRET}`
      );
      const debugData = await debugResponse.json();
      if (!debugData.data.is_valid) return new Response("Invalid token", { status: 401 });

      const userResponse = await fetch(`https://graph.facebook.com/me?fields=id,name,email,picture&access_token=${accessToken}`);
      const userData = await userResponse.json();

      const { id: fbId, name, email, picture } = userData;
      const profilePicture = picture.data.url;  // Facebook profile photo URL

      await env.D1_DB.prepare(
        "INSERT OR REPLACE INTO users (id, name, email, profile_picture, password_hash) VALUES (?, ?, ?, ?, ?)"
      ).bind(fbId, name, email, profilePicture, "facebook-oauth").run();

      const token = await signToken({ userId: fbId, email, exp: Math.floor(Date.now() / 1000) + 3600 }, env.JWT_SECRET);
      return new Response(JSON.stringify({ token, profilePicture }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Email/Password Register
    if (request.method === "POST" && url.pathname === "/auth/register") {
      try {
        const requestData = await request.json(); // Use requestData to access all potential fields
        const { name, email, password, date_of_birth } = requestData;

        if (!name || !email || !password) {
          return errorResponse("Name, email, and password are required.", 400);
        }
        // Basic validation for DOB format if provided
        if (date_of_birth && !/^\d{4}-\d{2}-\d{2}$/.test(date_of_birth)) {
          return errorResponse("date_of_birth must be in YYYY-MM-DD format.", 400);
        }

        const hashedPassword = await hashPassword(password);
        const newUserId = crypto.randomUUID();
        const familyId = crypto.randomUUID();
        const userRole = 'family_admin'; // New users create a family and become its admin
        const now = new Date().toISOString();
        const dob = date_of_birth || null;

        // Create the family first
        // Use requestData.name for family_name, or a default if name is not suitable for family name.
        const familyName = `${name}'s Family` // Example default family name
        await env.D1_DB.prepare(
          "INSERT INTO families (id, created_by_user_id, family_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
        ).bind(familyId, newUserId, familyName, now, now).run();

        // Then insert the user
        await env.D1_DB.prepare(
          "INSERT INTO users (id, name, email, password_hash, role, family_id, date_of_birth, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ).bind(newUserId, name, email, hashedPassword, userRole, familyId, dob, now, now).run();

        // Log registration event (before sending email or token, in case those fail)
        await logAuditEvent(env, request, 'register', newUserId, 'user', newUserId, 'success', { email: email, role: userRole, familyId: familyId });

        // Send welcome email using template
        try {
          const { subject, bodyHtml } = await getProcessedEmailTemplate(
            'welcome_email',
            { name: name, appName: "It's Just Us" }, // Use name from requestData
            env
          );

          console.log(`Attempting to send welcome email to: ${email}`); // Use email from requestData
          sendEmail(env, { to: email, subject, htmlBody: bodyHtml })
            .then(emailSuccess => { // Renamed variable to avoid conflict
              if (emailSuccess) {
                console.log(`Welcome email successfully dispatched to ${email}.`);
              } else {
                console.error(`Failed to dispatch welcome email to ${email}.`);
              }
            }).catch(emailError => { // Renamed variable
              console.error(`Error sending welcome email to ${email}:`, emailError);
            });
        } catch (templateError) {
            console.error("Error processing welcome email template:", templateError);
        }

        // Prepare token payload with new RBAC fields
        const tokenPayload = {
            userId: newUserId,
            email: email,
            role: userRole,
            family_id: familyId
            // exp and jti are added by signToken
        };
        const token = await signToken(tokenPayload, env.JWT_SECRET);

        // Update response to include new user fields
        return jsonResponse({
          message: "User registered successfully. A welcome email is being sent.",
          token: token, // Send token immediately upon registration
          user: {
            id: newUserId,
            name: name,
            email: email,
            role: userRole,
            family_id: familyId,
            date_of_birth: dob
            // profile_picture will be null initially
          }
        }, 201);

      } catch (dbError) {
        if (dbError.message && dbError.message.includes("UNIQUE constraint failed: users.email")) {
          return errorResponse("Email already exists. Please use a different email or login.", 409);
        }
        if (dbError.message && dbError.message.includes("UNIQUE constraint failed: families.id")) {
          // This could happen if UUID collision, though extremely rare.
          // Or if family creation failed silently and user insert then violates FK if that was added.
          // For now, general error.
          console.error("Family ID collision or related error during registration:", dbError);
          return errorResponse("Error during family setup in registration.", 500);
        }
        console.error("Error during registration:", dbError);
        return errorResponse("Error during registration: " + dbError.message, 500);
      }
    }

    // Email/Password Login
    if (request.method === "POST" && url.pathname === "/auth/login") {
      const requestData = await request.json();
      const { email, password } = requestData;
      const hashedPassword = await hashPassword(password);
      // Updated SELECT to fetch role and family_id
      const dbUser = await env.D1_DB.prepare(
        "SELECT id, name, email, password_hash, profile_picture, role, family_id, date_of_birth FROM users WHERE email = ? AND password_hash = ?"
      ).bind(email, hashedPassword).first();

      const ipAddress = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || "unknown";
      const userAgent = request.headers.get('User-Agent') || "unknown";

      if (!dbUser) {
        await logAuditEvent(env, request, 'login_failed', null, 'user', email, 'failure', { reason: 'Invalid credentials' });
        try {
            await env.D1_DB.prepare(
                "INSERT INTO failed_login_attempts (attempted_identifier, ip_address, user_agent) VALUES (?, ?, ?)"
            ).bind(email, ipAddress, userAgent).run();
        } catch (failedLoginError) {
            console.error("Error logging failed login attempt:", failedLoginError);
        }
        return errorResponse("Invalid credentials", 401);
      }

      await logAuditEvent(env, request, 'login', dbUser.id, 'user', dbUser.id, 'success');

      try {
        const loginTimestamp = new Date().toISOString(); // Use consistent timestamp for login
        const existingIp = await env.D1_DB.prepare(
          "SELECT id FROM user_known_ips WHERE user_id = ? AND ip_address = ?"
        ).bind(dbUser.id, ipAddress).first();

        if (existingIp) {
          await env.D1_DB.prepare(
            "UPDATE user_known_ips SET last_seen_at = ? WHERE id = ?"
          ).bind(loginTimestamp, existingIp.id).run();
        } else {
          await env.D1_DB.prepare(
            "INSERT INTO user_known_ips (user_id, ip_address, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?)"
          ).bind(dbUser.id, ipAddress, loginTimestamp, loginTimestamp).run();
        }
        // Update user's last_seen_at
        await env.D1_DB.prepare("UPDATE users SET last_seen_at = ? WHERE id = ?").bind(loginTimestamp, dbUser.id).run();

      } catch (ipTrackingError) {
          console.error("Error tracking user IP or last_seen_at:", ipTrackingError);
      }

      // Updated tokenPayload to include role and family_id
      const tokenPayload = {
        userId: dbUser.id,
        email: dbUser.email,
        name: dbUser.name,
        role: dbUser.role, // Added role
        family_id: dbUser.family_id, // Added family_id
        profile_picture: dbUser.profile_picture
        // exp and jti are added by signToken
      };
      const token = await signToken(tokenPayload, env.JWT_SECRET);

      // Updated user object in response to include role and family_id
      return jsonResponse({
        token,
        user: {
          id: dbUser.id,
          name: dbUser.name,
          email: dbUser.email,
          profile_picture: dbUser.profile_picture,
          role: dbUser.role,
          family_id: dbUser.family_id,
          date_of_birth: dbUser.date_of_birth
        }
      });
    }

    // Logout - Now requires token to blocklist
    if (url.pathname === "/auth/logout" && request.method === "POST") { // Changed to POST for clarity, though GET could work
      const authHeader = request.headers.get("Authorization");
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return errorResponse("No token provided for logout.", 400);
      }
      const token = authHeader.split(" ")[1];

      // We don't strictly need to verify the signature for logout blocklisting,
      // but decoding is needed to get jti and exp.
      // A lightweight decode might be better if performance is critical.
      // For simplicity, using verifyToken which also checks expiry but not blocklist yet for itself.
      const decodedPayload = await verifyToken(token, env.JWT_SECRET, env); // verifyToken now checks blocklist
                                                                           // so if it's already blocklisted, this would return null.
                                                                           // This is okay, means it's already dealt with.

      if (decodedPayload && decodedPayload.jti && decodedPayload.exp) {
        const expiresAtISO = new Date(decodedPayload.exp * 1000).toISOString();
        try {
          await env.D1_DB.prepare(
            "INSERT INTO jwt_blocklist (jti, user_id, expires_at) VALUES (?, ?, ?)"
          ).bind(decodedPayload.jti, decodedPayload.userId, expiresAtISO).run();
          await logAuditEvent(env, request, 'logout', decodedPayload.userId, 'jwt', decodedPayload.jti, 'success');
          return jsonResponse({ message: "Logout successful. Token blocklisted." });
        } catch (dbError) {
          // Handle potential unique constraint violation if jti somehow already exists (e.g. race condition or re-logout)
          if (dbError.message.includes("UNIQUE constraint failed")) {
             await logAuditEvent(env, request, 'logout_ignored', decodedPayload.userId, 'jwt', decodedPayload.jti, 'ignored', {reason: "Token already blocklisted"});
            return jsonResponse({ message: "Token already blocklisted or logout processed." });
          }
          console.error("Error blocklisting token:", dbError);
          await logAuditEvent(env, request, 'logout_failed', decodedPayload.userId, 'jwt', decodedPayload.jti, 'failure', {reason: "DB error"});
          return errorResponse("Failed to blocklist token.", 500);
        }
      } else {
        // If token is invalid (e.g. expired, bad signature, or already blocklisted and verifyToken returned null)
        // Still log an attempt if possible, though userId might be unknown
        const attemptedJti = token.split('.')[1] ? JSON.parse(atob(token.split('.')[1])).jti : "unknown_jti";
        await logAuditEvent(env, request, 'logout_failed', null, 'jwt', attemptedJti, 'failure', {reason: "Invalid or missing token for logout"});
        return errorResponse("Invalid or missing token for logout.", 400);
      }
    }

    // Messaging API Endpoints

    // POST /api/conversations - Create a new conversation
    if (url.pathname === "/api/conversations" && request.method === "POST") {
      if (!user) return errorResponse("Unauthorized", 401);
      try {
        const body = await request.json();
        const { participantIds, title } = body;

        if (!participantIds || !Array.isArray(participantIds) || participantIds.length === 0) {
          return errorResponse("Participant IDs are required and must be a non-empty array.", 400);
        }

        const creatorId = user.userId;
        const allParticipantIds = [...new Set([creatorId, ...participantIds])]; // Ensure creator is included and unique

        // Create conversation
        const conversationId = crypto.randomUUID(); // Generate ID in JS
        const now = new Date().toISOString();

        await env.D1_DB.prepare(
          "INSERT INTO conversations (id, title, created_by_user_id, created_at, updated_at, last_message_at) VALUES (?, ?, ?, ?, ?, ?)"
        ).bind(conversationId, title || null, creatorId, now, now, now).run();

        // Add participants
        const participantInserts = allParticipantIds.map(userId => {
          return env.D1_DB.prepare(
            "INSERT INTO conversation_participants (conversation_id, user_id, is_admin) VALUES (?, ?, ?)"
          ).bind(conversationId, userId, userId === creatorId).run();
        });
        await Promise.all(participantInserts);

        // Fetch the created conversation with participants to return
        // This is a simplified version; a more robust one might join with users table for names/pics
        const createdConversation = {
          id: conversationId,
          title: title || null,
          created_by_user_id: creatorId,
          created_at: now,
          updated_at: now,
          last_message_at: now,
          participants: allParticipantIds.map(uid => ({ user_id: uid, is_admin: uid === creatorId }))
        };

        return jsonResponse(createdConversation, 201);
      } catch (e) {
        console.error("Error creating conversation:", e);
        return errorResponse("Failed to create conversation: " + e.message, 500);
      }
    }

    // GET /api/conversations - Get all conversations for the current user
    if (url.pathname === "/api/conversations" && request.method === "GET") {
      if (!user) return errorResponse("Unauthorized", 401);
      try {
        const userId = user.userId;
        const { results } = await env.D1_DB.prepare(
          `SELECT c.id, c.title, c.created_by_user_id, c.created_at, c.updated_at, c.last_message_at,
                  (SELECT json_group_array(json_object('user_id', u.id, 'name', u.name, 'profile_picture', u.profile_picture))
                   FROM conversation_participants cp_detail
                   JOIN users u ON cp_detail.user_id = u.id
                   WHERE cp_detail.conversation_id = c.id) as participants_details,
                  (SELECT json_object('id', m.id, 'content', m.content, 'sender_id', m.sender_id, 'created_at', m.created_at)
                   FROM messages m
                   WHERE m.conversation_id = c.id
                   ORDER BY m.created_at DESC LIMIT 1) as last_message
           FROM conversations c
           JOIN conversation_participants cp ON c.id = cp.conversation_id
           WHERE cp.user_id = ?
           ORDER BY c.last_message_at DESC`
        ).bind(userId).all();

        const conversations = results.map(row => ({
            ...row,
            participants_details: JSON.parse(row.participants_details || '[]'),
            last_message: JSON.parse(row.last_message || '{}')
        }));

        return jsonResponse(conversations);
      } catch (e) {
        console.error("Error fetching conversations:", e);
        return errorResponse("Failed to fetch conversations: " + e.message, 500);
      }
    }

    // Regex to match /api/conversations/:conversationId/messages OR /api/conversations/:conversationId/websocket
    const conversationActionMatch = url.pathname.match(/^\/api\/conversations\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\/(messages|websocket)$/i);

    if (conversationActionMatch) {
      if (!user) return errorResponse("Unauthorized", 401);
      const conversationId = conversationActionMatch[1];
      const actionPath = conversationActionMatch[2];
      const userId = user.userId; // Authenticated user's ID

      // WebSocket Upgrade Route for a specific conversation
      if (actionPath === "websocket" && request.method === "GET") {
        try {
          const doId = env.CONVERSATION_DO.idFromString(conversationId);
          const stub = env.CONVERSATION_DO.get(doId);

          // Forward the request to the DO, adding user ID for the DO to identify the sender
          const doRequest = new Request(request.url, request);
          doRequest.headers.set("X-User-Id", userId);

          return await stub.fetch(doRequest);
        } catch (e) {
          console.error("Error forwarding WebSocket request to DO:", e);
          return errorResponse("Failed to establish WebSocket connection: " + e.message, 500);
        }
      }

      // Existing messages API (POST and GET)
      if (actionPath === "messages") {
         // Check if user is part of the conversation for both POST and GET
        const participantCheck = await env.D1_DB.prepare(
          "SELECT 1 FROM conversation_participants WHERE conversation_id = ? AND user_id = ?"
        ).bind(conversationId, userId).first();

        if (!participantCheck) {
          return errorResponse("Forbidden: You are not a participant in this conversation.", 403);
        }

        // POST /api/conversations/:conversationId/messages - Create a new message
        if (request.method === "POST") {
          try {
            const body = await request.json();
            const { content, message_type = 'text', media_url = null } = body;

            if (!content || content.trim() === "") {
              return errorResponse("Message content cannot be empty.", 400);
            }

            const messageId = crypto.randomUUID();
            const now = new Date().toISOString();

            // Fetch sender details (name, profile_picture) for the broadcasted message
            const senderDetails = await env.D1_DB.prepare(
              "SELECT name, profile_picture FROM users WHERE id = ?"
            ).bind(userId).first();

            const persistedMessage = {
              id: messageId,
              conversation_id: conversationId,
              sender_id: userId,
              content,
              message_type,
              media_url,
              created_at: now,
              updated_at: now,
              sender: {
                id: userId,
                name: senderDetails?.name || "User", // Fallback name
                profile_picture: senderDetails?.profile_picture || null
              }
            };

            // Persist to D1
            await env.D1_DB.prepare(
              "INSERT INTO messages (id, conversation_id, sender_id, content, message_type, media_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            ).bind(
                persistedMessage.id,
                persistedMessage.conversation_id,
                persistedMessage.sender_id,
                persistedMessage.content,
                persistedMessage.message_type,
                persistedMessage.media_url,
                persistedMessage.created_at,
                persistedMessage.updated_at
            ).run();

            await env.D1_DB.prepare(
              "UPDATE conversations SET last_message_at = ?, updated_at = ? WHERE id = ?"
            ).bind(now, now, conversationId).run();

            // Trigger broadcast via DO
            try {
              const doId = env.CONVERSATION_DO.idFromString(conversationId);
              const stub = env.CONVERSATION_DO.get(doId);
              const doBroadcastUrl = new URL(`/broadcast-message`, request.url.origin);

              ctx.waitUntil(stub.fetch(doBroadcastUrl.toString(), {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(persistedMessage)
              }));
            } catch(doError) {
                console.error(`Error calling DO for broadcast (ConvID: ${conversationId}): ${doError.message}`, doError.stack);
            }

            // Send Push Notifications from HTTP endpoint as well
            ctx.waitUntil((async () => {
                try {
                    const participantsResult = await env.D1_DB.prepare(
                        "SELECT user_id FROM conversation_participants WHERE conversation_id = ? AND user_id != ?"
                    ).bind(conversationId, userId).all();

                    if (participantsResult.results && participantsResult.results.length > 0) {
                        const senderName = senderDetails?.name || "Someone"; // Name fetched earlier for persistedMessage
                        for (const participant of participantsResult.results) {
                            const subscriptionsResult = await env.D1_DB.prepare(
                                "SELECT endpoint, keys_p256dh, keys_auth, user_id FROM push_subscriptions WHERE user_id = ?"
                            ).bind(participant.user_id).all();

                            if (subscriptionsResult.results) {
                                for (const sub of subscriptionsResult.results) {
                                    const pushPayload = JSON.stringify({
                                        title: "New Message",
                                        body: `${senderName}: ${content.substring(0,50)}${content.length > 50 ? '...' : ''}`, // use `content` from request body
                                        data: { conversationId: conversationId, messageId: persistedMessage.id }
                                    });
                                    await sendPushNotification(sub, pushPayload, env);
                                }
                            }
                        }
                    }
                } catch (pushError) {
                    console.error(`HTTP Endpoint Push Notification Error (ConvID: ${conversationId}): ${pushError.message}`, pushError.stack);
                }
            })());

            return jsonResponse(persistedMessage, 201);
          } catch (e) {
            console.error(`Error posting message to conversation ${conversationId}:`, e);
            return errorResponse("Failed to send message: " + e.message, 500);
          }
        }

        // GET /api/conversations/:conversationId/messages - Get all messages for a conversation
      if (request.method === "GET") {
        try {
          const { searchParams } = url;
          const limit = parseInt(searchParams.get("limit") || "50", 10);
          // `before` (timestamp or messageId for cursor pagination) can be added here later.
          // For now, simple limit offset (though offset not implemented, just latest N messages).

          const { results } = await env.D1_DB.prepare(
            `SELECT m.id, m.conversation_id, m.sender_id, m.content, m.message_type, m.media_url,
                    m.created_at, m.updated_at,
                    u.name as sender_name, u.profile_picture as sender_profile_picture
             FROM messages m
             JOIN users u ON m.sender_id = u.id
             WHERE m.conversation_id = ?
             ORDER BY m.created_at DESC
             LIMIT ?`
          ).bind(conversationId, limit).all();

          const messages = results.map(row => ({
            id: row.id,
            conversation_id: row.conversation_id,
            sender_id: row.sender_id,
            content: row.content,
            message_type: row.message_type,
            media_url: row.media_url,
            created_at: row.created_at,
            updated_at: row.updated_at,
            sender: {
              id: row.sender_id,
              name: row.sender_name,
              profile_picture: row.sender_profile_picture
            }
          }));
          return jsonResponse(messages);
        } catch (e) {
          console.error(`Error fetching messages for conversation ${conversationId}:`, e);
          return errorResponse("Failed to fetch messages: " + e.message, 500);
        }
      }
    }

    // Route for testing email sending functionality directly.
    // Requires MS_GRAPH_CLIENT_ID and MS_GRAPH_SENDING_USER_ID to be set in the environment.
    if (url.pathname === "/api/test-email") {
      if (!env.MS_GRAPH_CLIENT_ID || !env.MS_GRAPH_SENDING_USER_ID) {
        return new Response("MS Graph environment variables not configured for the test.", { status: 500 });
      }
      try {
        // IMPORTANT: Replace with a real email address you can check when testing
        const testEmailRecipient = "test-recipient@example.com";

        console.log(`Attempting to send test email to ${testEmailRecipient} via /api/test-email route.`);

        const success = await sendEmail(env, {
          to: testEmailRecipient,
          subject: "Test Email from Cloudflare Worker (MS Graph)",
          htmlBody: "<h1>Hello from the Test Route!</h1><p>This is a test email sent using the Microsoft Graph API service from your Cloudflare Worker.</p><p>If you received this, the service is working, but please ensure your secrets are correctly configured in the Cloudflare dashboard (MS_GRAPH_CLIENT_ID, MS_GRAPH_CLIENT_SECRET, MS_GRAPH_TENANT_ID, MS_GRAPH_SENDING_USER_ID).</p>"
        });

        if (success) {
          return new Response(JSON.stringify({ message: `Test email sent successfully to ${testEmailRecipient}. Check the inbox.` }), {
            headers: { "Content-Type": "application/json" },
            status: 200
          });
        } else {
          return new Response(JSON.stringify({ message: "Failed to send test email. Check worker logs for details." }), {
            headers: { "Content-Type": "application/json" },
            status: 500
          });
        }
      } catch (error) {
        console.error("Error in /api/test-email route:", error);
        return new Response(JSON.stringify({ message: "Error processing test email request.", error: error.message }), {
          headers: { "Content-Type": "application/json" },
          status: 500
        });
      }
    }

    // Fallback for routes not found
    // Admin API Endpoints for Third-Party Integrations
    const adminIntegrationsMatch = url.pathname.match(/^\/api\/admin\/integrations(?:\/(\d+))?$/);

    if (adminIntegrationsMatch) {
      if (!user) return errorResponse("Unauthorized", 401);
      // TODO: Add Admin Role Check here in the future.
      // For now, any authenticated user can access these admin routes.

      const integrationId = adminIntegrationsMatch[1] ? parseInt(adminIntegrationsMatch[1], 10) : null;

      try {
        // GET /api/admin/integrations
        if (request.method === "GET" && !integrationId) {
          const { results } = await env.D1_DB.prepare(
            "SELECT id, service_name, friendly_name, description, is_enabled, created_at, updated_at, " +
            "api_key_encrypted, client_id_encrypted, client_secret_encrypted, tenant_id_encrypted, other_config_encrypted " + // Select encrypted fields
            "FROM third_party_integrations"
          ).all();

          // Mask sensitive fields for listing
          const maskedResults = results.map(r => ({
              ...r,
              api_key_encrypted: r.api_key_encrypted ? "********" : null,
              client_id_encrypted: r.client_id_encrypted ? "********" : null,
              client_secret_encrypted: r.client_secret_encrypted ? "********" : null,
              tenant_id_encrypted: r.tenant_id_encrypted ? "********" : null,
              other_config_encrypted: r.other_config_encrypted ? "********" : null,
          }));
          return jsonResponse(maskedResults);
        }

        // POST /api/admin/integrations
        if (request.method === "POST" && !integrationId) {
          const body = await request.json();
          const { service_name, friendly_name, description, api_key, client_id, client_secret, tenant_id, other_config, is_enabled = false } = body;

          if (!service_name || !api_key) {
            return errorResponse("Service name and API key are required.", 400);
          }

          const apiKeyEnc = await encrypt(api_key, env);
          const clientIdEnc = await encrypt(client_id, env);
          const clientSecretEnc = await encrypt(client_secret, env);
          const tenantIdEnc = await encrypt(tenant_id, env);
          const otherConfigEnc = other_config ? await encrypt(JSON.stringify(other_config), env) : null;
          const now = new Date().toISOString();

          const { meta } = await env.D1_DB.prepare(
            "INSERT INTO third_party_integrations (service_name, friendly_name, description, api_key_encrypted, client_id_encrypted, client_secret_encrypted, tenant_id_encrypted, other_config_encrypted, is_enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(service_name, friendly_name, description, apiKeyEnc, clientIdEnc, clientSecretEnc, tenantIdEnc, otherConfigEnc, is_enabled ? 1 : 0, now, now).run();

          const lastId = meta.last_row_id;
          return jsonResponse({
              id: lastId, service_name, friendly_name, description, is_enabled, created_at: now, updated_at: now,
              api_key_encrypted: apiKeyEnc ? "********" : null, // Return masked
              client_id_encrypted: clientIdEnc ? "********" : null,
              client_secret_encrypted: clientSecretEnc ? "********" : null,
              tenant_id_encrypted: tenantIdEnc ? "********" : null,
              other_config_encrypted: otherConfigEnc ? "********" : null,
          }, 201);
        }

        // PUT /api/admin/integrations/:integrationId
        if (request.method === "PUT" && integrationId) {
          const body = await request.json();

          const existingIntegration = await env.D1_DB.prepare("SELECT * FROM third_party_integrations WHERE id = ?").bind(integrationId).first();
          if (!existingIntegration) return errorResponse("Integration not found.", 404);

          const updates = {};
          const params = [];

          if (body.service_name) { updates.service_name = body.service_name; }
          if (body.friendly_name) { updates.friendly_name = body.friendly_name; }
          if (body.description) { updates.description = body.description; }
          if (typeof body.is_enabled === 'boolean') { updates.is_enabled = body.is_enabled ? 1 : 0; }

          if (body.api_key) { updates.api_key_encrypted = await encrypt(body.api_key, env); }
          if (body.client_id) { updates.client_id_encrypted = await encrypt(body.client_id, env); }
          if (body.client_secret) { updates.client_secret_encrypted = await encrypt(body.client_secret, env); }
          if (body.tenant_id) { updates.tenant_id_encrypted = await encrypt(body.tenant_id, env); }
          if (body.other_config) { updates.other_config_encrypted = await encrypt(JSON.stringify(body.other_config), env); }

          updates.updated_at = new Date().toISOString();

          const setClauses = Object.keys(updates).map(key => `${key} = ?`).join(", ");
          if (setClauses.length === 0) return errorResponse("No update fields provided", 400);

          const queryParams = [...Object.values(updates), integrationId];
          await env.D1_DB.prepare(`UPDATE third_party_integrations SET ${setClauses} WHERE id = ?`).bind(...queryParams).run();

          const updatedIntegration = await env.D1_DB.prepare("SELECT * FROM third_party_integrations WHERE id = ?").bind(integrationId).first();
          return jsonResponse({
              ...updatedIntegration,
              api_key_encrypted: updatedIntegration.api_key_encrypted ? "********" : null,
              client_id_encrypted: updatedIntegration.client_id_encrypted ? "********" : null,
              client_secret_encrypted: updatedIntegration.client_secret_encrypted ? "********" : null,
              tenant_id_encrypted: updatedIntegration.tenant_id_encrypted ? "********" : null,
              other_config_encrypted: updatedIntegration.other_config_encrypted ? "********" : null,
          });
        }

        // DELETE /api/admin/integrations/:integrationId
        if (request.method === "DELETE" && integrationId) {
          const { meta } = await env.D1_DB.prepare("DELETE FROM third_party_integrations WHERE id = ?").bind(integrationId).run();
          if (meta.changes === 0) return errorResponse("Integration not found or already deleted.", 404);
          return new Response(null, { status: 204 });
        }
      } catch (e) {
        console.error("Error in admin integrations API:", e);
        if (e.message.includes("ENCRYPTION_KEY")) return errorResponse(e.message, 500); // Specific error for key issue
        return errorResponse("An error occurred: " + e.message, 500);
      }
    }

    // Admin API Endpoints for Seasonal Themes
    const adminThemesMatch = url.pathname.match(/^\/api\/admin\/themes(?:\/(\d+))?$/);
    if (adminThemesMatch) {
      if (!user) return errorResponse("Unauthorized", 401);
      // TODO: Add Admin Role Check here

      const themeId = adminThemesMatch[1] ? parseInt(adminThemesMatch[1], 10) : null;
      const now = new Date().toISOString();

      try {
        // GET /api/admin/themes
        if (request.method === "GET" && !themeId) {
          const { results } = await env.D1_DB.prepare("SELECT * FROM seasonal_themes ORDER BY start_date DESC").all();
          return jsonResponse(results);
        }

        // POST /api/admin/themes
        if (request.method === "POST" && !themeId) {
          const body = await request.json();
          const { name, description, start_date, end_date, theme_config_json, is_active = false } = body;

          if (!name) return errorResponse("Theme name is required.", 400);
          if (theme_config_json) {
            try { JSON.parse(theme_config_json); } catch (e) { return errorResponse("theme_config_json is not valid JSON.", 400); }
          }
          if (start_date && !/^\d{4}-\d{2}-\d{2}$/.test(start_date)) return errorResponse("start_date must be in YYYY-MM-DD format.", 400);
          if (end_date && !/^\d{4}-\d{2}-\d{2}$/.test(end_date)) return errorResponse("end_date must be in YYYY-MM-DD format.", 400);

          if (is_active) { // If setting this theme to active, deactivate others
            await env.D1_DB.prepare("UPDATE seasonal_themes SET is_active = 0 WHERE is_active = 1").run();
          }

          const { meta } = await env.D1_DB.prepare(
            "INSERT INTO seasonal_themes (name, description, start_date, end_date, theme_config_json, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(name, description, start_date, end_date, theme_config_json, is_active ? 1 : 0, now, now).run();

          const lastId = meta.last_row_id;
          const newTheme = await env.D1_DB.prepare("SELECT * FROM seasonal_themes WHERE id = ?").bind(lastId).first();
          return jsonResponse(newTheme, 201);
        }

        // GET /api/admin/themes/:themeId (Specific theme - useful for fetching before PUT)
        if (request.method === "GET" && themeId) {
            const theme = await env.D1_DB.prepare("SELECT * FROM seasonal_themes WHERE id = ?").bind(themeId).first();
            if (!theme) return errorResponse("Theme not found", 404);
            return jsonResponse(theme);
        }

        // PUT /api/admin/themes/:themeId
        if (request.method === "PUT" && themeId) {
          const body = await request.json();
          const existingTheme = await env.D1_DB.prepare("SELECT * FROM seasonal_themes WHERE id = ?").bind(themeId).first();
          if (!existingTheme) return errorResponse("Theme not found.", 404);

          const updates = {};
          if (body.name) updates.name = body.name;
          if (body.description !== undefined) updates.description = body.description; // Allow setting to null
          if (body.start_date !== undefined) {
            if (body.start_date !== null && !/^\d{4}-\d{2}-\d{2}$/.test(body.start_date)) return errorResponse("start_date must be in YYYY-MM-DD format or null.", 400);
            updates.start_date = body.start_date;
          }
          if (body.end_date !== undefined) {
            if (body.end_date !== null && !/^\d{4}-\d{2}-\d{2}$/.test(body.end_date)) return errorResponse("end_date must be in YYYY-MM-DD format or null.", 400);
            updates.end_date = body.end_date;
          }
          if (body.theme_config_json !== undefined) {
            if (body.theme_config_json !== null) {
                try { JSON.parse(body.theme_config_json); } catch (e) { return errorResponse("theme_config_json is not valid JSON.", 400); }
            }
            updates.theme_config_json = body.theme_config_json;
          }
          if (typeof body.is_active === 'boolean') {
            if (body.is_active && !existingTheme.is_active) { // If activating this theme
              await env.D1_DB.prepare("UPDATE seasonal_themes SET is_active = 0 WHERE is_active = 1 AND id != ?").bind(themeId).run();
            }
            updates.is_active = body.is_active ? 1 : 0;
          }

          if (Object.keys(updates).length === 0) return errorResponse("No update fields provided.", 400);
          updates.updated_at = now;

          const setClauses = Object.keys(updates).map(key => `${key} = ?`).join(", ");
          const queryParams = [...Object.values(updates), themeId];

          await env.D1_DB.prepare(`UPDATE seasonal_themes SET ${setClauses} WHERE id = ?`).bind(...queryParams).run();
          const updatedTheme = await env.D1_DB.prepare("SELECT * FROM seasonal_themes WHERE id = ?").bind(themeId).first();
          return jsonResponse(updatedTheme);
        }

        // DELETE /api/admin/themes/:themeId
        if (request.method === "DELETE" && themeId) {
          const { meta } = await env.D1_DB.prepare("DELETE FROM seasonal_themes WHERE id = ?").bind(themeId).run();
          if (meta.changes === 0) return errorResponse("Theme not found or already deleted.", 404);
          return new Response(null, { status: 204 });
        }
      } catch (e) {
        console.error("Error in admin themes API:", e);
        return errorResponse("An error occurred: " + e.message, 500);
      }
    }

    // Admin API Endpoints for Email Templates
    const adminEmailTemplatesMatch = url.pathname.match(/^\/api\/admin\/email-templates(?:\/([a-zA-Z0-9_-]+))?$/);
    if (adminEmailTemplatesMatch) {
        if (!user) return errorResponse("Unauthorized", 401);
        // TODO: Add Admin Role Check here in a future task

        const templateNameParam = adminEmailTemplatesMatch[1]; // This will be the template_name
        const now = new Date().toISOString();

        try {
            // GET /api/admin/email-templates
            if (request.method === "GET" && !templateNameParam) {
                const { results } = await env.D1_DB.prepare("SELECT * FROM email_templates ORDER BY template_name").all();
                return jsonResponse(results);
            }

            // GET /api/admin/email-templates/:templateName
            if (request.method === "GET" && templateNameParam) {
                const template = await env.D1_DB.prepare("SELECT * FROM email_templates WHERE template_name = ?").bind(templateNameParam).first();
                if (!template) return errorResponse("Email template not found.", 404);
                return jsonResponse(template);
            }

            // POST /api/admin/email-templates
            if (request.method === "POST" && !templateNameParam) {
                const body = await request.json();
                const { template_name, subject_template, body_html_template, default_sender_name, default_sender_email } = body;

                if (!template_name || !subject_template || !body_html_template) {
                    return errorResponse("template_name, subject_template, and body_html_template are required.", 400);
                }

                try {
                    const { meta } = await env.D1_DB.prepare(
                        "INSERT INTO email_templates (template_name, subject_template, body_html_template, default_sender_name, default_sender_email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
                    ).bind(template_name, subject_template, body_html_template, default_sender_name, default_sender_email, now, now).run();

                    const newTemplate = { id: meta.last_row_id, template_name, subject_template, body_html_template, default_sender_name, default_sender_email, created_at: now, updated_at: now };
                    return jsonResponse(newTemplate, 201);
                } catch (e) {
                    if (e.message.includes("UNIQUE constraint failed")) {
                        return errorResponse("An email template with this name already exists.", 409);
                    }
                    throw e; // Re-throw other DB errors
                }
            }

            // PUT /api/admin/email-templates/:templateName
            if (request.method === "PUT" && templateNameParam) {
                const body = await request.json();
                const existingTemplate = await env.D1_DB.prepare("SELECT id FROM email_templates WHERE template_name = ?").bind(templateNameParam).first();
                if (!existingTemplate) return errorResponse("Email template not found.", 404);

                const updates = {};
                if (body.subject_template !== undefined) updates.subject_template = body.subject_template;
                if (body.body_html_template !== undefined) updates.body_html_template = body.body_html_template;
                if (body.default_sender_name !== undefined) updates.default_sender_name = body.default_sender_name;
                if (body.default_sender_email !== undefined) updates.default_sender_email = body.default_sender_email;
                // template_name cannot be changed as it's the identifier in URL

                if (Object.keys(updates).length === 0) return errorResponse("No update fields provided.", 400);
                updates.updated_at = now;

                const setClauses = Object.keys(updates).map(key => `${key} = ?`).join(", ");
                const queryParams = [...Object.values(updates), templateNameParam];

                await env.D1_DB.prepare(`UPDATE email_templates SET ${setClauses} WHERE template_name = ?`).bind(...queryParams).run();
                const updatedTemplate = await env.D1_DB.prepare("SELECT * FROM email_templates WHERE template_name = ?").bind(templateNameParam).first();
                return jsonResponse(updatedTemplate);
            }

            // DELETE /api/admin/email-templates/:templateName
            if (request.method === "DELETE" && templateNameParam) {
                const { meta } = await env.D1_DB.prepare("DELETE FROM email_templates WHERE template_name = ?").bind(templateNameParam).run();
                if (meta.changes === 0) return errorResponse("Email template not found or already deleted.", 404);
                return new Response(null, { status: 204 });
            }
        } catch (e) {
            console.error("Error in admin email templates API:", e);
            return errorResponse("An error occurred: " + e.message, 500);
        }
    }


    // Push Notification Subscription Endpoints
    if (url.pathname === "/api/notifications/subscribe" && request.method === "POST") {
      if (!user) return errorResponse("Unauthorized", 401);
      try {
        const body = await request.json();
        const { subscription } = body;

        if (!subscription || !subscription.endpoint || !subscription.keys || !subscription.keys.p256dh || !subscription.keys.auth) {
          return errorResponse("Invalid subscription object provided.", 400);
        }

        // Use INSERT OR IGNORE to handle potential duplicate entries gracefully based on UNIQUE constraint
        const { success, meta } = await env.D1_DB.prepare(
          "INSERT OR IGNORE INTO push_subscriptions (user_id, endpoint, keys_p256dh, keys_auth) VALUES (?, ?, ?, ?)"
        ).bind(user.userId, subscription.endpoint, subscription.keys.p256dh, subscription.keys.auth).run();

        if (!success) { // Should not happen with D1 if query is valid, but good practice
            return errorResponse("Failed to store subscription.", 500);
        }

        // meta.changes will be 0 if the record was ignored (already exists), 1 if inserted.
        if (meta.changes > 0) {
            return jsonResponse({ message: "Subscription saved successfully." }, 201);
        } else {
            return jsonResponse({ message: "Subscription already exists." }, 200);
        }

      } catch (e) {
        console.error("Error subscribing for push notifications:", e);
        return errorResponse("Failed to subscribe: " + e.message, 500);
      }
    }

    if (url.pathname === "/api/notifications/unsubscribe" && request.method === "POST") {
      if (!user) return errorResponse("Unauthorized", 401);
      try {
        const body = await request.json();
        const { endpoint } = body;

        if (!endpoint) {
          return errorResponse("Endpoint is required to unsubscribe.", 400);
        }

        const { meta } = await env.D1_DB.prepare(
          "DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?"
        ).bind(user.userId, endpoint).run();

        if (meta.changes > 0) {
          return jsonResponse({ message: "Unsubscribed successfully." }, 200);
        } else {
          return jsonResponse({ message: "Subscription not found or already unsubscribed." }, 404);
        }
      } catch (e) {
        console.error("Error unsubscribing from push notifications:", e);
        return errorResponse("Failed to unsubscribe: " + e.message, 500);
      }
    }

    // Microsoft Graph User Authentication OAuth Endpoints
    if (url.pathname === "/auth/microsoft/initiate") {
      if (!user) return errorResponse("User not authenticated", 401);

      try {
        const msGraphApp = await env.D1_DB.prepare(
            "SELECT client_id, tenant_id_encrypted FROM third_party_integrations WHERE service_name = 'MicrosoftGraphDelegated' AND is_enabled = 1"
        ).first();

        if (!msGraphApp || !msGraphApp.client_id) {
            return errorResponse("Microsoft Graph (Delegated) integration not configured or disabled.", 500);
        }

        const clientId = msGraphApp.client_id; // Not encrypted as per schema assumption
        const tenantId = msGraphApp.tenant_id_encrypted ? await decrypt(msGraphApp.tenant_id_encrypted, env) : 'common';

        const state = crypto.randomUUID(); // Simple CSRF token
        // Store state in a temporary way, e.g., KV store with TTL, or a cookie if frontend can handle it.
        // For this example, we'll assume a cookie (though direct cookie setting in API might be tricky depending on setup)
        // Or, for workers, maybe a short-lived KV entry: await env.STATE_KV.put(`ms_oauth_state_${state}`, user.userId, { expirationTtl: 300 });
        // For now, let's just generate it and expect client to pass it back. A real app needs secure state handling.
        // A simple cookie approach (ensure HttpOnly and Secure in production worker):
        const stateCookie = `ms_oauth_state=${state}; Path=/; Max-Age=300; HttpOnly; Secure; SameSite=Lax`;


        const redirectUri = `${new URL(request.url).origin}/auth/microsoft/callback`;
        const scope = "openid profile email offline_access Calendars.ReadWrite User.Read";

        const authUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?` +
          `client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=${encodeURIComponent(scope)}&state=${state}&response_mode=query`;

        const headers = new Headers({ 'Location': authUrl });
        // If using cookies for state, add Set-Cookie header
        headers.append('Set-Cookie', stateCookie);

        return new Response(null, { status: 302, headers });

      } catch (e) {
        console.error("Error initiating MS Graph auth:", e);
        return errorResponse("Failed to initiate Microsoft authentication: " + e.message, 500);
      }
    }

    if (url.pathname === "/auth/microsoft/callback") {
      // This is the redirect URI path
      const code = url.searchParams.get("code");
      const stateParam = url.searchParams.get("state");
      const error = url.searchParams.get("error");
      const errorDescription = url.searchParams.get("error_description");

      if (error) {
        console.error(`MS Graph OAuth Error: ${error} - ${errorDescription}`);
        return errorResponse(`Microsoft Authentication Error: ${errorDescription || error}`, 400);
      }

      if (!code) return errorResponse("Missing authorization code from Microsoft.", 400);

      // TODO: Validate state parameter against stored state (e.g., from cookie or KV)
      // const storedState = request.headers.get('Cookie')?.match(/ms_oauth_state=([^;]+)/)?.[1];
      // if (!stateParam || stateParam !== storedState) {
      //   return errorResponse("Invalid state parameter. CSRF attempt?", 400);
      // }
      // Clear the state cookie/KV entry after validation.

      // The `user` object (authenticated app user) is not directly available here as it's a redirect.
      // If you stored user.userId with the state, retrieve it here. For now, assume we need to link it.
      // For this example, we'll assume the user is already logged into our app and we can get their ID
      // via the main app session (which `getUser` would normally handle if this wasn't a redirect).
      // This part is tricky without a session mechanism tied to the OAuth flow itself.
      // A common pattern is to have the state parameter also encode the user's session ID or use a short-lived mapping.
      // For now, we'll proceed as if `user.userId` is available (e.g. if state validation linked it back).
      // This needs a robust solution in a real app, possibly by redirecting to a logged-in page that makes this call.
      // Let's assume for now, the user.userId will be derived from the 'state' or a prior session.
      // For this subtask, we'll acknowledge this complexity and proceed with a placeholder for userId.
      // A real implementation might require user to be logged into the app first, then link account.
      // The `user` from `getUser(request, env)` might be null here.
      // We need a way to associate this callback with an existing app user.
      // The state parameter is critical for this.
      // Let's assume for now: this callback is hit by a user who IS logged in to our app.
      // This means the JWT for our app would need to be present or some other session identifier.
      // If not, we need to handle this as potentially linking to a new or existing user based on email from MS.

      // Let's assume the `user` object *is* available because the callback is part of an authenticated session.
      // This would be true if the initial /auth/microsoft/initiate was done by an authenticated user
      // and the browser maintained that session.
  if (!user && url.pathname !== "/auth/microsoft/callback") { // Allow callback to proceed without initial user for now
        // This condition might need refinement based on how user context is established for the callback
        // For other protected MS Graph routes, user would be required.
  } else if (url.pathname.startsWith("/api/me/") && !user) { // Example of protecting other /api/me routes
     return errorResponse("Unauthorized for MS Graph user data", 401);
  }
  // const appUserId = user ? user.userId : null; // Handle cases where user might not be strictly required for the callback itself.

  // For the MS OAuth callback, the user context needs to be established carefully.
  // If the state parameter correctly links back to an app session, user.userId can be retrieved.
  // For this example, we'll proceed assuming `user.userId` is available if needed,
  // acknowledging the complexity for the callback itself.
  const appUserId = user ? user.userId : null;


      try {
        const msGraphApp = await env.D1_DB.prepare(
            "SELECT client_id, client_secret_encrypted, tenant_id_encrypted FROM third_party_integrations WHERE service_name = 'MicrosoftGraphDelegated' AND is_enabled = 1"
        ).first();

        if (!msGraphApp || !msGraphApp.client_id || !msGraphApp.client_secret_encrypted) {
            return errorResponse("Microsoft Graph (Delegated) integration not configured or disabled for token exchange.", 500);
        }

        const clientId = msGraphApp.client_id;
        const clientSecret = await decrypt(msGraphApp.client_secret_encrypted, env);
        const tenantId = msGraphApp.tenant_id_encrypted ? await decrypt(msGraphApp.tenant_id_encrypted, env) : 'common';

        const redirectUri = `${new URL(request.url).origin}/auth/microsoft/callback`;
        const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;

        const params = new URLSearchParams();
        params.append('client_id', clientId);
        params.append('scope', "openid profile email offline_access Calendars.ReadWrite User.Read");
        params.append('code', code);
        params.append('redirect_uri', redirectUri);
        params.append('grant_type', 'authorization_code');
        params.append('client_secret', clientSecret);

        const tokenResponse = await fetch(tokenUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params.toString()
        });

        if (!tokenResponse.ok) {
            const errorData = await tokenResponse.text();
            console.error("MS Graph token exchange error:", errorData);
            return errorResponse(`Failed to exchange code for token: ${tokenResponse.status} - ${errorData}`, 500);
        }
        const tokens = await tokenResponse.json();

        // Get MS Graph User ID (/me)
        const meResponse = await fetch("https://graph.microsoft.com/v1.0/me", {
            headers: { 'Authorization': `Bearer ${tokens.access_token}` }
        });
        if (!meResponse.ok) {
            const errorData = await meResponse.text();
            return errorResponse(`Failed to fetch MS Graph user profile: ${meResponse.status} - ${errorData}`, 500);
        }
        const msGraphUser = await meResponse.json();
        const msGraphUserId = msGraphUser.id;
        // const msGraphUserEmail = msGraphUser.mail || msGraphUser.userPrincipalName;
        // Here you might want to check if msGraphUserEmail matches user.email from your app's session for extra security.

        const accessTokenEnc = await encrypt(tokens.access_token, env);
        const refreshTokenEnc = await encrypt(tokens.refresh_token, env);
        const expiryMs = Date.now() + (tokens.expires_in * 1000);
        const scopes = tokens.scope; // Granted scopes
        const nowISO = new Date().toISOString();

        // INSERT OR REPLACE logic for D1 (SQLite)
        // user_id is UNIQUE, so ON CONFLICT will replace the entire row if user_id matches.
        await env.D1_DB.prepare(
          "INSERT INTO user_ms_graph_tokens (user_id, ms_graph_user_id, access_token_encrypted, refresh_token_encrypted, token_expiry_timestamp_ms, scopes, created_at, updated_at) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT(user_id) DO UPDATE SET " +
          "ms_graph_user_id = excluded.ms_graph_user_id, access_token_encrypted = excluded.access_token_encrypted, refresh_token_encrypted = excluded.refresh_token_encrypted, " +
          "token_expiry_timestamp_ms = excluded.token_expiry_timestamp_ms, scopes = excluded.scopes, updated_at = excluded.updated_at"
        ).bind(appUserId, msGraphUserId, accessTokenEnc, refreshTokenEnc, expiryMs, scopes, nowISO, nowISO).run();

        // Redirect to a frontend page indicating success
        return Response.redirect(`${new URL(request.url).origin}/settings?ms_graph_linked=true`, 302);

      } catch (e) {
        console.error("Error in MS Graph OAuth callback:", e);
        if (e.message.includes("ENCRYPTION_KEY")) return errorResponse(e.message, 500);
        return errorResponse("Failed to process Microsoft authentication callback: " + e.message, 500);
      }
    }

    // Admin Test Harness API Endpoints
    if (url.pathname === "/api/admin/test-harness/verify-pin" && request.method === "POST") {
      if (!user) return errorResponse("Unauthorized", 401);
      // TODO: Add specific Admin Role Check if available in `user` object in future
      // if (!user.roles || !user.roles.includes('admin')) return errorResponse("Forbidden", 403);

      try {
        const requestData = await request.json();
        if (!requestData || typeof requestData.pin !== 'string' || requestData.pin.length === 0) {
          return errorResponse("PIN is required and must be a non-empty string.", 400);
        }

        const storedPin = await env.D1_DB.prepare("SELECT pin_hash FROM admin_test_access WHERE id = 1").first();
        if (!storedPin || !storedPin.pin_hash) {
          return errorResponse("Admin PIN not configured in the system.", 500);
        }

        const hashedPinFromRequest = await hashPin(requestData.pin);

        if (hashedPinFromRequest === storedPin.pin_hash) {
          // Optional: Could issue a short-lived token here for subsequent test harness actions
          return jsonResponse({ verified: true, message: "PIN verified successfully." });
        } else {
          return errorResponse("Invalid PIN.", 403);
        }
      } catch (e) {
        console.error("Error in /api/admin/test-harness/verify-pin:", e);
        if (e.message === 'PIN must be a non-empty string.') return errorResponse(e.message, 400);
        return errorResponse("An error occurred during PIN verification: " + e.message, 500);
      }
    }

    if (url.pathname === "/api/admin/test-harness/db/initialize" && request.method === "POST") {
      if (!user) return errorResponse("Unauthorized", 401);
      // TODO: Add specific Admin Role Check
      // if (!user.roles || !user.roles.includes('admin')) return errorResponse("Forbidden", 403);
      // Optional: Check for recent PIN verification if a mechanism for that exists

      try {
        const sampleSeedSql = `
          INSERT OR IGNORE INTO email_templates (template_name, subject_template, body_html_template, default_sender_name, default_sender_email, created_at, updated_at) VALUES ('test_harness_template_1', 'Test Harness Subject 1', '<p>Test Body 1 for {{name}} from Test Harness</p>', 'Test Harness Sender', 'test@example.com', datetime('now'), datetime('now'));
          INSERT OR IGNORE INTO seasonal_themes (name, description, start_date, end_date, theme_config_json, is_active, created_at, updated_at) VALUES ('TestHarnessTheme1', 'A test theme initialized by the test harness', date('now'), date('now', '+1 month'), '{"primaryColor":"#BADA55", "font":"Arial"}', 0, datetime('now'), datetime('now'));
          -- Add a dummy user for testing relations, if password_hash is not nullable, provide one.
          -- INSERT OR IGNORE INTO users (id, name, email, password_hash) VALUES ('test-harness-user-01', 'Test Harness User', 'test-harness@example.com', 'dummy_hash_for_test_user');
        `;

        // Note: D1's exec() can run multiple statements separated by semicolons.
        const result = await env.D1_DB.exec(sampleSeedSql);

        if (result.error) {
          console.error("DB Initialization via test harness failed:", result.error);
          return errorResponse(`DB Initialization failed: ${result.error}`, 500);
        }

        // D1 exec() result object for multiple statements might not give individual counts easily.
        // It gives { count: number_of_statements_executed, duration: time_in_ms }
        // We assume success if no error is thrown.
        return jsonResponse({
          success: true,
          message: "Sample database initialization executed successfully.",
          statements_executed: result.count, // Number of statements D1 attempted
          duration: result.duration
        });

      } catch (e) {
        console.error("Error in /api/admin/test-harness/db/initialize:", e);
        return errorResponse("An error occurred during DB initialization: " + e.message, 500);
      }
    }

    }

    // Admin Test Harness - Part 2: Test Token Generation & User Creation
    if (url.pathname === "/api/admin/test-harness/generate-test-token" && request.method === "POST") {
      if (!user) return errorResponse("Unauthorized", 401);
      // TODO: Add specific Admin Role Check

      try {
        const requestData = await request.json();
        const { userId: targetUserId, role: requestedRole, expiresInMinutes } = requestData;

        if (!targetUserId || typeof targetUserId !== 'string') {
          return errorResponse("Target userId is required and must be a string.", 400);
        }

        const targetUser = await env.D1_DB.prepare("SELECT email FROM users WHERE id = ?").bind(targetUserId).first();
        if (!targetUser) {
          return errorResponse("Target user not found.", 404);
        }

        const minutes = parseInt(expiresInMinutes) || 10; // Default to 10 minutes
        const expiration = Math.floor(Date.now() / 1000) + (minutes * 60);

        const payload = {
          userId: targetUserId,
          email: targetUser.email,
          // role: requestedRole || targetUser.role, // Uncomment and adapt if users.role exists
          exp: expiration,
          jti: crypto.randomUUID(),
          isTestToken: true // Special claim for test tokens
        };

        const testToken = await signToken(payload, env.JWT_SECRET);
        return jsonResponse({ userId: targetUserId, testToken: testToken, expiresAt: new Date(expiration * 1000).toISOString() });

      } catch (e) {
        console.error("Error in /api/admin/test-harness/generate-test-token:", e);
        return errorResponse("An error occurred during test token generation: " + e.message, 500);
      }
    }

    if (url.pathname === "/api/admin/test-harness/create-test-user" && request.method === "POST") {
      if (!user) return errorResponse("Unauthorized", 401);
      // TODO: Add specific Admin Role Check

      try {
        const requestData = await request.json();
        const { name, email, password, role: requestedRole } = requestData; // role is optional for now

        if (!name || typeof name !== 'string' || name.trim() === "") {
          return errorResponse("User name is required.", 400);
        }
        if (!email || typeof email !== 'string' || !email.includes('@')) { // Basic email validation
          return errorResponse("A valid email is required.", 400);
        }
        if (!password || typeof password !== 'string' || password.length < 6) { // Basic password length
          return errorResponse("Password is required and must be at least 6 characters.", 400);
        }

        const hashedPassword = await hashPassword(password);
        const newUserId = crypto.randomUUID().replace(/-/g, ''); // Generate UUID for user ID, matching schema

        // Assuming 'users' table does NOT have a 'role' column yet, per subtask self-correction.
        // If 'role' column is added later, this SQL and binding needs to be updated.
        await env.D1_DB.prepare(
          "INSERT INTO users (id, name, email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))"
        ).bind(newUserId, name, email, hashedPassword).run();

        // Log the audit event
        // Assuming `user.userId` is the ID of the admin performing the action
        await logAuditEvent(env, request, 'create_test_user', user.userId, 'user', newUserId, 'success', { testUserName: name, testUserEmail: email });

        return jsonResponse({ message: "Test user created successfully.", userId: newUserId, email: email }, 201);

      } catch (e) {
        console.error("Error in /api/admin/test-harness/create-test-user:", e);
        if (e.message && e.message.toLowerCase().includes("unique constraint failed: users.email")) {
          return errorResponse("Email already exists.", 409);
        }
        if (e.message && e.message.toLowerCase().includes("unique constraint failed: users.id")) {
          // Extremely unlikely with UUIDs but good to be aware of
          return errorResponse("User ID generation conflict. Please try again.", 500);
        }
        return errorResponse("An error occurred during test user creation: " + e.message, 500);
      }
    }

    return errorResponse("Not Found", 404);
  },
};
export { MyDurableObject, ConversationDurableObject, VideoCallSignalingDO };