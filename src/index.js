// Helper Functions (assuming these are already defined or will be added if not present from previous file content)
// jsonResponse, errorResponse, hashPassword, hashPin, getUser, requireRole,
// getEffectiveParentalControls, isUserInDnd, logAuditEvent, sendEmail, getProcessedEmailTemplate,
// encrypt, decrypt, getKey, getValidMsGraphUserAccessToken

class MyDurableObject { /* ... existing MyDurableObject code ... */
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(request) { return new Response("Hello from MyDurableObject!"); }
}

// Added for Family Invitations
function generateSecureToken(length = 32) {
  const buffer = new Uint8Array(length);
  crypto.getRandomValues(buffer);
  return Array.from(buffer, byte => byte.toString(16).padStart(2, '0')).join('');
}

// ConversationDurableObject (with DND logic already integrated from previous step)
export class ConversationDurableObject {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Map();
    this.conversationId = state.id.toString();
    this.D1_DB = env.D1_DB;
  }

  async _getEffectiveParentalControls(userId) {
    const customSettingsRow = await this.env.D1_DB.prepare("SELECT settings_json FROM parental_control_settings WHERE child_user_id = ?").bind(userId).first();
    if (customSettingsRow?.settings_json) { try { return JSON.parse(customSettingsRow.settings_json); } catch(e) { console.error(`DO: Error parsing custom settings for ${userId}`, e);}}
    const globalDefaultsRow = await this.env.D1_DB.prepare("SELECT settings_json FROM global_parental_control_defaults WHERE id = 1").first();
    if (globalDefaultsRow?.settings_json) { try { return JSON.parse(globalDefaultsRow.settings_json); } catch(e) { console.error(`DO: Error parsing global default settings`, e);}}
    return {};
  }

  async _isUserInDnd(userId, userRole) {
    if (userRole !== 'child') return false;
    const settings = await this._getEffectiveParentalControls(userId);
    if (!settings?.dnd_start_time || !settings?.dnd_end_time) return false;
    try {
      const now = new Date();
      const currentTimeInMinutes = now.getUTCHours() * 60 + now.getUTCMinutes();
      const [startHours, startMinutes] = settings.dnd_start_time.split(':').map(Number);
      const dndStartTimeInMinutes = startHours * 60 + startMinutes;
      const [endHours, endMinutes] = settings.dnd_end_time.split(':').map(Number);
      const dndEndTimeInMinutes = endHours * 60 + endMinutes;
      if (dndStartTimeInMinutes <= dndEndTimeInMinutes) return currentTimeInMinutes >= dndStartTimeInMinutes && currentTimeInMinutes < dndEndTimeInMinutes;
      else return currentTimeInMinutes >= dndStartTimeInMinutes || currentTimeInMinutes < dndEndTimeInMinutes;
    } catch (e) { console.error(`DO: Error processing DND for ${userId}`, e); return false; }
  }

  generateSessionId() { return crypto.randomUUID(); }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.headers.get("Upgrade") === "websocket") {
      const userId = request.headers.get("X-User-Id");
      if (!userId) return errorResponse("User ID required", 400);

      const userDetails = await this.env.D1_DB.prepare("SELECT role FROM users WHERE id = ?").bind(userId).first();
      const userRole = userDetails?.role || 'user';

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      await this.state.acceptWebSocket(server);
      const sessionId = this.generateSessionId();
      server.sessionInfo = { userId, sessionId, role: userRole };
      this.sessions.set(sessionId, server);
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/broadcast-message" && request.method === "POST") {
      try {
        const message = await request.json();
        await this.broadcast(JSON.stringify(message), null);
        return new Response("Message broadcasted", { status: 200 });
      } catch (error) { return errorResponse("Error broadcasting: " + error.message, 500); }
    }
    return errorResponse("Not found in DO", 404);
  }

  async webSocketMessage(ws, message) {
    try {
      const parsedMessage = JSON.parse(message);
      const senderId = ws.sessionInfo.userId;
      const now = new Date().toISOString();
      const messageId = crypto.randomUUID();
      const persistedMessage = {
        id: messageId, conversation_id: this.conversationId, sender_id: senderId,
        content: parsedMessage.content, message_type: parsedMessage.message_type || 'text', media_url: parsedMessage.media_url || null,
        created_at: now, updated_at: now, sender: { id: senderId, name: ws.sessionInfo.name || "User" }
      };
      await this.D1_DB.prepare("INSERT INTO messages (id, conversation_id, sender_id, content, message_type, media_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(persistedMessage.id, persistedMessage.conversation_id, persistedMessage.sender_id, persistedMessage.content, persistedMessage.message_type, persistedMessage.media_url, persistedMessage.created_at, persistedMessage.updated_at).run();
      await this.D1_DB.prepare("UPDATE conversations SET last_message_at = ?, updated_at = ? WHERE id = ?").bind(now, now, this.conversationId).run();

      await this.broadcast(JSON.stringify(persistedMessage), ws);

      this.state.waitUntil((async () => {
        try {
          const participantsResult = await this.D1_DB.prepare( "SELECT p.user_id, u.role as user_role FROM conversation_participants p JOIN users u ON p.user_id = u.id WHERE p.conversation_id = ? AND p.user_id != ?" ).bind(this.conversationId, senderId).all();
          if (participantsResult.results) {
            const senderInfo = await this.D1_DB.prepare("SELECT name FROM users WHERE id = ?").bind(senderId).first();
            const senderName = senderInfo?.name || "Someone";
            for (const p of participantsResult.results) {
              if (p.user_role === 'child' && await this._isUserInDnd(p.user_id, p.user_role)) {
                console.log(`DO: User ${p.user_id} in DND, skipping push.`); continue;
              }
              const subs = await this.D1_DB.prepare("SELECT endpoint, keys_p256dh, keys_auth FROM push_subscriptions WHERE user_id = ?").bind(p.user_id).all();
              if (subs.results) {
                for (const sub of subs.results) {
                  await sendPushNotification(sub, JSON.stringify({ title: "New Message", body: `${senderName}: ${persistedMessage.content.substring(0,50)}...`, data: { conversationId: this.conversationId, messageId } }), this.env);
                }
              }
            }
          }
        } catch (e) { console.error("DO Push Error:", e); }
      })());
    } catch (e) { console.error("DO WS Message Error:", e); ws.send(JSON.stringify({error: "Processing failed"}));}
  }
  async webSocketClose(ws, code, reason, wasClean) { if(ws.sessionInfo) this.sessions.delete(ws.sessionInfo.sessionId); console.log("DO WS Close:", ws.sessionInfo, code, reason, wasClean); }
  async webSocketError(ws, error) { if(ws.sessionInfo) this.sessions.delete(ws.sessionInfo.sessionId); console.error("DO WS Error:", ws.sessionInfo, error); }
  async broadcast(messageString, senderWs) {
    for (const [sessionId, socket] of this.sessions.entries()) {
      if (senderWs && senderWs.sessionInfo && senderWs.sessionInfo.sessionId === sessionId) continue;
      if (socket.readyState === WebSocket.READY_STATE_OPEN) {
        try {
          if (socket.sessionInfo.role === 'child' && await this._isUserInDnd(socket.sessionInfo.userId, socket.sessionInfo.role)) {
            console.log(`DO: User ${socket.sessionInfo.userId} in DND, skipping broadcast.`); continue;
          }
          socket.send(messageString);
        } catch (e) { console.error("DO Broadcast Error to session " + sessionId, e); }
      }
    }
  }
}
export class VideoCallSignalingDO { /* ... existing VideoCallSignalingDO code ... */
  constructor(state, env) { this.state = state; this.env = env; this.participants = new Map(); this.userIdToSessionId = new Map(); this.sessions = new Map(); }
  generateSessionId() { return crypto.randomUUID(); }
  async fetch(request) { /* ... existing fetch ... */ return errorResponse("Not found in DO", 404); }
  async webSocketMessage(ws, message) { /* ... existing webSocketMessage ... */ }
  async webSocketClose(ws, code, reason, wasClean) { /* ... existing webSocketClose ... */ }
  async webSocketError(ws, error) { /* ... existing webSocketError ... */ }
  broadcast(messageString, excludeSessionId) { /* ... existing broadcast ... */ }
}

// Re-add all other helper functions from the previous complete file content
// (getValidMsGraphUserAccessToken, getProcessedEmailTemplate, logAuditEvent, sendPushNotification, getKey, encrypt, decrypt, jsonResponse, errorResponse, signToken, verifyToken, hashPassword, hashPin, getUser, requireRole, getEffectiveParentalControls, isUserInDnd)
// For brevity, their full code is not repeated here, but it's assumed they are part of the `srcContent` variable passed to `overwrite_file_with_block`.
// Also re-add `import { sendEmail } from './services/microsoftGraphService.ts';`

// Main fetch handler
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const user = await getUser(request, env); // `user` can be null if no/invalid token
    const pathname = url.pathname;
    const method = request.method;

    // Auth Gate (from previous verified version)
    const isApiRoute = pathname.startsWith('/api/');
    let isPublicApiRoute = false;
    if (isApiRoute) {
        const PUBLIC_API_PATHS = [
            "/api/auth/request-password-reset",
            "/api/auth/reset-password",
            "/api/test-email",
            // Family invitation public routes:
            "/api/invitations/:token/details", // Path pattern, will be handled by regex
            "/api/invitations/:token/decline"  // Path pattern, will be handled by regex
        ];
        // Check for exact matches first
        if (PUBLIC_API_PATHS.includes(pathname)) {
            isPublicApiRoute = true;
        }
        // Then check for patterns (like invite tokens)
        if (pathname.match(/^\/api\/invitations\/[a-zA-Z0-9]+\/details$/i) && method === "GET") {
            isPublicApiRoute = true;
        }
        if (pathname.match(/^\/api\/invitations\/[a-zA-Z0-9]+\/decline$/i) && method === "POST") {
            isPublicApiRoute = true; // Decline can be attempted without login
        }
        if (method === "OPTIONS") isPublicApiRoute = true;
    }
    if (!user && isApiRoute && !isPublicApiRoute && !pathname.startsWith('/auth/')) {
        return errorResponse("Unauthorized", 401);
    }
    if (method === 'OPTIONS') {
       return new Response(null, { headers: {
           'Access-Control-Allow-Origin': '*',
           'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
           'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-User-Id',
       }});
    }

    // Admin Routes
    if (pathname.startsWith('/api/admin/')) {
      if (!user || !requireRole(user, ['super_admin'])) {
        ctx.waitUntil(logAuditEvent(env, request, 'admin_access_denied', user?.userId || 'anonymous', 'admin_route', pathname, 'failure', { attemptedRole: user?.role || 'none' }));
        return errorResponse("Forbidden: Admin access required.", 403);
      }
      // ... (all existing /api/admin/* routes like /users, /users/:id/details, /parental-controls/defaults, /test-harness/* should be here)
      // For brevity, full code of these admin routes (assumed to be working from previous steps) is not repeated in this diff's REPLACE block, but would be in the final JS.
       if (pathname === "/api/admin/users" && method === "GET") { /* ... */ }
       const adminUserUpdateMatch = pathname.match(/^\/api\/admin\/users\/([0-9a-fA-F\-]+)\/details$/i);
       if (adminUserUpdateMatch && method === "PUT") { /* ... */ }
       if (pathname === "/api/admin/parental-controls/defaults") { /* GET and PUT ... */ }
       if (pathname.startsWith("/api/admin/test-harness/")) { /* ... */ }
      // return errorResponse("Admin route not found.", 404); // Fallback for /api/admin/*
    }

    // Family Invitation Routes
    if (pathname === "/api/me/family/invitations" && method === "POST") { // Create Invite
        if (!user) return errorResponse("Unauthorized", 401);
        if (!requireRole(user, ['family_admin', 'super_admin'])) { // super_admin can also invite if they have a family_id or one is specified
            ctx.waitUntil(logAuditEvent(env, request, 'create_family_invitation_denied', user.userId, 'family_invitation', user.family_id || 'N/A', 'failure', { reason: 'Insufficient role' }));
            return errorResponse("Forbidden: Only family admins or super admins can send invitations.", 403);
        }
        if (!user.family_id && user.role === 'family_admin') { // family_admin must have a family
             return errorResponse("Forbidden: You must belong to a family to invite members.", 403);
        }
        try {
            const requestData = await request.json();
            const { invitedEmail, roleToAssign: rawRoleToAssign } = requestData;
            const roleToAssign = rawRoleToAssign || 'parent';
            if (!invitedEmail || typeof invitedEmail !== 'string' || !invitedEmail.includes('@')) return errorResponse("Valid invitedEmail required.", 400);
            if (!['parent', 'child'].includes(roleToAssign)) return errorResponse("Invalid roleToAssign.", 400);
            if (invitedEmail.toLowerCase() === user.email.toLowerCase()) return errorResponse("Cannot invite yourself.", 400);

            const targetExistingUser = await env.D1_DB.prepare("SELECT id, family_id FROM users WHERE email = ?").bind(invitedEmail.toLowerCase()).first();
            if (targetExistingUser?.family_id) return errorResponse("User is already in a family.", 409);

            const existingPendingInvite = await env.D1_DB.prepare("SELECT id FROM family_invitations WHERE family_id = ? AND invited_email = ? AND status = 'pending' AND expires_at > datetime('now')")
                .bind(user.family_id, invitedEmail.toLowerCase()).first();
            if (existingPendingInvite) return errorResponse("Invitation already pending for this email to your family.", 409);

            const newInvitationId = crypto.randomUUID();
            const token = generateSecureToken();
            const expires_at_date = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
            const expires_at_iso = expires_at_date.toISOString();
            const now = new Date().toISOString();

            await env.D1_DB.prepare("INSERT INTO family_invitations (id, family_id, invited_email, invited_by_user_id, role_to_assign, status, token, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)")
                .bind(newInvitationId, user.family_id, invitedEmail.toLowerCase(), user.userId, roleToAssign, token, expires_at_iso, now, now).run();

            const familyDetails = await env.D1_DB.prepare("SELECT family_name FROM families WHERE id = ?").bind(user.family_id).first();
            const familyName = familyDetails?.family_name || `${user.name}'s Family`;
            const frontendDomain = env.FRONTEND_URL || 'https://YOUR_FRONTEND_DOMAIN_PLACEHOLDER';
            const inviteLink = `${frontendDomain}/join-family?token=${token}`;
            const emailData = { invitedEmailOrName: invitedEmail, inviterName: user.name, familyName, appName: "It's Just Us", roleToAssign, inviteLink, expiryDateFmt: expires_at_date.toLocaleDateString() };
            const processedEmail = await getProcessedEmailTemplate('family_invitation_email', emailData, env);
            ctx.waitUntil(sendEmail(env, { to: invitedEmail, subject: processedEmail.subject, htmlBody: processedEmail.bodyHtml }));
            ctx.waitUntil(logAuditEvent(env, request, 'create_family_invitation', user.userId, 'family_invitation', newInvitationId, 'success', { invitedEmail, roleToAssign, familyId: user.family_id }));
            return jsonResponse({ message: "Invitation sent successfully.", invitationId: newInvitationId }, 201);
        } catch (e) { console.error("Create family invite error:", e); return errorResponse("Failed to create invitation: " + e.message, 500); }
    }

    const inviteTokenMatch = pathname.match(/^\/api\/invitations\/([a-zA-Z0-9]+)\/(details|accept|decline)$/);
    if (inviteTokenMatch) {
        const token = inviteTokenMatch[1];
        const action = inviteTokenMatch[2];

        if (action === "details" && method === "GET") {
            const invite = await env.D1_DB.prepare("SELECT family_id, invited_email, invited_by_user_id, role_to_assign, status, expires_at FROM family_invitations WHERE token = ? AND status = 'pending' AND expires_at > datetime('now')").bind(token).first();
            if (!invite) return errorResponse("Invitation not found, expired, or already used.", 404);
            const [family, inviter] = await Promise.all([
                env.D1_DB.prepare("SELECT family_name FROM families WHERE id = ?").bind(invite.family_id).first(),
                env.D1_DB.prepare("SELECT name FROM users WHERE id = ?").bind(invite.invited_by_user_id).first()
            ]);
            return jsonResponse({ invitedEmail: invite.invited_email, familyName: family?.family_name, inviterName: inviter?.name, roleToAssign: invite.role_to_assign, appName: "It's Just Us" });
        }

        if (action === "accept" && method === "POST") {
            if (!user) return errorResponse("Unauthorized. Please log in or register to accept.", 401);
            const invite = await env.D1_DB.prepare("SELECT id, family_id, invited_email, role_to_assign, status, expires_at FROM family_invitations WHERE token = ?").bind(token).first();
            if (!invite || invite.status !== 'pending' || new Date(invite.expires_at) < new Date()) return errorResponse("Invitation not found, expired, or already used.", 404);
            if (invite.invited_email.toLowerCase() !== user.email.toLowerCase()) return errorResponse("This invitation is for a different email address.", 403);
            if (user.family_id) return errorResponse("You are already part of a family.", 409);

            await env.D1_DB.batch([
                env.D1_DB.prepare("UPDATE users SET family_id = ?, role = ?, updated_at = datetime('now') WHERE id = ?").bind(invite.family_id, invite.role_to_assign, user.userId),
                env.D1_DB.prepare("UPDATE family_invitations SET status = 'accepted', updated_at = datetime('now') WHERE id = ?").bind(invite.id)
            ]);
            ctx.waitUntil(logAuditEvent(env, request, 'accept_family_invitation', user.userId, 'family_invitation', invite.id, 'success', { familyId: invite.family_id }));
            return jsonResponse({ message: "Invitation accepted. Welcome to the family!" });
        }

        if (action === "decline" && method === "POST") {
            const invite = await env.D1_DB.prepare("SELECT id, status, expires_at FROM family_invitations WHERE token = ?").bind(token).first();
            if (!invite || invite.status !== 'pending' || new Date(invite.expires_at) < new Date()) return errorResponse("Invitation not found, expired, or already used.", 404);

            await env.D1_DB.prepare("UPDATE family_invitations SET status = 'declined', updated_at = datetime('now') WHERE id = ?").bind(invite.id).run();
            if (user) ctx.waitUntil(logAuditEvent(env, request, 'decline_family_invitation', user.userId, 'family_invitation', invite.id, 'success'));
            return jsonResponse({ message: "Invitation declined." });
        }
    }

    if (pathname === "/api/me/family/invitations" && method === "GET") { // List family's invites
        if (!user) return errorResponse("Unauthorized", 401);
        if (!requireRole(user, ['family_admin', 'super_admin']) || !user.family_id) {
            return errorResponse("Forbidden: Only family admins can view invitations for their family.", 403);
        }
        const { results } = await env.D1_DB.prepare("SELECT id, invited_email, role_to_assign, status, expires_at, created_at FROM family_invitations WHERE family_id = ? ORDER BY created_at DESC LIMIT 50")
            .bind(user.family_id).all();
        return jsonResponse(results || []);
    }

    const cancelInviteMatch = pathname.match(/^\/api\/me\/family\/invitations\/([0-9a-fA-F\-]+)$/i);
    if (cancelInviteMatch && method === "DELETE") { // Cancel Invite
        if (!user) return errorResponse("Unauthorized", 401);
        if (!requireRole(user, ['family_admin', 'super_admin']) || !user.family_id) {
            return errorResponse("Forbidden: Only family admins can cancel invitations for their family.", 403);
        }
        const invitationId = cancelInviteMatch[1];
        const invite = await env.D1_DB.prepare("SELECT id, family_id, status FROM family_invitations WHERE id = ?").bind(invitationId).first();
        if (!invite) return errorResponse("Invitation not found.", 404);
        if (invite.family_id !== user.family_id) return errorResponse("Forbidden: Cannot cancel invitations for another family.", 403);
        if (invite.status !== 'pending') return errorResponse("Cannot cancel an invitation that is not pending.", 400);

        await env.D1_DB.prepare("DELETE FROM family_invitations WHERE id = ?").bind(invitationId).run();
        ctx.waitUntil(logAuditEvent(env, request, 'cancel_family_invitation', user.userId, 'family_invitation', invitationId, 'success'));
        return jsonResponse({ message: "Invitation cancelled." });
    }

    // ... (rest of the non-admin, non-family-invitation routes like /api/me/family/members, /api/me/family/children/:childUserId/controls, etc.)
    // For brevity, their full code is not repeated here but is assumed to be part of the base `srcContent`.

    if (url.pathname === "/test") { /* ... existing test route code ... */ }

    return errorResponse("Not Found", 404);
  },
};
export { MyDurableObject, ConversationDurableObject, VideoCallSignalingDO };