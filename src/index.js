class MyDurableObject {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    return new Response("Hello from Durable Object!");
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
async function signToken(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
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

async function verifyToken(token, secret) {
  const [header, payload, signature] = token.split(".");
  const signatureInput = `${header}.${payload}`;
  
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const expectedSignature = new Uint8Array(
    atob(signature)
      .split("")
      .map(c => c.charCodeAt(0))
  );
  const isValid = await crypto.subtle.verify(
    "HMAC",
    key,
    expectedSignature,
    encoder.encode(signatureInput)
  );
  
  if (!isValid) return null;
  return JSON.parse(atob(payload));
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function getUser(request, env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.split(" ")[1];
  return await verifyToken(token, env.JWT_SECRET);
}

import { sendEmail } from './services/microsoftGraphService.ts';

const redirectUri = "https://its-just-us.your-account.workers.dev/auth/facebook/callback";

const PUBLIC_ROUTES = [
  "/test",
  "/auth/facebook",
  "/auth/facebook/callback",
  "/auth/facebook/token",
  "/auth/register",
  "/auth/login",
  "/auth/logout",
  "/api/auth/request-password-reset",
  "/api/auth/reset-password",
  "/api/test-email"
  // Note: /api/conversations and /api/conversations/:id/messages are NOT public
];


export default {
  async fetch(request, env, ctx) { // Added ctx for waitUntil if needed later
    const url = new URL(request.url);
    const user = await getUser(request, env);

    // Centralized Auth Check for non-public API routes
    if (!PUBLIC_ROUTES.includes(url.pathname) && url.pathname.startsWith("/api/") && !user) {
        return errorResponse("Unauthorized", 401);
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
        const body = await request.json().catch(() => ({})); // Allow empty body for default title/participants
        const { title, max_participants } = body;
        const creatorId = user.userId;

        const callId = crypto.randomUUID();
        const roomName = crypto.randomUUID(); // Simple unique room name
        const now = new Date().toISOString();
        const callStatus = 'pending'; // Initial status

        await env.D1_DB.prepare(
          "INSERT INTO video_calls (id, room_name, created_by_user_id, title, start_time, status, max_participants, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ).bind(callId, roomName, creatorId, title || `Call by ${user.name || creatorId}`, now, callStatus, max_participants || null, now, now).run();
        // Note: user.name might not be in JWT. If not, a default title or fetching user name would be better.

        // Add creator as participant
        await env.D1_DB.prepare(
          "INSERT INTO call_participants (call_id, user_id, status) VALUES (?, ?, ?)"
        ).bind(callId, creatorId, 'host').run();

        const newCall = {
          id: callId,
          room_name: roomName,
          created_by_user_id: creatorId,
          title: title || `Call by ${user.name || creatorId}`,
          start_time: now,
          status: callStatus,
          max_participants: max_participants || null,
          created_at: now,
          participants: [{ user_id: creatorId, status: 'host' }] // Simplified participant list
        };
        return jsonResponse(newCall, 201);
      } catch (e) {
        console.error("Error creating video call:", e);
        return errorResponse("Failed to create video call: " + e.message, 500);
      }
    }

    // GET /api/video/calls - List video calls for the user
    if (url.pathname === "/api/video/calls" && request.method === "GET") {
      if (!user) return errorResponse("Unauthorized", 401);
      try {
        const userId = user.userId;
        // Fetch calls created by user OR where user is a participant
        const { results } = await env.D1_DB.prepare(
          `SELECT DISTINCT vc.id, vc.room_name, vc.title, vc.start_time, vc.status, vc.created_by_user_id, vc.max_participants,
                  (SELECT COUNT(*) FROM call_participants cp_count WHERE cp_count.call_id = vc.id AND cp_count.left_at IS NULL) as current_participant_count
           FROM video_calls vc
           LEFT JOIN call_participants cp ON vc.id = cp.call_id
           WHERE vc.created_by_user_id = ? OR cp.user_id = ?
           ORDER BY vc.start_time DESC`
        ).bind(userId, userId).all();

        return jsonResponse(results);
      } catch (e) {
        console.error("Error fetching video calls:", e);
        return errorResponse("Failed to fetch video calls: " + e.message, 500);
      }
    }

    // Regex for /api/video/calls/:callId/(join|leave)
    const videoCallActionMatch = url.pathname.match(/^\/api\/video\/calls\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\/(join|leave)$/i);

    if (videoCallActionMatch) {
      if (!user) return errorResponse("Unauthorized", 401);
      const callId = videoCallActionMatch[1];
      const action = videoCallActionMatch[2];
      const userId = user.userId;
      const now = new Date().toISOString();

      // Check if call exists
      const call = await env.D1_DB.prepare("SELECT id, status, max_participants FROM video_calls WHERE id = ?").bind(callId).first();
      if (!call) {
        return errorResponse("Video call not found.", 404);
      }

      if (action === "join") {
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
        // Placeholder for frontend URL - ideally from env variable
        const frontendBaseUrl = env.FRONTEND_URL || "http://localhost:3000"; // Replace with actual env var later
        const resetLink = `${frontendBaseUrl}/reset-password?token=${plainToken}`;

        const subject = "Your Password Reset Request";
        const htmlBody = `
          <h1>Password Reset</h1>
          <p>You requested a password reset. Click the link below to reset your password. This link is valid for ${expiryMinutes} minutes.</p>
          <a href="${resetLink}">${resetLink}</a>
          <p>If you did not request this, please ignore this email.</p>
        `;

        // Non-blocking email send
        sendEmail(env, { to: email, subject, htmlBody })
          .then(success => console.log(success ? `Password reset email dispatched to ${email}.` : `Failed to dispatch password reset email to ${email}.`))
          .catch(err => console.error(`Error sending password reset email to ${email}:`, err));

        return new Response(JSON.stringify({ message: "If your email is registered, you will receive a password reset link." }), { status: 200, headers: { "Content-Type": "application/json" } });

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
        const subject = "Your Password Has Been Reset";
        const htmlBody = `
          <h1>Password Successfully Reset</h1>
          <p>Your password for It's Just Us has been successfully reset.</p>
          <p>If you did not make this change, please contact support immediately.</p>
        `;
        sendEmail(env, { to: userEmail, subject, htmlBody })
          .then(success => console.log(success ? `Password change confirmation email dispatched to ${userEmail}.` : `Failed to dispatch password change confirmation to ${userEmail}.`))
          .catch(err => console.error(`Error sending password change confirmation to ${userEmail}:`, err));

        return new Response(JSON.stringify({ message: "Password reset successfully." }), { status: 200, headers: { "Content-Type": "application/json" } });

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
        const { name, email, password } = await request.json();
        if (!name || !email || !password) {
          return new Response(JSON.stringify({ message: "Missing name, email, or password" }), { status: 400, headers: { "Content-Type": "application/json" } });
        }

        const hashedPassword = await hashPassword(password);

        // Insert user into database
        await env.D1_DB.prepare(
          "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)"
        ).bind(name, email, hashedPassword).run();

        // Send welcome email
        const welcomeSubject = `Welcome to It's Just Us, ${name}!`;
        const welcomeHtmlBody = `
          <h1>Welcome, ${name}!</h1>
          <p>Thank you for registering at It's Just Us.</p>
          <p>We're excited to have you join our community!</p>
          <br>
          <p>Best regards,</p>
          <p>The It's Just Us Team</p>
        `;

        console.log(`Attempting to send welcome email to: ${email}`);
        // Send welcome email asynchronously (non-blocking).
        // The registration process should not fail or be delayed if the email sending encounters an issue.
        // Errors in email sending are logged separately.
        sendEmail(env, {
          to: email,
          subject: welcomeSubject,
          htmlBody: welcomeHtmlBody
        }).then(success => {
          if (success) {
            console.log(`Welcome email successfully dispatched to ${email}.`);
          } else {
            console.error(`Failed to dispatch welcome email to ${email}.`);
          }
        }).catch(error => {
          console.error(`Error sending welcome email to ${email}:`, error);
        });

        return new Response(JSON.stringify({ message: "User registered successfully. A welcome email is being sent." }), {
          status: 201,
          headers: { "Content-Type": "application/json" }
        });

      } catch (dbError) {
        // Check for unique constraint error for email
        if (dbError.message && dbError.message.includes("UNIQUE constraint failed: users.email")) {
          console.error("Registration failed: Email already exists.", dbError);
          return new Response(JSON.stringify({ message: "Email already exists. Please use a different email or login." }), {
            status: 409, // Conflict
            headers: { "Content-Type": "application/json" }
          });
        }
        console.error("Error during registration:", dbError);
        return new Response(JSON.stringify({ message: "Error during registration.", error: dbError.message }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }

    // Email/Password Login
    if (request.method === "POST" && url.pathname === "/auth/login") {
      const { email, password } = await request.json();
      const hashedPassword = await hashPassword(password);
      const user = await env.D1_DB.prepare(
        "SELECT id, email FROM users WHERE email = ? AND password_hash = ?"
      ).bind(email, hashedPassword).first();
      if (!user) return new Response("Invalid credentials", { status: 401 });
      const token = await signToken({ userId: user.id, email, exp: Math.floor(Date.now() / 1000) + 3600 }, env.JWT_SECRET);
      return new Response(JSON.stringify({ token }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Logout (client-side)
    if (url.pathname === "/auth/logout") {
      return new Response("Logout successful (discard token client-side)", { status: 200 });
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

    // Regex to match /api/conversations/:conversationId/messages
    // Assumes conversationId is a UUID (standard format with hyphens)
    const messageMatch = url.pathname.match(/^\/api\/conversations\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\/messages$/i);

    if (messageMatch) {
      if (!user) return errorResponse("Unauthorized", 401);
      const conversationId = messageMatch[1];
      const userId = user.userId;

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

          const messageId = crypto.randomUUID(); // Generate ID in JS
          const now = new Date().toISOString();

          await env.D1_DB.prepare(
            "INSERT INTO messages (id, conversation_id, sender_id, content, message_type, media_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(messageId, conversationId, userId, content, message_type, media_url, now, now).run();

          // Update conversation's last_message_at and updated_at
          await env.D1_DB.prepare(
            "UPDATE conversations SET last_message_at = ?, updated_at = ? WHERE id = ?"
          ).bind(now, now, conversationId).run();

          // Fetch the created message with sender details (simplified)
          const createdMessage = {
            id: messageId,
            conversation_id: conversationId,
            sender_id: userId,
            content,
            message_type,
            media_url,
            created_at: now,
            updated_at: now,
            sender: { id: user.userId, name: user.name, profile_picture: user.profile_picture } // Assuming user object has name/profile_picture
          };
          // Note: user.name and user.profile_picture might not be in JWT. A DB query might be needed for full sender details.
          // For now, this is a simplification.

          return jsonResponse(createdMessage, 201);
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

    return errorResponse("Not Found", 404);
  },
};
export { MyDurableObject };