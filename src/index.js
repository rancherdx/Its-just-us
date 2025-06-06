class MyDurableObject {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    return new Response("Hello from Durable Object!");
  }
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const user = await getUser(request, env);

    // Test route (expanded schema)
    if (url.pathname === "/test") {
      try {
        await env.D1_DB.prepare(`
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password_hash TEXT,
            profile_picture TEXT
          )
        `).run();

        await env.D1_DB.prepare(`
          CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at DATETIME NOT NULL
          )
        `).run();

        await env.D1_DB.prepare(`
          CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT,
            media TEXT,
            visibility TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
          )
        `).run();

        await env.D1_DB.prepare(`
          CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            receiver_id INTEGER,
            content TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
          )
        `).run();

        await env.D1_DB.prepare(`
          CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            date TEXT NOT NULL,
            description TEXT,
            reminders TEXT,
            created_by INTEGER,
            FOREIGN KEY (created_by) REFERENCES users(id)
          )
        `).run();

        await env.D1_DB.prepare(`
          INSERT OR IGNORE INTO users (name, email, password_hash) VALUES (?, ?, ?)
        `).bind("Dominick Rancher", "dominick@designspek.com", await hashPassword("test")).run();

        const { results } = await env.D1_DB.prepare(`SELECT * FROM users`).all();
        return new Response(JSON.stringify(results, null, 2), {
          headers: { "Content-Type": "application/json" },
        });
      } catch (error) {
        return new Response(`Error: ${error.message}`, { status: 500 });
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

    // Protect API routes
    if (!user && !["/test", "/auth/facebook", "/auth/facebook/callback", "/auth/facebook/token", "/auth/register", "/auth/login", "/auth/logout"].includes(url.pathname)) {
      return new Response("Unauthorized", { status: 401 });
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

    return new Response("Page not found", { status: 404 });
  },
};
export { MyDurableObject };