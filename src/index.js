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
      const { name, email, password } = await request.json();
      const hashedPassword = await hashPassword(password);
      await env.D1_DB.prepare(
        "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)"
      ).bind(name, email, hashedPassword).run();
      return new Response("User registered", { status: 201 });
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

    return new Response("Page not found", { status: 404 });
  },
};
export { MyDurableObject };