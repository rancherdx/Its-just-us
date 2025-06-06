// src/services/microsoftGraphService.ts

interface Env {
  MS_GRAPH_CLIENT_ID: string;
  MS_GRAPH_CLIENT_SECRET: string;
  MS_GRAPH_TENANT_ID: string;
  MS_GRAPH_SENDING_USER_ID: string; // User ID or UPN of the sending mailbox
  // ... other environment variables
}

interface EmailArgs {
  to: string;
  subject: string;
  htmlBody: string;
}

interface TokenCache {
  accessToken: string | null;
  expiresAt: number | null;
}

// Basic in-memory token cache
let tokenCache: TokenCache = {
  accessToken: null,
  expiresAt: null,
};

async function getAccessToken(env: Env): Promise<string> {
  if (tokenCache.accessToken && tokenCache.expiresAt && Date.now() < tokenCache.expiresAt) {
    console.log("Using cached MS Graph token");
    return tokenCache.accessToken;
  }

  console.log("Requesting new MS Graph token");
  const tokenUrl = `https://login.microsoftonline.com/${env.MS_GRAPH_TENANT_ID}/oauth2/v2.0/token`;
  const params = new URLSearchParams();
  params.append('client_id', env.MS_GRAPH_CLIENT_ID);
  params.append('scope', 'https://graph.microsoft.com/.default');
  params.append('client_secret', env.MS_GRAPH_CLIENT_SECRET);
  params.append('grant_type', 'client_credentials');

  try {
    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const errorData = await response.text();
      throw new Error(`Failed to get MS Graph token: ${response.status} ${response.statusText} - ${errorData}`);
    }

    const data: { access_token: string; expires_in: number } = await response.json();

    tokenCache = {
      accessToken: data.access_token,
      // Cache token for slightly less than its actual expiry to be safe (e.g., 5 minutes buffer)
      expiresAt: Date.now() + (data.expires_in - 300) * 1000,
    };
    console.log("Successfully obtained new MS Graph token");
    return data.access_token;

  } catch (error) {
    console.error("Error fetching MS Graph access token:", error);
    throw error; // Re-throw the error to be handled by the caller
  }
}

export async function sendEmail(env: Env, { to, subject, htmlBody }: EmailArgs): Promise<boolean> {
  console.log(`Attempting to send email to: ${to} with subject: ${subject}`);
  try {
    const accessToken = await getAccessToken(env);

    const sendMailUrl = `https://graph.microsoft.com/v1.0/users/${env.MS_GRAPH_SENDING_USER_ID}/sendMail`;

    const emailPayload = {
      message: {
        subject: subject,
        body: {
          contentType: 'HTML',
          content: htmlBody,
        },
        toRecipients: [
          {
            emailAddress: {
              address: to,
            },
          },
        ],
      },
      saveToSentItems: 'true', // Optional: Save a copy in the sender's Sent Items
    };

    const response = await fetch(sendMailUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(emailPayload),
    });

    if (response.status === 202) { // 202 Accepted is success for sendMail
      console.log(`Email successfully sent to ${to}. Status: ${response.status}`);
      return true;
    } else {
      const errorData = await response.text();
      console.error(`Failed to send email. Status: ${response.status} ${response.statusText}. Details: ${errorData}`);
      return false;
    }
  } catch (error) {
    console.error(`Error in sendEmail function: ${error}`);
    return false;
  }
}

// Example of a helper function for a specific email type (optional, can be added later)
/*
export async function sendWelcomeEmail(env: Env, userEmail: string): Promise<boolean> {
  const subject = "Welcome to Our Platform!";
  const htmlBody = `
    <h1>Welcome, ${userEmail}!</h1>
    <p>Thank you for signing up. We're excited to have you.</p>
  `;
  return sendEmail(env, { to: userEmail, subject, htmlBody });
}
*/
