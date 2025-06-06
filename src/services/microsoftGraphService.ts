// src/services/microsoftGraphService.ts

/**
 * Defines the structure for environment variables required by the Microsoft Graph service.
 * These variables are expected to be available in the Cloudflare Worker's environment.
 */
interface Env {
  /** The Azure AD application (client) ID for MS Graph authentication. */
  MS_GRAPH_CLIENT_ID: string;
  /** The client secret for the Azure AD application. */
  MS_GRAPH_CLIENT_SECRET: string;
  /** The Azure AD tenant ID. */
  MS_GRAPH_TENANT_ID: string;
  /** The User ID or User Principal Name (UPN) of the mailbox from which emails will be sent. */
  MS_GRAPH_SENDING_USER_ID: string;
  // ... other environment variables that might be present but not used by this service
}

/**
 * Defines the structure for the arguments required to send an email.
 */
interface EmailArgs {
  /** The recipient's email address. */
  to: string;
  /** The subject line of the email. */
  subject: string;
  /** The HTML content of the email body. */
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
      // Reduce token's actual lifetime by 300 seconds (5 minutes) to ensure it's refreshed before actual expiry,
      // mitigating potential clock skew issues or propagation delays.
      expiresAt: Date.now() + (data.expires_in - 300) * 1000,
    };
    console.log("Successfully obtained new MS Graph token");
    return data.access_token;

  } catch (error) {
    console.error("Error fetching MS Graph access token:", error);
    throw error; // Re-throw the error to be handled by the caller
  }
}

/**
 * Sends an email using the Microsoft Graph API.
 * It handles acquiring an access token (and caching it) and then making the send mail request.
 *
 * @param env The environment object containing necessary MS Graph credentials.
 * @param emailArgs An object containing the recipient, subject, and HTML body of the email.
 * @returns A promise that resolves to `true` if the email is sent successfully (status 202),
 *          and `false` otherwise. Logs errors to the console.
 */
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
      // Saves a copy of the sent email in the sender's "Sent Items" folder.
      // Set to 'false' if this behavior is not desired.
      saveToSentItems: 'true',
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
