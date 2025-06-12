// src/services/microsoftGraphService.ts

interface BaseEnv {
  MS_GRAPH_CLIENT_ID: string; // For app-only token for sendEmail
  MS_GRAPH_CLIENT_SECRET: string; // For app-only token for sendEmail
  MS_GRAPH_TENANT_ID: string; // For app-only token for sendEmail
  MS_GRAPH_SENDING_USER_ID: string; // For app-only email sending

  D1_DB: D1Database;
  ENCRYPTION_KEY: string;
  // Functions that will be attached by index.js to env before calling service methods
  getValidMsGraphUserAccessToken?: (userId: string, env: BaseEnv) => Promise<string>;
  encrypt?: (text: string, env: BaseEnv) => Promise<string | null>;
  decrypt?: (encryptedText: string, env: BaseEnv) => Promise<string | null>;
}

// --- App-only token logic (existing for sendEmail) ---
interface TokenCache {
  accessToken: string | null;
  expiresAt: number | null;
}
let appOnlyTokenCache: TokenCache = { accessToken: null, expiresAt: null };

async function getAppOnlyAccessToken(env: BaseEnv): Promise<string> {
  if (appOnlyTokenCache.accessToken && appOnlyTokenCache.expiresAt && Date.now() < appOnlyTokenCache.expiresAt) {
    return appOnlyTokenCache.accessToken;
  }
  const tokenUrl = `https://login.microsoftonline.com/${env.MS_GRAPH_TENANT_ID}/oauth2/v2.0/token`;
  const params = new URLSearchParams();
  params.append('client_id', env.MS_GRAPH_CLIENT_ID);
  params.append('scope', 'https://graph.microsoft.com/.default');
  params.append('client_secret', env.MS_GRAPH_CLIENT_SECRET);
  params.append('grant_type', 'client_credentials');

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });

  if (!response.ok) {
    const errorData = await response.text();
    console.error(`MS Graph app-only token fetch error: ${response.status}`, errorData);
    throw new Error(`Failed to get MS Graph app-only token: ${response.status} ${errorData}`);
  }
  const data: { access_token: string; expires_in: number } = await response.json();
  appOnlyTokenCache = {
    accessToken: data.access_token,
    expiresAt: Date.now() + (data.expires_in - 300) * 1000, // 5 min buffer
  };
  return data.access_token;
}

export async function sendEmail(env: BaseEnv, { to, subject, htmlBody }: { to: string; subject: string; htmlBody: string }): Promise<boolean> {
  try {
    const accessToken = await getAppOnlyAccessToken(env); // Uses app-only token
    const sendMailUrl = `https://graph.microsoft.com/v1.0/users/${env.MS_GRAPH_SENDING_USER_ID}/sendMail`;
    const emailPayload = {
      message: { subject, body: { contentType: 'HTML', content: htmlBody }, toRecipients: [{ emailAddress: { address: to } }] },
      saveToSentItems: 'true',
    };
    const response = await fetch(sendMailUrl, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(emailPayload),
    });
    if (response.status === 202) {
      console.log(`Email successfully sent to ${to}.`);
      return true;
    } else {
      const errorData = await response.text();
      console.error(`Failed to send email via MS Graph. Status: ${response.status}`, errorData);
      return false;
    }
  } catch (error) {
    console.error(`Error in sendEmail (MS Graph):`, error);
    return false;
  }
}

// --- User-delegated Calendar Service Methods ---

export async function listUserCalendars(userId: string, env: BaseEnv): Promise<any> {
  if (!env.getValidMsGraphUserAccessToken) throw new Error("getValidMsGraphUserAccessToken not available on env");
  try {
    const accessToken = await env.getValidMsGraphUserAccessToken(userId, env);
    const response = await fetch("https://graph.microsoft.com/v1.0/me/calendars", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) {
      const errorData = await response.text();
      console.error(`MS Graph API Error (${response.status}) listing calendars for user ${userId}:`, errorData);
      throw new Error(`MS Graph API Error: ${response.statusText} - ${errorData}`);
    }
    return await response.json();
  } catch (error) {
    console.error(`Error in listUserCalendars for user ${userId}:`, error);
    throw error;
  }
}

export async function getCalendarEvents(userId: string, calendarId: string, timeWindowStartISO: string, timeWindowEndISO: string, env: BaseEnv): Promise<any> {
  if (!env.getValidMsGraphUserAccessToken) throw new Error("getValidMsGraphUserAccessToken not available on env");
  try {
    const accessToken = await env.getValidMsGraphUserAccessToken(userId, env);
    const eventsUrl = `https://graph.microsoft.com/v1.0/me/calendars/${calendarId}/events?$filter=start/dateTime ge '${timeWindowStartISO}' and end/dateTime le '${timeWindowEndISO}'&$select=id,subject,start,end,organizer,attendees,bodyPreview,webLink&$orderby=start/dateTime`;

    const response = await fetch(eventsUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) {
      const errorData = await response.text();
      console.error(`MS Graph API Error (${response.status}) fetching events for user ${userId}, calendar ${calendarId}:`, errorData);
      throw new Error(`MS Graph API Error: ${response.statusText} - ${errorData}`);
    }
    return await response.json();
  } catch (error) {
    console.error(`Error in getCalendarEvents for user ${userId}, calendar ${calendarId}:`, error);
    throw error;
  }
}

export async function createCalendarEvent(userId: string, calendarId: string | null, eventData: object, env: BaseEnv): Promise<any> {
  if (!env.getValidMsGraphUserAccessToken) throw new Error("getValidMsGraphUserAccessToken not available on env");
  try {
    const accessToken = await env.getValidMsGraphUserAccessToken(userId, env);
    const createEventUrl = calendarId
      ? `https://graph.microsoft.com/v1.0/me/calendars/${calendarId}/events`
      : `https://graph.microsoft.com/v1.0/me/events`; // Default calendar if no ID

    const response = await fetch(createEventUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(eventData),
    });

    if (response.status !== 201) {
      const errorData = await response.text();
      console.error(`MS Graph API Error (${response.status}) creating event for user ${userId}:`, errorData);
      throw new Error(`MS Graph API Error: ${response.statusText} - ${errorData}`);
    }
    return await response.json();
  } catch (error) {
    console.error(`Error in createCalendarEvent for user ${userId}:`, error);
    throw error;
  }
}
