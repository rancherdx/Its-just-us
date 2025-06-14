# API Reference

This document provides a reference for the HTTP API endpoints available in the 'It's Just Us' backend application. All API routes under `/api/` generally require authentication unless otherwise specified. Timestamps are typically in ISO 8601 format.

## 1. Authentication (`/auth` and `/api/auth`)

### `POST /auth/register`
Registers a new user.
*   **Request Body:** `application/json`
    ```json
    {
      "name": "string (required)",
      "email": "string (required, unique)",
      "password": "string (required, min length)"
    }
    ```
*   **Response (201 Created):** `application/json`
    ```json
    {
      "message": "User registered successfully. A welcome email is being sent.",
      "token": "string (JWT)",
      "user": {
        "id": "string (user_id)",
        "name": "string",
        "email": "string",
        "profile_picture": "string (url, nullable)"
      }
    }
    ```
*   **Response (Error 4xx/5xx):** `{ "error": "Error message" }`

### `POST /auth/login`
Logs in an existing user.
*   **Request Body:** `application/json`
    ```json
    {
      "email": "string (required)",
      "password": "string (required)"
    }
    ```
*   **Response (200 OK):** `application/json`
    ```json
    {
      "token": "string (JWT)",
      "user": {
        "id": "string (user_id)",
        "name": "string",
        "email": "string",
        "profile_picture": "string (url, nullable)"
      }
    }
    ```
*   **Response (Error 401/400):** `{ "error": "Invalid credentials" / "Error message" }`

### `POST /auth/logout`
Logs out a user by adding their current JWT to a blocklist.
*   **Headers:** `Authorization: Bearer <JWT>` (Required)
*   **Response (200 OK):** `{ "message": "Logout successful." }`
*   **Response (Error):** `{ "error": "Error message" }`

### `POST /api/auth/request-password-reset`
Initiates a password reset process by sending an email with a reset link.
*   **Request Body:** `application/json`
    ```json
    {
      "email": "string (required)"
    }
    ```
*   **Response (200 OK):** `{ "message": "If your email is registered, you will receive a password reset link." }`

### `POST /api/auth/reset-password`
Resets the user's password using a token from the password reset email.
*   **Request Body:** `application/json`
    ```json
    {
      "token": "string (required, from email link)",
      "newPassword": "string (required)"
    }
    ```
*   **Response (200 OK):** `{ "message": "Password reset successfully." }`

### `GET /auth/microsoft/initiate`
Initiates the OAuth 2.0 flow for Microsoft Graph user authentication (for calendar, etc.).
*   **Requires Authentication:** Yes (app user must be logged in).
*   **Response:** 302 Redirect to Microsoft login page.

### `GET /auth/microsoft/callback`
Handles the callback from Microsoft after user authentication and consent. Exchanges auth code for tokens.
*   **Response:** 302 Redirect to a frontend page (e.g., `/settings?ms_graph_linked=true` or an error page).

---
## 2. Conversations & Messages (`/api/conversations`)

Authentication required for all endpoints.

### `POST /api/conversations`
Creates a new conversation.
*   **Request Body:** `application/json`
    ```json
    {
      "participantIds": ["string (user_id)", "..."], // IDs of other users to include
      "title": "string (optional, for group chats)"
    }
    ```
*   **Response (201 Created):** `application/json`
    ```json
    {
      "id": "string (conversation_id)",
      "title": "string (nullable)",
      "created_by_user_id": "string (user_id of creator)",
      "created_at": "string (ISO8601 timestamp)",
      "updated_at": "string (ISO8601 timestamp)",
      "last_message_at": "string (ISO8601 timestamp, nullable)",
      "participants": [
        { "user_id": "string", "joined_at": "string", "is_admin": "boolean" }
      ]
    }
    ```

### `GET /api/conversations`
Gets all conversations for the authenticated user.
*   **Response (200 OK):** `application/json` - Array of conversation objects.
    ```json
    [
      {
        "id": "string (conversation_id)",
        "title": "string (nullable)",
        // ... other conversation fields ...
        "participants": [ // Full participant details
          { "id": "string (user_id)", "name": "string", "profile_picture": "string (nullable)" }
        ],
        "last_message": { // Snippet of the last message
          "id": "string (message_id)",
          "sender_id": "string (user_id)",
          "content": "string (snippet)",
          "created_at": "string (ISO8601 timestamp)"
        }
      }
    ]
    ```

### `POST /api/conversations/:conversationId/messages`
Sends a new message to a specific conversation.
*   **Path Parameters:** `conversationId` (string)
*   **Request Body:** `application/json`
    ```json
    {
      "content": "string (required)",
      "message_type": "string (optional, default 'text')",
      "media_url": "string (optional, if message_type is image/video/file)"
    }
    ```
*   **Response (201 Created):** `application/json` - The created message object.
    ```json
    {
      "id": "string (message_id)",
      "conversation_id": "string",
      "sender_id": "string (user_id)",
      "content": "string",
      "message_type": "string",
      "created_at": "string (ISO8601 timestamp)",
      // ... other message fields ...
      "sender": { // Enriched sender info for broadcast via DO
          "id": "string (user_id)",
          "name": "string",
          "profile_picture": "string (nullable)"
      }
    }
    ```

### `GET /api/conversations/:conversationId/messages`
Retrieves messages for a specific conversation.
*   **Path Parameters:** `conversationId` (string)
*   **Query Parameters:** `limit` (integer, optional, default 50)
*   **Response (200 OK):** `application/json` - Array of message objects.
    ```json
    [
      {
        "id": "string (message_id)",
        "sender_id": "string (user_id)",
        "content": "string",
        // ... other message fields ...
        "sender": { // Details of the sender
          "id": "string (user_id)",
          "name": "string",
          "profile_picture": "string (nullable)"
        }
      }
    ]
    ```

### `GET /api/conversations/:conversationId/websocket`
Upgrades the HTTP connection to a WebSocket for real-time messaging in the specified conversation.
*   **Path Parameters:** `conversationId` (string)
*   **Response:** 101 Switching Protocols (if successful).

---
## 3. Video Calls (`/api/video/calls`)

Authentication required for all endpoints.

### `POST /api/video/calls`
Creates a new video call session.
*   **Request Body:** `application/json` (optional)
    ```json
    {
      "title": "string (optional)",
      "max_participants": "integer (optional)"
    }
    ```
*   **Response (201 Created):** `application/json`
    ```json
    {
      "id": "string (call_id)",
      "room_name": "string (unique room identifier)",
      "title": "string (nullable)",
      "created_by_user_id": "string (user_id)",
      "start_time": "string (ISO8601 timestamp)",
      "status": "string (e.g., 'pending')",
      // ... other call fields ...
      "cf_calls_session_id": "string (optional, from Cloudflare Calls)",
      "cf_client_token": "string (optional, for client to join CF Call)"
    }
    ```

### `GET /api/video/calls`
Retrieves video call history for the authenticated user.
*   **Response (200 OK):** `application/json` - Array of video call objects.
    ```json
    [
      {
        "id": "string (call_id)",
        "room_name": "string",
        "title": "string (nullable)",
        // ... other call fields ...
        "current_participant_count": "integer",
        "cf_calls_session_id": "string (optional)",
        "cf_client_token": "string (optional)"
      }
    ]
    ```

### `POST /api/video/calls/:callId/join`
Allows authenticated user to join a video call.
*   **Path Parameters:** `callId` (string)
*   **Response (200 OK):** `{ "message": "Successfully joined call." }`

### `POST /api/video/calls/:callId/leave`
Allows authenticated user to leave a video call.
*   **Path Parameters:** `callId` (string)
*   **Response (200 OK):** `{ "message": "Successfully left call." }`

### `GET /api/video/calls/:callId/signal`
Upgrades HTTP connection to WebSocket for WebRTC signaling for the specified video call.
*   **Path Parameters:** `callId` (string)
*   **Response:** 101 Switching Protocols.

---
## 4. User Profile & Settings (`/api/me`)

Authentication required for all endpoints.

### `GET /api/me/calendars`
Lists the authenticated user's Microsoft calendars (requires MS Graph link).
*   **Response (200 OK):** `application/json` - Array of MS Graph calendar objects.
    ```json
    [
      { "id": "string (ms_calendar_id)", "name": "string", ... }
    ]
    ```

### `POST /api/me/calendar/link`
Links a specific Microsoft calendar ID to the user's profile for syncing.
*   **Request Body:** `application/json`
    ```json
    {
      "msCalendarId": "string (required, ID of the MS calendar)"
    }
    ```
*   **Response (200 OK):** `{ "message": "Calendar linked successfully." }`

### `GET /api/me/calendar/events`
Fetches events from the user's linked Microsoft calendar.
*   **Query Parameters:**
    *   `startDateISO`: string (ISO8601, required)
    *   `endDateISO`: string (ISO8601, required)
*   **Response (200 OK):** `application/json` - Array of MS Graph event objects.

### `POST /api/me/calendar/events`
Creates a new event in the user's linked Microsoft calendar.
*   **Request Body:** `application/json` - MS Graph event resource structure.
    ```json
    {
      "subject": "string",
      "body": { "contentType": "HTML", "content": "string" },
      "start": { "dateTime": "string (ISO8601)", "timeZone": "string" },
      "end": { "dateTime": "string (ISO8601)", "timeZone": "string" },
      // ... other MS Graph event fields ...
    }
    ```
*   **Response (201 Created):** `application/json` - The created MS Graph event object.

---
## 5. Push Notifications (`/api/notifications`)

Authentication required for all endpoints.

### `POST /api/notifications/subscribe`
Subscribes a client device to receive push notifications.
*   **Request Body:** `application/json`
    ```json
    {
      "subscription": { // Standard PushSubscription object
        "endpoint": "string (URL)",
        "keys": {
          "p256dh": "string",
          "auth": "string"
        }
      }
    }
    ```
*   **Response (201 Created / 200 OK):** `{ "message": "Subscribed successfully." }`

### `POST /api/notifications/unsubscribe`
Unsubscribes a client device from push notifications.
*   **Request Body:** `application/json`
    ```json
    {
      "endpoint": "string (URL of the subscription to remove)"
    }
    ```
*   **Response (200 OK / 204 No Content):** `{ "message": "Unsubscribed successfully." }` or no content.

---
## 6. Admin - Third-Party Integrations (`/api/admin/integrations`)

Requires Admin authentication (role check to be implemented).

### `GET /api/admin/integrations`
Lists all configured third-party integrations. Sensitive fields (API keys, secrets) are masked.
*   **Response (200 OK):** Array of integration objects.

### `POST /api/admin/integrations`
Creates a new third-party integration. Plaintext secrets provided in the request are encrypted before storage.
*   **Request Body:** `application/json` (fields: `service_name`, `friendly_name?`, `api_key?`, `client_id?`, `client_secret?`, `tenant_id?`, etc.)
*   **Response (201 Created):** The created integration object (secrets masked).

### `GET /api/admin/integrations/:integrationId`
Retrieves a specific third-party integration. Secrets are masked.
*   **Path Parameters:** `integrationId` (integer)
*   **Response (200 OK):** The integration object.

### `PUT /api/admin/integrations/:integrationId`
Updates an existing third-party integration. Plaintext secrets provided are encrypted.
*   **Path Parameters:** `integrationId` (integer)
*   **Request Body:** `application/json` (fields to update)
*   **Response (200 OK):** The updated integration object (secrets masked).

### `DELETE /api/admin/integrations/:integrationId`
Deletes a third-party integration.
*   **Path Parameters:** `integrationId` (integer)
*   **Response (204 No Content).**

---
## 7. Admin - Seasonal Themes (`/api/admin/themes`)

Requires Admin authentication.

### `GET /api/admin/themes`
Lists all seasonal themes.
*   **Response (200 OK):** Array of theme objects.

### `POST /api/admin/themes`
Creates a new seasonal theme.
*   **Request Body:** `application/json` (fields: `name`, `description?`, `start_date?`, `end_date?`, `theme_config_json?`, `is_active?`)
*   **Response (201 Created):** The created theme object.

### `GET /api/admin/themes/:themeName`
Retrieves a specific theme by its unique name.
*   **Path Parameters:** `themeName` (string)
*   **Response (200 OK):** The theme object.

### `PUT /api/admin/themes/:themeName`
Updates an existing theme. If setting `is_active=true`, other themes may be deactivated.
*   **Path Parameters:** `themeName` (string)
*   **Request Body:** `application/json` (fields to update)
*   **Response (200 OK):** The updated theme object.

### `DELETE /api/admin/themes/:themeName`
Deletes a theme.
*   **Path Parameters:** `themeName` (string)
*   **Response (204 No Content).**

---
## 8. Admin - Email Templates (`/api/admin/email-templates`)

Requires Admin authentication.

### `GET /api/admin/email-templates`
Lists all email templates.
*   **Response (200 OK):** Array of email template objects.

### `POST /api/admin/email-templates`
Creates a new email template.
*   **Request Body:** `application/json` (fields: `template_name`, `subject_template`, `body_html_template`, `default_sender_name?`, `default_sender_email?`)
*   **Response (201 Created):** The created template object.

### `GET /api/admin/email-templates/:templateName`
Retrieves a template by its unique name.
*   **Path Parameters:** `templateName` (string)
*   **Response (200 OK):** The template object.

### `PUT /api/admin/email-templates/:templateName`
Updates an existing email template.
*   **Path Parameters:** `templateName` (string)
*   **Request Body:** `application/json` (fields to update)
*   **Response (200 OK):** The updated template object.

### `DELETE /api/admin/email-templates/:templateName`
Deletes an email template.
*   **Path Parameters:** `templateName` (string)
*   **Response (204 No Content).**

---
## 9. Admin - Test Harness (Planned - `/api/admin/test-harness`)
These endpoints are planned for a special admin testing page and will require specific authentication (PIN + Admin OAuth).

*   `POST /api/admin/test-harness/verify-pin`: Verifies the admin test PIN.
*   `POST /api/admin/test-harness/db/initialize`: Initializes/seeds database from SQL files.
*   `POST /api/admin/test-harness/generate-test-token`: Generates a JWT for a specified user/role for testing.
*   `POST /api/admin/test-harness/create-test-user`: Creates a test user.

---
## 10. Miscellaneous

### `GET /test`
A simple test route, may check basic D1 connectivity. (Consider removal in production).

### `GET /api/test-email`
Route for directly testing the email sending functionality via MS Graph. (Consider admin protection or removal in production).

```
