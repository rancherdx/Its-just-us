// Function to send email using the MailChannels API
async function sendEmail(to, subject, body) {
  const response = await fetch("https://api.mailchannels.net/tx/v1/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: to }] }],
      from: { email: "no-reply@itsjust.us", name: "Itsjust.us" },
      subject,
      content: [{ type: "text/plain", value: body }],
    }),
  });

  // Check if the email was sent successfully
  return response.ok;
}

// Main handler for the Worker
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Handle the send-email API endpoint
    if (url.pathname === "/api/send-email" && request.method === "POST") {
      try {
        // Call the sendEmail function
        const emailSent = await sendEmail("user@example.com", "Welcome!", "Thanks for joining!");

        if (emailSent) {
          return new Response("Email sent successfully!", { status: 200 });
        } else {
          return new Response("Failed to send email.", { status: 500 });
        }
      } catch (error) {
        console.error("Error sending email:", error);
        return new Response("Internal server error.", { status: 500 });
      }
    }

    // Return 404 for any other paths
    return new Response("Not found", { status: 404 });
  },
};