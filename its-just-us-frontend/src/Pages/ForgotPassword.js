import React, { useState } from "react";
import api from "../services/api"; // Assuming this path is correct based on Login.js and Register.js
// We might not need useNavigate for this page if we just show a message.
// import { useNavigate } from "react-router-dom";

function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState(""); // For displaying success/error messages

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage(""); // Clear previous messages
    try {
      const response = await api.post("/api/auth/request-password-reset", { email });
      // Backend returns: { message: "If your email is registered, you will receive a password reset link." }
      if (response.data && response.data.message) {
        setMessage(response.data.message);
      } else {
        // Fallback, though backend should always provide a message
        setMessage("Password reset request submitted. Please check your email.");
      }
    } catch (error) {
      console.error("Forgot password request failed:", error);
      if (error.response && error.response.data && error.response.data.message) {
        setMessage(`Error: ${error.response.data.message}`);
      } else if (error.message) {
        setMessage(`Error: ${error.message}`);
      } else {
        setMessage("Failed to submit password reset request. Please try again.");
      }
    }
  };

  return (
    <div>
      <h2>Forgot Password</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="email">Email Address:</label>
          <input
            type="email"
            id="email"
            placeholder="Enter your email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <button type="submit">Request Password Reset</button>
      </form>
      {message && <p>{message}</p>}
    </div>
  );
}

export default ForgotPassword;
