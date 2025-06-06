import React, { useState } from "react";
import api from "../services/api"; // Assuming this path is correct based on Login.js and Register.js
// We might not need useNavigate for this page if we just show a message.
// import { useNavigate } from "react-router-dom";

/**
 * ForgotPassword component.
 * This page allows users to enter their email address to request a password reset link.
 * It communicates with the backend API to initiate the password reset process.
 */
function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState(""); // State to display success or error messages to the user

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage(""); // Clear any previous messages before a new submission
    try {
      // Make API call to request password reset
      const response = await api.post("/api/auth/request-password-reset", { email });
      // Backend typically returns a message like: { message: "If your email is registered, you will receive a password reset link." }
      if (response.data && response.data.message) {
        setMessage(response.data.message); // Display the message from the backend
      } else {
        // Fallback message if the backend response is not as expected
        setMessage("Password reset request submitted. Please check your email.");
      }
    } catch (error) {
      console.error("Forgot password request failed:", error);
      // Handle various error response structures to provide the best possible message
      if (error.response && error.response.data && error.response.data.message) {
        setMessage(`Error: ${error.response.data.message}`);
      } else if (error.message) {
        setMessage(`Error: ${error.message}`);
      } else {
        // Generic fallback error message
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
