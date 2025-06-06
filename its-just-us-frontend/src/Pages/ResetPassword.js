import React, { useState, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import api from "../services/api"; // Assuming this path is correct

/**
 * ResetPassword component.
 * This page allows users to set a new password using a token provided in the URL.
 * The token is typically received via an email link.
 * It validates the token and new password, then communicates with the backend API.
 */
function ResetPassword() {
  const [searchParams] = useSearchParams(); // Hook to access URL query parameters
  const navigate = useNavigate(); // Hook for programmatic navigation
  const [token, setToken] = useState(null);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState(""); // State for displaying validation or API error messages

  // useEffect hook to extract the 'token' from the URL query parameters when the component mounts.
  useEffect(() => {
    const urlToken = searchParams.get("token");
    if (urlToken) {
      setToken(urlToken); // Store the found token in state
    } else {
      // If no token is found in the URL, set an error message.
      setError("Password reset token not found in URL. Please use the link from your email.");
    }
  }, [searchParams]); // Dependency array ensures this effect runs when searchParams change.

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage(""); // Clear previous success messages
    setError("");   // Clear previous error messages

    // Ensure a token was found and is available.
    if (!token) {
      setError("Cannot reset password without a token. Please use the link from your email.");
      return;
    }

    // Client-side validation: Check if passwords match.
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    // Client-side validation: Basic password length check.
    if (newPassword.length < 6) {
        setError("Password must be at least 6 characters long.");
        return;
    }

    try {
      // Make API call to reset the password
      const response = await api.post("/api/auth/reset-password", { token, newPassword });
      if (response.data && response.data.message) {
        setMessage(response.data.message + " You can now log in with your new password.");
        // Optionally, redirect to login after a short delay
        setTimeout(() => {
          navigate("/login");
        }, 3000); // 3 seconds delay
      } else {
        setMessage("Password reset successfully. You can now log in.");
        setTimeout(() => {
          navigate("/login");
        }, 3000);
      }
    } catch (err) {
      console.error("Reset password failed:", err);
      if (err.response && err.response.data && err.response.data.message) {
        setError(`Error: ${err.response.data.message}`);
      } else if (err.message) {
        setError(`Error: ${err.message}`);
      } else {
        setError("Failed to reset password. Please try again or request a new link.");
      }
    }
  };

  if (!token && !error) { // Still checking for token from effect
    return <p>Loading token...</p>;
  }

  return (
    <div>
      <h2>Reset Password</h2>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {message && <p style={{ color: "green" }}>{message}</p>}
      {!message && ( // Only show form if no success message is displayed
        <form onSubmit={handleSubmit}>
          <div>
            <label htmlFor="newPassword">New Password:</label>
            <input
              type="password"
              id="newPassword"
              placeholder="Enter new password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
          </div>
          <div>
            <label htmlFor="confirmPassword">Confirm New Password:</label>
            <input
              type="password"
              id="confirmPassword"
              placeholder="Confirm new password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>
          <button type="submit" disabled={!token}>Reset Password</button>
        </form>
      )}
    </div>
  );
}

export default ResetPassword;
