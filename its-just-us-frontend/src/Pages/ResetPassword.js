import React, { useState, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import api from "../services/api"; // Assuming this path is correct

function ResetPassword() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [token, setToken] = useState(null);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState(""); // Specific for validation errors or API errors

  useEffect(() => {
    const urlToken = searchParams.get("token");
    if (urlToken) {
      setToken(urlToken);
    } else {
      setError("Password reset token not found in URL. Please use the link from your email.");
    }
  }, [searchParams]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");

    if (!token) {
      setError("Cannot reset password without a token. Please use the link from your email.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (newPassword.length < 6) { // Basic password length validation
        setError("Password must be at least 6 characters long.");
        return;
    }

    try {
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
