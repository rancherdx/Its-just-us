import React, { useState } from "react";
import api from "../services/api";
import { useNavigate } from "react-router-dom";

function Register() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await api.post("/auth/register", { name, email, password });
      // Assuming a successful response (e.g., 201 status) will have a body like:
      // { message: "User registered successfully. A welcome email is being sent." }
      if (response.data && response.data.message) {
        alert(response.data.message); // Display success message
      } else {
        alert("Registration successful!"); // Fallback success message
      }
      navigate("/login");
    } catch (error) {
      console.error("Registration failed:", error);
      if (error.response && error.response.data && error.response.data.message) {
        alert(`Registration failed: ${error.response.data.message}`); // Display backend error message
      } else if (error.message) {
        alert(`Registration failed: ${error.message}`);
      } else {
        alert("Registration failed. Please try again."); // Generic error message
      }
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input type="text" placeholder="Name" onChange={(e) => setName(e.target.value)} />
      <input type="email" placeholder="Email" onChange={(e) => setEmail(e.target.value)} />
      <input type="password" placeholder="Password" onChange={(e) => setPassword(e.target.value)} />
      <button type="submit">Register</button>
    </form>
  );
}

export default Register;