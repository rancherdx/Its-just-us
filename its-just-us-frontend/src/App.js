import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Newsfeed from "./pages/Newsfeed";
import Messenger from "./pages/Messenger";
import Calendar from "./pages/Calendar";

function App() {
  const isAuthenticated = () => !!localStorage.getItem("token");
  const ProtectedRoute = ({ children }) => {
    return isAuthenticated() ? children : <Navigate to="/login" />;
  };

  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/newsfeed" element={<ProtectedRoute><Newsfeed /></ProtectedRoute>} />
        <Route path="/messenger" element={<ProtectedRoute><Messenger /></ProtectedRoute>} />
        <Route path="/calendar" element={<ProtectedRoute><Calendar /></ProtectedRoute>} />
        <Route path="/" element={<Navigate to="/newsfeed" />} />
      </Routes>
    </Router>
  );
}

export default App;