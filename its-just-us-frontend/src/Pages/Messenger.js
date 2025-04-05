import React, { useState, useEffect } from "react";
import api from "../services/api";

function Messenger() {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState("");

  useEffect(() => {
    api.get("/messages").then((response) => setMessages(response.data));
  }, []);

  const handleMessageSubmit = async (e) => {
    e.preventDefault();
    await api.post("/messages", { content: newMessage });
    setNewMessage("");
    api.get("/messages").then((response) => setMessages(response.data));
  };

  return (
    <div>
      {messages.map((message) => (
        <p key={message.id}>{message.content}</p>
      ))}
      <form onSubmit={handleMessageSubmit}>
        <input type="text" value={newMessage} onChange={(e) => setNewMessage(e.target.value)} />
        <button type="submit">Send</button>
      </form>
    </div>
  );
}

export default Messenger;