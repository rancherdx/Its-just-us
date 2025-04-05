import React, { useState, useEffect } from "react";
import api from "../services/api";

function Newsfeed() {
  const [posts, setPosts] = useState([]);
  const [newPost, setNewPost] = useState("");

  useEffect(() => {
    api.get("/posts").then((response) => setPosts(response.data));
  }, []);

  const handlePostSubmit = async (e) => {
    e.preventDefault();
    await api.post("/posts", { content: newPost });
    setNewPost("");
    api.get("/posts").then((response) => setPosts(response.data));
  };
  return (
    <div>
      <form onSubmit={handlePostSubmit}>
        <textarea value={newPost} onChange={(e) => setNewPost(e.target.value)} />
        <button type="submit">Post</button>
      </form>
      {posts.map((post) => (
        <div key={post.id}>
          <p>{post.content}</p>
        </div>
      ))}
    </div>
  );
}

export default Newsfeed;