import axios from "axios";

const API_BASE_URL = "https://its-just-us.design-spek-co.workers.dev/"; // Replace with your Cloudflare Worker URL

const api = axios.create({
  baseURL: API_BASE_URL,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default api;