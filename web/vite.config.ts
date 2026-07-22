import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      "/api": "http://127.0.0.1:8082",
      "/oauth": "http://127.0.0.1:8082",
      "/.well-known": "http://127.0.0.1:8082",
      "/verify-email": "http://127.0.0.1:8082",
      "/media": "http://127.0.0.1:8082",
    },
  },
});
