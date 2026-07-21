import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The cockpit is served two ways:
//   - dev: `npm run dev` (Vite on :5173), proxying the API to the backend on :8000
//   - prod: built to dist/ and served same-origin by `orthrus serve --cockpit`
// so the API base is always a relative "/api".
export default defineConfig(({ mode }) => ({
  // Served under /cockpit/ by `orthrus serve --cockpit` in prod; at / in dev.
  base: mode === "production" ? "/cockpit/" : "/",
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": "http://127.0.0.1:8000",
      "/health": "http://127.0.0.1:8000",
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2020",
  },
}));
