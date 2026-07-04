import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import tsConfigPaths from "vite-tsconfig-paths";
import { tanstackRouter } from "@tanstack/router-plugin/vite";

// Plain Vite + TanStack Router SPA. Builds to static assets in dist/ —
// no server, deploy to any static host. The console talks to the IAM
// backend only over its REST API (VITE_API_BASE_URL).
export default defineConfig({
  plugins: [
    tsConfigPaths(),
    tailwindcss(),
    // Router plugin must run before the React plugin.
    tanstackRouter({ target: "react", autoCodeSplitting: true }),
    react(),
  ],
  server: { port: 5173 },
});
