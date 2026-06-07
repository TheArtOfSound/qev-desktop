import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/qev-desktop/",
  build: {
    target: "es2022"
  },
  optimizeDeps: {
    include: ["libsodium-wrappers-sumo"]
  }
});
