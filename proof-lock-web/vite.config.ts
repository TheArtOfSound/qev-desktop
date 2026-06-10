import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(fileURLToPath(import.meta.url));
const sodiumBundle = path.resolve(
  rootDir,
  "node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js"
);

export default defineConfig({
  plugins: [react()],
  base: "./",
  resolve: {
    alias: {
      "libsodium-wrappers-sumo": sodiumBundle
    }
  },
  build: {
    target: "es2022",
    commonjsOptions: {
      transformMixedEsModules: true
    }
  },
  optimizeDeps: {
    exclude: ["libsodium-wrappers-sumo"]
  }
});
