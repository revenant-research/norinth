// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

/// <reference types="vitest" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../app/dashboard/static",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8001",
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    // restore spies to their originals before each test so a spy installed in
    // one test cannot stack on or capture a late call from another
    restoreMocks: true,
  },
});
