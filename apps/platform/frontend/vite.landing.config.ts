// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// standalone build of the marketing landing for hosting under /norinth on the
// revenant group site
export default defineConfig({
  plugins: [react()],
  base: "/norinth/",
  build: {
    outDir: "dist-landing",
    emptyOutDir: true,
    rollupOptions: {
      input: "landing.html",
    },
  },
});
