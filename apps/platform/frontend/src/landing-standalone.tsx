import React from "react";
import { createRoot } from "react-dom/client";

// self-hosted fonts bundled into the build so the page makes no third-party call
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-sans/700.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";

import { LandingPage } from "./components/landing";
import "./styles.css";

createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <LandingPage />
  </React.StrictMode>,
);
