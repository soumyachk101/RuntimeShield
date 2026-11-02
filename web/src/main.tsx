// Entry point. Self-hosted fonts come from the @fontsource packages
// (SIL OFL); binary font files are NOT vendored into the repo — @fontsource
// is the self-hosting mechanism, and the system fallbacks are declared in
// global.css (--rs-font-ui / --rs-font-mono).
import "@fontsource/geist-sans/400.css";
import "@fontsource/geist-sans/500.css";
import "@fontsource/geist-sans/600.css";
import "@fontsource/geist-mono/400.css";
import "@fontsource/geist-mono/500.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import "./styles/global.css";

const container = document.getElementById("root");
if (!container) {
  // Fail loudly in the document rather than rendering nothing silently.
  document.body.innerHTML =
    '<pre style="padding:24px;font-family:monospace;color:#f87171">RuntimeShield console failed to mount: missing #root element.</pre>';
} else {
  createRoot(container).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
