import React from "react";
import ReactDOM from "react-dom/client";
import { LazyMotion, domAnimation } from "framer-motion";
import App from "./App";

// `strict` + `m.*` components (instead of `motion.*`) keep the full framer
// runtime out of the bundle; domAnimation covers all animations/gestures used.
ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <LazyMotion features={domAnimation} strict>
      <App />
    </LazyMotion>
  </React.StrictMode>,
);
