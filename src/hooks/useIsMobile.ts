import { useEffect, useState } from "react";

/**
 * True when running on a mobile Tauri target (Android/iOS). The app runs inside
 * the platform WebView, so the user-agent reliably identifies mobile. Evaluated
 * once at module init and returned as state so components can render
 * platform-specific chrome (drawer vs dialog, no custom title bar, etc.).
 */
function detectMobile(): boolean {
  if (typeof navigator === "undefined") return false;
  return /android|iphone|ipad|ipod/i.test(navigator.userAgent);
}

export const IS_MOBILE = detectMobile();

export function useIsMobile(): boolean {
  const [isMobile] = useState(IS_MOBILE);
  useEffect(() => {}, []);
  return isMobile;
}
