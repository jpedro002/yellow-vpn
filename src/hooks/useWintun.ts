import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export type WintunStage =
  | "checking"
  | "downloading"
  | "extracting"
  | "ready"
  | "error";

interface Progress {
  stage: "download" | "extract";
  downloaded: number;
  total: number;
}

export interface WintunState {
  stage: WintunStage;
  downloaded: number;
  total: number;
  error: string | null;
  retry: () => void;
}

/** First-run gate: ensures wintun.dll exists (downloads on Windows if missing),
 *  exposing live download progress from the `wintun://progress` event. */
export function useWintun(): WintunState {
  const [stage, setStage] = useState<WintunStage>("checking");
  const [downloaded, setDownloaded] = useState(0);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    let un: (() => void) | undefined;

    setStage("checking");
    setError(null);
    setDownloaded(0);
    setTotal(0);

    listen<Progress>("wintun://progress", (e) => {
      if (cancelled) return;
      const p = e.payload;
      setStage(p.stage === "extract" ? "extracting" : "downloading");
      setDownloaded(p.downloaded);
      setTotal(p.total);
    }).then((f) => {
      un = f;
    });

    invoke<boolean>("ensure_wintun")
      .then(() => {
        if (!cancelled) setStage("ready");
      })
      .catch((err) => {
        if (!cancelled) {
          setError(String(err));
          setStage("error");
        }
      });

    return () => {
      cancelled = true;
      un?.();
    };
  }, [attempt]);

  return { stage, downloaded, total, error, retry: () => setAttempt((a) => a + 1) };
}
