import { motion, useReducedMotion } from "framer-motion";
import { AlertTriangle, RotateCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { WintunState } from "@/hooks/useWintun";

const mb = (b: number) => (b / 1048576).toFixed(1);

export function SetupGate({ stage, downloaded, total, error, retry }: WintunState) {
  const reduce = useReducedMotion();
  const pct = total > 0 ? Math.round((downloaded / total) * 100) : 0;
  const indeterminate =
    stage === "checking" || stage === "extracting" || (stage === "downloading" && total === 0);

  const subtitle =
    stage === "checking"
      ? "Checking network driver…"
      : stage === "downloading"
        ? "Downloading network driver"
        : stage === "extracting"
          ? "Installing driver…"
          : "Setup failed";

  return (
    <div className="flex w-full max-w-sm flex-col items-center gap-6 text-center">
      <motion.img
        src="/yellow_vpn_icon.svg"
        alt="Yellow VPN"
        className="h-16 w-16 rounded-2xl shadow-lg"
        animate={reduce || stage === "error" ? {} : { scale: [1, 1.06, 1] }}
        transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
      />

      <div className="space-y-1">
        <h1 className="text-lg font-bold tracking-tight">Preparing Yellow VPN</h1>
        <p
          className={`font-mono text-xs ${
            stage === "error" ? "text-destructive" : "text-muted-foreground"
          }`}
        >
          {subtitle}
        </p>
      </div>

      {stage === "error" ? (
        <div className="flex w-full flex-col items-center gap-3">
          <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-left">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
            <p className="font-mono text-[11px] leading-relaxed text-muted-foreground">
              {error}
            </p>
          </div>
          <Button onClick={retry} className="gap-2 font-semibold">
            <RotateCw className="h-4 w-4" /> Retry
          </Button>
        </div>
      ) : (
        <div className="w-full space-y-2">
          {/* Progress track */}
          <div className="relative h-2 w-full overflow-hidden rounded-full bg-secondary">
            {indeterminate ? (
              <motion.span
                className="absolute inset-y-0 w-1/3 rounded-full bg-brand"
                animate={reduce ? { x: 0 } : { x: ["-100%", "300%"] }}
                transition={{ duration: 1.1, repeat: Infinity, ease: "easeInOut" }}
              />
            ) : (
              <motion.span
                className="absolute inset-y-0 left-0 rounded-full bg-brand"
                animate={{ width: `${pct}%` }}
                transition={{ ease: "easeOut", duration: 0.2 }}
              />
            )}
          </div>
          <div className="flex justify-between font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            <span>{indeterminate ? "please wait" : `${pct}%`}</span>
            {total > 0 && stage === "downloading" && (
              <span>
                {mb(downloaded)} / {mb(total)} MB
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
