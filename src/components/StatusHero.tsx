import { m, AnimatePresence, useReducedMotion } from "framer-motion";
import { Profile, WireState, stateLabel } from "@/lib/vpn";
import { Button } from "@/components/ui/button";

export function StatusHero({
  raw,
  active,
  onConnect,
  onDisconnect,
  canConnect,
}: {
  raw: WireState | null;
  active: Profile | null;
  onConnect: () => void;
  onDisconnect: () => void;
  canConnect: boolean;
}) {
  const reduce = useReducedMotion();
  const connected = raw === "Established";
  const linking =
    raw === "Connecting" || (!!raw && typeof raw === "object" && "Reconnecting" in raw);

  const core = connected ? "bg-ok" : linking ? "bg-brand" : "bg-transparent";
  const ring = connected ? "border-ok" : "border-brand";
  const glow = connected ? "bg-ok" : "bg-brand";

  const headline = connected
    ? "Connected"
    : raw === "Connecting"
      ? "Connecting"
      : raw && typeof raw === "object"
        ? stateLabel(raw)
        : "Not connected";

  return (
    <section className="flex flex-col items-center gap-7 rounded-lg border border-line bg-card p-8">
      {/* Signal core — the signature element */}
      <div className="relative flex h-44 w-44 items-center justify-center">
        {(connected || linking) && (
          <div className={`absolute h-24 w-24 rounded-full ${glow} opacity-20 blur-2xl`} />
        )}
        {linking && (
          <>
            <span className={`signal-ring absolute h-24 w-24 rounded-full border ${ring}`} />
            <span className={`signal-ring signal-ring-2 absolute h-24 w-24 rounded-full border ${ring}`} />
            <span className={`signal-ring signal-ring-3 absolute h-24 w-24 rounded-full border ${ring}`} />
          </>
        )}
        <m.span
          key={connected ? "on" : linking ? "link" : "off"}
          initial={reduce ? false : { scale: 0.6, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ type: "spring", stiffness: 260, damping: 18 }}
          className={
            connected
              ? `h-20 w-20 rounded-full ${core} shadow-[0_0_40px] shadow-ok/40`
              : linking
                ? `h-20 w-20 rounded-full ${core} shadow-[0_0_40px] shadow-brand/40`
                : "h-20 w-20 rounded-full border-2 border-dashed border-muted-foreground/40"
          }
        />
      </div>

      {/* Status text */}
      <div className="h-12 text-center">
        <AnimatePresence mode="wait">
          <m.p
            key={headline}
            initial={reduce ? false : { opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={reduce ? undefined : { opacity: 0, y: -6 }}
            transition={{ duration: 0.18 }}
            className="text-2xl font-bold tracking-tight"
          >
            {headline}
          </m.p>
        </AnimatePresence>
        <p
          className={`mt-1 font-mono text-xs ${
            connected ? "text-ok" : linking ? "text-brand" : "text-muted-foreground"
          }`}
        >
          {connected
            ? `secure tunnel · ${active?.protocol ?? ""}`
            : linking
              ? "negotiating tunnel…"
              : active
                ? `${active.host}:${active.port}`
                : "select a profile"}
        </p>
      </div>

      {/* Active profile chip */}
      {active && (
        <div className="flex w-full items-center justify-center gap-2 font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
          <span className="rounded bg-secondary px-2 py-0.5 text-foreground">{active.name}</span>
          <span className="rounded border border-line px-2 py-0.5">{active.protocol}</span>
          {active.insecure && <span className="rounded px-2 py-0.5 text-destructive">insecure</span>}
        </div>
      )}

      {/* Action */}
      <m.div className="w-full" whileTap={reduce ? undefined : { scale: 0.98 }}>
        {connected || linking ? (
          <Button
            variant="outline"
            className="w-full border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive"
            onClick={onDisconnect}
          >
            Disconnect
          </Button>
        ) : (
          <Button
            className="w-full text-base font-semibold"
            size="lg"
            onClick={onConnect}
            disabled={!canConnect}
          >
            Connect
          </Button>
        )}
      </m.div>
    </section>
  );
}
