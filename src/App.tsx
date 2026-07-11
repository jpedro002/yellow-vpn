import { useEffect, useState } from "react";
import { motion, useReducedMotion, type Variants } from "framer-motion";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Minus, X } from "lucide-react";
import { Toaster } from "@/components/ui/sonner";
import { useVpnState } from "@/hooks/useVpnState";
import { useWintun } from "@/hooks/useWintun";
import { StatusHero } from "@/components/StatusHero";
import { ProfileList } from "@/components/ProfileList";
import { SetupGate } from "@/components/SetupGate";
import {
  Profile,
  listProfiles,
  createProfile,
  updateProfile,
  deleteProfile,
  connectProfile,
  disconnect,
} from "@/lib/vpn";
import "./App.css";

function tone(raw: ReturnType<typeof useVpnState>["raw"]) {
  if (raw === "Established") return { dot: "bg-ok", text: "text-ok", label: "ONLINE", live: false };
  if (raw === "Connecting") return { dot: "bg-brand", text: "text-brand", label: "LINKING", live: true };
  if (raw && typeof raw === "object") return { dot: "bg-warn", text: "text-warn", label: "RETRY", live: true };
  return { dot: "bg-muted-foreground", text: "text-muted-foreground", label: "OFFLINE", live: false };
}

export default function App() {
  const { raw } = useVpnState();
  const setup = useWintun();
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [selected, setSelected] = useState<Profile | null>(null);
  const reduce = useReducedMotion();

  async function refresh() {
    const list = await listProfiles();
    setProfiles(list);
    setSelected((cur) => (cur ? list.find((p) => p.id === cur.id) ?? null : null));
  }
  useEffect(() => {
    refresh();
  }, []);

  const t = tone(raw);

  const container: Variants = {
    hidden: {},
    show: { transition: { staggerChildren: reduce ? 0 : 0.08, delayChildren: 0.05 } },
  };
  const item: Variants = {
    hidden: { opacity: 0, y: reduce ? 0 : 14 },
    show: { opacity: 1, y: 0, transition: { duration: 0.4, ease: [0.16, 1, 0.3, 1] } },
  };

  const win = getCurrentWindow();

  return (
    <div className="relative flex h-full flex-col overflow-hidden rounded-xl border border-line bg-background text-foreground">
      <Toaster theme="dark" richColors position="top-right" />

      {/* Ambient atmosphere */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-[-12%] h-[420px] w-[760px] -translate-x-1/2 rounded-full bg-brand/10 blur-[130px]" />
        <div
          className="absolute inset-0 opacity-[0.035]"
          style={{
            backgroundImage:
              "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
            backgroundSize: "34px 34px",
          }}
        />
      </div>

      <motion.div
        className="relative flex flex-1 flex-col"
        variants={container}
        initial="hidden"
        animate="show"
      >
        {/* Custom title bar (OS decoration is off) — drag region + window controls */}
        <motion.header
          variants={item}
          data-tauri-drag-region
          className="flex select-none items-center justify-between border-b border-line py-3 pl-6 pr-2"
        >
          <div className="pointer-events-none flex items-center gap-2.5">
            <img
              src="/yellow_vpn_icon.svg"
              alt="Yellow VPN"
              className="h-7 w-7 rounded-md shadow-sm"
            />
            <div className="flex items-baseline gap-2">
              <span className="text-xl font-extrabold tracking-tight text-brand">YELLOW</span>
              <span className="font-mono text-xs uppercase tracking-[0.35em] text-muted-foreground">
                vpn
              </span>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="pointer-events-none flex items-center gap-2 font-mono text-[11px]">
              <span className="relative flex h-2 w-2">
                {t.live && !reduce && (
                  <span className={`absolute inline-flex h-full w-full animate-ping rounded-full ${t.dot} opacity-75`} />
                )}
                <span className={`relative inline-flex h-2 w-2 rounded-full ${t.dot}`} />
              </span>
              <span className={`uppercase tracking-widest ${t.text}`}>{t.label}</span>
            </div>
            <div className="flex items-center">
              <button
                aria-label="Minimize"
                onClick={() => win.minimize()}
                className="flex h-8 w-9 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
              >
                <Minus className="h-4 w-4" />
              </button>
              <button
                aria-label="Close to tray"
                onClick={() => win.close()}
                className="flex h-8 w-9 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-destructive hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>
        </motion.header>

        {/* First-run driver setup gate, then the control panel */}
        {setup.stage !== "ready" ? (
          <main className="flex flex-1 items-center justify-center p-6">
            <SetupGate {...setup} />
          </main>
        ) : (
          <main className="mx-auto grid w-full max-w-5xl flex-1 content-start gap-5 p-6 md:grid-cols-[1.05fr_1fr]">
            <motion.div variants={item}>
              <StatusHero
                raw={raw}
                active={selected}
                canConnect={!!selected}
                onConnect={() => selected && connectProfile(selected)}
                onDisconnect={() => disconnect()}
              />
            </motion.div>
            <motion.div variants={item}>
              <ProfileList
                profiles={profiles}
                selectedId={selected?.id ?? null}
                onSelect={setSelected}
                onCreate={async (p) => {
                  await createProfile(p);
                  await refresh();
                }}
                onEdit={async (id, p) => {
                  await updateProfile(id, p);
                  await refresh();
                }}
                onDelete={async (id) => {
                  await deleteProfile(id);
                  await refresh();
                }}
              />
            </motion.div>
          </main>
        )}

        {/* Status bar */}
        <motion.footer
          variants={item}
          className="flex items-center justify-between border-t border-line px-6 py-2.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground"
        >
          <span>{profiles.length} profile{profiles.length === 1 ? "" : "s"}</span>
          <span className="text-muted-foreground/60">yellow vpn · v0.1.0</span>
        </motion.footer>
      </motion.div>
    </div>
  );
}
