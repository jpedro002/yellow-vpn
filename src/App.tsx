import { useEffect, useState } from "react";
import { Reveal, useReducedMotion } from "@/lib/motion";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { getVersion } from "@tauri-apps/api/app";
import iconUrl from "@/assets/yellow_vpn_icon.svg";
import { Minus, X } from "lucide-react";
import { toast } from "sonner";
import { Toaster } from "@/components/ui/sonner";
import { useVpnState } from "@/hooks/useVpnState";
import { useWintun } from "@/hooks/useWintun";
import { useIsMobile } from "@/hooks/useIsMobile";
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
  const isMobile = useIsMobile();
  // App version read from tauri.conf.json at runtime (single source of truth),
  // so the footer never drifts from the shipped build.
  const [version, setVersion] = useState<string | null>(null);
  useEffect(() => {
    getVersion().then(setVersion).catch(() => {});
  }, []);
  // Optimistic "Connecting" so the UI reacts instantly on tap. On mobile the
  // state is polled (~1.2s) and a fast connect can jump straight to Established,
  // skipping Connecting; this bridges that gap until the real state arrives.
  const [pending, setPending] = useState(false);
  useEffect(() => {
    if (raw === "Established" || raw === "Disconnected" || (raw && typeof raw === "object"))
      setPending(false);
  }, [raw]);
  const shownRaw =
    pending && (raw == null || raw === "Disconnected") ? ("Connecting" as const) : raw;

  async function refresh() {
    const list = await listProfiles();
    setProfiles(list);
    setSelected((cur) => (cur ? list.find((p) => p.id === cur.id) ?? null : null));
  }
  useEffect(() => {
    refresh();
  }, []);

  async function handleConnect() {
    if (!selected) return;
    setPending(true);
    try {
      await connectProfile(selected);
    } catch (e) {
      const msg = String(e);
      toast.error(
        msg.includes("UAC") || msg.includes("elevation")
          ? "Connection needs administrator access — approve the prompt to continue."
          : `Couldn't start the connection: ${msg}`,
      );
      setPending(false);
    }
  }

  const t = tone(shownRaw);

  // Window controls exist only on desktop (custom OS decoration). On mobile the
  // OS owns the window chrome, so there is no Tauri window to drive.
  const win = isMobile ? null : getCurrentWindow();

  return (
    <div
      className={`relative flex h-full flex-col overflow-hidden bg-background text-foreground ${
        isMobile ? "" : "rounded-xl border border-line"
      }`}
    >
      <Toaster theme="dark" richColors position="bottom-right" />

      {/* Ambient atmosphere */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-[-12%] h-105 w-190 -translate-x-1/2 rounded-full bg-brand/10 blur-[130px]" />
        <div
          className="absolute inset-0 opacity-[0.035]"
          style={{
            backgroundImage:
              "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
            backgroundSize: "34px 34px",
          }}
        />
      </div>

      <Reveal reduce={reduce} className="relative flex min-h-0 flex-1 flex-col">
        {/* Desktop: custom title bar (OS decoration off) — drag region + window
            controls. Mobile: a plain header; the OS draws the status bar, so we
            just pad for the safe-area inset and show branding + status. */}
        <header
          data-reveal-item
          {...(isMobile ? {} : { "data-tauri-drag-region": true })}
          className="flex select-none items-center justify-between border-b border-line py-3 pl-6 pr-2"
          style={isMobile ? { paddingTop: "calc(env(safe-area-inset-top) + 0.75rem)" } : undefined}
        >
          <div className="pointer-events-none flex items-center gap-2.5">
            <img
              src={iconUrl}
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
            {!isMobile && win && (
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
            )}
          </div>
        </header>

        {/* First-run driver setup gate, then the control panel */}
        {setup.stage !== "ready" ? (
          <main className="flex flex-1 items-center justify-center p-6">
            <SetupGate {...setup} />
          </main>
        ) : (
          <main className="mx-auto grid min-h-0 w-full max-w-5xl flex-1 content-start gap-5 overflow-y-auto p-6 md:grid-cols-[1.05fr_1fr]">
            <div data-reveal-item>
              <StatusHero
                raw={shownRaw}
                active={selected}
                canConnect={!!selected}
                onConnect={handleConnect}
                onDisconnect={() => {
                  setPending(false);
                  disconnect();
                }}
              />
            </div>
            <div data-reveal-item>
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
            </div>
          </main>
        )}

        {/* Status bar */}
        <footer
          data-reveal-item
          className="flex items-center justify-between border-t border-line px-6 py-2.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground"
        >
          <span>{profiles.length} profile{profiles.length === 1 ? "" : "s"}</span>
          <span className="text-muted-foreground/60">yellow vpn{version ? ` · v${version}` : ""}</span>
        </footer>
      </Reveal>
    </div>
  );
}
