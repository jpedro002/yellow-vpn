import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { toast } from "sonner";
import { ClientMessage, WireState, stateLabel, vpnNotice } from "@/lib/vpn";
import { IS_MOBILE } from "@/hooks/useIsMobile";

export interface VpnHandlers {
  /** The gateway demands a new password; `prompt` is its own text. */
  onPasswordExpired?: (prompt: string) => void;
  /** The gateway accepted the replacement password sent with the last connect. */
  onPasswordChanged?: () => void;
}

export function useVpnState(handlers: VpnHandlers = {}) {
  const [raw, setRaw] = useState<WireState | null>(null);
  // Latest handlers without re-subscribing the listener/poll on every render.
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  useEffect(() => {
    // Mobile: plugin JS events are ACL-blocked, so poll the app command
    // vpn_status (which bridges to the Kotlin VpnService) for the tunnel state.
    if (IS_MOBILE) {
      let alive = true;
      let last = "";
      const poll = async () => {
        try {
          const s = await invoke<WireState>("vpn_status");
          if (!alive) return;
          setRaw(s);
          const key = stateLabel(s);
          if (key !== last) {
            last = key;
            if (s === "Established") toast.success("Connected", { id: "vpn" });
            else if (s === "Connecting") toast.loading("Connecting…", { id: "vpn" });
            else if (typeof s === "object" && "Reconnecting" in s)
              toast.warning("Reconnecting…", { id: "vpn" });
            else if (s === "Disconnected") toast.dismiss("vpn");
          }
          // Password-rotation notices are consume-once on the native side, so a
          // failure here only delays them until the next tick.
          const n = await vpnNotice();
          if (!alive) return;
          if (n.passwordChanged) handlersRef.current.onPasswordChanged?.();
          if (n.passwordExpired !== null) {
            toast.dismiss("vpn");
            handlersRef.current.onPasswordExpired?.(n.passwordExpired);
          }
        } catch {
          /* ignore transient poll errors */
        }
      };
      poll();
      const iv = setInterval(poll, 1200);
      return () => {
        alive = false;
        clearInterval(iv);
      };
    }

    const un = listen<ClientMessage>("vpn://state", (e) => {
      const msg = e.payload;
      if (msg === "PasswordChanged") {
        handlersRef.current.onPasswordChanged?.();
      } else if (typeof msg === "object" && "State" in msg) {
        const s = msg.State;
        setRaw(s);
        if (s === "Established") toast.success("Connected", { id: "vpn" });
        else if (s === "Connecting") toast.loading("Connecting…", { id: "vpn" });
        else if (s === "Disconnected") toast("Disconnected", { id: "vpn" });
        else if (typeof s === "object" && "Reconnecting" in s)
          toast.warning(stateLabel(s), { id: "vpn" });
      } else if (typeof msg === "object" && "PasswordExpired" in msg) {
        // Terminal for this attempt: the engine stopped, nothing is connecting.
        setRaw("Disconnected");
        toast.dismiss("vpn");
        handlersRef.current.onPasswordExpired?.(msg.PasswordExpired.prompt);
      } else if (typeof msg === "object" && "Error" in msg) {
        toast.error(msg.Error.message);
      }
    });
    return () => {
      un.then((f) => f());
    };
  }, []);

  const status = raw ? stateLabel(raw) : "Disconnected";
  return { status, raw };
}
