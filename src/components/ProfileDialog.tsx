import { useState, useEffect } from "react";
import { Reveal, useReducedMotion } from "@/lib/motion";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Drawer,
  DrawerContent,
  DrawerFooter,
  DrawerTrigger,
} from "@/components/ui/drawer";
import { useIsMobile } from "@/hooks/useIsMobile";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { NewProfile, Profile, Protocol } from "@/lib/vpn";

const empty: NewProfile = {
  name: "",
  host: "",
  port: 443,
  username: "",
  password: "",
  protocol: "AnyConnect",
  insecure: false,
  cert_sha256: null,
};

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-1.5">
      <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      {children}
    </div>
  );
}

function ColumnHeader({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3">
      <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-brand">
        {children}
      </span>
      <span className="h-px flex-1 bg-line" />
    </div>
  );
}

export function ProfileDialog({
  trigger,
  initial,
  onSubmit,
}: {
  trigger: React.ReactNode;
  initial?: Profile;
  onSubmit: (p: NewProfile) => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [f, setF] = useState<NewProfile>(empty);
  const reduce = useReducedMotion();
  const isMobile = useIsMobile();

  useEffect(() => {
    if (open) setF(initial ? { ...initial } : empty);
  }, [open, initial]);

  const valid = f.name && f.host && f.username;

  async function save() {
    await onSubmit({
      ...f,
      cert_sha256: f.cert_sha256?.trim() ? f.cert_sha256.trim() : null,
    });
    setOpen(false);
  }

  const heading = (
    <div data-reveal-item>
      <DialogHeader className="mb-5">
        <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-brand">
          {initial ? "Edit connection" : "New connection"}
        </p>
        <DialogTitle className="text-xl">
          {initial ? initial.name || "Profile" : "Configure profile"}
        </DialogTitle>
      </DialogHeader>
    </div>
  );

  const actions = (
    <>
      <Button variant="ghost" onClick={() => setOpen(false)}>
        Cancel
      </Button>
      <Button onClick={save} disabled={!valid} className="font-semibold">
        {initial ? "Save changes" : "Create profile"}
      </Button>
    </>
  );

  // The form body is identical across desktop/mobile; only the shell differs
  // (centered Dialog on desktop, bottom Drawer on mobile). The two-column grid
  // collapses to a single column on narrow screens.
  const fields = (
    <>
          <div className="grid grid-cols-1 gap-x-6 gap-y-5 sm:grid-cols-2">
            {/* Left column — gateway */}
            <div data-reveal-item className="grid content-start gap-4">
              <ColumnHeader>Gateway</ColumnHeader>
              <Field label="Profile name">
                <Input
                  placeholder="e.g. Work HQ"
                  value={f.name}
                  onChange={(e) => setF({ ...f, name: e.target.value })}
                />
              </Field>
              <div className="grid grid-cols-[1fr_5rem] gap-3">
                <Field label="Host">
                  <Input
                    className="font-mono"
                    placeholder="vpn.example.com"
                    value={f.host}
                    onChange={(e) => setF({ ...f, host: e.target.value })}
                  />
                </Field>
                <Field label="Port">
                  <Input
                    className="font-mono"
                    type="number"
                    value={f.port}
                    onChange={(e) => setF({ ...f, port: Number(e.target.value) })}
                  />
                </Field>
              </div>
              <Field label="Protocol">
                <Select
                  value={f.protocol}
                  onValueChange={(v) => setF({ ...f, protocol: v as Protocol })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="AnyConnect">AnyConnect (Cisco)</SelectItem>
                    <SelectItem value="Checkpoint">Check Point SNX</SelectItem>
                    <SelectItem value="FortiGate">FortiGate SSL VPN</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
            </div>

            {/* Right column — credentials */}
            <div data-reveal-item className="grid content-start gap-4">
              <ColumnHeader>Credentials</ColumnHeader>
              <Field label="Username">
                <Input
                  value={f.username}
                  onChange={(e) => setF({ ...f, username: e.target.value })}
                />
              </Field>
              <Field label="Password">
                <Input
                  type="password"
                  value={f.password}
                  onChange={(e) => setF({ ...f, password: e.target.value })}
                />
              </Field>
              <Field label="Server cert SHA-256 (optional)">
                <Input
                  className="font-mono text-xs"
                  placeholder="pin fingerprint…"
                  value={f.cert_sha256 ?? ""}
                  onChange={(e) => setF({ ...f, cert_sha256: e.target.value })}
                />
              </Field>
            </div>
          </div>

          {/* Danger toggle — full width */}
          <div data-reveal-item className="mt-5">
            <div
              className={`flex items-center justify-between rounded-md border px-3 py-2.5 transition-colors ${
                f.insecure ? "border-destructive/50 bg-destructive/10" : "border-line"
              }`}
            >
              <div>
                <p className="text-sm font-medium">Skip certificate check</p>
                <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                  Insecure — vulnerable to MITM
                </p>
              </div>
              <Switch
                checked={f.insecure}
                onCheckedChange={(v) => setF({ ...f, insecure: v })}
              />
            </div>
          </div>
    </>
  );

  // Mobile: bottom drawer (more responsive, thumb-friendly, matches the platform).
  if (isMobile) {
    return (
      <Drawer open={open} onOpenChange={setOpen}>
        <DrawerTrigger asChild>{trigger}</DrawerTrigger>
        <DrawerContent>
          <div className="h-1 w-full bg-brand" />
          <Reveal
            reduce={reduce}
            className="overflow-y-auto px-5 pt-4"
            y={10}
            gap={0.05}
            delay={0.04}
            duration={0.22}
          >
            {heading}
            {fields}
          </Reveal>
          <DrawerFooter className="flex-row justify-end gap-2 border-t border-line">
            {actions}
          </DrawerFooter>
        </DrawerContent>
      </Drawer>
    );
  }

  // Desktop: centered dialog.
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="gap-0 overflow-hidden p-0 sm:max-w-2xl">
        <div className="h-1 w-full bg-brand" />
        <Reveal
          reduce={reduce}
          className="p-6"
          y={10}
          gap={0.05}
          delay={0.04}
          duration={0.22}
        >
          {heading}
          {fields}
          <div data-reveal-item>
            <DialogFooter className="mt-6 gap-2 sm:gap-2">{actions}</DialogFooter>
          </div>
        </Reveal>
      </DialogContent>
    </Dialog>
  );
}
