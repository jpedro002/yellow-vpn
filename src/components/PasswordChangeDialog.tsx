import { useEffect, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Drawer, DrawerContent, DrawerFooter } from "@/components/ui/drawer";
import { useIsMobile } from "@/hooks/useIsMobile";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

/**
 * Asks for a replacement password after the gateway reports the current one as
 * expired. `onSubmit` reconnects with the new password; the gateway validates it
 * against its own policy, so the only checks here are the ones that can be wrong
 * by typo: non-empty, different from the old one, and typed twice the same.
 */
export function PasswordChangeDialog({
  open,
  profileName,
  prompt,
  currentPassword,
  onSubmit,
  onCancel,
}: {
  open: boolean;
  profileName: string;
  /** The gateway's own wording, shown as-is. */
  prompt: string;
  currentPassword: string;
  onSubmit: (newPassword: string) => void;
  onCancel: () => void;
}) {
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const isMobile = useIsMobile();

  useEffect(() => {
    if (open) {
      setNext("");
      setAgain("");
    }
  }, [open]);

  const mismatch = again.length > 0 && next !== again;
  const same = next.length > 0 && next === currentPassword;
  const valid = next.length > 0 && next === again && !same;

  const submit = () => {
    if (valid) onSubmit(next);
  };

  const body = (
    <div className="grid gap-4">
      <p className="whitespace-pre-line text-sm text-muted-foreground">
        {prompt || "Your password has expired."}
      </p>
      <label className="grid gap-1.5">
        <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
          New password
        </span>
        <Input
          type="password"
          autoFocus
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
        />
      </label>
      <label className="grid gap-1.5">
        <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
          Retype password
        </span>
        <Input
          type="password"
          autoComplete="new-password"
          value={again}
          onChange={(e) => setAgain(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") submit();
          }}
        />
      </label>
      {(mismatch || same) && (
        <p className="font-mono text-[11px] text-destructive">
          {same ? "The new password must differ from the current one." : "Passwords do not match."}
        </p>
      )}
    </div>
  );

  const heading = (
    <DialogHeader className="mb-5">
      <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-brand">
        Password expired
      </p>
      <DialogTitle className="text-xl">{profileName || "Change password"}</DialogTitle>
    </DialogHeader>
  );

  const actions = (
    <>
      <Button variant="ghost" onClick={onCancel}>
        Cancel
      </Button>
      <Button onClick={submit} disabled={!valid} className="font-semibold">
        Change and connect
      </Button>
    </>
  );

  if (isMobile) {
    return (
      <Drawer open={open} onOpenChange={(o) => !o && onCancel()}>
        <DrawerContent>
          <div className="h-1 w-full bg-brand" />
          <div className="overflow-y-auto px-5 pt-4">
            {heading}
            {body}
          </div>
          <DrawerFooter className="flex-row justify-end gap-2 border-t border-line">
            {actions}
          </DrawerFooter>
        </DrawerContent>
      </Drawer>
    );
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onCancel()}>
      <DialogContent className="gap-0 overflow-hidden p-0 sm:max-w-md">
        <div className="h-1 w-full bg-brand" />
        <div className="p-6">
          {heading}
          {body}
          <DialogFooter className="mt-6 gap-2 sm:gap-2">{actions}</DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  );
}
