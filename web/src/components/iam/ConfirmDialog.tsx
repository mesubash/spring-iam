import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import type { ReactNode } from "react";

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  target,
  confirmLabel = "Confirm",
  destructive = false,
  onConfirm,
  pending = false,
  children,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  title: string;
  description?: ReactNode;
  target?: string;
  confirmLabel?: string;
  destructive?: boolean;
  onConfirm: () => void;
  pending?: boolean;
  children?: ReactNode;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description ? <DialogDescription>{description}</DialogDescription> : null}
          {target ? (
            <p className="mt-2 rounded border border-[var(--border)] bg-[var(--background)] px-2 py-1 font-mono text-xs">
              {target}
            </p>
          ) : null}
        </DialogHeader>
        {children}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
            Cancel
          </Button>
          <Button
            onClick={onConfirm}
            disabled={pending}
            style={destructive ? { backgroundColor: "var(--destructive)", color: "#fff" } : undefined}
          >
            {pending ? "Working..." : confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}