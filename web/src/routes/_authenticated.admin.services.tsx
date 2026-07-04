import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { servicesApi } from "@/api/resources";
import type { ServiceRegistryEntry } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { formatDate } from "@/lib/format";
import { useAuthz } from "@/context/AuthzContext";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export const Route = createFileRoute("/_authenticated/admin/services")({
  component: ServicesPage,
});

function ServicesPage() {
  const { features } = useAuthz();
  const q = useQuery({ queryKey: ["services"], queryFn: servicesApi.list });
  const [creating, setCreating] = useState(false);
  const [issuedKey, setIssuedKey] = useState<{ name: string; apiKey: string } | null>(null);

  if (features && !features["service-registry"]) {
    return <p className="text-sm text-[var(--muted-foreground)]">Service registry disabled.</p>;
  }

  const columns: Column<ServiceRegistryEntry>[] = [
    { key: "name", header: "Name", render: (s) => <span className="font-mono text-[13px]">{s.name}</span> },
    { key: "dn", header: "Display name", render: (s) => s.displayName ?? "—" },
    { key: "dom", header: "Owned domains", render: (s) => s.ownedDomains?.join(", ") ?? "—" },
    { key: "seen", header: "Last seen", render: (s) => formatDate(s.lastSeenAt) },
  ];

  return (
    <div>
      <PageHeader
        title="Services"
        description="Registered non-human clients of the IAM API."
        actions={<Button onClick={() => setCreating(true)}>Register service</Button>}
      />
      <DataTable columns={columns} rows={q.data} loading={q.isLoading} empty="No services." rowKey={(s) => s.id} />
      {creating ? (
        <RegisterDialog
          open
          onOpenChange={setCreating}
          onIssued={(k) => {
            setCreating(false);
            setIssuedKey(k);
          }}
        />
      ) : null}
      {issuedKey ? (
        <Dialog open onOpenChange={(v) => !v && setIssuedKey(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>API key for {issuedKey.name}</DialogTitle>
            </DialogHeader>
            <p className="text-sm text-[var(--destructive)]">
              Copy this key now — you won't see it again after closing this dialog.
            </p>
            <div className="rounded border border-[var(--border)] bg-[var(--background)] p-2 font-mono text-xs break-all">
              {issuedKey.apiKey}
            </div>
            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => {
                  navigator.clipboard.writeText(issuedKey.apiKey);
                  toast.success("Copied");
                }}
              >
                Copy
              </Button>
              <Button onClick={() => setIssuedKey(null)}>Done</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
    </div>
  );
}

function RegisterDialog({
  open,
  onOpenChange,
  onIssued,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onIssued: (k: { name: string; apiKey: string }) => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [domains, setDomains] = useState("");
  const m = useMutation({
    mutationFn: () =>
      servicesApi.create({
        name,
        displayName,
        ownedDomains: domains.split(",").map((d) => d.trim()).filter(Boolean),
      }),
    onSuccess: (res) => {
      toast.success("Service registered");
      qc.invalidateQueries({ queryKey: ["services"] });
      onIssued({ name: res.name, apiKey: res.apiKey });
    },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader><DialogTitle>Register service</DialogTitle></DialogHeader>
        <div className="space-y-2">
          <Label>Name</Label>
          <Input value={name} onChange={(e) => setName(e.target.value)} />
          <Label>Display name</Label>
          <Input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          <Label>Owned domains (comma separated)</Label>
          <Input value={domains} onChange={(e) => setDomains(e.target.value)} />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => m.mutate()} disabled={m.isPending || !name}>
            {m.isPending ? "Registering..." : "Register"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}