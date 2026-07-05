import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { servicesApi } from "@/api/resources";
import type { ServiceClient } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { Can } from "@/components/iam/Can";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { Tag } from "@/components/iam/badges";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useAuthz } from "@/context/AuthzContext";
import { formatDate } from "@/lib/format";

export const Route = createFileRoute("/_authenticated/admin/services")({
  component: () => (
    <PermissionGuardedPage permission="platform.service.read">
      <ServicesPage />
    </PermissionGuardedPage>
  ),
});

function ServicesPage() {
  const { features } = useAuthz();
  const q = useQuery({ queryKey: ["services"], queryFn: servicesApi.list });
  const [filter, setFilter] = useState("");
  const [creating, setCreating] = useState(false);
  const [issuedKey, setIssuedKey] = useState<{ name: string; apiKey: string } | null>(null);

  const rows = useMemo(() => {
    const arr = q.data ?? [];
    const f = filter.trim().toLowerCase();
    return f
      ? arr.filter(
          (s) =>
            s.name.toLowerCase().includes(f) ||
            (s.displayName ?? "").toLowerCase().includes(f) ||
            (s.ownedDomains ?? []).some((d) => d.toLowerCase().includes(f)),
        )
      : arr;
  }, [q.data, filter]);

  if (features && !features["service-registry"]) {
    return (
      <p className="text-sm text-[var(--muted-foreground)]">
        The service-registry feature is disabled on this deployment.
      </p>
    );
  }

  const columns: Column<ServiceClient>[] = [
    {
      key: "name",
      header: "Name",
      render: (s) => <span className="font-mono text-[13px]">{s.name}</span>,
    },
    { key: "dn", header: "Display name", render: (s) => s.displayName || "—" },
    {
      key: "dom",
      header: "Owned domains",
      render: (s) =>
        (s.ownedDomains ?? []).length ? (
          <span className="flex flex-wrap gap-1">
            {s.ownedDomains.map((d) => (
              <Tag key={d} mono>
                {d}
              </Tag>
            ))}
          </span>
        ) : (
          "—"
        ),
    },
    { key: "seen", header: "Last seen", width: "170px", render: (s) => formatDate(s.lastSeenAt) },
  ];

  return (
    <div>
      <PageHeader
        title="Services"
        description="Registered service clients that call the IAM API with an API key and own permission domains."
        actions={
          <Can permission="platform.service.manage">
            <Button onClick={() => setCreating(true)}>Register service</Button>
          </Can>
        }
      />
      <Input
        className="mb-3 max-w-xs"
        placeholder="Filter services…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      <DataTable
        columns={columns}
        rows={rows}
        loading={q.isLoading}
        empty="No services registered."
        rowKey={(s) => s.id}
      />
      <p className="mt-3 text-xs text-[var(--muted-foreground)]">
        Permission manifests are synced by each service itself via{" "}
        <span className="font-mono">PUT /api/v1/services/&#123;name&#125;/permissions</span> using
        its API key — there is no manual sync here.
      </p>
      {creating ? (
        <RegisterServiceDialog
          open
          onOpenChange={setCreating}
          onIssued={(k) => {
            setCreating(false);
            setIssuedKey(k);
          }}
        />
      ) : null}
      {issuedKey ? (
        <ApiKeyDialog issued={issuedKey} onClose={() => setIssuedKey(null)} />
      ) : null}
    </div>
  );
}

function RegisterServiceDialog({
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

  const parsedDomains = domains
    .split(",")
    .map((d) => d.trim())
    .filter(Boolean);

  const m = useMutation({
    mutationFn: () =>
      servicesApi.create({
        name: name.trim(),
        displayName: displayName.trim() || undefined,
        ownedDomains: parsedDomains,
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
        <DialogHeader>
          <DialogTitle>Register service</DialogTitle>
        </DialogHeader>
        <div className="space-y-2">
          <div>
            <Label>Name</Label>
            <Input
              className="mt-1 font-mono text-xs"
              placeholder="billing-service"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div>
            <Label>Display name (optional)</Label>
            <Input
              className="mt-1"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </div>
          <div>
            <Label>Owned domains (comma-separated)</Label>
            <Input
              className="mt-1 font-mono text-xs"
              placeholder="billing, invoices"
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
            />
            <p className="mt-1 text-xs text-[var(--muted-foreground)]">
              The service may only sync permissions inside the domains it owns.
            </p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={m.isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => m.mutate()}
            disabled={m.isPending || !name.trim() || parsedDomains.length === 0}
          >
            {m.isPending ? "Registering…" : "Register"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ApiKeyDialog({
  issued,
  onClose,
}: {
  issued: { name: string; apiKey: string };
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>API key for {issued.name}</DialogTitle>
        </DialogHeader>
        <p className="text-sm text-[var(--destructive)]">
          Copy this key now. It is shown exactly once — after you close this dialog it cannot be
          retrieved again.
        </p>
        <div className="break-all rounded border border-[var(--border)] bg-[var(--background)] p-2 font-mono text-xs">
          {issued.apiKey}
        </div>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={async () => {
              await navigator.clipboard.writeText(issued.apiKey);
              setCopied(true);
              toast.success("API key copied");
            }}
          >
            {copied ? "Copied" : "Copy key"}
          </Button>
          <Button onClick={onClose}>Done</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
