import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { authApi } from "@/api/resources";
import type { Session } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { DataTable, type Column } from "@/components/iam/DataTable";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/iam/ConfirmDialog";
import { formatDate } from "@/lib/format";
import { useNavigate } from "@tanstack/react-router";
import { useAuth } from "@/context/AuthContext";

export const Route = createFileRoute("/_authenticated/me/sessions")({
  component: MySessionsPage,
});

function MySessionsPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { logout } = useAuth();
  const q = useQuery({ queryKey: ["sessions"], queryFn: () => authApi.sessions() });
  const [toRevoke, setToRevoke] = useState<Session | null>(null);
  const [confirmAll, setConfirmAll] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirmSelected, setConfirmSelected] = useState(false);

  const sessions = useMemo(() => q.data ?? [], [q.data]);
  const allSelected = sessions.length > 0 && sessions.every((s) => selected.has(s.id));

  const toggle = (id: string) =>
    setSelected((prev) => {
      const s = new Set(prev);
      if (s.has(id)) s.delete(id);
      else s.add(id);
      return s;
    });
  const toggleAll = () => setSelected(allSelected ? new Set() : new Set(sessions.map((s) => s.id)));

  const revoke = useMutation({
    mutationFn: (id: string) => authApi.revokeSession(id),
    onSuccess: () => {
      toast.success("Session revoked");
      qc.invalidateQueries({ queryKey: ["sessions"] });
      setToRevoke(null);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const revokeSelected = useMutation({
    mutationFn: async () => {
      const results = await Promise.allSettled(
        Array.from(selected).map((id) => authApi.revokeSession(id)),
      );
      const failed = results.filter((r) => r.status === "rejected").length;
      return { total: results.length, failed };
    },
    onSuccess: ({ total, failed }) => {
      if (failed === 0) toast.success(`${total} session${total === 1 ? "" : "s"} revoked`);
      else toast.warning(`${total - failed} revoked, ${failed} failed`);
      setSelected(new Set());
      setConfirmSelected(false);
      qc.invalidateQueries({ queryKey: ["sessions"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const logoutAll = useMutation({
    mutationFn: () => authApi.logoutAll(),
    onSuccess: async () => {
      toast.success("Signed out on all devices");
      await logout();
      navigate({ to: "/login" });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<Session>[] = [
    {
      key: "select",
      width: "36px",
      header: (
        <input
          type="checkbox"
          className="h-4 w-4 cursor-pointer"
          aria-label="Select all sessions"
          checked={allSelected}
          onChange={toggleAll}
        />
      ),
      render: (s) => (
        <input
          type="checkbox"
          className="h-4 w-4 cursor-pointer"
          aria-label="Select session"
          checked={selected.has(s.id)}
          onChange={() => toggle(s.id)}
          onClick={(e) => e.stopPropagation()}
        />
      ),
    },
    { key: "device", header: "Device", render: (s) => s.deviceLabel ?? "—" },
    { key: "ip", header: "IP", render: (s) => s.createdIp ?? "—" },
    { key: "created", header: "Created", render: (s) => formatDate(s.createdAt) },
    { key: "used", header: "Last used", render: (s) => formatDate(s.lastUsedAt) },
    {
      key: "actions",
      header: "",
      width: "120px",
      render: (s) => (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setToRevoke(s)}
          style={{ color: "var(--destructive)" }}
        >
          Revoke
        </Button>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="My Sessions"
        description="Devices signed in with your account."
        actions={
          <div className="flex items-center gap-2">
            {selected.size > 0 ? (
              <Button
                variant="outline"
                style={{ color: "var(--destructive)" }}
                onClick={() => setConfirmSelected(true)}
              >
                Revoke selected ({selected.size})
              </Button>
            ) : null}
            <Button variant="outline" onClick={() => setConfirmAll(true)}>
              Log out all devices
            </Button>
          </div>
        }
      />
      <DataTable
        columns={columns}
        rows={q.data}
        loading={q.isLoading}
        empty="No active sessions."
        rowKey={(s) => s.id}
      />
      <ConfirmDialog
        open={!!toRevoke}
        onOpenChange={(v) => !v && setToRevoke(null)}
        title="Revoke session"
        description="This device will be signed out immediately."
        target={toRevoke?.deviceLabel ?? toRevoke?.id}
        confirmLabel="Revoke"
        destructive
        pending={revoke.isPending}
        onConfirm={() => toRevoke && revoke.mutate(toRevoke.id)}
      />
      <ConfirmDialog
        open={confirmSelected}
        onOpenChange={setConfirmSelected}
        title="Revoke selected sessions"
        description="The selected devices are signed out immediately. If this device is among them you will be logged out too."
        target={`${selected.size} session${selected.size === 1 ? "" : "s"}`}
        confirmLabel="Revoke selected"
        destructive
        pending={revokeSelected.isPending}
        onConfirm={() => revokeSelected.mutate()}
      />
      <ConfirmDialog
        open={confirmAll}
        onOpenChange={setConfirmAll}
        title="Log out all devices"
        description="Every session, including this one, will be signed out."
        confirmLabel="Log out all"
        destructive
        pending={logoutAll.isPending}
        onConfirm={() => logoutAll.mutate()}
      />
    </div>
  );
}
