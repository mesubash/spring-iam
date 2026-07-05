import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { pdpApi, rolesApi, type AuthorizeInput } from "@/api/resources";
import type { ExplainResult, ExplainStep } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { PermissionGuardedPage } from "@/components/iam/PermissionGuardedPage";
import { DecisionBadge, Tag } from "@/components/iam/badges";
import { SubjectPicker } from "@/components/iam/SubjectPicker";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/admin/explain")({
  component: () => (
    <PermissionGuardedPage permission="platform.audit.read">
      <ExplainPage />
    </PermissionGuardedPage>
  ),
});

const ROOT_SCOPE = "00000000-0000-0000-0000-000000000001";

type FormState = {
  subjectId: string;
  permission: string;
  resourceType: string;
  resourceId: string;
  scopeId: string;
  context: string;
};

const initialForm: FormState = {
  subjectId: "",
  permission: "",
  resourceType: "",
  resourceId: "",
  scopeId: ROOT_SCOPE,
  context: "",
};

function buildInput(f: FormState): AuthorizeInput {
  let ctx: Record<string, unknown> | undefined;
  if (f.context.trim()) {
    try {
      ctx = JSON.parse(f.context);
    } catch (e) {
      throw new Error("Context is not valid JSON: " + (e as Error).message);
    }
  }
  return {
    subject: f.subjectId.trim(),
    permission: f.permission.trim(),
    resource: {
      type: f.resourceType.trim() || undefined,
      id: f.resourceId.trim() || undefined,
      scopeId: f.scopeId.trim() || ROOT_SCOPE,
    },
    ...(ctx ? { context: ctx } : {}),
  };
}

function ExplainPage() {
  return (
    <div>
      <PageHeader
        title="Explain"
        description="Trace how the PDP decides an authorization request, stage by stage. Explain and simulate never write audit entries."
      />
      <Tabs defaultValue="explain">
        <TabsList>
          <TabsTrigger value="explain">Explain</TabsTrigger>
          <TabsTrigger value="simulate">Simulate</TabsTrigger>
        </TabsList>
        <TabsContent value="explain" className="mt-4">
          <ExplainTab />
        </TabsContent>
        <TabsContent value="simulate" className="mt-4">
          <SimulateTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ------------------------------ Request form ----------------------------- */

function RequestFields({
  form,
  setForm,
}: {
  form: FormState;
  setForm: (f: FormState) => void;
}) {
  const [jsonErr, setJsonErr] = useState<string | null>(null);
  const set = (k: keyof FormState) => (v: string) => setForm({ ...form, [k]: v });
  return (
    <div className="space-y-2">
      <div>
        <Label>Subject</Label>
        <div className="mt-1">
          <SubjectPicker value={form.subjectId} onChange={set("subjectId")} />
        </div>
      </div>
      <div>
        <Label>Permission</Label>
        <Input
          className="mt-1 font-mono text-xs"
          placeholder="domain.resource.action"
          value={form.permission}
          onChange={(e) => set("permission")(e.target.value)}
        />
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div>
          <Label>Resource type</Label>
          <Input
            className="mt-1"
            placeholder="optional"
            value={form.resourceType}
            onChange={(e) => set("resourceType")(e.target.value)}
          />
        </div>
        <div>
          <Label>Resource ID</Label>
          <Input
            className="mt-1"
            placeholder="optional"
            value={form.resourceId}
            onChange={(e) => set("resourceId")(e.target.value)}
          />
        </div>
      </div>
      <div>
        <Label>Scope ID</Label>
        <Input
          className="mt-1 font-mono text-xs"
          value={form.scopeId}
          onChange={(e) => set("scopeId")(e.target.value)}
        />
      </div>
      <div>
        <Label>Context (JSON, optional)</Label>
        <Textarea
          className="mt-1 font-mono text-xs"
          rows={4}
          placeholder='{"ip": "10.0.0.1"}'
          value={form.context}
          onChange={(e) => {
            set("context")(e.target.value);
            if (!e.target.value.trim()) {
              setJsonErr(null);
              return;
            }
            try {
              JSON.parse(e.target.value);
              setJsonErr(null);
            } catch (err) {
              setJsonErr((err as Error).message);
            }
          }}
        />
        {jsonErr ? <p className="mt-1 text-xs text-[var(--destructive)]">Invalid JSON: {jsonErr}</p> : null}
      </div>
    </div>
  );
}

/* -------------------------------- Stepper -------------------------------- */

function outcomeTone(o: ExplainStep["outcome"]): "success" | "destructive" | "neutral" {
  if (o === "PASS" || o === "ALLOW") return "success";
  if (o === "FAIL" || o === "DENY") return "destructive";
  return "neutral";
}

function ResultPanel({ result }: { result: ExplainResult }) {
  return (
    <div>
      <div className="mb-4 flex items-center gap-3 rounded border border-[var(--border)] bg-[var(--background)] px-3 py-2">
        <DecisionBadge decision={result.allowed ? "ALLOW" : "DENY"} />
        <span className="font-mono text-xs text-[var(--muted-foreground)]">{result.reason}</span>
      </div>
      <ol>
        {result.steps.map((step, i) => {
          const tone = outcomeTone(step.outcome);
          const last = i === result.steps.length - 1;
          return (
            <li key={`${step.name}-${i}`} className="relative flex gap-3 pb-4">
              {!last ? (
                <span
                  aria-hidden
                  className="absolute bottom-0 left-[11px] top-6 w-px bg-[var(--border)]"
                />
              ) : null}
              <span
                aria-hidden
                className={cn(
                  "z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-[10px] font-semibold",
                  tone === "success" &&
                    "border-[var(--success)] bg-[var(--success-subtle)] text-[var(--success)]",
                  tone === "destructive" &&
                    "border-[var(--destructive)] bg-[var(--destructive-subtle)] text-[var(--destructive)]",
                  tone === "neutral" &&
                    "border-[var(--border)] bg-[var(--muted)] text-[var(--muted-foreground)]",
                )}
              >
                {i + 1}
              </span>
              <div className="min-w-0 flex-1 pt-0.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[13px] font-medium">{step.name}</span>
                  <Tag tone={tone}>{step.outcome}</Tag>
                </div>
                {step.detail ? (
                  <p className="mt-0.5 text-xs text-[var(--muted-foreground)]">{step.detail}</p>
                ) : null}
              </div>
            </li>
          );
        })}
      </ol>
      <p className="mt-2 border-t border-[var(--border)] pt-2 text-xs text-[var(--muted-foreground)]">
        Diagnostic trace only — no audit entry was written for this request.
      </p>
    </div>
  );
}

function ResultCard({
  result,
  pending,
  placeholder,
}: {
  result: ExplainResult | null;
  pending: boolean;
  placeholder: string;
}) {
  return (
    <div className="rounded border border-[var(--border)] bg-[var(--card)] p-4">
      {pending ? (
        <p className="text-sm text-[var(--muted-foreground)]">Evaluating…</p>
      ) : result ? (
        <ResultPanel result={result} />
      ) : (
        <p className="text-sm text-[var(--muted-foreground)]">{placeholder}</p>
      )}
    </div>
  );
}

/* ------------------------------- Explain tab ----------------------------- */

function ExplainTab() {
  const [form, setForm] = useState<FormState>(initialForm);
  const [result, setResult] = useState<ExplainResult | null>(null);
  const m = useMutation({
    mutationFn: () => pdpApi.explain(buildInput(form)),
    onSuccess: setResult,
    onError: (e: Error) => toast.error(e.message),
  });
  const valid = form.subjectId.trim() && form.permission.trim();
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[360px_1fr]">
      <form
        className="h-fit rounded border border-[var(--border)] bg-[var(--card)] p-4"
        onSubmit={(e) => {
          e.preventDefault();
          m.mutate();
        }}
      >
        <RequestFields form={form} setForm={setForm} />
        <Button type="submit" className="mt-3 w-full" disabled={!valid || m.isPending}>
          {m.isPending ? "Explaining…" : "Explain decision"}
        </Button>
      </form>
      <ResultCard
        result={result}
        pending={m.isPending}
        placeholder="Submit a request to see the decision pipeline."
      />
    </div>
  );
}

/* ------------------------------ Simulate tab ----------------------------- */

type HypoAssignment = { roleId: string; scopeId: string };

function SimulateTab() {
  const [form, setForm] = useState<FormState>(initialForm);
  const [adds, setAdds] = useState<HypoAssignment[]>([{ roleId: "", scopeId: ROOT_SCOPE }]);
  const [result, setResult] = useState<ExplainResult | null>(null);
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => rolesApi.list() });

  const m = useMutation({
    mutationFn: () =>
      pdpApi.simulate({
        request: buildInput(form),
        addAssignments: adds.filter((a) => a.roleId.trim() && a.scopeId.trim()),
      }),
    onSuccess: setResult,
    onError: (e: Error) => toast.error(e.message),
  });
  const valid = form.subjectId.trim() && form.permission.trim();

  const setAdd = (i: number, patch: Partial<HypoAssignment>) =>
    setAdds(adds.map((a, j) => (j === i ? { ...a, ...patch } : a)));

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[360px_1fr]">
      <form
        className="h-fit rounded border border-[var(--border)] bg-[var(--card)] p-4"
        onSubmit={(e) => {
          e.preventDefault();
          m.mutate();
        }}
      >
        <RequestFields form={form} setForm={setForm} />
        <div className="mt-3 border-t border-[var(--border)] pt-3">
          <div className="mb-2 flex items-center justify-between">
            <Label>Hypothetical assignments</Label>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setAdds([...adds, { roleId: "", scopeId: ROOT_SCOPE }])}
            >
              Add row
            </Button>
          </div>
          <div className="space-y-2">
            {adds.map((a, i) => (
              <div key={i} className="flex items-center gap-2">
                <select
                  value={a.roleId}
                  onChange={(e) => setAdd(i, { roleId: e.target.value })}
                  className="h-9 w-0 flex-1 rounded border border-[var(--border)] bg-[var(--card)] px-2 text-xs"
                >
                  <option value="">Select role…</option>
                  {(roles.data ?? []).map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.displayName || r.name}
                    </option>
                  ))}
                </select>
                <Input
                  className="w-0 flex-1 font-mono text-xs"
                  placeholder="Scope ID"
                  value={a.scopeId}
                  onChange={(e) => setAdd(i, { scopeId: e.target.value })}
                />
                <button
                  type="button"
                  className="text-xs text-[var(--muted-foreground)] hover:text-[var(--destructive)]"
                  onClick={() => setAdds(adds.filter((_, j) => j !== i))}
                >
                  Remove
                </button>
              </div>
            ))}
            {adds.length === 0 ? (
              <p className="text-xs text-[var(--muted-foreground)]">
                No hypothetical assignments — the simulation runs against the subject's real assignments.
              </p>
            ) : null}
          </div>
        </div>
        <Button type="submit" className="mt-3 w-full" disabled={!valid || m.isPending}>
          {m.isPending ? "Simulating…" : "Simulate decision"}
        </Button>
      </form>
      <ResultCard
        result={result}
        pending={m.isPending}
        placeholder="Simulate re-runs the decision with hypothetical role assignments added. Nothing is persisted."
      />
    </div>
  );
}
