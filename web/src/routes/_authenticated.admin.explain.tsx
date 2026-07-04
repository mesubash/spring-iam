import { createFileRoute } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { authzApi } from "@/api/resources";
import type { ExplainResult } from "@/api/types";
import { PageHeader } from "@/components/iam/PageHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DecisionBadge, Tag } from "@/components/iam/badges";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/admin/explain")({
  head: () => ({ meta: [{ title: "Explain — IAM Console" }] }),
  component: ExplainPage,
});

function ExplainPage() {
  const [subjectId, setSubjectId] = useState("");
  const [permission, setPermission] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [resourceId, setResourceId] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [context, setContext] = useState("{}");
  const [jsonErr, setJsonErr] = useState<string | null>(null);
  const [result, setResult] = useState<ExplainResult | null>(null);

  const m = useMutation({
    mutationFn: () => {
      let ctx: unknown = {};
      try {
        ctx = context.trim() ? JSON.parse(context) : {};
      } catch (e) {
        throw new Error("Context is not valid JSON: " + (e as Error).message);
      }
      return authzApi.explain({
        subjectId,
        permission,
        resourceType: resourceType || undefined,
        resourceId: resourceId || undefined,
        scopeId: scopeId || undefined,
        context: ctx,
      });
    },
    onSuccess: (r) => setResult(r),
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <div>
      <PageHeader title="Explain" description="Walk through how the server would decide an authorization request." />
      <div className="grid grid-cols-[360px_1fr] gap-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            m.mutate();
          }}
          className="space-y-2 rounded border border-[var(--border)] bg-[var(--card)] p-4"
        >
          <Label>Subject ID</Label>
          <Input value={subjectId} onChange={(e) => setSubjectId(e.target.value)} required />
          <Label>Permission</Label>
          <Input value={permission} onChange={(e) => setPermission(e.target.value)} required />
          <Label>Resource type</Label>
          <Input value={resourceType} onChange={(e) => setResourceType(e.target.value)} />
          <Label>Resource ID</Label>
          <Input value={resourceId} onChange={(e) => setResourceId(e.target.value)} />
          <Label>Scope ID</Label>
          <Input value={scopeId} onChange={(e) => setScopeId(e.target.value)} />
          <Label>Context JSON</Label>
          <textarea
            value={context}
            onChange={(e) => {
              setContext(e.target.value);
              try {
                JSON.parse(e.target.value || "{}");
                setJsonErr(null);
              } catch (err) {
                setJsonErr((err as Error).message);
              }
            }}
            rows={6}
            className="w-full rounded border border-[var(--border)] bg-[var(--card)] p-2 font-mono text-xs"
          />
          {jsonErr ? <p className="text-xs text-[var(--destructive)]">{jsonErr}</p> : null}
          <Button type="submit" disabled={m.isPending || !subjectId || !permission || !!jsonErr} className="w-full">
            {m.isPending ? "Explaining..." : "Explain"}
          </Button>
        </form>

        <div className="rounded border border-[var(--border)] bg-[var(--card)] p-4">
          {!result ? (
            <p className="text-sm text-[var(--muted-foreground)]">Submit a request to see the pipeline trace.</p>
          ) : (
            <div>
              <div className="mb-4 flex items-center gap-2">
                <span className="text-sm font-semibold">Final decision:</span>
                <DecisionBadge decision={result.decision} />
              </div>
              <ol className="space-y-2">
                {(result.steps ?? []).map((step, i) => (
                  <li
                    key={i}
                    className={cn(
                      "flex gap-3 rounded border p-3",
                      step.passed
                        ? "border-[var(--success)]/30 bg-[var(--success-subtle)]"
                        : "border-[var(--destructive)]/30 bg-[var(--destructive-subtle)]",
                    )}
                  >
                    <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-current text-xs font-semibold" aria-hidden>
                      {i + 1}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold">{step.stage}</span>
                        <Tag tone={step.passed ? "success" : "destructive"}>{step.passed ? "PASS" : "FAIL"}</Tag>
                        {step.decision ? <Tag>{step.decision}</Tag> : null}
                      </div>
                      {step.rule ? (
                        <div className="mt-1 font-mono text-xs text-[var(--foreground)]">{step.rule}</div>
                      ) : null}
                      {step.detail ? (
                        <div className="mt-1 text-xs text-[var(--muted-foreground)]">{step.detail}</div>
                      ) : null}
                      {step.data ? (
                        <pre className="mt-2 max-h-40 overflow-auto rounded bg-[var(--card)] p-2 text-[11px]">
                          {JSON.stringify(step.data, null, 2)}
                        </pre>
                      ) : null}
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}