import { useEffect, useMemo, useState } from "react";
import type { Permission } from "@/api/types";
import { CircleCheck } from "lucide-react";
import { Tag } from "@/components/iam/badges";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

// Hierarchical permission view shared by the role editor, the permissions
// catalog and My Access: domain -> resource -> permission with +/- expanders.
// Pass `selected` + `onSetMany` for the selectable (tri-state checkbox) mode;
// omit them for a plain read-only tree.

type ResourceNode = { key: string; resource: string; perms: Permission[] };
type DomainNode = { key: string; domain: string; resources: ResourceNode[]; permIds: string[] };

export function buildPermissionTree(perms: Permission[]): DomainNode[] {
  const domains = new Map<string, Map<string, Permission[]>>();
  for (const p of perms) {
    const d = p.domain ?? p.key.split(".")[0] ?? "other";
    const r = p.resource ?? p.key.split(".")[1] ?? "other";
    if (!domains.has(d)) domains.set(d, new Map());
    const byResource = domains.get(d)!;
    if (!byResource.has(r)) byResource.set(r, []);
    byResource.get(r)!.push(p);
  }
  return Array.from(domains.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([domain, byResource]) => {
      const resources = Array.from(byResource.entries())
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([resource, list]) => ({
          key: `${domain}.${resource}`,
          resource,
          perms: list.sort((a, b) =>
            (a.description ?? a.key).localeCompare(b.description ?? b.key),
          ),
        }));
      return {
        key: domain,
        domain,
        resources,
        permIds: resources.flatMap((r) => r.perms.map((p) => p.id)),
      };
    });
}

function TriCheckbox({
  checked,
  indeterminate,
  disabled,
  onChange,
}: {
  checked: boolean;
  indeterminate: boolean;
  disabled?: boolean;
  onChange: () => void;
}) {
  return (
    <input
      type="checkbox"
      className="mt-0.5"
      checked={checked}
      disabled={disabled}
      ref={(el) => {
        if (el) el.indeterminate = indeterminate;
      }}
      onChange={onChange}
      onClick={(e) => e.stopPropagation()}
    />
  );
}

function Expander({ open }: { open: boolean }) {
  return (
    <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded border border-[var(--border)] text-xs leading-none text-[var(--muted-foreground)]">
      {open ? "−" : "+"}
    </span>
  );
}

export function PermissionTree({
  perms,
  selected,
  onSetMany,
  readOnly = false,
}: {
  perms: Permission[];
  /** permission ids currently granted — enables checkbox mode */
  selected?: Set<string>;
  /** called with the leaf ids of the toggled branch/leaf and the new state */
  onSetMany?: (ids: string[], on: boolean) => void;
  readOnly?: boolean;
}) {
  const selectable = !!selected && !!onSetMany;
  const [filter, setFilter] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [seeded, setSeeded] = useState(false);

  const tree = useMemo(() => buildPermissionTree(perms), [perms]);

  // Open the first few domains (and their resources) by default so the page
  // doesn't greet the user with a wall of closed rows.
  useEffect(() => {
    if (!seeded && tree.length > 0) {
      setExpanded(
        new Set(tree.slice(0, 5).flatMap((d) => [d.key, ...d.resources.map((r) => r.key)])),
      );
      setSeeded(true);
    }
  }, [seeded, tree]);
  const allIds = useMemo(() => tree.flatMap((d) => d.permIds), [tree]);

  // Search narrows the tree and force-expands whatever matched.
  const { visibleTree, forcedOpen } = useMemo(() => {
    const f = filter.toLowerCase();
    if (!f) return { visibleTree: tree, forcedOpen: null as Set<string> | null };
    const open = new Set<string>();
    const narrowed = tree
      .map((d) => {
        const resources = d.resources
          .map((r) => ({
            ...r,
            perms: r.perms.filter(
              (p) =>
                p.key.toLowerCase().includes(f) || (p.description ?? "").toLowerCase().includes(f),
            ),
          }))
          .filter((r) => r.perms.length > 0);
        if (resources.length > 0) {
          open.add(d.key);
          resources.forEach((r) => open.add(r.key));
        }
        return { ...d, resources, permIds: resources.flatMap((r) => r.perms.map((p) => p.id)) };
      })
      .filter((d) => d.resources.length > 0);
    return { visibleTree: narrowed, forcedOpen: open };
  }, [tree, filter]);

  const isOpen = (key: string) => (forcedOpen ? forcedOpen.has(key) : expanded.has(key));
  const toggleOpen = (key: string) => {
    if (forcedOpen) return;
    setExpanded((prev) => {
      const s = new Set(prev);
      if (s.has(key)) s.delete(key);
      else s.add(key);
      return s;
    });
  };
  const expandAll = () =>
    setExpanded(new Set(tree.flatMap((d) => [d.key, ...d.resources.map((r) => r.key)])));
  const collapseAll = () => setExpanded(new Set());

  const countIn = (ids: string[]) => (selected ? ids.filter((id) => selected.has(id)).length : 0);

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search permissions by name or key..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="w-full sm:max-w-xs"
        />
        <Button variant="outline" size="sm" onClick={expandAll}>
          Expand all
        </Button>
        <Button variant="outline" size="sm" onClick={collapseAll}>
          Collapse all
        </Button>
        {selectable && !readOnly ? (
          <>
            <Button variant="outline" size="sm" onClick={() => onSetMany!(allIds, true)}>
              Check all
            </Button>
            <Button variant="outline" size="sm" onClick={() => onSetMany!(allIds, false)}>
              Uncheck all
            </Button>
          </>
        ) : null}
        <span className="ml-auto text-sm text-[var(--muted-foreground)]">
          {selectable
            ? `${countIn(allIds)} of ${allIds.length} selected`
            : `${allIds.length} permissions`}
        </span>
      </div>

      <div className="rounded-md border border-[var(--border)]">
        {visibleTree.length === 0 ? (
          <div className="p-4 text-sm text-[var(--muted-foreground)]">No permissions match.</div>
        ) : (
          visibleTree.map((d) => {
            const dCount = countIn(d.permIds);
            const dOpen = isOpen(d.key);
            return (
              <div key={d.key} className="border-b border-[var(--border)] last:border-b-0">
                <div
                  role="button"
                  tabIndex={0}
                  onClick={() => toggleOpen(d.key)}
                  onKeyDown={(e) => e.key === "Enter" && toggleOpen(d.key)}
                  className="flex cursor-pointer items-center gap-2 px-3 py-2 hover:bg-[var(--muted)]"
                >
                  <Expander open={dOpen} />
                  {selectable ? (
                    <TriCheckbox
                      checked={dCount === d.permIds.length && d.permIds.length > 0}
                      indeterminate={dCount > 0 && dCount < d.permIds.length}
                      disabled={readOnly}
                      onChange={() => onSetMany!(d.permIds, dCount < d.permIds.length)}
                    />
                  ) : null}
                  <span className="text-sm font-semibold capitalize">{d.domain}</span>
                  <span className="ml-auto text-xs text-[var(--muted-foreground)]">
                    {selectable ? `${dCount}/${d.permIds.length}` : d.permIds.length}
                  </span>
                </div>
                {dOpen
                  ? d.resources.map((r) => {
                      const rIds = r.perms.map((p) => p.id);
                      const rCount = countIn(rIds);
                      const rOpen = isOpen(r.key);
                      return (
                        <div key={r.key}>
                          <div
                            role="button"
                            tabIndex={0}
                            onClick={() => toggleOpen(r.key)}
                            onKeyDown={(e) => e.key === "Enter" && toggleOpen(r.key)}
                            className="flex cursor-pointer items-center gap-2 py-1.5 pl-10 pr-3 hover:bg-[var(--muted)]"
                          >
                            <Expander open={rOpen} />
                            {selectable ? (
                              <TriCheckbox
                                checked={rCount === rIds.length && rIds.length > 0}
                                indeterminate={rCount > 0 && rCount < rIds.length}
                                disabled={readOnly}
                                onChange={() => onSetMany!(rIds, rCount < rIds.length)}
                              />
                            ) : null}
                            <span className="text-sm capitalize">
                              {r.resource.replace(/[._-]/g, " ")}
                            </span>
                            <span className="ml-auto text-xs text-[var(--muted-foreground)]">
                              {selectable ? `${rCount}/${rIds.length}` : rIds.length}
                            </span>
                          </div>
                          {rOpen
                            ? r.perms.map((p) => (
                                <label
                                  key={p.id}
                                  className="flex items-start gap-2 py-1 pl-[4.5rem] pr-3 hover:bg-[var(--muted)]"
                                >
                                  {selectable ? (
                                    <TriCheckbox
                                      checked={selected!.has(p.id)}
                                      indeterminate={false}
                                      disabled={readOnly}
                                      onChange={() => onSetMany!([p.id], !selected!.has(p.id))}
                                    />
                                  ) : (
                                    <CircleCheck className="mt-0.5 h-4 w-4 shrink-0 fill-[var(--primary)] text-[var(--primary-foreground)]" />
                                  )}
                                  <span className="flex flex-col">
                                    <span className="flex items-center gap-2 text-[13px] leading-tight">
                                      {p.description ?? p.key}
                                      {p.isDeprecated ? <Tag tone="warning">Deprecated</Tag> : null}
                                    </span>
                                    <span className="font-mono text-[11px] text-[var(--muted-foreground)]">
                                      {p.key}
                                    </span>
                                  </span>
                                </label>
                              ))
                            : null}
                        </div>
                      );
                    })
                  : null}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
