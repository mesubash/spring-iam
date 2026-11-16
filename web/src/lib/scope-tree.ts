import type { Scope } from "@/api/types";

export type ScopeNode = { scope: Scope; children: ScopeNode[] };

/** Nest scopes by parent link, siblings sorted by name. Orphans become roots. */
export function buildScopeTree(scopes: Scope[]): ScopeNode[] {
  const nodes = new Map<string, ScopeNode>(scopes.map((s) => [s.id, { scope: s, children: [] }]));
  const roots: ScopeNode[] = [];
  for (const node of nodes.values()) {
    const parent = node.scope.parentId ? nodes.get(node.scope.parentId) : undefined;
    if (parent) parent.children.push(node);
    else roots.push(node);
  }
  const sortRec = (list: ScopeNode[]) => {
    list.sort((a, b) => a.scope.name.localeCompare(b.scope.name));
    list.forEach((n) => sortRec(n.children));
  };
  sortRec(roots);
  return roots;
}

/** The given scopes plus every ancestor, so a filtered tree stays connected. */
export function withAncestors(all: Scope[], keepIds: Iterable<string>): Scope[] {
  const byId = new Map(all.map((s) => [s.id, s]));
  const keep = new Set<string>();
  for (const id of keepIds) {
    let cur = byId.get(id);
    while (cur && !keep.has(cur.id)) {
      keep.add(cur.id);
      cur = cur.parentId ? byId.get(cur.parentId) : undefined;
    }
  }
  return all.filter((s) => keep.has(s.id));
}
