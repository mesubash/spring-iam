import { Link, Outlet, useNavigate, useRouterState } from "@tanstack/react-router";
import { useAuth } from "@/context/AuthContext";
import { useAuthz } from "@/context/AuthzContext";
import { cn } from "@/lib/utils";
import { LogOut } from "lucide-react";
import { useState } from "react";

type NavItem = { to: string; label: string; permission?: string; featureFlag?: keyof import("@/api/types").FeatureFlags };

const meItems: NavItem[] = [
  { to: "/me/access", label: "My Access" },
  { to: "/me/sessions", label: "My Sessions" },
  { to: "/me/security", label: "Security" },
];

const adminItems: NavItem[] = [
  { to: "/admin/dashboard", label: "Dashboard" },
  { to: "/admin/scopes", label: "Scopes", permission: "platform.scope.read" },
  { to: "/admin/roles", label: "Roles", permission: "platform.role.read" },
  { to: "/admin/assignments", label: "Assignments", permission: "platform.assignment.read" },
  { to: "/admin/deny-rules", label: "Deny Rules", permission: "platform.deny_rule.read" },
  { to: "/admin/policies", label: "Policies", permission: "platform.policy.read" },
  { to: "/admin/context-attributes", label: "Context Attributes", permission: "platform.policy.read" },
  { to: "/admin/resource-grants", label: "Resource Grants", featureFlag: "resource-grants" },
  { to: "/admin/groups", label: "Groups", featureFlag: "groups" },
  { to: "/admin/services", label: "Services", featureFlag: "service-registry" },
  { to: "/admin/permissions", label: "Permissions", permission: "platform.permission.read" },
  { to: "/admin/audit", label: "Audit", permission: "platform.audit.read" },
  { to: "/admin/explain", label: "Explain", permission: "platform.audit.read" },
];

export function AppLayout() {
  const { identity, logout } = useAuth();
  const { scopes, scopeId, setScopeId, can, features } = useAuthz();
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [menuOpen, setMenuOpen] = useState(false);

  const visibleAdmin = adminItems.filter((i) => {
    if (i.featureFlag && features && !features[i.featureFlag]) return false;
    if (i.permission && !can(i.permission)) return false;
    return true;
  });

  const handleLogout = async () => {
    await logout();
    navigate({ to: "/login" });
  };

  return (
    <div className="flex min-h-screen w-full bg-[var(--background)] text-[var(--foreground)]">
      <aside className="flex w-[240px] shrink-0 flex-col border-r border-[var(--border)] bg-[var(--sidebar)]">
        <div className="flex h-12 items-center border-b border-[var(--border)] px-4 text-[15px] font-semibold">
          IAM Console
        </div>
        <nav className="flex-1 overflow-y-auto px-2 py-3 text-[13px]">
          <NavGroup label="Me" items={meItems} pathname={pathname} />
          {visibleAdmin.length > 0 ? (
            <NavGroup label="Administration" items={visibleAdmin} pathname={pathname} />
          ) : null}
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 items-center justify-between border-b border-[var(--border)] bg-[var(--card)] px-4">
          <div className="flex items-center gap-2">
            <label className="text-xs text-[var(--muted-foreground)]" htmlFor="scope-switcher">
              Scope
            </label>
            <select
              id="scope-switcher"
              value={scopeId ?? ""}
              onChange={(e) => setScopeId(e.target.value)}
              className="h-8 rounded border border-[var(--border)] bg-[var(--card)] px-2 text-sm focus:border-[var(--ring)] focus:outline-none focus:ring-1 focus:ring-[var(--ring)]"
            >
              {scopes.length === 0 ? <option value="">No scopes</option> : null}
              {scopes.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.path ?? s.name}
                </option>
              ))}
            </select>
          </div>
          <div className="relative">
            <button
              type="button"
              onClick={() => setMenuOpen((v) => !v)}
              className="flex h-8 items-center gap-2 rounded px-2 text-sm hover:bg-[var(--background)]"
            >
              <span className="text-[var(--muted-foreground)]">{identity?.email ?? "…"}</span>
            </button>
            {menuOpen ? (
              <div className="absolute right-0 top-9 z-20 w-48 rounded border border-[var(--border)] bg-[var(--card)] py-1 shadow-sm">
                <button
                  type="button"
                  onClick={handleLogout}
                  className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm hover:bg-[var(--background)]"
                >
                  <LogOut className="h-3.5 w-3.5" /> Sign out
                </button>
              </div>
            ) : null}
          </div>
        </header>
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-6xl px-6 py-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

function NavGroup({
  label,
  items,
  pathname,
}: {
  label: string;
  items: NavItem[];
  pathname: string;
}) {
  return (
    <div className="mb-4">
      <div className="px-2 pb-1 text-[11px] font-medium uppercase tracking-wide text-[var(--muted-foreground)]">
        {label}
      </div>
      <ul>
        {items.map((item) => {
          const active = pathname === item.to || pathname.startsWith(item.to + "/");
          return (
            <li key={item.to}>
              <Link
                to={item.to}
                className={cn(
                  "block rounded px-2 py-1.5 text-[13px] focus:outline-none focus:ring-1 focus:ring-[var(--ring)]",
                  active
                    ? "bg-[var(--primary-subtle)] font-medium text-[var(--primary)]"
                    : "text-[var(--foreground)] hover:bg-[var(--background)]",
                )}
              >
                {item.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </div>
  );
}