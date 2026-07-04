import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

export type Column<T> = {
  key: string;
  header: ReactNode;
  render: (row: T) => ReactNode;
  className?: string;
  width?: string;
};

export function DataTable<T>({
  columns,
  rows,
  loading = false,
  empty = "No results.",
  rowKey,
  onRowClick,
}: {
  columns: Column<T>[];
  rows: T[] | undefined;
  loading?: boolean;
  empty?: ReactNode;
  rowKey: (row: T, idx: number) => string;
  onRowClick?: (row: T) => void;
}) {
  return (
    <div className="overflow-hidden rounded border border-[var(--border)] bg-[var(--card)]">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-[var(--border)] bg-[var(--background)]">
            {columns.map((c) => (
              <th
                key={c.key}
                style={{ width: c.width }}
                className={cn(
                  "px-3 py-2 text-left text-xs font-medium uppercase tracking-wide text-[var(--muted-foreground)]",
                  c.className,
                )}
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading ? (
            Array.from({ length: 5 }).map((_, i) => (
              <tr key={`sk-${i}`} className="border-b border-[var(--border)]">
                {columns.map((c) => (
                  <td key={c.key} className="h-10 px-3 py-2">
                    <div className="h-3 w-24 animate-pulse rounded bg-[var(--muted)]" />
                  </td>
                ))}
              </tr>
            ))
          ) : !rows || rows.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length}
                className="px-3 py-8 text-center text-sm text-[var(--muted-foreground)]"
              >
                {empty}
              </td>
            </tr>
          ) : (
            rows.map((r, i) => (
              <tr
                key={rowKey(r, i)}
                tabIndex={onRowClick ? 0 : -1}
                onClick={onRowClick ? () => onRowClick(r) : undefined}
                onKeyDown={
                  onRowClick
                    ? (e) => {
                        if (e.key === "Enter") onRowClick(r);
                      }
                    : undefined
                }
                className={cn(
                  "border-b border-[var(--border)] last:border-b-0",
                  onRowClick && "cursor-pointer hover:bg-[var(--background)] focus:outline-none focus:ring-1 focus:ring-[var(--ring)]",
                )}
              >
                {columns.map((c) => (
                  <td
                    key={c.key}
                    className={cn("h-10 px-3 py-2 align-middle text-[var(--foreground)]", c.className)}
                  >
                    {c.render(r)}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}