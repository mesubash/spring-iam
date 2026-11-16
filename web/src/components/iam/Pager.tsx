import { Button } from "@/components/ui/button";

/**
 * Prev/Next for 0-based pages. Pass totalPages when the endpoint returns a
 * PageResponse; for plain arrays pass hasNext (a full page came back).
 */
export function Pager({
  page,
  onPage,
  totalPages,
  hasNext,
}: {
  page: number;
  onPage: (page: number) => void;
  totalPages?: number;
  hasNext?: boolean;
}) {
  const next = totalPages !== undefined ? page + 1 < totalPages : !!hasNext;
  if (page === 0 && !next) return null;
  return (
    <div className="mt-3 flex items-center gap-2">
      <span className="text-xs text-[var(--muted-foreground)]">
        Page {page + 1}
        {totalPages ? ` of ${totalPages}` : ""}
      </span>
      <div className="ml-auto flex gap-2">
        <Button variant="outline" size="sm" disabled={page === 0} onClick={() => onPage(page - 1)}>
          Prev
        </Button>
        <Button variant="outline" size="sm" disabled={!next} onClick={() => onPage(page + 1)}>
          Next
        </Button>
      </div>
    </div>
  );
}
