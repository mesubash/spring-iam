import { toast } from "sonner";
import { Copy, Download } from "lucide-react";

/** Recovery-code grid with copy-all and download actions. Shown once at enrollment. */
export function RecoveryCodes({ codes }: { codes: string[] }) {
  const text = codes.join("\n");

  const copy = () =>
    navigator.clipboard
      .writeText(text)
      .then(() => toast.success("Recovery codes copied"))
      .catch(() => toast.error("Could not copy"));

  const download = () => {
    const blob = new Blob([`Recovery codes\n\n${text}\n`], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="rounded-md border border-[var(--border)]">
      <div className="flex items-center justify-between border-b border-[var(--border)] px-3 py-1.5">
        <span className="text-xs font-medium text-[var(--muted-foreground)]">
          {codes.length} recovery codes
        </span>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={copy}
            aria-label="Copy all"
            className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-[var(--muted-foreground)] hover:bg-[var(--muted)] hover:text-[var(--foreground)]"
          >
            <Copy className="h-3.5 w-3.5" /> Copy
          </button>
          <button
            type="button"
            onClick={download}
            aria-label="Download"
            className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-[var(--muted-foreground)] hover:bg-[var(--muted)] hover:text-[var(--foreground)]"
          >
            <Download className="h-3.5 w-3.5" /> Download
          </button>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 bg-[var(--muted)]/35 p-3 font-mono text-xs">
        {codes.map((c) => (
          <span key={c}>{c}</span>
        ))}
      </div>
    </div>
  );
}
