import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { identitiesApi } from "@/api/resources";
import type { IdentityAdmin } from "@/api/types";
import { useAuthz } from "@/context/AuthzContext";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { X } from "lucide-react";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type Props = {
  value: string;
  onChange: (subjectId: string) => void;
  placeholder?: string;
  id?: string;
  className?: string;
};

/**
 * Subject selector: searches identities by email and stores the subject UUID.
 * Falls back to a raw UUID input when the caller lacks platform.identity.read.
 * Pasting a raw UUID always works, so service/group subjects stay addressable.
 */
export function SubjectPicker({ value, onChange, placeholder, id, className }: Props) {
  const { can } = useAuthz();
  const canSearch = can("platform.identity.read");

  if (!canSearch) {
    return (
      <Input
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value.trim())}
        placeholder={placeholder ?? "Subject ID (UUID)"}
        className={cn("font-mono text-xs", className)}
      />
    );
  }
  return (
    <SearchPicker id={id} value={value} onChange={onChange} placeholder={placeholder} className={className} />
  );
}

function SearchPicker({ value, onChange, placeholder, id, className }: Props) {
  const [text, setText] = useState("");
  const [debounced, setDebounced] = useState("");
  const [open, setOpen] = useState(false);
  const [picked, setPicked] = useState<IdentityAdmin | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(text), 250);
    return () => clearTimeout(t);
  }, [text]);

  // Resolve an externally-set UUID (e.g. deep link) to an email label.
  const resolveQ = useQuery({
    queryKey: ["identity", value],
    queryFn: () => identitiesApi.get(value),
    enabled: !!value && UUID_RE.test(value) && picked?.id !== value,
    retry: false,
    staleTime: 60_000,
  });
  useEffect(() => {
    if (resolveQ.data && resolveQ.data.id === value) setPicked(resolveQ.data);
  }, [resolveQ.data, value]);

  const searchQ = useQuery({
    queryKey: ["identities", "search", debounced],
    queryFn: () => identitiesApi.list({ query: debounced || undefined, limit: 20 }),
    enabled: open,
    staleTime: 30_000,
  });
  const options = useMemo(
    () => (Array.isArray(searchQ.data) ? searchQ.data : []),
    [searchQ.data],
  );

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, []);

  const pick = (identity: IdentityAdmin) => {
    setPicked(identity);
    onChange(identity.id);
    setText("");
    setOpen(false);
  };

  const clear = () => {
    setPicked(null);
    onChange("");
    setText("");
  };

  if (value && picked?.id === value) {
    return (
      <div
        className={cn(
          "flex h-9 items-center justify-between gap-2 rounded border border-[var(--border)] bg-[var(--card)] px-2",
          className,
        )}
      >
        <div className="min-w-0">
          <span className="block truncate text-sm">{picked.email}</span>
        </div>
        <button
          type="button"
          onClick={clear}
          aria-label="Clear subject"
          className="shrink-0 rounded p-0.5 text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
    );
  }

  return (
    <div ref={rootRef} className={cn("relative", className)}>
      <Input
        id={id}
        value={text}
        onChange={(e) => {
          const v = e.target.value;
          setText(v);
          setOpen(true);
          // Raw UUID paste is accepted directly.
          if (UUID_RE.test(v.trim())) onChange(v.trim());
          else if (value) onChange("");
        }}
        onFocus={() => setOpen(true)}
        placeholder={placeholder ?? "Search users by email…"}
        autoComplete="off"
      />
      {open ? (
        <div className="absolute left-0 right-0 top-10 z-30 max-h-64 overflow-y-auto rounded border border-[var(--border)] bg-[var(--card)] py-1 shadow-sm">
          {searchQ.isLoading ? (
            <div className="px-3 py-2 text-xs text-[var(--muted-foreground)]">Searching…</div>
          ) : options.length === 0 ? (
            <div className="px-3 py-2 text-xs text-[var(--muted-foreground)]">
              {UUID_RE.test(text.trim()) ? "Using raw UUID." : "No matching users."}
            </div>
          ) : (
            options.map((identity) => (
              <button
                key={identity.id}
                type="button"
                onClick={() => pick(identity)}
                className="flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left hover:bg-[var(--background)]"
              >
                <span className="truncate text-sm">{identity.email}</span>
                <span
                  className={cn(
                    "shrink-0 text-[10px] uppercase",
                    identity.accountStatus === "ACTIVE"
                      ? "text-[var(--muted-foreground)]"
                      : "text-[var(--warning)]",
                  )}
                >
                  {identity.accountStatus !== "ACTIVE" ? identity.accountStatus : ""}
                </span>
              </button>
            ))
          )}
        </div>
      ) : null}
    </div>
  );
}
