import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { permissionsApi } from "@/api/resources";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Check, ChevronsUpDown } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Permission-key picker backed by the catalog. Free text stays allowed —
 * typing a value not in the list (wildcards like `invoice.*.*`) keeps it.
 */
export function PermissionCombobox({
  id,
  value,
  onChange,
  placeholder = "domain.resource.action",
  allowFreeText = true,
}: {
  /** Put on the trigger button so a <Label htmlFor> names the picker. */
  id?: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  allowFreeText?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const permsQ = useQuery({
    queryKey: ["permissions"],
    queryFn: () => permissionsApi.list(),
    retry: false,
  });

  const items = useMemo(() => {
    const f = query.toLowerCase();
    const all = permsQ.data ?? [];
    const filtered = f
      ? all.filter(
          (p) => p.key.toLowerCase().includes(f) || (p.description ?? "").toLowerCase().includes(f),
        )
      : all;
    return filtered.slice(0, 50);
  }, [permsQ.data, query]);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          id={id}
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className="w-full justify-between font-mono text-xs font-normal"
        >
          <span className={cn("truncate", !value && "text-[var(--muted-foreground)]")}>
            {value || placeholder}
          </span>
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[--radix-popover-trigger-width] p-0" align="start">
        <Command shouldFilter={false}>
          <CommandInput
            placeholder="Search permissions..."
            value={query}
            onValueChange={setQuery}
          />
          <CommandList className="max-h-64">
            <CommandEmpty>
              {allowFreeText && query ? (
                <button
                  type="button"
                  className="w-full cursor-pointer px-2 py-1.5 text-left font-mono text-xs hover:bg-[var(--muted)]"
                  onClick={() => {
                    onChange(query);
                    setOpen(false);
                  }}
                >
                  Use “{query}”
                </button>
              ) : (
                "No permissions match."
              )}
            </CommandEmpty>
            <CommandGroup>
              {allowFreeText && query && !items.some((p) => p.key === query) ? (
                <CommandItem
                  value={`__free__${query}`}
                  onSelect={() => {
                    onChange(query);
                    setOpen(false);
                  }}
                >
                  <span className="font-mono text-xs">Use “{query}”</span>
                </CommandItem>
              ) : null}
              {items.map((p) => (
                <CommandItem
                  key={p.id}
                  value={p.key}
                  onSelect={() => {
                    onChange(p.key);
                    setOpen(false);
                  }}
                >
                  <Check
                    className={cn("mr-2 h-4 w-4", value === p.key ? "opacity-100" : "opacity-0")}
                  />
                  <span className="flex min-w-0 flex-col">
                    <span className="truncate font-mono text-xs">{p.key}</span>
                    {p.description ? (
                      <span className="truncate text-xs text-[var(--muted-foreground)]">
                        {p.description}
                      </span>
                    ) : null}
                  </span>
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
