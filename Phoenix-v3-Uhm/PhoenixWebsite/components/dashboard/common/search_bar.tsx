import { Search } from "lucide-react";
import type { KeyboardEvent } from "react";

export function SearchBar({
  value,
  onChange,
  onSubmit,
  placeholder,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  onSubmit?: () => void;
  placeholder?: string;
  className?: string;
}) {
  const handleKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && onSubmit) onSubmit();
  };
  return (
    <div className={`relative w-full max-w-[320px] ${className ?? ""}`}>
      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/35" />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={handleKey}
        placeholder={placeholder}
        className="h-8 w-full rounded-md border border-white/[0.06] bg-white/[0.02] pl-8 pr-2.5 text-[12.5px] text-white placeholder:text-white/30 focus:border-white/15 focus:outline-none focus:ring-0"
      />
    </div>
  );
}
