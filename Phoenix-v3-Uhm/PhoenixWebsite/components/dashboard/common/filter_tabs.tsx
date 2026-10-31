export function FilterTabs<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: readonly { value: T; label: string; count?: number }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="flex items-center gap-0.5 rounded-md bg-white/[0.03] p-0.5">
      {options.map((opt) => {
        const active = value === opt.value;
        return (
          <button
            key={opt.value}
            type="button"
            onClick={() => onChange(opt.value)}
            className={
              "flex items-center gap-1.5 rounded-[5px] px-2.5 py-1 text-[11.5px] font-medium transition-colors " +
              (active ? "bg-white/[0.06] text-white" : "text-white/50 hover:text-white/80")
            }
          >
            {opt.label}
            {typeof opt.count === "number" && (
              <span className={active ? "text-white/60" : "text-white/30"}>
                {opt.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
