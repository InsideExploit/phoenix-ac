const SKEL_W = [72, 55, 85, 48, 68, 40, 78, 60, 52];

export function SkeletonRows({ cols, rows = 8 }: { cols: number; rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <tr key={i} className="border-b border-white/[0.04] last:border-0">
          {Array.from({ length: cols }).map((_, j) => (
            <td key={j} className="px-4 py-[13px]">
              <div
                className="skel-bar"
                style={{
                  width: `${SKEL_W[(i * cols + j) % SKEL_W.length]}%`,
                  animationDelay: `${(i * cols + j) * 90}ms`,
                }}
              />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}
