'use client';
export function BgFx() {
  return (
    <>
      <div
        aria-hidden="true"
        className="pointer-events-none fixed -top-64 -right-64 z-[9990] h-[600px] w-[600px] rounded-full bg-primary/[0.05] blur-[160px] mix-blend-screen animate-[orb-a_18s_ease-in-out_infinite]"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none fixed -bottom-64 -left-32 z-[9990] h-[500px] w-[500px] rounded-full bg-primary/[0.04] blur-[150px] mix-blend-screen animate-[orb-b_22s_ease-in-out_infinite]"
      />
    </>
  );
}
