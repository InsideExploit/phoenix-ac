import { Nav } from "@/components/site/nav";
import { Footer } from "@/components/site/footer";

export function PageShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background">
      <Nav />
      <main className="pt-32 pb-24">
        <div className="container-page">{children}</div>
      </main>
      <Footer />
    </div>
  );
}
