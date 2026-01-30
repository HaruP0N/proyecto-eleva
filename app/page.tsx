import Link from "next/link";
import ProjectCarousel from "@/components/ProjectCarousel";

export default function HomePage() {
  return (
    <main>
      <section className="mx-auto grid max-w-6xl grid-cols-1 gap-8 px-4 py-12 md:grid-cols-2">
        <div className="rounded-2xl bg-white p-8 shadow-sm">
          <h1 className="text-4xl font-extrabold tracking-tight text-[var(--eleva-blue)]">
            Especialistas en Cielo Americano
            <span className="text-slate-900"> y trabajos de construcción</span>
          </h1>
          <p className="mt-4 text-slate-600">
            Instalación, mantención y remodelaciones. Productos con stock y atención directa para cotizar tu pedido.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <Link className="rounded-lg bg-[var(--eleva-blue)] px-4 py-2 text-white hover:opacity-95" href="/productos">
              Ver productos
            </Link>
            <Link className="rounded-lg border px-4 py-2 hover:bg-slate-50" href="/contacto">
              Cotizar / Contactar
            </Link>
          </div>
        </div>
        <div className="rounded-2xl bg-gradient-to-br from-[var(--eleva-blue)] to-[var(--eleva-blue-2)] p-8 text-white shadow-sm">
          <h2 className="text-xl font-semibold">¿Qué hacemos?</h2>
          <ul className="mt-4 space-y-2 text-white/90">
            <li>• Cielo americano (suministro e instalación)</li>
            <li>• Revestimientos interiores</li>
            <li>• Terminaciones y remodelaciones</li>
            <li>• Obras menores y mejoramiento</li>
          </ul>
          <p className="mt-6 text-sm text-white/80">
            Escríbenos con tu medida/fotos y te respondemos con una cotización.
          </p>
        </div>
      </section>
      <section className="mx-auto max-w-6xl px-4 pb-14">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-2xl font-bold text-slate-900">Proyectos realizados</h3>
          <Link className="text-sm font-medium text-[var(--eleva-blue)] hover:underline" href="/proyectos">
            Ver todos
          </Link>
        </div>
        <ProjectCarousel />
      </section>
    </main>
  );
}
