import type { ReactNode } from 'react'

export function SectionCard({ title, description, icon, children, action }: {
  title: string
  description?: string
  icon?: ReactNode
  children?: ReactNode
  action?: ReactNode
}) {
  return <section className="overflow-hidden rounded-2xl border border-border bg-card shadow-sm">
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border/70 px-4 py-4 sm:px-5 lg:px-6 lg:py-5">
      <div className="flex min-w-0 items-start gap-3">
        {icon ? <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary">{icon}</span> : null}
        <div className="min-w-0">
          <h2 className="font-semibold tracking-tight">{title}</h2>
          {description ? <p className="mt-1 text-sm text-muted-foreground">{description}</p> : null}
        </div>
      </div>
      {action}
    </div>
    <div className="p-4 sm:p-5 lg:p-6">{children}</div>
  </section>
}
