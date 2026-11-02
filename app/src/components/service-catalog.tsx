'use client'

import { useMemo, useState } from 'react'
import { SERVICE_CATALOG, type ServiceCategory } from '../lib/presets.ts'

const CATEGORIES: ServiceCategory[] = [
  'Cloud & Infrastructure', 'Developer Platforms', 'AI & LLM',
  'Payments', 'Monitoring & Analytics', 'Communication', 'Data & Storage',
]

export function ServiceCatalog() {
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState('All')
  const services = useMemo(() => SERVICE_CATALOG.filter((service) => {
    const matchesCategory = category === 'All' || service.category === category
    const haystack = `${service.label} ${service.description} ${service.category}`.toLowerCase()
    return matchesCategory && haystack.includes(query.trim().toLowerCase())
  }), [query, category])

  return (
    <div className="space-y-5">
      <div className="grid min-w-0 gap-3 sm:grid-cols-[1fr_16rem]">
        <input aria-label="Search services" placeholder="Search providers…" value={query} onChange={(e) => setQuery(e.target.value)}
          className="h-11 w-full min-w-0 rounded-lg border border-input bg-background px-3 text-base sm:text-sm" />
        <select aria-label="Filter category" value={category} onChange={(e) => setCategory(e.target.value)}
          className="h-11 min-w-0 w-full rounded-lg border border-input bg-background px-3 text-base sm:text-sm">
          <option>All</option>
          {CATEGORIES.map((item) => <option key={item}>{item}</option>)}
        </select>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {services.map((service) => (
          <a key={service.id} href={`/vault/new?service=${service.id}`}
            className="flex min-h-36 min-w-0 flex-col gap-2 rounded-xl border border-border bg-card p-4 hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring active:bg-muted/60">
            <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
              <h2 className="min-w-0 break-words font-semibold">{service.label}</h2>
              <span className="rounded-full bg-muted px-2 py-1 text-[11px] text-muted-foreground">{service.category}</span>
            </div>
            <p className="min-w-0 flex-1 break-words text-sm text-muted-foreground">{service.description}</p>
            <span className="min-h-8 text-sm font-medium underline underline-offset-4">Configure credential →</span>
          </a>
        ))}
        {services.length === 0 && <p className="text-sm text-muted-foreground sm:col-span-2 lg:col-span-3">No matching provider. You can still add a custom service.</p>}
      </div>
      <a href="/vault/new?service=custom" className="inline-flex min-h-11 w-full items-center justify-center rounded-lg border border-border px-3 py-2 text-sm font-medium hover:bg-muted/40 sm:w-auto">
        + Add a custom service
      </a>
    </div>
  )
}
