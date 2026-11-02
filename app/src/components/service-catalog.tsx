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
      <div className="flex flex-col gap-3 sm:flex-row">
        <input aria-label="Search services" placeholder="Search providers…" value={query} onChange={(e) => setQuery(e.target.value)}
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm" />
        <select aria-label="Filter category" value={category} onChange={(e) => setCategory(e.target.value)}
          className="rounded-md border border-input bg-background px-3 py-2 text-sm sm:min-w-56">
          <option>All</option>
          {CATEGORIES.map((item) => <option key={item}>{item}</option>)}
        </select>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {services.map((service) => (
          <a key={service.id} href={`/vault/new?service=${service.id}`}
            className="rounded-lg border border-border p-4 space-y-2 hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
            <div className="flex items-center justify-between gap-2">
              <h2 className="font-semibold">{service.label}</h2>
              <span className="text-xs text-muted-foreground">{service.category}</span>
            </div>
            <p className="text-sm text-muted-foreground">{service.description}</p>
            <span className="text-xs underline">Configure credential →</span>
          </a>
        ))}
        {services.length === 0 && <p className="text-sm text-muted-foreground sm:col-span-2 lg:col-span-3">No matching provider. You can still add a custom service.</p>}
      </div>
      <a href="/vault/new?service=custom" className="inline-flex rounded-md border border-border px-3 py-2 text-sm font-medium hover:bg-muted/40">
        + Add a custom service
      </a>
    </div>
  )
}
