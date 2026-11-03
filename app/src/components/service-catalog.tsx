'use client'

import { useMemo, useState } from 'react'
import { ArrowUpRight, Check, ChevronRight, Plus, Search, X } from 'lucide-react'
import { SERVICE_CATALOG, type ServiceCategory } from '../lib/presets.ts'

const CATEGORIES: Array<'All' | ServiceCategory> = [
  'All', 'Cloud & Infrastructure', 'Developer Platforms', 'AI & LLM',
  'Payments', 'Monitoring & Analytics', 'Communication', 'Data & Storage',
]

function categoryTone(category: ServiceCategory) {
  if (category === 'AI & LLM') return 'bg-violet-500/10 text-violet-700 dark:text-violet-300'
  if (category === 'Cloud & Infrastructure') return 'bg-sky-500/10 text-sky-700 dark:text-sky-300'
  if (category === 'Developer Platforms') return 'bg-slate-500/10 text-slate-700 dark:text-slate-300'
  if (category === 'Payments') return 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
  if (category === 'Monitoring & Analytics') return 'bg-amber-500/10 text-amber-700 dark:text-amber-300'
  if (category === 'Communication') return 'bg-pink-500/10 text-pink-700 dark:text-pink-300'
  return 'bg-cyan-500/10 text-cyan-700 dark:text-cyan-300'
}

export function ServiceCatalog() {
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState<'All' | ServiceCategory>('All')
  const services = useMemo(() => SERVICE_CATALOG.filter((service) => {
    const matchesCategory = category === 'All' || service.category === category
    const haystack = (service.label + ' ' + service.description + ' ' + service.category + ' ' + service.hosts.join(' ')).toLowerCase()
    return matchesCategory && haystack.includes(query.trim().toLowerCase())
  }), [query, category])

  return (
    <div className="space-y-5">
      <div className="rounded-2xl border border-border bg-card p-3.5 sm:p-4">
        <label className="flex h-11 items-center gap-2.5 rounded-xl border border-input bg-background px-3.5 focus-within:border-primary/50 focus-within:ring-2 focus-within:ring-primary/10">
          <Search className="size-4 shrink-0 text-muted-foreground" />
          <input aria-label="Search providers" placeholder="Search by provider, category or API host…" value={query} onChange={(event) => setQuery(event.target.value)} className="h-full min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground/70" />
          {query && <button type="button" aria-label="Clear search" onClick={() => setQuery('')} className="grid size-7 shrink-0 place-items-center rounded-lg text-muted-foreground hover:bg-muted hover:text-foreground"><X className="size-3.5" /></button>}
        </label>
        <div className="scrollbar-hide mt-3 flex gap-1.5 overflow-x-auto pb-0.5" role="group" aria-label="Filter providers by category">
          {CATEGORIES.map((item) => {
            const active = category === item
            return <button key={item} type="button" aria-pressed={active} onClick={() => setCategory(item)} className={'min-h-8 shrink-0 rounded-lg px-3 text-xs font-medium transition-colors ' + (active ? 'bg-primary text-primary-foreground shadow-sm' : 'bg-muted/70 text-muted-foreground hover:bg-muted hover:text-foreground')}>{item}</button>
          })}
        </div>
      </div>

      <div className="flex items-center justify-between gap-3">
        <div><h2 className="text-sm font-semibold">Available providers</h2><p className="mt-0.5 text-xs text-muted-foreground">Choose a provider to start with its curated API and authentication defaults.</p></div>
        <span className="shrink-0 rounded-full border border-border bg-card px-2.5 py-1 text-[11px] font-medium tabular-nums text-muted-foreground">{services.length} / {SERVICE_CATALOG.length}</span>
      </div>

      {services.length === 0 ? (
        <div className="grid justify-items-center rounded-2xl border border-dashed border-border bg-card px-5 py-12 text-center">
          <span className="grid size-11 place-items-center rounded-xl bg-muted text-muted-foreground"><Search className="size-5" /></span>
          <p className="mt-3 text-sm font-semibold">No providers found</p>
          <p className="mt-1 max-w-xs text-xs leading-relaxed text-muted-foreground">Try a different search term or choose another category.</p>
          <button type="button" onClick={() => { setQuery(''); setCategory('All') }} className="mt-3 inline-flex min-h-9 items-center gap-1.5 rounded-lg px-3 text-xs font-semibold text-primary hover:bg-primary/5">Clear filters <X className="size-3.5" /></button>
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {services.map((service) => (
            <a key={service.id} href={'/vault/new?service=' + service.id} className="group flex min-h-[180px] min-w-0 flex-col rounded-2xl border border-border bg-card p-4 transition duration-150 hover:-translate-y-0.5 hover:border-primary/30 hover:shadow-md hover:shadow-black/[0.035] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
              <div className="flex items-start justify-between gap-3">
                <span className={'grid size-10 shrink-0 place-items-center rounded-xl text-base font-bold ' + categoryTone(service.category)}>{service.label.slice(0, 1)}</span>
                <span className="grid size-8 place-items-center rounded-lg text-muted-foreground transition-colors group-hover:bg-primary/8 group-hover:text-primary"><ArrowUpRight className="size-4" /></span>
              </div>
              <div className="mt-3 flex items-center gap-2">
                <h3 className="min-w-0 truncate text-sm font-semibold">{service.label}</h3>
                <span className="inline-flex shrink-0 items-center gap-1 text-[10px] font-medium text-emerald-700 dark:text-emerald-300"><Check className="size-3" /> Preset</span>
              </div>
              <p className="mt-1.5 line-clamp-2 min-h-9 text-xs leading-relaxed text-muted-foreground">{service.description}</p>
              <div className="mt-auto flex min-w-0 items-center justify-between gap-2 border-t border-border/70 pt-3">
                <span className="truncate font-mono text-[10px] text-muted-foreground">{service.hosts[0]}</span>
                <span className="inline-flex shrink-0 items-center gap-1 text-[11px] font-semibold text-primary">Configure <ChevronRight className="size-3.5 transition-transform group-hover:translate-x-0.5" /></span>
              </div>
            </a>
          ))}
        </div>
      )}

      <a href="/vault/new?service=custom" className="group flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-dashed border-border bg-muted/20 p-4 transition-colors hover:border-primary/40 hover:bg-primary/[0.025] sm:px-5">
        <div className="flex min-w-0 items-center gap-3">
          <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-border bg-card text-muted-foreground group-hover:text-primary"><Plus className="size-5" /></span>
          <span className="min-w-0"><span className="block text-sm font-semibold">Need another provider?</span><span className="mt-1 block text-xs text-muted-foreground">Request a custom service adapter from your trusted Runner.</span></span>
        </div>
        <span className="inline-flex min-h-9 items-center gap-1.5 rounded-lg px-3 text-xs font-semibold text-primary transition-colors group-hover:bg-primary/5">Custom provider <ChevronRight className="size-3.5" /></span>
      </a>
    </div>
  )
}
