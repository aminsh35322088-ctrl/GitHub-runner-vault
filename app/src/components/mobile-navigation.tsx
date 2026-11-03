import {
  Activity,
  ChartNoAxesCombined,
  ClipboardList,
  LayoutDashboard,
  MoreHorizontal,
  Plus,
  Settings as SettingsIcon,
  ShieldCheck,
  Workflow,
} from 'lucide-react'
import { cn } from '../lib/utils.ts'

const primaryItems = [
  { href: '/vault', label: 'Home', icon: LayoutDashboard },
  { href: '/vault/requests', label: 'Requests', icon: ClipboardList },
  { href: '/vault/services', label: 'Add', icon: Plus },
  { href: '/vault/validation', label: 'Health', icon: ShieldCheck },
]

const moreItems = [
  { href: '/vault/integrations', label: 'Integrations', icon: Workflow },
  { href: '/vault/analytics', label: 'Usage analytics', icon: ChartNoAxesCombined },
  { href: '/vault/audit', label: 'Audit log', icon: Activity },
  { href: '/vault/settings', label: 'Settings', icon: SettingsIcon },
]

function isActive(current: string, href: string): boolean {
  if (href === '/vault') return current === href || current.startsWith('/vault/credentials/')
  if (href === '/vault/services') {
    return current === href || current.startsWith('/vault/new') || current.startsWith('/vault/register/')
  }
  return current === href || current.startsWith(href + '/')
}

export function MobileNavigation({ current }: { current: string }) {
  const moreActive = moreItems.some((item) => isActive(current, item.href))

  return (
    <nav aria-label="Mobile navigation" className="fixed inset-x-0 bottom-0 z-30 border-t border-border/80 bg-background/95 pb-[env(safe-area-inset-bottom)] shadow-[0_-10px_30px_-22px_rgba(0,0,0,.35)] backdrop-blur-xl lg:hidden">
      <div className="mx-auto grid max-w-2xl grid-cols-5 gap-1 px-2 pt-1.5">
        {primaryItems.map((item) => {
          const Icon = item.icon
          const active = isActive(current, item.href)
          return (
            <a key={item.href} href={item.href} aria-current={active ? 'page' : undefined} className={cn('flex min-h-12 flex-col items-center justify-center gap-1 rounded-xl px-1 text-[10px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring', active ? 'text-emerald-700 dark:text-emerald-300' : 'text-muted-foreground hover:bg-muted')}>
              <span className={cn('grid size-7 place-items-center rounded-lg transition-colors', active ? 'bg-emerald-500/10' : '')}><Icon className="size-[18px]" aria-hidden /></span>
              <span>{item.label}</span>
            </a>
          )
        })}
        <details className="relative min-w-0">
          <summary aria-label="More navigation links" aria-current={moreActive ? 'page' : undefined} className={cn('flex min-h-12 cursor-pointer list-none flex-col items-center justify-center gap-1 rounded-xl px-1 text-[10px] font-semibold transition-colors marker:hidden focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring [&::-webkit-details-marker]:hidden', moreActive ? 'text-emerald-700 dark:text-emerald-300' : 'text-muted-foreground hover:bg-muted')}>
            <span className={cn('grid size-7 place-items-center rounded-lg transition-colors', moreActive ? 'bg-emerald-500/10' : '')}><MoreHorizontal className="size-[18px]" aria-hidden /></span>
            <span>More</span>
          </summary>
          <div className="absolute bottom-[calc(100%+0.5rem)] right-0 z-50 w-[min(18rem,calc(100vw-1rem))] rounded-2xl border border-border bg-popover p-2 text-popover-foreground shadow-2xl shadow-black/15">
            <p className="px-3 pb-2 pt-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">More workspace</p>
            {moreItems.map((item) => {
              const Icon = item.icon
              const active = isActive(current, item.href)
              return (
                <a key={item.href} href={item.href} aria-current={active ? 'page' : undefined} className={cn('flex min-h-12 items-center gap-3 rounded-xl px-3 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring', active ? 'bg-primary/10 text-primary' : 'text-foreground hover:bg-muted')}>
                  <Icon className="size-4 shrink-0" aria-hidden />
                  <span className="min-w-0 flex-1">{item.label}</span>
                  {active && <span className="size-1.5 rounded-full bg-primary" />}
                </a>
              )
            })}
          </div>
        </details>
      </div>
    </nav>
  )
}
