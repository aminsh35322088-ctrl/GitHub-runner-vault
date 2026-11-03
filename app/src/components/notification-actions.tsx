'use client'

import { useState } from 'react'
import { AlertTriangle, Bell, Check, CheckCheck, ChevronRight, CircleAlert, X } from 'lucide-react'
import { Button } from './ui/button'
import { markAllNotificationsReadAction, markNotificationReadAction } from '../vault-actions.ts'

type NotificationItem = {
  id: string
  kind: string
  severity: 'info' | 'warning' | 'critical'
  title: string
  message: string
  credentialId: string | null
  credentialName: string
  createdAt: number
  readAt: number | null
}

export function NotificationBell({
  unread,
  notifications,
}: {
  unread: number
  notifications: NotificationItem[]
}) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function markOne(id: string) {
    setBusy(true)
    setError('')
    try {
      await markNotificationReadAction(id)
      window.location.reload()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not update notification')
      setBusy(false)
    }
  }

  async function markAll() {
    setBusy(true)
    setError('')
    try {
      await markAllNotificationsReadAction()
      window.location.reload()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not update notifications')
      setBusy(false)
    }
  }

  return (
    <div className="relative">
      <Button
        size="icon-lg"
        variant="outline"
        aria-label={unread ? 'Notifications, ' + unread + ' unread' : 'Notifications'}
        aria-expanded={open}
        aria-haspopup="dialog"
        onClick={() => setOpen((value) => !value)}
        className="relative rounded-xl"
      >
        <Bell className="size-[18px]" aria-hidden />
        {unread > 0 && <span className="absolute -right-1 -top-1 grid min-h-5 min-w-5 place-items-center rounded-full bg-destructive px-1 text-[10px] font-bold leading-none text-white">{unread > 99 ? '99+' : unread}</span>}
      </Button>

      {open && (
        <section
          role="dialog"
          aria-label="Vault notifications"
          className="absolute right-0 top-[calc(100%+0.65rem)] z-50 flex max-h-[min(78dvh,34rem)] w-[min(23rem,calc(100vw-1.25rem))] flex-col overflow-hidden rounded-2xl border border-border bg-popover text-popover-foreground shadow-2xl shadow-black/15"
        >
          <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
            <div className="min-w-0">
              <h2 className="text-sm font-semibold">Notifications</h2>
              <p className="mt-0.5 text-xs text-muted-foreground">{unread} unread · Vault activity</p>
            </div>
            <div className="flex shrink-0 items-center gap-1">
              {unread > 0 && <Button size="icon-sm" variant="ghost" disabled={busy} aria-label="Mark all notifications read" title="Mark all read" onClick={() => void markAll()}><CheckCheck className="size-4"/></Button>}
              <Button size="icon-sm" variant="ghost" aria-label="Close notifications" onClick={() => setOpen(false)}><X className="size-4"/></Button>
            </div>
          </div>

          {notifications.length === 0 ? (
            <div className="grid min-h-40 place-items-center px-6 py-8 text-center">
              <span className="grid size-11 place-items-center rounded-2xl bg-muted text-muted-foreground"><Bell className="size-5"/></span>
              <p className="mt-3 text-sm font-medium">All quiet</p>
              <p className="mt-1 text-xs text-muted-foreground">Credential and security events will appear here.</p>
            </div>
          ) : (
            <div className="min-h-0 overflow-y-auto">
              {notifications.map((item) => (
                <article key={item.id} className={'border-b border-border/70 px-4 py-3 last:border-0 ' + (!item.readAt ? 'bg-primary/[0.035]' : '')}>
                  <div className="flex items-start gap-2.5">
                    <span className={'mt-0.5 grid size-8 shrink-0 place-items-center rounded-xl ' + (item.severity === 'critical' ? 'bg-destructive/10 text-destructive' : item.severity === 'warning' ? 'bg-warning/10 text-warning' : 'bg-primary/10 text-primary')}>
                      {item.severity === 'critical' ? <CircleAlert className="size-4"/> : item.severity === 'warning' ? <AlertTriangle className="size-4"/> : <Check className="size-4"/>}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-start justify-between gap-2">
                        <h3 className="break-words text-sm font-semibold leading-snug">{item.title}</h3>
                        {!item.readAt && <span className="mt-1 size-2 shrink-0 rounded-full bg-primary" aria-label="Unread"/>}
                      </div>
                      <p className="mt-1 break-words text-xs leading-relaxed text-muted-foreground">{item.message}</p>
                      <div className="mt-2 flex items-center justify-between gap-2">
                        <time className="text-[11px] text-muted-foreground" dateTime={new Date(item.createdAt).toISOString()}>
                          {new Date(item.createdAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
                        </time>
                        <div className="flex items-center gap-2">
                          {item.credentialId && <a href={item.kind === 'credential_registration_requested' ? '/vault/requests' : '/vault/credentials/' + item.credentialId} className="inline-flex items-center gap-1 text-[11px] font-medium text-primary hover:underline">{item.kind === 'credential_registration_requested' ? 'Review request' : item.credentialName || 'Credential'}<ChevronRight className="size-3"/></a>}
                          {!item.readAt && <button type="button" disabled={busy} onClick={() => void markOne(item.id)} aria-label="Mark notification read" className="rounded-md p-1 text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-50"><Check className="size-3.5"/></button>}
                        </div>
                      </div>
                    </div>
                  </div>
                </article>
              ))}
            </div>
          )}

          {error && <p role="alert" className="border-t border-border px-4 py-2 text-xs text-destructive">{error}</p>}
          <div className="border-t border-border bg-muted/30 px-4 py-2 text-center">
            <span className="text-[11px] text-muted-foreground">Showing the latest {notifications.length} notifications · updates on refresh</span>
          </div>
        </section>
      )}
    </div>
  )
}
