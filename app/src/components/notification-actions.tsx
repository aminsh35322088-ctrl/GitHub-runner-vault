'use client'

import { useState } from 'react'
import { Button } from './ui/button'
import { markAllNotificationsReadAction, markNotificationReadAction } from '../vault-actions.ts'

export function MarkNotificationRead({ id, read }: { id: string; read: boolean }) {
  const [busy, setBusy] = useState(false)
  async function mark() {
    setBusy(true)
    try { await markNotificationReadAction(id); window.location.reload() } finally { setBusy(false) }
  }
  if (read) return <span className="text-xs text-muted-foreground">Read</span>
  return <Button size="sm" variant="outline" disabled={busy} onClick={() => void mark()}>{busy ? 'Saving…' : 'Mark read'}</Button>
}

export function MarkAllNotificationsRead() {
  const [busy, setBusy] = useState(false)
  async function mark() {
    setBusy(true)
    try { await markAllNotificationsReadAction(); window.location.reload() } finally { setBusy(false) }
  }
  return <Button variant="outline" size="sm" disabled={busy} onClick={() => void mark()}>{busy ? 'Saving…' : 'Mark all read'}</Button>
}
