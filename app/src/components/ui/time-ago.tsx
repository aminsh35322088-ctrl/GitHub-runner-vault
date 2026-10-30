// Hydration-safe timestamp cell used by every table in the dashboard.
//
// The problem it solves: a timestamp rendered with the ambient timezone and
// `Date.now()` cannot produce the same text on the server and in the browser.
// The worker runs in UTC, the visitor does not, so `toLocaleDateString` alone
// disagreed on the calendar day for any timestamp near midnight UTC — 22 of
// the 40 most recent production rows. React reported that as error #418 and
// the user was shown a date that was not their own.
//
// The fix is a two-pass render, which is React's documented answer for
// output that legitimately differs between server and client:
//
//   pass 1  server AND the hydrating client both render the absolute date
//           pinned to UTC. Identical text, so hydration matches. This is
//           also what a visitor without JS keeps seeing.
//   pass 2  once hydrated, re-render in the visitor's own timezone and
//           allow the relative buckets ("5m ago") that depend on wall clock.
//
// `useSyncExternalStore` is the primitive for "am I hydrated": it is the only
// hook that takes an explicit server snapshot, so the gate cannot drift. It
// also keeps this file free of `useEffect`, per the project's React rules.

'use client'

import { useSyncExternalStore } from 'react'
import { formatAbsoluteDate, formatTime } from 'sigillo-app/src/lib/utils'

// Hydration never "changes" after it happens, so the store never notifies.
const subscribe = () => () => {}
const getClientSnapshot = () => true
const getServerSnapshot = () => false

export function TimeAgo({ ts, className }: { ts: number; className?: string }) {
  const hydrated = useSyncExternalStore(subscribe, getClientSnapshot, getServerSnapshot)

  // Snapshot-at-render on purpose: these cells never re-render on their own,
  // so a ticking clock would buy nothing and only add timers to every row.
  const timeZone = hydrated ? Intl.DateTimeFormat().resolvedOptions().timeZone : 'UTC'
  const label = hydrated
    ? formatTime({ ts, now: Date.now(), timeZone })
    : formatAbsoluteDate({ ts, timeZone: 'UTC' })

  return (
    <time
      dateTime={new Date(ts).toISOString()}
      title={new Date(ts).toLocaleString('en-US', { timeZone, timeZoneName: 'short' })}
      className={className}
    >
      {label}
    </time>
  )
}
