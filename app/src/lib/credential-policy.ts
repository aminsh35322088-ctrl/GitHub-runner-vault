// Who may see and use a credential. Pure functions so the rule table from the
// design (Active+Visible = usable; Active+Invisible, Disabled, Expired = not) is
// tested directly and shared by the registry listing and the use endpoint.

export type CredentialState = {
  status: 'pending' | 'active' | 'disabled'
  visible: boolean
  expiresAt: number | null
  externallyManaged?: boolean
  hasValue: boolean
}

export type Availability =
  | { available: true }
  | { available: false; reason: 'pending' | 'disabled' | 'hidden' | 'expired' | 'no_value' }

export function isExpired(expiresAt: number | null, now: number): boolean {
  return expiresAt !== null && expiresAt <= now
}

/** Whether the credential may appear in the runner's registry AND be requested for use. */
export function availability(state: CredentialState, now: number): Availability {
  if (state.status === 'pending') return { available: false, reason: 'pending' }
  if (state.status === 'disabled') return { available: false, reason: 'disabled' }
  // Hidden is checked before expired so a hidden credential never reveals that it
  // exists or what state it is in. "expired" is only ever reported for a
  // credential the model could already see, which lets it ask for a renewal.
  if (!state.visible) return { available: false, reason: 'hidden' }
  if (isExpired(state.expiresAt, now)) return { available: false, reason: 'expired' }
  // Metadata-only entries are discoverable ("GitHub access exists") but the vault
  // holds no value for them, so the vault can never deliver or proxy one.
  if (!state.externallyManaged && !state.hasValue) return { available: false, reason: 'no_value' }
  return { available: true }
}

/** What a runner or model is told when a credential is not available. Deliberately
 *  coarse for hidden credentials so their existence is not confirmed. */
export function publicReason(reason: Extract<Availability, { available: false }>['reason']): string {
  switch (reason) {
    case 'expired': return 'expired'
    case 'disabled': return 'unavailable'
    case 'hidden': return 'unavailable'
    case 'pending': return 'unavailable'
    case 'no_value': return 'unavailable'
  }
}
