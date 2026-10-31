// Value encryption for the credential registry (AES-256-GCM).
//
// Differences from the upstream secret encryption on purpose:
//  - ENCRYPTION_KEY is mandatory and must be exactly 32 random bytes (base64).
//    There is no fallback derived from another secret: a missing or malformed
//    key makes every operation fail instead of silently using a weaker one.
//  - The ciphertext is bound to its row with GCM additional authenticated data
//    (credential id + key version), so a ciphertext copied into another row, or
//    re-labelled with another key version, fails authentication.
//  - The key is passed in, never read from ambient state, so the policy is unit-testable.

export class CredentialCryptoError extends Error {}

const KEY_BYTES = 32
const IV_BYTES = 12

function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value)
  return Uint8Array.from(binary, (c) => c.charCodeAt(0))
}

function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

export async function importEncryptionKey(base64Key: unknown): Promise<CryptoKey> {
  if (typeof base64Key !== 'string' || !base64Key.trim()) {
    throw new CredentialCryptoError('ENCRYPTION_KEY is not configured')
  }
  let raw: Uint8Array<ArrayBuffer>
  try {
    raw = fromBase64(base64Key.trim())
  } catch {
    throw new CredentialCryptoError('ENCRYPTION_KEY is not valid base64')
  }
  if (raw.byteLength !== KEY_BYTES) {
    throw new CredentialCryptoError(`ENCRYPTION_KEY must decode to exactly ${KEY_BYTES} bytes`)
  }
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

function additionalData(credentialId: string, keyVersion: number): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`credential:${credentialId}:v${keyVersion}`)
}

export async function encryptCredentialValue(
  key: CryptoKey,
  credentialId: string,
  keyVersion: number,
  plaintext: string,
): Promise<{ encrypted: string; iv: string }> {
  if (!plaintext) throw new CredentialCryptoError('refusing to encrypt an empty value')
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES))
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: additionalData(credentialId, keyVersion) },
    key,
    new TextEncoder().encode(plaintext),
  )
  return { encrypted: toBase64(new Uint8Array(ciphertext)), iv: toBase64(iv) }
}

export async function decryptCredentialValue(
  key: CryptoKey,
  credentialId: string,
  keyVersion: number,
  encrypted: string,
  iv: string,
): Promise<string> {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(iv), additionalData: additionalData(credentialId, keyVersion) },
      key,
      fromBase64(encrypted),
    )
    return new TextDecoder().decode(plaintext)
  } catch {
    // Never echo the underlying error: it can carry nothing useful and we do not
    // want ciphertext-shaped data in logs.
    throw new CredentialCryptoError('credential value could not be decrypted')
  }
}
