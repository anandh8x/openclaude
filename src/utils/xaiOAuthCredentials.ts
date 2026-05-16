import { isBareMode } from './envUtils.js'
import { createCombinedAbortSignal } from './combinedAbortSignal.js'
import { getSecureStorage } from './secureStorage/index.js'
import { asTrimmedString } from '../services/api/codexOAuthShared.js'
import {
  getXaiOAuthClientId,
  normalizeExpiresAtMs,
  parseJwtExpiryMs,
  XAI_OAUTH_TOKEN_ENDPOINT,
} from '../services/api/xaiOAuthShared.js'

export const XAI_OAUTH_STORAGE_KEY = 'xaiOAuth' as const
const XAI_OAUTH_TOKEN_REFRESH_SKEW_MS = 90_000
const XAI_OAUTH_TOKEN_REFRESH_RETRY_COOLDOWN_MS = 60_000

export type XaiOAuthCredentialBlob = {
  accessToken: string
  refreshToken?: string
  idToken?: string
  expiresAt?: number
  profileId?: string
  lastRefreshAt?: number
  lastRefreshFailureAt?: number
}

type XaiOAuthTokenRefreshResponse = {
  access_token?: string
  refresh_token?: string
  id_token?: string
  expires_in?: number
}

let inFlightXaiOAuthRefresh:
  | Promise<{
      refreshed: boolean
      credentials?: XaiOAuthCredentialBlob
    }>
  | null = null
let inMemoryLastRefreshFailureAt: number | null = null

function getXaiOAuthSecureStorage() {
  return getSecureStorage({ allowPlainTextFallback: false })
}

function normalizeXaiOAuthCredentialBlob(
  value: unknown,
): XaiOAuthCredentialBlob | undefined {
  if (!value || typeof value !== 'object') return undefined

  const record = value as Record<string, unknown>
  const accessToken = asTrimmedString(record.accessToken)
  if (!accessToken) return undefined

  const refreshToken = asTrimmedString(record.refreshToken)
  const idToken = asTrimmedString(record.idToken)
  const profileId = asTrimmedString(record.profileId)
  const expiresAt =
    normalizeExpiresAtMs(record.expiresAt) ??
    parseJwtExpiryMs(accessToken) ??
    parseJwtExpiryMs(idToken)
  const lastRefreshAt =
    typeof record.lastRefreshAt === 'number' &&
    Number.isFinite(record.lastRefreshAt)
      ? record.lastRefreshAt
      : undefined
  const lastRefreshFailureAt =
    typeof record.lastRefreshFailureAt === 'number' &&
    Number.isFinite(record.lastRefreshFailureAt)
      ? record.lastRefreshFailureAt
      : undefined

  return {
    accessToken,
    refreshToken,
    idToken,
    expiresAt,
    profileId,
    lastRefreshAt,
    lastRefreshFailureAt,
  }
}

function shouldRefreshXaiOAuthToken(blob: XaiOAuthCredentialBlob): boolean {
  if (blob.expiresAt === undefined) {
    return false
  }

  return blob.expiresAt <= Date.now() + XAI_OAUTH_TOKEN_REFRESH_SKEW_MS
}

function isWithinRefreshFailureCooldown(
  blob: XaiOAuthCredentialBlob,
  now = Date.now(),
): boolean {
  const lastRefreshFailureAt = Math.max(
    blob.lastRefreshFailureAt ?? 0,
    inMemoryLastRefreshFailureAt ?? 0,
  )

  return Boolean(
    lastRefreshFailureAt &&
      now - lastRefreshFailureAt < XAI_OAUTH_TOKEN_REFRESH_RETRY_COOLDOWN_MS,
  )
}

function getRefreshErrorMessage(status: number, bodyText: string): string {
  if (!bodyText.trim()) {
    return `xAI OAuth token refresh failed with status ${status}.`
  }

  try {
    const parsed = JSON.parse(bodyText) as Record<string, unknown>
    const message =
      asTrimmedString(parsed.error_description) ??
      asTrimmedString(parsed.error) ??
      bodyText.trim()
    return `xAI OAuth token refresh failed with status ${status}: ${message}`
  } catch {
    return `xAI OAuth token refresh failed with status ${status}: ${bodyText.trim()}`
  }
}

export function readXaiOAuthCredentials(): XaiOAuthCredentialBlob | undefined {
  if (isBareMode()) return undefined

  try {
    const data = getXaiOAuthSecureStorage().read()
    return normalizeXaiOAuthCredentialBlob(data?.xaiOAuth)
  } catch {
    return undefined
  }
}

export async function readXaiOAuthCredentialsAsync(): Promise<
  XaiOAuthCredentialBlob | undefined
> {
  if (isBareMode()) return undefined

  try {
    const data = await getXaiOAuthSecureStorage().readAsync()
    return normalizeXaiOAuthCredentialBlob(data?.xaiOAuth)
  } catch {
    return undefined
  }
}

export function saveXaiOAuthCredentials(
  credentials: XaiOAuthCredentialBlob,
): { success: boolean; warning?: string } {
  if (isBareMode()) {
    return { success: false, warning: 'Bare mode: secure storage is disabled.' }
  }

  const normalized = normalizeXaiOAuthCredentialBlob(credentials)
  if (!normalized) {
    return { success: false, warning: 'xAI OAuth credentials are incomplete.' }
  }

  const secureStorage = getXaiOAuthSecureStorage()
  const previous = secureStorage.read() || {}
  const previousCredentials = normalizeXaiOAuthCredentialBlob(
    previous[XAI_OAUTH_STORAGE_KEY],
  )
  const next = {
    ...(previous as Record<string, unknown>),
    [XAI_OAUTH_STORAGE_KEY]: {
      ...normalized,
      profileId: normalized.profileId ?? previousCredentials?.profileId,
      lastRefreshAt: normalized.lastRefreshAt ?? Date.now(),
    },
  }
  const result = secureStorage.update(next as typeof previous)
  if (result.success) {
    const stored = normalizeXaiOAuthCredentialBlob(next[XAI_OAUTH_STORAGE_KEY])
    inMemoryLastRefreshFailureAt = stored?.lastRefreshFailureAt ?? null
  }
  return result
}

export function clearXaiOAuthCredentials(): {
  success: boolean
  warning?: string
} {
  if (isBareMode()) {
    return { success: true }
  }

  const secureStorage = getXaiOAuthSecureStorage()
  const previous = secureStorage.read() || {}
  const next = { ...(previous as Record<string, unknown>) }
  delete next[XAI_OAUTH_STORAGE_KEY]
  const result = secureStorage.update(next as typeof previous)
  if (result.success) {
    inMemoryLastRefreshFailureAt = null
  }
  return result
}

function persistXaiOAuthRefreshFailure(
  credentials: XaiOAuthCredentialBlob,
  occurredAt: number,
): void {
  const result = saveXaiOAuthCredentials({
    ...credentials,
    lastRefreshFailureAt: occurredAt,
  })
  if (!result.success) {
    inMemoryLastRefreshFailureAt = occurredAt
  }
}

export async function refreshXaiOAuthAccessTokenIfNeeded(options?: {
  force?: boolean
}): Promise<{
  refreshed: boolean
  credentials?: XaiOAuthCredentialBlob
}> {
  if (isBareMode()) {
    return { refreshed: false }
  }

  const current = await readXaiOAuthCredentialsAsync()
  if (!current) {
    return { refreshed: false }
  }

  if (!current.refreshToken) {
    return { refreshed: false, credentials: current }
  }
  const refreshToken = current.refreshToken

  if (!options?.force && !shouldRefreshXaiOAuthToken(current)) {
    return { refreshed: false, credentials: current }
  }

  if (!options?.force && isWithinRefreshFailureCooldown(current)) {
    return { refreshed: false, credentials: current }
  }

  if (inFlightXaiOAuthRefresh) {
    return inFlightXaiOAuthRefresh
  }

  inFlightXaiOAuthRefresh = (async () => {
    const refreshAttemptedAt = Date.now()
    const clientId = getXaiOAuthClientId()
    if (!clientId) {
      return { refreshed: false, credentials: current }
    }

    try {
      const body = new URLSearchParams({
        client_id: clientId,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      })

      const { signal, cleanup } = createCombinedAbortSignal(undefined, {
        timeoutMs: 15_000,
      })
      let payload: XaiOAuthTokenRefreshResponse
      try {
        const response = await fetch(XAI_OAUTH_TOKEN_ENDPOINT, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body,
          signal,
        })

        if (!response.ok) {
          const bodyText = await response.text().catch(() => '')
          throw new Error(getRefreshErrorMessage(response.status, bodyText))
        }

        payload = (await response.json()) as XaiOAuthTokenRefreshResponse
      } finally {
        cleanup()
      }

      const accessToken = asTrimmedString(payload.access_token)
      if (!accessToken) {
        throw new Error(
          'xAI OAuth token refresh succeeded without a new access token.',
        )
      }

      const expiresAt =
        typeof payload.expires_in === 'number' &&
        Number.isFinite(payload.expires_in)
          ? Date.now() + payload.expires_in * 1000
          : parseJwtExpiryMs(accessToken) ??
            parseJwtExpiryMs(payload.id_token) ??
            current.expiresAt

      const next: XaiOAuthCredentialBlob = {
        accessToken,
        refreshToken:
          asTrimmedString(payload.refresh_token) ?? current.refreshToken,
        idToken: asTrimmedString(payload.id_token) ?? current.idToken,
        expiresAt,
        profileId: current.profileId,
        lastRefreshAt: Date.now(),
      }

      const saveResult = saveXaiOAuthCredentials(next)
      if (!saveResult.success) {
        throw new Error(
          saveResult.warning ??
            'xAI OAuth token refresh succeeded but credentials could not be saved.',
        )
      }

      return { refreshed: true, credentials: next }
    } catch (error) {
      persistXaiOAuthRefreshFailure(current, refreshAttemptedAt)
      throw error
    } finally {
      inFlightXaiOAuthRefresh = null
    }
  })()

  return inFlightXaiOAuthRefresh
}
