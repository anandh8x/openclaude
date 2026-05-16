import { createCombinedAbortSignal } from '../../utils/combinedAbortSignal.js'
import { asTrimmedString, decodeJwtPayload } from './codexOAuthShared.js'

export const XAI_OAUTH_DISCOVERY_URL =
  'https://auth.x.ai/.well-known/openid-configuration'
export const XAI_OAUTH_AUTHORIZATION_ENDPOINT =
  'https://auth.x.ai/oauth2/authorize'
export const XAI_OAUTH_TOKEN_ENDPOINT = 'https://auth.x.ai/oauth2/token'
export const XAI_OAUTH_SCOPE =
  'openid profile email offline_access grok-cli:access api:access'
export const XAI_OAUTH_REDIRECT_URI = 'http://127.0.0.1:56121/callback'
export const XAI_OAUTH_CALLBACK_HOST = '127.0.0.1'
export const XAI_OAUTH_CALLBACK_PORT = 56121
export const XAI_OAUTH_CALLBACK_PATH = '/callback'
export const XAI_OAUTH_TEST_CLIENT_ID_ENV =
  'OPENCLAUDE_XAI_OAUTH_TEST_CLIENT_ID'

export type XaiOAuthDiscovery = {
  authorization_endpoint: string
  token_endpoint: string
}

export function getXaiOAuthClientId(
  env: NodeJS.ProcessEnv = process.env,
): string {
  return asTrimmedString(env[XAI_OAUTH_TEST_CLIENT_ID_ENV]) ?? ''
}

export function validateXaiOAuthEndpoint(
  value: string,
  label: string,
): string {
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new Error(`xAI OAuth ${label} endpoint is not a valid URL.`)
  }

  const hostname = parsed.hostname.toLowerCase()
  if (
    parsed.protocol !== 'https:' ||
    (hostname !== 'x.ai' && !hostname.endsWith('.x.ai'))
  ) {
    throw new Error(
      `xAI OAuth ${label} endpoint must use HTTPS on x.ai or a subdomain of x.ai.`,
    )
  }

  return parsed.toString()
}

export function validateXaiOAuthRedirectUri(value: string): string {
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new Error('xAI OAuth redirect URI is not a valid URL.')
  }

  if (
    parsed.protocol !== 'http:' ||
    parsed.hostname !== XAI_OAUTH_CALLBACK_HOST ||
    parsed.port !== String(XAI_OAUTH_CALLBACK_PORT) ||
    parsed.pathname !== XAI_OAUTH_CALLBACK_PATH
  ) {
    throw new Error(
      'xAI OAuth redirect URI must be http://127.0.0.1:56121/callback.',
    )
  }

  return parsed.toString()
}

export function parseJwtExpiryMs(token: string | undefined): number | undefined {
  if (!token) return undefined
  const exp = decodeJwtPayload(token)?.exp
  if (typeof exp === 'number' && Number.isFinite(exp)) {
    return exp * 1000
  }
  return undefined
}

export function normalizeExpiresAtMs(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    return value
  }
  return undefined
}

export function getXaiOAuthEntitlementMessage(): string {
  return [
    'xAI Grok OAuth returned 403 Forbidden.',
    'Check for the wrong xAI account, a missing or unsupported Grok/SuperGrok subscription tier, a selected model that is not included, or exhausted quota.',
  ].join(' ')
}

export async function discoverXaiOAuthEndpoints(options?: {
  discoveryUrl?: string
  signal?: AbortSignal
}): Promise<XaiOAuthDiscovery> {
  const discoveryUrl = validateXaiOAuthEndpoint(
    options?.discoveryUrl ?? XAI_OAUTH_DISCOVERY_URL,
    'discovery',
  )
  const { signal, cleanup } = createCombinedAbortSignal(options?.signal, {
    timeoutMs: 15_000,
  })

  try {
    const response = await fetch(discoveryUrl, { signal })
    if (!response.ok) {
      throw new Error(
        `xAI OAuth discovery failed with status ${response.status}.`,
      )
    }

    const payload = (await response.json()) as Record<string, unknown>
    const authorizationEndpoint =
      asTrimmedString(payload.authorization_endpoint) ??
      XAI_OAUTH_AUTHORIZATION_ENDPOINT
    const tokenEndpoint =
      asTrimmedString(payload.token_endpoint) ?? XAI_OAUTH_TOKEN_ENDPOINT

    return {
      authorization_endpoint: validateXaiOAuthEndpoint(
        authorizationEndpoint,
        'authorization',
      ),
      token_endpoint: validateXaiOAuthEndpoint(tokenEndpoint, 'token'),
    }
  } finally {
    cleanup()
  }
}
