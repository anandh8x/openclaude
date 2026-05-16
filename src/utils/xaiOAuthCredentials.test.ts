import { afterEach, describe, expect, mock, test } from 'bun:test'

function makeJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' }))
    .toString('base64url')
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${header}.${body}.signature`
}

describe('xaiOAuthCredentials', () => {
  const originalSimple = process.env.CLAUDE_CODE_SIMPLE
  const originalClientId = process.env.OPENCLAUDE_XAI_OAUTH_TEST_CLIENT_ID
  const originalFetch = globalThis.fetch

  afterEach(() => {
    mock.restore()
    globalThis.fetch = originalFetch

    if (originalSimple === undefined) {
      delete process.env.CLAUDE_CODE_SIMPLE
    } else {
      process.env.CLAUDE_CODE_SIMPLE = originalSimple
    }

    if (originalClientId === undefined) {
      delete process.env.OPENCLAUDE_XAI_OAUTH_TEST_CLIENT_ID
    } else {
      process.env.OPENCLAUDE_XAI_OAUTH_TEST_CLIENT_ID = originalClientId
    }
  })

  test('refreshXaiOAuthAccessTokenIfNeeded refreshes expiring stored credentials', async () => {
    delete process.env.CLAUDE_CODE_SIMPLE
    process.env.OPENCLAUDE_XAI_OAUTH_TEST_CLIENT_ID = 'client-id'

    const expiringAccessToken = makeJwt({
      exp: Math.floor((Date.now() + 30_000) / 1000),
    })
    const freshAccessToken = makeJwt({
      exp: Math.floor((Date.now() + 3_600_000) / 1000),
    })

    let storageState: Record<string, unknown> = {
      xaiOAuth: {
        accessToken: expiringAccessToken,
        refreshToken: 'refresh-old',
      },
    }

    mock.module('./secureStorage/index.js', () => ({
      getSecureStorage: (options?: { allowPlainTextFallback?: boolean }) => {
        expect(options?.allowPlainTextFallback).toBe(false)
        return {
          read: () => storageState,
          readAsync: async () => storageState,
          update: (next: Record<string, unknown>) => {
            storageState = next
            return { success: true }
          },
        }
      },
    }))

    let capturedBody = ''
    globalThis.fetch = mock(async (_input, init) => {
      capturedBody =
        init?.body instanceof URLSearchParams ? init.body.toString() : ''
      return new Response(
        JSON.stringify({
          access_token: freshAccessToken,
          refresh_token: 'refresh-new',
          expires_in: 3600,
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      )
    }) as unknown as typeof fetch

    const { refreshXaiOAuthAccessTokenIfNeeded, readXaiOAuthCredentials } =
      await import(
        // @ts-expect-error cache-busting query string for Bun module mocks
        './xaiOAuthCredentials.js?refresh-success'
      )

    const result = await refreshXaiOAuthAccessTokenIfNeeded()
    expect(result.refreshed).toBe(true)
    expect(capturedBody).toContain('grant_type=refresh_token')
    expect(capturedBody).toContain('client_id=client-id')
    expect(capturedBody).toContain('refresh_token=refresh-old')

    const stored = readXaiOAuthCredentials()
    expect(stored?.accessToken).toBe(freshAccessToken)
    expect(stored?.refreshToken).toBe('refresh-new')
    expect(stored?.expiresAt).toBeGreaterThan(Date.now())
  })

  test('opaque non-expiring access tokens do not crash or refresh early', async () => {
    delete process.env.CLAUDE_CODE_SIMPLE
    process.env.OPENCLAUDE_XAI_OAUTH_TEST_CLIENT_ID = 'client-id'

    let storageState: Record<string, unknown> = {
      xaiOAuth: {
        accessToken: 'opaque-token',
        refreshToken: 'refresh-token',
      },
    }

    mock.module('./secureStorage/index.js', () => ({
      getSecureStorage: () => ({
        read: () => storageState,
        readAsync: async () => storageState,
        update: (next: Record<string, unknown>) => {
          storageState = next
          return { success: true }
        },
      }),
    }))

    const fetchMock = mock(async () => new Response('{}'))
    globalThis.fetch = fetchMock as unknown as typeof fetch

    const { refreshXaiOAuthAccessTokenIfNeeded } = await import(
      // @ts-expect-error cache-busting query string for Bun module mocks
      './xaiOAuthCredentials.js?opaque-token'
    )

    const result = await refreshXaiOAuthAccessTokenIfNeeded()
    expect(result.refreshed).toBe(false)
    expect(result.credentials?.accessToken).toBe('opaque-token')
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
