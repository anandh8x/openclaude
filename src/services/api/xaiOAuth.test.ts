import { afterEach, expect, mock, test } from 'bun:test'
import {
  buildXaiOAuthAuthorizeUrl,
  XaiOAuthService,
} from './xaiOAuth.js'
import {
  validateXaiOAuthEndpoint,
  validateXaiOAuthRedirectUri,
  getXaiOAuthEntitlementMessage,
  XAI_OAUTH_AUTHORIZATION_ENDPOINT,
  XAI_OAUTH_SCOPE,
  XAI_OAUTH_TOKEN_ENDPOINT,
} from './xaiOAuthShared.js'

type FakeResponseCapture = {
  body: string
  headers: Record<string, string>
  statusCode: number | null
}

type FakeServerResponse = {
  destroyed: boolean
  headersSent: boolean
  writableEnded: boolean
  writeHead: (statusCode: number, headers?: Record<string, string>) => void
  end: (chunk?: string) => void
}

type FakeAuthCodeListenerInstance = {
  callbackPath: string
  capture: FakeResponseCapture | null
  start: (port?: number, host?: string) => Promise<number>
  waitForAuthorization: (
    state: string,
    onReady: () => Promise<void>,
  ) => Promise<string>
  hasPendingResponse: () => boolean
  handleSuccessRedirect: (
    scopes: string[],
    customHandler?: (res: FakeServerResponse, scopes: string[]) => void,
  ) => void
  handleErrorRedirect: (customHandler?: (res: FakeServerResponse) => void) => void
  cancelPendingAuthorization: (error?: Error) => void
}

const originalFetch = globalThis.fetch

afterEach(() => {
  mock.restore()
  globalThis.fetch = originalFetch
})

test('xAI OAuth 403 entitlement message mentions account, subscription, model, and quota', () => {
  const message = getXaiOAuthEntitlementMessage().toLowerCase()

  expect(message).toContain('wrong')
  expect(message).toContain('account')
  expect(message).toContain('subscription')
  expect(message).toContain('model')
  expect(message).toContain('quota')
})

function createFakeServerResponse(capture: FakeResponseCapture): FakeServerResponse {
  return {
    destroyed: false,
    headersSent: false,
    writableEnded: false,
    writeHead(statusCode: number, headers?: Record<string, string>) {
      capture.statusCode = statusCode
      capture.headers = { ...(headers ?? {}) }
      this.headersSent = true
    },
    end(chunk?: string) {
      if (chunk) {
        capture.body += chunk
      }
      this.writableEnded = true
    },
  }
}

function createFakeAuthCodeListener(callbackPath: string): FakeAuthCodeListenerInstance {
  let pending = false
  const instance: FakeAuthCodeListenerInstance = {
    callbackPath,
    capture: null,
    async start(port?: number, host?: string) {
      expect(port).toBe(56121)
      expect(host).toBe('127.0.0.1')
      return 56121
    },
    async waitForAuthorization(state, onReady) {
      expect(state).toBeTruthy()
      pending = true
      instance.capture = { body: '', headers: {}, statusCode: null }
      await onReady()
      return 'auth-code'
    },
    hasPendingResponse() {
      return pending
    },
    handleSuccessRedirect(scopes, customHandler) {
      if (!pending || !instance.capture) return
      const res = createFakeServerResponse(instance.capture)
      customHandler?.(res, scopes)
      if (!res.writableEnded) res.end()
      pending = false
    },
    handleErrorRedirect(customHandler) {
      if (!pending || !instance.capture) return
      const res = createFakeServerResponse(instance.capture)
      customHandler?.(res)
      if (!res.writableEnded) res.end()
      pending = false
    },
    cancelPendingAuthorization() {
      pending = false
    },
  }
  return instance
}

test('buildXaiOAuthAuthorizeUrl includes PKCE, state, nonce, plan, and referrer', () => {
  const authUrl = new URL(
    buildXaiOAuthAuthorizeUrl({
      authorizationEndpoint: XAI_OAUTH_AUTHORIZATION_ENDPOINT,
      clientId: 'client-id',
      codeChallenge: 'challenge',
      state: 'state-value',
      nonce: 'nonce-value',
    }),
  )

  expect(authUrl.origin + authUrl.pathname).toBe(XAI_OAUTH_AUTHORIZATION_ENDPOINT)
  expect(authUrl.searchParams.get('response_type')).toBe('code')
  expect(authUrl.searchParams.get('client_id')).toBe('client-id')
  expect(authUrl.searchParams.get('redirect_uri')).toBe(
    'http://127.0.0.1:56121/callback',
  )
  expect(authUrl.searchParams.get('scope')).toBe(XAI_OAUTH_SCOPE)
  expect(authUrl.searchParams.get('code_challenge')).toBe('challenge')
  expect(authUrl.searchParams.get('code_challenge_method')).toBe('S256')
  expect(authUrl.searchParams.get('state')).toBe('state-value')
  expect(authUrl.searchParams.get('nonce')).toBe('nonce-value')
  expect(authUrl.searchParams.get('plan')).toBe('generic')
  expect(authUrl.searchParams.get('referrer')).toBe('openclaude')
})

test('xAI OAuth endpoint and redirect validation reject unsafe URLs', () => {
  expect(() =>
    validateXaiOAuthEndpoint('https://auth.x.ai/oauth2/token', 'token'),
  ).not.toThrow()
  expect(() =>
    validateXaiOAuthEndpoint('http://auth.x.ai/oauth2/token', 'token'),
  ).toThrow('must use HTTPS')
  expect(() =>
    validateXaiOAuthEndpoint('https://example.com/oauth2/token', 'token'),
  ).toThrow('x.ai')
  expect(() =>
    validateXaiOAuthRedirectUri('http://localhost:56121/callback'),
  ).toThrow('127.0.0.1')
  expect(() =>
    validateXaiOAuthRedirectUri('http://127.0.0.1:56121/callback'),
  ).not.toThrow()
})

test('XaiOAuthService exchanges authorization code for tokens', async () => {
  let capturedAuthUrl = ''
  let capturedBody = ''

  globalThis.fetch = mock(async (_input, init) => {
    capturedBody =
      init?.body instanceof URLSearchParams ? init.body.toString() : ''
    return new Response(
      JSON.stringify({
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        id_token: 'id-token',
        expires_in: 3600,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      },
    )
  }) as unknown as typeof fetch

  const service = new XaiOAuthService({
    clientId: 'client-id',
    createAuthCodeListener: callbackPath =>
      createFakeAuthCodeListener(callbackPath) as never,
    discoverEndpoints: async () => ({
      authorization_endpoint: XAI_OAUTH_AUTHORIZATION_ENDPOINT,
      token_endpoint: XAI_OAUTH_TOKEN_ENDPOINT,
    }),
  })

  const tokens = await service.startOAuthFlow(async authUrl => {
    capturedAuthUrl = authUrl
  })

  expect(tokens.accessToken).toBe('access-token')
  expect(tokens.refreshToken).toBe('refresh-token')
  expect(tokens.idToken).toBe('id-token')
  expect(tokens.expiresAt).toBeGreaterThan(Date.now())
  expect(capturedAuthUrl).toContain('client_id=client-id')
  expect(capturedBody).toContain('grant_type=authorization_code')
  expect(capturedBody).toContain('code=auth-code')
  expect(capturedBody).toContain('client_id=client-id')
})
