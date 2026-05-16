import { AuthCodeListener } from '../oauth/auth-code-listener.js'
import {
  generateCodeChallenge,
  generateCodeVerifier,
  generateState,
} from '../oauth/crypto.js'
import { createCombinedAbortSignal } from '../../utils/combinedAbortSignal.js'
import { asTrimmedString, escapeHtml } from './codexOAuthShared.js'
import {
  discoverXaiOAuthEndpoints,
  getXaiOAuthClientId,
  validateXaiOAuthRedirectUri,
  XAI_OAUTH_CALLBACK_HOST,
  XAI_OAUTH_CALLBACK_PATH,
  XAI_OAUTH_CALLBACK_PORT,
  XAI_OAUTH_REDIRECT_URI,
  XAI_OAUTH_SCOPE,
  type XaiOAuthDiscovery,
} from './xaiOAuthShared.js'

type XaiOAuthTokenResponse = {
  access_token?: string
  refresh_token?: string
  id_token?: string
  expires_in?: number
}

export type XaiOAuthTokens = {
  accessToken: string
  refreshToken?: string
  idToken?: string
  expiresAt?: number
}

export function buildXaiOAuthAuthorizeUrl(options: {
  authorizationEndpoint: string
  clientId: string
  codeChallenge: string
  state: string
  nonce: string
  redirectUri?: string
}): string {
  const redirectUri = validateXaiOAuthRedirectUri(
    options.redirectUri ?? XAI_OAUTH_REDIRECT_URI,
  )
  const authUrl = new URL(options.authorizationEndpoint)

  authUrl.searchParams.append('response_type', 'code')
  authUrl.searchParams.append('client_id', options.clientId)
  authUrl.searchParams.append('redirect_uri', redirectUri)
  authUrl.searchParams.append('scope', XAI_OAUTH_SCOPE)
  authUrl.searchParams.append('code_challenge', options.codeChallenge)
  authUrl.searchParams.append('code_challenge_method', 'S256')
  authUrl.searchParams.append('state', options.state)
  authUrl.searchParams.append('nonce', options.nonce)
  authUrl.searchParams.append('plan', 'generic')
  authUrl.searchParams.append('referrer', 'openclaude')

  return authUrl.toString()
}

function renderSuccessPage(): string {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><title>xAI OAuth Complete</title></head>
  <body>
    <h1>xAI Grok OAuth complete</h1>
    <p>You can return to OpenClaude now.</p>
  </body>
</html>`
}

function renderErrorPage(message: string): string {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><title>xAI OAuth Failed</title></head>
  <body>
    <h1>xAI Grok OAuth failed</h1>
    <p>${escapeHtml(message)}</p>
    <p>You can close this window and try again in OpenClaude.</p>
  </body>
</html>`
}

function renderCancelledPage(): string {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><title>xAI OAuth Cancelled</title></head>
  <body>
    <h1>xAI Grok OAuth cancelled</h1>
    <p>You can close this window and retry in OpenClaude.</p>
  </body>
</html>`
}

async function exchangeAuthorizationCode(options: {
  authorizationCode: string
  codeVerifier: string
  clientId: string
  tokenEndpoint: string
  signal?: AbortSignal
}): Promise<XaiOAuthTokens> {
  const redirectUri = validateXaiOAuthRedirectUri(XAI_OAUTH_REDIRECT_URI)
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: options.authorizationCode,
    redirect_uri: redirectUri,
    client_id: options.clientId,
    code_verifier: options.codeVerifier,
  })

  const { signal, cleanup } = createCombinedAbortSignal(options.signal, {
    timeoutMs: 15_000,
  })

  let payload: XaiOAuthTokenResponse
  try {
    const response = await fetch(options.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
      signal,
    })

    if (!response.ok) {
      const errorText = await response.text().catch(() => '')
      throw new Error(
        errorText.trim()
          ? `xAI OAuth token exchange failed (${response.status}): ${errorText.trim()}`
          : `xAI OAuth token exchange failed with status ${response.status}.`,
      )
    }

    payload = (await response.json()) as XaiOAuthTokenResponse
  } finally {
    cleanup()
  }

  const accessToken = asTrimmedString(payload.access_token)
  if (!accessToken) {
    throw new Error(
      'xAI OAuth completed, but the token response was missing an access token.',
    )
  }

  const expiresAt =
    typeof payload.expires_in === 'number' && Number.isFinite(payload.expires_in)
      ? Date.now() + payload.expires_in * 1000
      : undefined

  return {
    accessToken,
    refreshToken: asTrimmedString(payload.refresh_token),
    idToken: asTrimmedString(payload.id_token),
    expiresAt,
  }
}

type XaiOAuthListener = Pick<
  AuthCodeListener,
  | 'start'
  | 'hasPendingResponse'
  | 'waitForAuthorization'
  | 'handleSuccessRedirect'
  | 'handleErrorRedirect'
  | 'cancelPendingAuthorization'
>

type XaiOAuthServiceOptions = {
  createAuthCodeListener?: (callbackPath: string) => XaiOAuthListener
  discoverEndpoints?: () => Promise<XaiOAuthDiscovery>
  clientId?: string
}

export class XaiOAuthService {
  private authCodeListener: XaiOAuthListener | null = null
  private tokenExchangeAbortController: AbortController | null = null

  constructor(private readonly options: XaiOAuthServiceOptions = {}) {}

  private buildCancellationError(): Error {
    return new Error('xAI OAuth flow was cancelled.')
  }

  async startOAuthFlow(
    authURLHandler: (authUrl: string) => Promise<void>,
  ): Promise<XaiOAuthTokens> {
    const clientId = this.options.clientId ?? getXaiOAuthClientId()
    if (!clientId) {
      throw new Error(
        'xAI OAuth is waiting on an official OpenClaude xAI OAuth public client ID. This build does not include one yet.',
      )
    }

    const endpoints =
      this.options.discoverEndpoints?.() ?? discoverXaiOAuthEndpoints()
    const { authorization_endpoint, token_endpoint } = await endpoints
    const authCodeListener =
      this.options.createAuthCodeListener?.(XAI_OAUTH_CALLBACK_PATH) ??
      new AuthCodeListener(XAI_OAUTH_CALLBACK_PATH)

    this.authCodeListener = authCodeListener

    try {
      await authCodeListener.start(
        XAI_OAUTH_CALLBACK_PORT,
        XAI_OAUTH_CALLBACK_HOST,
      )

      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)
      const state = generateState()
      const nonce = generateState()
      const authUrl = buildXaiOAuthAuthorizeUrl({
        authorizationEndpoint: authorization_endpoint,
        clientId,
        codeChallenge,
        state,
        nonce,
      })

      try {
        const authorizationCode = await authCodeListener.waitForAuthorization(
          state,
          async () => {
            await authURLHandler(authUrl)
          },
        )

        const tokenExchangeAbortController = new AbortController()
        this.tokenExchangeAbortController = tokenExchangeAbortController

        let tokens: XaiOAuthTokens
        try {
          tokens = await exchangeAuthorizationCode({
            authorizationCode,
            codeVerifier,
            clientId,
            tokenEndpoint: token_endpoint,
            signal: tokenExchangeAbortController.signal,
          })
        } finally {
          if (this.tokenExchangeAbortController === tokenExchangeAbortController) {
            this.tokenExchangeAbortController = null
          }
        }

        if (this.authCodeListener !== authCodeListener) {
          throw this.buildCancellationError()
        }

        authCodeListener.handleSuccessRedirect([], res => {
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
          })
          res.end(renderSuccessPage())
        })

        return tokens
      } catch (error) {
        const resolvedError =
          this.authCodeListener === authCodeListener
            ? error
            : this.buildCancellationError()

        if (authCodeListener.hasPendingResponse()) {
          const isCancellation =
            resolvedError instanceof Error &&
            resolvedError.message === 'xAI OAuth flow was cancelled.'

          authCodeListener.handleErrorRedirect(res => {
            res.writeHead(isCancellation ? 200 : 400, {
              'Content-Type': 'text/html; charset=utf-8',
            })
            res.end(
              isCancellation
                ? renderCancelledPage()
                : renderErrorPage(
                    resolvedError instanceof Error
                      ? resolvedError.message
                      : String(resolvedError),
                  ),
            )
          })
        }
        throw resolvedError
      } finally {
        this.cleanup()
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      if (
        message.includes('EADDRINUSE') ||
        message.includes(String(XAI_OAUTH_CALLBACK_PORT))
      ) {
        throw new Error(
          `xAI OAuth needs ${XAI_OAUTH_CALLBACK_HOST}:${XAI_OAUTH_CALLBACK_PORT} for its callback. Close any app already using that port or forward it from your remote machine and try again.`,
        )
      }
      throw error
    }
  }

  cleanup(): void {
    const cancellationError = this.buildCancellationError()

    this.tokenExchangeAbortController?.abort(cancellationError)
    this.tokenExchangeAbortController = null

    if (this.authCodeListener?.hasPendingResponse()) {
      this.authCodeListener.handleErrorRedirect(res => {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
        })
        res.end(renderCancelledPage())
      })
    }

    this.authCodeListener?.cancelPendingAuthorization(cancellationError)
    this.authCodeListener = null
  }
}
