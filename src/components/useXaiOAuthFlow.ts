import * as React from 'react'

import {
  XaiOAuthService,
  type XaiOAuthTokens,
} from '../services/api/xaiOAuth.js'
import { openBrowser } from '../utils/browser.js'
import { isBareMode } from '../utils/envUtils.js'
import { saveXaiOAuthCredentials } from '../utils/xaiOAuthCredentials.js'

export type XaiOAuthFlowStatus =
  | { state: 'starting' }
  | {
      state: 'waiting'
      authUrl: string
      browserOpened: boolean | null
    }
  | {
      state: 'error'
      message: string
    }

type PersistXaiOAuthCredentials = (options?: { profileId?: string }) => void

type XaiOAuthFlowDependencies = {
  createOAuthService?: () => Pick<
    XaiOAuthService,
    'startOAuthFlow' | 'cleanup'
  >
  openBrowser?: typeof openBrowser
  saveXaiOAuthCredentials?: typeof saveXaiOAuthCredentials
  isBareMode?: typeof isBareMode
}

function createDefaultOAuthService(): Pick<
  XaiOAuthService,
  'startOAuthFlow' | 'cleanup'
> {
  return new XaiOAuthService()
}

export function useXaiOAuthFlow(options: {
  onAuthenticated: (
    tokens: XaiOAuthTokens,
    persistCredentials: PersistXaiOAuthCredentials,
  ) => void | Promise<void>
  deps?: XaiOAuthFlowDependencies
}): XaiOAuthFlowStatus {
  const { onAuthenticated } = options
  const createOAuthService =
    options.deps?.createOAuthService ?? createDefaultOAuthService
  const openBrowserFn = options.deps?.openBrowser ?? openBrowser
  const saveCredentials =
    options.deps?.saveXaiOAuthCredentials ?? saveXaiOAuthCredentials
  const isBareModeFn = options.deps?.isBareMode ?? isBareMode
  const [status, setStatus] = React.useState<XaiOAuthFlowStatus>({
    state: 'starting',
  })

  React.useEffect(() => {
    if (isBareModeFn()) {
      setStatus({
        state: 'error',
        message:
          'xAI Grok OAuth is unavailable in --bare because secure storage is disabled.',
      })
      return
    }

    let cancelled = false
    const oauthService = createOAuthService()

    void oauthService
      .startOAuthFlow(async authUrl => {
        if (cancelled) return
        setStatus({
          state: 'waiting',
          authUrl,
          browserOpened: null,
        })
        const browserOpened = await openBrowserFn(authUrl)
        if (cancelled) return
        setStatus({
          state: 'waiting',
          authUrl,
          browserOpened,
        })
      })
      .then(async tokens => {
        if (cancelled) return

        const persistCredentials: PersistXaiOAuthCredentials = options => {
          const saved = saveCredentials({
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            idToken: tokens.idToken,
            expiresAt: tokens.expiresAt,
            profileId: options?.profileId,
          })
          if (!saved.success) {
            throw new Error(
              saved.warning ??
                'xAI Grok OAuth succeeded, but credentials could not be saved securely.',
            )
          }
        }

        await onAuthenticated(tokens, persistCredentials)
      })
      .catch(error => {
        if (cancelled) return
        setStatus({
          state: 'error',
          message: error instanceof Error ? error.message : String(error),
        })
      })

    return () => {
      cancelled = true
      oauthService.cleanup()
    }
  }, [
    createOAuthService,
    isBareModeFn,
    onAuthenticated,
    openBrowserFn,
    saveCredentials,
  ])

  return status
}
