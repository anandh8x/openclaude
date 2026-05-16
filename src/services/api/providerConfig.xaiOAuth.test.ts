import { afterEach, beforeEach, expect, test } from 'bun:test'
import {
  acquireSharedMutationLock,
  releaseSharedMutationLock,
} from '../../test/sharedMutationLock.js'

import { resolveProviderRequest } from './providerConfig.js'

const ENV_KEYS = [
  'CLAUDE_CODE_USE_OPENAI',
  'XAI_OAUTH',
  'XAI_OAUTH_CREDENTIAL_SOURCE',
  'OPENAI_BASE_URL',
  'OPENAI_MODEL',
  'OPENAI_API_FORMAT',
  'XAI_API_KEY',
] as const

const originalEnv: Record<string, string | undefined> = {}

beforeEach(async () => {
  await acquireSharedMutationLock('providerConfig.xaiOAuth.test.ts')
  for (const key of ENV_KEYS) {
    originalEnv[key] = process.env[key]
    delete process.env[key]
  }
})

afterEach(() => {
  try {
    for (const key of ENV_KEYS) {
      if (originalEnv[key] === undefined) {
        delete process.env[key]
      } else {
        process.env[key] = originalEnv[key]
      }
    }
  } finally {
    releaseSharedMutationLock()
  }
})

test('xai-oauth resolves to xAI base URL and codex responses transport', () => {
  process.env.CLAUDE_CODE_USE_OPENAI = '1'
  process.env.XAI_OAUTH = '1'
  process.env.XAI_OAUTH_CREDENTIAL_SOURCE = 'oauth'
  process.env.OPENAI_BASE_URL = 'https://api.x.ai/v1'
  process.env.OPENAI_MODEL = 'grok-4.3'

  const request = resolveProviderRequest()

  expect(request.baseUrl).toBe('https://api.x.ai/v1')
  expect(request.requestedModel).toBe('grok-4.3')
  expect(request.resolvedModel).toBe('grok-4.3')
  expect(request.transport).toBe('codex_responses')
})

test('existing xai API-key provider stays on chat completions by default', () => {
  process.env.CLAUDE_CODE_USE_OPENAI = '1'
  process.env.OPENAI_BASE_URL = 'https://api.x.ai/v1'
  process.env.OPENAI_MODEL = 'grok-4.3'
  process.env.XAI_API_KEY = 'xai-key'

  const request = resolveProviderRequest()

  expect(request.baseUrl).toBe('https://api.x.ai/v1')
  expect(request.resolvedModel).toBe('grok-4.3')
  expect(request.transport).toBe('chat_completions')
})
