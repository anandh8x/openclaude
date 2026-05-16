import { defineVendor } from '../define.js'

export default defineVendor({
  id: 'xai-oauth',
  label: 'xAI Grok OAuth (SuperGrok Subscription)',
  classification: 'openai-compatible',
  defaultBaseUrl: 'https://api.x.ai/v1',
  defaultModel: 'grok-4.3',
  setup: {
    requiresAuth: true,
    authMode: 'oauth',
    credentialEnvVars: [],
  },
  transportConfig: {
    kind: 'openai-compatible',
    openaiShim: {
      supportsApiFormatSelection: false,
    },
  },
  preset: {
    id: 'xai-oauth',
    description: 'Use a Grok/SuperGrok subscription through browser OAuth',
    label: 'xAI Grok OAuth',
    name: 'xAI Grok OAuth (SuperGrok Subscription)',
    apiKeyEnvVars: [],
    modelEnvVars: ['OPENAI_MODEL'],
  },
  validation: {
    kind: 'credential-env',
    routing: {
      enablementEnvVar: 'XAI_OAUTH',
      matchDefaultBaseUrl: true,
      matchBaseUrlHosts: ['api.x.ai'],
    },
    credentialEnvVars: [],
    allowLocalBaseUrlWithoutCredential: true,
    missingCredentialMessage:
      'xAI OAuth credentials are required. Choose xAI Grok OAuth in /provider to sign in.',
  },
  catalog: {
    source: 'static',
    models: [
      {
        id: 'grok-4.3',
        apiName: 'grok-4.3',
        label: 'Grok 4.3',
        modelDescriptorId: 'grok-4.3',
      },
      {
        id: 'grok-4',
        apiName: 'grok-4',
        label: 'Grok 4',
        modelDescriptorId: 'grok-4',
      },
      {
        id: 'grok-3',
        apiName: 'grok-3',
        label: 'Grok 3',
        modelDescriptorId: 'grok-3',
      },
    ],
  },
  usage: { supported: false },
})
