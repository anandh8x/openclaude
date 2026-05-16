// src/integrations/profileResolver.ts
// Resolves a stored profile.provider string to a descriptor-backed route.
// This bridges legacy preset names, vendor ids, gateway ids, and custom strings.

import { getGateway, getVendor } from './registry.js'
import { isProviderPreset, routeForPreset } from './compatibility.js'

export type ResolvedProfileRoute = {
  vendorId: string
  gatewayId?: string
  routeId: string
}

const PROVIDER_ALIASES: Record<string, string> = {
  'grok-oauth': 'xai-oauth',
  'x-ai-oauth': 'xai-oauth',
  'xai-grok-oauth': 'xai-oauth',
}

export function normalizeProviderRouteAlias(provider: string): string {
  return PROVIDER_ALIASES[provider.trim().toLowerCase()] ?? provider
}

/**
 * Resolve a stored profile provider string to a route.
 *
 * Resolution order:
 *   1. Try compatibility preset mapping
 *   2. Try direct vendor id lookup
 *   3. Try gateway id lookup
 *   4. Return safe unknown-provider fallback
 */
export function resolveProfileRoute(provider: string): ResolvedProfileRoute {
  const normalizedProvider = normalizeProviderRouteAlias(provider)

  // 1. Try preset mapping
  if (isProviderPreset(normalizedProvider)) {
    return routeForPreset(normalizedProvider)
  }

  // 2. Try direct vendor id
  const vendor = getVendor(normalizedProvider)
  if (vendor) {
    return { vendorId: vendor.id, routeId: vendor.id }
  }

  // 3. Try gateway id
  const gateway = getGateway(normalizedProvider)
  if (gateway) {
    return {
      vendorId: gateway.vendorId ?? 'openai',
      gatewayId: gateway.id,
      routeId: gateway.id,
    }
  }

  // 4. Safe fallback — OpenAI-compatible so the user can still interact,
  //    but the routeId makes it clear this is unrecognised.
  return { vendorId: 'openai', routeId: 'unknown-fallback' }
}
