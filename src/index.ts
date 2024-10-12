import { GoogleAuth } from 'google-auth-library'
import type { Authenticator } from 'integreat'
import authenticate from './authenticate.js'

// https://github.com/googleapis/google-auth-library-nodejs#impersonated-credentials-client

export interface Authentication extends Record<string, unknown> {
  status: string
  token?: string
  error?: string
  expire?: number
}

const authenticator: Authenticator = {
  authenticate: authenticate(GoogleAuth),

  isAuthenticated(
    authentication: Authentication | null,
    _options,
    _action,
  ): boolean {
    return (
      !!authentication?.token &&
      (typeof authentication.expire !== 'number' ||
        authentication.expire > Date.now())
    )
  },

  authentication: {
    asHttpHeaders(authentication: Authentication | null) {
      const { status, token } = authentication || {}
      if (status === 'granted' && token) {
        return {
          Authorization: `Bearer ${token}`,
        }
      } else {
        return {}
      }
    },
  },
}

export default authenticator
