import { Authentication } from './index.js'
import { GoogleAuth } from 'google-auth-library'

export interface AuthOptions extends Record<string, unknown> {
  scopes?: string | string[]
}

export default function (Auth: typeof GoogleAuth) {
  return async (options: AuthOptions | null): Promise<Authentication> => {
    const { scopes = 'https://www.googleapis.com/auth/cloud-platform' } =
      options || {}
    const authOptions = { scopes }
    const auth = new Auth(authOptions)

    try {
      const token = await auth.getAccessToken()
      return token
        ? { status: 'granted', token, expire: Date.now() + 3600000 }
        : { status: 'refused', error: 'Google Auth returned no token' }
    } catch (err) {
      return {
        status: 'refused',
        error: `Google Auth returned an error: ${
          err instanceof Error ? err.message : String(err)
        }`,
      }
    }
  }
}
