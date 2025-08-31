import { Authentication } from './index.js'
import { GoogleAuth } from 'google-auth-library'

export interface AuthOptions extends Record<string, unknown> {
  type?: string
  aud?: string
  url?: string
  scopes?: string | string[]
}

const createError = (error: unknown) => ({
  status: 'refused',
  error: `Google Auth returned an error: ${
    error instanceof Error ? error.message : String(error)
  }`,
})

/**
 * Get a Google Access Token.
 */
async function getAccessToken(auth: GoogleAuth): Promise<Authentication> {
  try {
    const token = await auth.getAccessToken()
    if (token) {
      return { status: 'granted', token, expire: Date.now() + 3600000 }
    } else {
      return { status: 'refused', error: 'Google Auth returned no token' }
    }
  } catch (error) {
    return createError(error)
  }
}

/**
 * Get a Google ID Token.
 */
async function getIdentityToken(
  auth: GoogleAuth,
  aud?: string,
  url?: string,
): Promise<Authentication> {
  if (typeof url !== 'string' || !url) {
    return { status: 'refused', error: 'No url was specified for the ID token' }
  }

  try {
    const client = await auth.getIdTokenClient(aud ?? url)
    const response = await client.fetch(url)
    if (!response.ok) {
      return createError(response.statusText)
    }

    const { id_token: token, expiry_date: expire } = client.credentials

    if (token) {
      return { status: 'granted', token, expire: expire ?? undefined }
    } else {
      return { status: 'refused', error: 'Google Auth returned no token' }
    }
  } catch (error) {
    return createError(error)
  }
}

/**
 * Returns an authenication object with token and expire timestamp gotten from
 * Google Auth.
 *
 * When `type` is `idToken`, `url` is required and `aud` is optional. The
 * returned token will be a JWT and the expire timestamp will be the exact
 * timestamp from Google.
 *
 * When `type` is `accessToken` or not set, `url` and `aud` are disregarded.
 * The returned token will be a Google Access Token, and the expire timestamp
 * will be set to one hour in the future.
 *
 * `scopes` are used for all token types, but perhaps most relevant for access
 * tokens.
 *
 * Any error or missing required option will cause a refused authentication
 * object to be returned.
 */
export default function (Auth: typeof GoogleAuth) {
  return async (options: AuthOptions | null): Promise<Authentication> => {
    const {
      scopes = 'https://www.googleapis.com/auth/cloud-platform',
      type = 'accessToken',
      aud,
      url,
    } = options || {}
    const authOptions = { scopes }
    const auth = new Auth(authOptions)

    return type === 'idToken'
      ? await getIdentityToken(auth, aud, url)
      : await getAccessToken(auth)
  }
}
