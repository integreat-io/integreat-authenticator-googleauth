import test from 'node:test'
import assert from 'node:assert/strict'
import sinon from 'sinon'
import { GoogleAuth, IdTokenClient } from 'google-auth-library'

import authenticate from './authenticate.js'

// Tests -- access token

test('should call google auth and return an authentication object with an access token that expires within the hour', async () => {
  let getAccessTokenMock
  function GoogleAuthMock(_options: Record<string, unknown>) {
    const instance = sinon.createStubInstance(GoogleAuth)
    getAccessTokenMock = instance.getAccessToken
    getAccessTokenMock.resolves('t0k3n')
    return instance
  }
  const options = { type: 'accessToken' }
  const before = Date.now() + 3600000

  const ret = await authenticate(
    GoogleAuthMock as unknown as typeof GoogleAuth,
  )(options)

  const after = Date.now() + 3600000
  assert.ok(ret)
  assert.equal(ret.status, 'granted')
  assert.equal(ret.token, 't0k3n')
  assert.equal(typeof ret.expire, 'number')
  assert((ret.expire as number) >= before)
  assert((ret.expire as number) <= after)
  assert.equal((getAccessTokenMock as sinon.SinonSpy | undefined)?.callCount, 1)
})

test('should return access token by default', async () => {
  let getAccessTokenMock
  function GoogleAuthMock(_options: Record<string, unknown>) {
    const instance = sinon.createStubInstance(GoogleAuth)
    getAccessTokenMock = instance.getAccessToken
    getAccessTokenMock.resolves('t0k3n')
    return instance
  }
  const options = {}
  const before = Date.now() + 3600000

  const ret = await authenticate(
    GoogleAuthMock as unknown as typeof GoogleAuth,
  )(options)

  const after = Date.now() + 3600000
  assert.ok(ret)
  assert.equal(ret.status, 'granted')
  assert.equal(ret.token, 't0k3n')
  assert.equal(typeof ret.expire, 'number')
  assert((ret.expire as number) >= before)
  assert((ret.expire as number) <= after)
  assert.equal((getAccessTokenMock as sinon.SinonSpy | undefined)?.callCount, 1)
})

test('should call google auth with default scope', async () => {
  let getAccessTokenMock
  function GoogleAuthMock(_options: Record<string, unknown>) {
    const instance = sinon.createStubInstance(GoogleAuth)
    getAccessTokenMock = instance.getAccessToken
    getAccessTokenMock.resolves('t0k3n')
    return instance
  }
  const options = {}
  const AuthMock = sinon.spy(GoogleAuthMock)

  const ret = await authenticate(AuthMock as unknown as typeof GoogleAuth)(
    options,
  )

  assert.ok(ret)
  assert.equal(ret.status, 'granted')
  assert.equal(AuthMock.callCount, 1)
  assert.deepEqual(AuthMock.args[0][0], {
    scopes: 'https://www.googleapis.com/auth/cloud-platform',
  })
})

test('should call google auth with provided scopes', async () => {
  let getAccessTokenMock
  function GoogleAuthMock(_options: Record<string, unknown>) {
    const instance = sinon.createStubInstance(GoogleAuth)
    getAccessTokenMock = instance.getAccessToken
    getAccessTokenMock.resolves('t0k3n')
    return instance
  }
  const options = {
    scopes: [
      'https://www.googleapis.com/auth/cloud-platform',
      'https://www.googleapis.com/auth/userinfo.profile',
    ],
  }
  const AuthMock = sinon.spy(GoogleAuthMock)

  const ret = await authenticate(AuthMock as unknown as typeof GoogleAuth)(
    options,
  )

  assert.ok(ret)
  assert.equal(ret.status, 'granted')
  assert.equal(AuthMock.callCount, 1)
  assert.deepEqual(AuthMock.args[0][0], {
    scopes: [
      'https://www.googleapis.com/auth/cloud-platform',
      'https://www.googleapis.com/auth/userinfo.profile',
    ],
  })
})

test('should return rejected auth when no token', async () => {
  function GoogleAuthMock(_options: Record<string, unknown>) {
    const instance = sinon.createStubInstance(GoogleAuth)
    instance.getAccessToken.resolves(null)
    return instance
  }
  const options = {}

  const ret = await authenticate(
    GoogleAuthMock as unknown as typeof GoogleAuth,
  )(options)

  assert.ok(ret)
  assert.equal(ret.status, 'refused')
  assert.equal(ret.error, 'Google Auth returned no token')
  assert.equal(ret.token, undefined)
})

test('should return rejected auth when access is forbidden', async () => {
  function GoogleAuthMock(_options: Record<string, unknown>) {
    const instance = sinon.createStubInstance(GoogleAuth)
    instance.getAccessToken.rejects(new Error('Forbidden'))
    return instance
  }
  const options = {}

  const ret = await authenticate(
    GoogleAuthMock as unknown as typeof GoogleAuth,
  )(options)

  assert.ok(ret)
  assert.equal(ret.status, 'refused')
  assert.equal(ret.error, 'Google Auth returned an error: Forbidden')
  assert.equal(ret.token, undefined)
})

// Tests -- identity token

test('should call google auth and return an authentication object with an ID token', async () => {
  const expire = Date.now() + 3600000
  const credentials = { id_token: 't0k3n', expiry_date: expire }
  const fetch = sinon.stub().resolves(new Response())
  const googleClient = { credentials, fetch } as unknown as IdTokenClient
  let getIdTokenClientMock: sinon.SinonStub
  function GoogleAuthMock(_options: Record<string, unknown>) {
    const instance = sinon.createStubInstance(GoogleAuth)
    getIdTokenClientMock = instance.getIdTokenClient
    getIdTokenClientMock.resolves(googleClient)
    return instance
  }
  const options = {
    type: 'idToken',
    aud: 'iap-client-id',
    url: 'https://iap-url.com',
  }

  const ret = await authenticate(
    GoogleAuthMock as unknown as typeof GoogleAuth,
  )(options)

  assert.ok(ret)
  assert.equal(ret.status, 'granted')
  assert.equal(ret.token, 't0k3n')
  assert.equal(ret.expire, expire)
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  assert.equal(getIdTokenClientMock!.callCount, 1)
  assert.equal(
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    getIdTokenClientMock!.args[0][0],
    'iap-client-id',
  )
  assert.equal(fetch.callCount, 1)
  assert.equal(fetch.args[0][0], 'https://iap-url.com')
})

test('should use url as fallback for aud', async () => {
  const expire = Date.now() + 3600000
  const credentials = { id_token: 't0k3n', expiry_date: expire }
  const fetch = sinon.stub().resolves(new Response())
  const googleClient = { credentials, fetch } as unknown as IdTokenClient
  let getIdTokenClientMock: sinon.SinonStub
  function GoogleAuthMock(_options: Record<string, unknown>) {
    const instance = sinon.createStubInstance(GoogleAuth)
    getIdTokenClientMock = instance.getIdTokenClient
    getIdTokenClientMock.resolves(googleClient)
    return instance
  }
  const options = {
    type: 'idToken',
    url: 'https://cloud-run-1234-uc.a.run.app',
  }

  const ret = await authenticate(
    GoogleAuthMock as unknown as typeof GoogleAuth,
  )(options)

  assert.ok(ret)
  assert.equal(ret.status, 'granted')
  assert.equal(ret.token, 't0k3n')
  assert.equal(ret.expire, expire)
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  assert.equal(getIdTokenClientMock!.callCount, 1)
  assert.equal(
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    getIdTokenClientMock!.args[0][0],
    'https://cloud-run-1234-uc.a.run.app',
  )
  assert.equal(fetch.callCount, 1)
  assert.equal(fetch.args[0][0], 'https://cloud-run-1234-uc.a.run.app')
})

test('should reject when no aud or url', async () => {
  const fetch = sinon.stub().resolves(new Response())
  const googleClient = { credentials: {}, fetch } as unknown as IdTokenClient
  let getIdTokenClientMock: sinon.SinonStub
  function GoogleAuthMock(_options: Record<string, unknown>) {
    const instance = sinon.createStubInstance(GoogleAuth)
    getIdTokenClientMock = instance.getIdTokenClient
    getIdTokenClientMock.resolves(googleClient)
    return instance
  }
  const options = {
    type: 'idToken',
    // No url or aud
  }

  const ret = await authenticate(
    GoogleAuthMock as unknown as typeof GoogleAuth,
  )(options)

  assert.ok(ret)
  assert.equal(ret.status, 'refused')
  assert.equal(ret.error, 'No url was specified for the ID token')
  assert.equal(ret.token, undefined)
  assert.equal(ret.expire, undefined)
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  assert.equal(getIdTokenClientMock!.callCount, 0)
  assert.equal(fetch.callCount, 0)
})

test('should reject when credentials are not provided', async () => {
  const fetch = sinon.stub().resolves(new Response())
  const googleClient = { credentials: {}, fetch } as unknown as IdTokenClient
  let getIdTokenClientMock: sinon.SinonStub
  function GoogleAuthMock(_options: Record<string, unknown>) {
    const instance = sinon.createStubInstance(GoogleAuth)
    getIdTokenClientMock = instance.getIdTokenClient
    getIdTokenClientMock.resolves(googleClient)
    return instance
  }
  const options = {
    type: 'idToken',
    url: 'https://cloud-run-1234-uc.a.run.app',
  }

  const ret = await authenticate(
    GoogleAuthMock as unknown as typeof GoogleAuth,
  )(options)

  assert.ok(ret)
  assert.equal(ret.status, 'refused')
  assert.equal(ret.error, 'Google Auth returned no token')
  assert.equal(ret.token, undefined)
  assert.equal(ret.expire, undefined)
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  assert.equal(getIdTokenClientMock!.callCount, 1)
  assert.equal(fetch.callCount, 1)
})

test('should return error when fetching fails', async () => {
  const fetch = sinon
    .stub()
    .resolves(new Response(null, { status: 404, statusText: 'Unknown url' }))
  const googleClient = { credentials: {}, fetch } as unknown as IdTokenClient
  let getIdTokenClientMock: sinon.SinonStub
  function GoogleAuthMock(_options: Record<string, unknown>) {
    const instance = sinon.createStubInstance(GoogleAuth)
    getIdTokenClientMock = instance.getIdTokenClient
    getIdTokenClientMock.resolves(googleClient)
    return instance
  }
  const options = {
    type: 'idToken',
    url: 'https://cloud-run-1234-uc.a.run.app',
  }

  const ret = await authenticate(
    GoogleAuthMock as unknown as typeof GoogleAuth,
  )(options)

  assert.ok(ret)
  assert.equal(ret.status, 'refused')
  assert.equal(ret.error, 'Google Auth returned an error: Unknown url')
  assert.equal(ret.token, undefined)
  assert.equal(ret.expire, undefined)
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  assert.equal(getIdTokenClientMock!.callCount, 1)
  assert.equal(fetch.callCount, 1)
})
