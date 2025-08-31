import test from 'node:test'
import assert from 'node:assert/strict'
import sinon from 'sinon'
import { GoogleAuth } from 'google-auth-library'

import authenticate from './authenticate.js'

// Tests

test('should call google auth and return an authentication object that expires within the hour', async () => {
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
  assert(ret)
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

  assert(ret)
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

  assert(ret)
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

  assert(ret)
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

  assert(ret)
  assert.equal(ret.status, 'refused')
  assert.equal(ret.error, 'Google Auth returned an error: Forbidden')
  assert.equal(ret.token, undefined)
})
