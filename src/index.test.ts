import test from 'node:test'
import assert from 'node:assert/strict'

import auth from './index.js'

// Setup

const action = {
  type: 'GET',
  payload: { type: 'entry' },
  meta: { ident: { id: 'johnf' } },
}

const options = {}

// Tests

test('should be an authenticator', () => {
  assert(auth)
  assert.equal(typeof auth.authenticate, 'function')
  assert.equal(typeof auth.isAuthenticated, 'function')
})

// Tests - isAuthenticated

test('should return false when token is undefined', () => {
  const authentication = { status: 'refused' }

  const ret = auth.isAuthenticated(authentication, options, action)

  assert.equal(ret, false)
})

test('should return true when token is set', () => {
  const authentication = {
    status: 'granted',
    token: 't0k3n',
    expire: Date.now() + 3600000,
  }

  const ret = auth.isAuthenticated(authentication, options, action)

  assert.equal(ret, true)
})

test('should return false when expire is passed', () => {
  const authentication = {
    status: 'granted',
    token: 't0k3n',
    expire: Date.now() - 60000,
  }

  const ret = auth.isAuthenticated(authentication, options, action)

  assert.equal(ret, false)
})

test('should return true when expire is not set', () => {
  const authentication = { status: 'granted', token: 't0k3n' }

  const ret = auth.isAuthenticated(authentication, options, action)

  assert.equal(ret, true)
})

// Tests - asHttpHeaders

test('should return empty object when no token', () => {
  const authentication = { status: 'refused' }
  const expected = {}

  const ret = auth.authentication.asHttpHeaders(authentication)

  assert.deepEqual(ret, expected)
})

test('should return empty object when refused', () => {
  const authentication = { status: 'refused', token: 't0k3n' }
  const expected = {}

  const ret = auth.authentication.asHttpHeaders(authentication)

  assert.deepEqual(ret, expected)
})

test('should return Authorization Bearer header', () => {
  const authentication = { status: 'granted', token: 't0k3n' }
  const expected = {
    Authorization: 'Bearer t0k3n',
  }

  const ret = auth.authentication.asHttpHeaders(authentication)

  assert.deepEqual(ret, expected)
})
