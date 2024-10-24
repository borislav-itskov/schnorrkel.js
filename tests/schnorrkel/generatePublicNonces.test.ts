import { describe, expect, it } from 'vitest'

import Schnorrkel from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'


describe('testing generatePublicNonces', () => {
  it('should generate public nonces', () => {
    const schnorrkel = new Schnorrkel()

    const publicNonces = schnorrkel.generatePublicNonces()

    expect(publicNonces).toBeDefined()
    expect(publicNonces.kPublic).toBeDefined()
    expect(publicNonces.kTwoPublic).toBeDefined()
    expect(publicNonces.kPublic.buffer).toHaveLength(33)
    expect(publicNonces.kTwoPublic.buffer).toHaveLength(33)
  })
})