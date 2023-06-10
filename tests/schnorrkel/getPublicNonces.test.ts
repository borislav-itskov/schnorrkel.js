import { describe, expect, it } from 'vitest'

import Schnorrkel from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'


describe('testing getPublicNonces', () => {
  it('should generate the public nonces and afterwards get them successfully', () => {
    const schnorrkel = new Schnorrkel()

    const keyPair = generateRandomKeys()
    const publicNonces = schnorrkel.generatePublicNonces(keyPair.privateKey)

    expect(publicNonces).toBeDefined()
    expect(publicNonces.kPublic).toBeDefined()
    expect(publicNonces.kTwoPublic).toBeDefined()
    expect(publicNonces.kPublic.buffer).toHaveLength(33)
    expect(publicNonces.kTwoPublic.buffer).toHaveLength(33)

    const retrievedPublicNonces = schnorrkel.getPublicNonces(keyPair.privateKey)
    expect(retrievedPublicNonces.kPublic.buffer).to.equal(publicNonces.kPublic.buffer)
    expect(retrievedPublicNonces.kTwoPublic.buffer).to.equal(publicNonces.kTwoPublic.buffer)
  })
})