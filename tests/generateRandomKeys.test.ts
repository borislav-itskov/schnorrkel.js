import { describe, expect, it } from 'vitest'

import Schnorrkel from '../src/index'

describe('testing generateRandomKeys', () => {
  it('should generate key pair', () => {
    const keyPair = Schnorrkel.generateRandomKeys()

    expect(keyPair).toBeDefined()
    expect(keyPair.privateKey).toBeDefined()
    expect(keyPair.publicKey).toBeDefined()
    expect(keyPair.privateKey.toHex()).toHaveLength(64)
    expect(keyPair.publicKey.toHex()).toHaveLength(66)
    expect(keyPair.privateKey.toHex()).not.toEqual(keyPair.publicKey.toHex())
  })

  it('should generate different key pairs', () => {
    const keyPairOne = Schnorrkel.generateRandomKeys()
    const keyPairTwo = Schnorrkel.generateRandomKeys()

    expect(keyPairOne.publicKey.toHex()).not.toEqual(keyPairTwo.publicKey.toHex())
    expect(keyPairOne.privateKey.toHex()).not.toEqual(keyPairTwo.privateKey.toHex())
  })
})