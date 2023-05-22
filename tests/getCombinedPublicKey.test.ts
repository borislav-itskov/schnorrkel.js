import { describe, expect, it } from 'vitest'

import Schnorrkel from '../src/index'
import { Key } from '../src/types'

describe('testing getCombinedPublicKey', () => {
  it('should get combined public key', () => {
    const keyPairOne = Schnorrkel.generateRandomKeys()
    const keyPairTwo = Schnorrkel.generateRandomKeys()

    const combinedPublicKey = Schnorrkel.getCombinedPublicKey([keyPairOne.publicKey, keyPairTwo.publicKey])
    expect(combinedPublicKey).toBeDefined()
    expect(combinedPublicKey).toBeInstanceOf(Key)
    expect(combinedPublicKey.toHex()).toHaveLength(66)
  })

  it('should get same combined public key', () => {
    const keyPairOne = Schnorrkel.generateRandomKeys()
    const keyPairTwo = Schnorrkel.generateRandomKeys()

    const combinedPublicKey = Schnorrkel.getCombinedPublicKey([keyPairOne.publicKey, keyPairTwo.publicKey])
    const combinedPublicKeyTwo = Schnorrkel.getCombinedPublicKey([keyPairTwo.publicKey, keyPairOne.publicKey])

    expect(combinedPublicKey.toHex()).toEqual(combinedPublicKeyTwo.toHex())
  })

  it('should get same combined public key with different order', () => {
    const keyPairOne = Schnorrkel.generateRandomKeys()
    const keyPairTwo = Schnorrkel.generateRandomKeys()

    const combinedPublicKey = Schnorrkel.getCombinedPublicKey([keyPairOne.publicKey, keyPairTwo.publicKey])
    const combinedPublicKeyTwo = Schnorrkel.getCombinedPublicKey([keyPairTwo.publicKey, keyPairOne.publicKey])

    expect(combinedPublicKey.toHex()).toEqual(combinedPublicKeyTwo.toHex())

  })

  it('shoud get combined public key that is different from the original public keys', () => {
    const keyPairOne = Schnorrkel.generateRandomKeys()
    const keyPairTwo = Schnorrkel.generateRandomKeys()

    const combinedPublicKey = Schnorrkel.getCombinedPublicKey([keyPairOne.publicKey, keyPairTwo.publicKey])
    expect(combinedPublicKey.toHex()).not.toEqual(keyPairOne.publicKey.toHex())
    expect(combinedPublicKey.toHex()).not.toEqual(keyPairTwo.publicKey.toHex())
  })
})