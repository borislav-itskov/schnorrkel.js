import { describe, expect, it, expectTypeOf } from 'vitest'

import Schnorrkel, { Key } from '../src/index'
import { _hashPrivateKey } from '../src/core'

describe('testing generateCombinedPublicKeyWithSalt', () => {
  it('should generate combined public key', () => {
    const keyPairOne = Schnorrkel.generateRandomKeys()
    const keyPairTwo = Schnorrkel.generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]
    const { combinedKey, hashedKey } = Schnorrkel.generateCombinedPublicKeyWithSalt(publicKeys)

    expect(combinedKey).toBeDefined()
    expect(combinedKey).toBeInstanceOf(Key)
    expect(combinedKey.toHex()).toHaveLength(66)
    expect(hashedKey).toBeDefined()
    expectTypeOf(hashedKey).toBeString()
  })

  it('should throw error if less than 2 public keys are provided', () => {
    const keyPairOne = Schnorrkel.generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey]

    expect(() => Schnorrkel.generateCombinedPublicKeyWithSalt(publicKeys)).toThrow('At least 2 public keys should be provided')
  })

  it('should generate different combined public key for same public keys', () => {
    const keyPairOne = Schnorrkel.generateRandomKeys()
    const keyPairTwo = Schnorrkel.generateRandomKeys()
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    type Output = ReturnType<typeof Schnorrkel.generateCombinedPublicKeyWithSalt>
    const combinedKeys: Output['combinedKey'][] = []
    const hashedKeys: Output['hashedKey'][] = []

    for (let i = 0; i < 100; i++) {
      const value = Schnorrkel.generateCombinedPublicKeyWithSalt(publicKeys)
      expect(combinedKeys).not.toContain(value.combinedKey)
      expect(hashedKeys).not.toContain(value.hashedKey)

      combinedKeys.push(value.combinedKey)
      hashedKeys.push(value.hashedKey)
    }
  })
})