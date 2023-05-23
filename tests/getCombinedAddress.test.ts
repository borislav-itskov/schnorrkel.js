import { describe, expect, it, expectTypeOf  } from 'vitest'

import Schnorrkel from '../src/index'

describe('testing getCombinedAddress', () => {
  it('should get combined address', () => {
    const keyPairOne = Schnorrkel.generateRandomKeys()
    const keyPairTwo = Schnorrkel.generateRandomKeys()

    const combinedAddress = Schnorrkel.getCombinedAddress([keyPairOne.publicKey, keyPairTwo.publicKey])
    expect(combinedAddress).toBeDefined()
    expectTypeOf(combinedAddress).toBeString()
  })

  it('should requires two public keys or more', () => {
    const keyPair = Schnorrkel.generateRandomKeys()

    expect(() => Schnorrkel.getCombinedAddress([keyPair.publicKey])).toThrowError('At least 2 public keys should be provided')
  })
})