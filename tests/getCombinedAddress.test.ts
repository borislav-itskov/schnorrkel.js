import { describe, expect, it, expectTypeOf  } from 'vitest'

import Schnorrkel from '../src/index'

describe('testing getCombinedAddress', () => {
  it('should get combined address', () => {
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()

    const combinedAddress = Schnorrkel.getCombinedAddress([keyPairOne.publicKey, keyPairTwo.publicKey])
    expect(combinedAddress).toBeDefined()
    expectTypeOf(combinedAddress).toBeString()
  })

  it('should requires two public keys or more', () => {
    const keyPair = generateRandomKeys()

    expect(() => Schnorrkel.getCombinedAddress([keyPair.publicKey])).toThrowError('At least 2 public keys should be provided')
  })
})