import { describe, expect, it } from 'vitest'

import Schnorrkel, { KeyPair } from '../src/index'
import { _hashPrivateKey } from '../src/core'


describe('testing KeyPair', () => {
  it('should load from json', () => {
    const keyPairOne = Schnorrkel.generateRandomKeys()
    const keyPairTwo = KeyPair.fromJson(keyPairOne.toJson())

    expect(keyPairOne.publicKey.buffer).toEqual(keyPairTwo.publicKey.buffer)
    expect(keyPairOne.privateKey.buffer).toEqual(keyPairTwo.privateKey.buffer)
    expect(keyPairOne.toJson()).toEqual(keyPairTwo.toJson())
  })

  it('should throw error if json is invalid', () => {
    const keyPair = Schnorrkel.generateRandomKeys()
    const jsonData = keyPair.toJson()

    const invalidJsonData = jsonData.slice(0, -1)

    expect(() => KeyPair.fromJson(invalidJsonData)).toThrow('Invalid JSON')
  })
})