import { describe, expect, it } from 'vitest'

import { UnsafeSchnorrkel } from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'


describe('testing fromJson', () => {
  it('should create Schnorrkel instance from json', () => {
    const schnorrkel = new UnsafeSchnorrkel()

    const keyPair = generateRandomKeys()
    schnorrkel.generatePublicNonces()
    const jsonData = schnorrkel.toJson()

    const schnorrkelFromJson = UnsafeSchnorrkel.fromJson(jsonData)
    const jsonDataFromJson = schnorrkelFromJson.toJson()

    expect(jsonData).toEqual(jsonDataFromJson)
  })

  it('should throw error if json is invalid', () => {
    const schnorrkel = new UnsafeSchnorrkel()

    const keyPair = generateRandomKeys()
    schnorrkel.generatePublicNonces()
    const jsonData = schnorrkel.toJson()

    const invalidJsonData = jsonData.slice(0, -1)

    expect(() => UnsafeSchnorrkel.fromJson(invalidJsonData)).toThrow('Invalid JSON')
  })
})