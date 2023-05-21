import { describe, expect, it } from 'vitest'

import Schnorrkel from '../src/index'
import { _hashPrivateKey } from '../src/core'


describe('testing fromJson', () => {
  it('should create Schnorrkel instance from json', () => {
    const schnorrkel = new Schnorrkel()

    const keyPair = Schnorrkel.generateRandomKeys()
    schnorrkel.generatePublicNonces(keyPair.privateKey)
    const jsonData = schnorrkel.toJson()

    const schnorrkelFromJson = Schnorrkel.fromJson(jsonData)
    const jsonDataFromJson = schnorrkelFromJson.toJson()

    expect(jsonData).toEqual(jsonDataFromJson)
  })

  it('should throw error if json is invalid', () => {
    const schnorrkel = new Schnorrkel()

    const keyPair = Schnorrkel.generateRandomKeys()
    schnorrkel.generatePublicNonces(keyPair.privateKey)
    const jsonData = schnorrkel.toJson()

    const invalidJsonData = jsonData.slice(0, -1)

    expect(() => Schnorrkel.fromJson(invalidJsonData)).toThrow('Invalid JSON')
  })
})