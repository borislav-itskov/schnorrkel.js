import { describe, expect, it } from 'vitest'

import Schnorrkel from '../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../src/core'


describe('testing generatePublicNonces', () => {
  it('should generate public nonces', () => {
    const schnorrkel = new Schnorrkel()

    const keyPair = generateRandomKeys()
    const publicNonces = schnorrkel.generatePublicNonces(keyPair.privateKey)

    expect(publicNonces).toBeDefined()
    expect(publicNonces.kPublic).toBeDefined()
    expect(publicNonces.kTwoPublic).toBeDefined()
    expect(publicNonces.kPublic.buffer).toHaveLength(33)
    expect(publicNonces.kTwoPublic.buffer).toHaveLength(33)
  })

  it('should overwrite public nonces with same private key', () => {
    const schnorrkel = new Schnorrkel()

    const keyPair = generateRandomKeys()
    const publicNoncesOne = schnorrkel.generatePublicNonces(keyPair.privateKey)
    const jsonDataOne = schnorrkel.toJson()
    const publicNoncesTwo = schnorrkel.generatePublicNonces(keyPair.privateKey)
    const jsonDataTwo = schnorrkel.toJson()

    expect(publicNoncesOne.kPublic).not.toEqual(publicNoncesTwo.kPublic)
    expect(publicNoncesOne.kTwoPublic).not.toEqual(publicNoncesTwo.kTwoPublic)

    const dataOne = JSON.parse(jsonDataOne)
    const dataTwo = JSON.parse(jsonDataTwo)

    const hash = _hashPrivateKey(keyPair.privateKey.buffer)

    expect(dataOne.nonces[hash]).not.toEqual(dataTwo.nonces[hash])
  })
})