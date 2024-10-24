import { describe, expect, it } from 'vitest'

import {UnsafeSchnorrkel} from '../../src/index'
import { _hashPrivateKey } from '../../src/core'


describe('testing generatePublicNonces', () => {
  it('should overwrite public nonces with same private key', () => {
    const schnorrkel = new UnsafeSchnorrkel()

    const publicNoncesOne = schnorrkel.generatePublicNonces()
    const jsonDataOne = schnorrkel.toJson()
    const publicNoncesTwo = schnorrkel.generatePublicNonces()
    const jsonDataTwo = schnorrkel.toJson()

    expect(publicNoncesOne.kPublic).not.toEqual(publicNoncesTwo.kPublic)
    expect(publicNoncesOne.kTwoPublic).not.toEqual(publicNoncesTwo.kTwoPublic)

    const dataOne = JSON.parse(jsonDataOne)
    const dataTwo = JSON.parse(jsonDataTwo)

    const firstNonceId = Object.keys(dataOne.nonces)[0]
    const secondNonceId = Object.keys(dataTwo.nonces)[0]
    expect(dataOne.nonces[firstNonceId]).not.toEqual(dataTwo.nonces[secondNonceId])
  })
})