import { describe, expect, it } from 'vitest'

import Schnorrkel from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'


describe('testing hasNonces', () => {
  it('should check if there are nonces set before manipulating them', () => {
    const schnorrkel = new Schnorrkel()

    const keyPair = generateRandomKeys()
    expect(schnorrkel.hasNonces()).to.equal(false)
    schnorrkel.generatePublicNonces()
    expect(schnorrkel.hasNonces()).to.equal(true)
  })
})