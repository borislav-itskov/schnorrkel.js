import { describe, expect, it } from 'vitest'

import Schnorrkel from '../../src/index'
import { generateRandomKeys } from '../../src/core'
import { ethers } from 'ethers'

describe('testing sign', () => {
  it('should sign a message', () => {
    const keyPair = generateRandomKeys()

    const msg = 'test message'
    const hash = ethers.utils.solidityKeccak256(['string'], [msg])
    const signature = Schnorrkel.sign(keyPair.privateKey, hash)

    expect(signature).toBeDefined()
    expect(signature.finalPublicNonce.buffer).toHaveLength(33)
    expect(signature.signature.buffer).toHaveLength(32)
    expect(signature.challenge.buffer).toHaveLength(32)
  })

  it('should sign a hash', () => {
    const keyPair = generateRandomKeys()

    const msg = 'test message'
    const hash = ethers.utils.solidityKeccak256(['string'], [msg])
    const signature = Schnorrkel.sign(keyPair.privateKey, hash)

    expect(signature).toBeDefined()
    expect(signature.finalPublicNonce.buffer).toHaveLength(33)
    expect(signature.signature.buffer).toHaveLength(32)
    expect(signature.challenge.buffer).toHaveLength(32)
  })
})