import { describe, expect, it } from 'vitest'

import Schnorrkel from '../../src/index'
import { generateRandomKeys } from '../../src/core'
import { ethers } from 'ethers'

describe('testing sign', () => {
  it('should sign a message with solidityKeccak256', () => {
    const keyPair = generateRandomKeys()

    const msg = 'test message'
    const hash = ethers.utils.solidityKeccak256(['string'], [msg])
    const signature = Schnorrkel.sign(keyPair.privateKey, hash)

    expect(signature).toBeDefined()
    expect(signature.publicNonce.buffer).toHaveLength(33)
    expect(signature.signature.buffer).toHaveLength(32)
    expect(signature.challenge.buffer).toHaveLength(32)
  })

  it('should sign a message with keccak256', () => {
    const keyPair = generateRandomKeys()

    const msg = 'test message'
    const hash = ethers.utils.hashMessage(msg)
    const signature = Schnorrkel.sign(keyPair.privateKey, hash)

    expect(signature).toBeDefined()
    expect(signature.publicNonce.buffer).toHaveLength(33)
    expect(signature.signature.buffer).toHaveLength(32)
    expect(signature.challenge.buffer).toHaveLength(32)
  })
})