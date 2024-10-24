import { describe, expect, it } from 'vitest'

import Schnorrkel from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'
import { ethers } from 'ethers'


describe('testing multiSigSign', () => {
  it('should generate multi signature', () => {
    const schnorrkelOne = new Schnorrkel()
    const schnorrkelTwo = new Schnorrkel()

    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicNoncesOne = schnorrkelOne.generatePublicNonces()
    const publicNoncesTwo = schnorrkelTwo.generatePublicNonces()

    const publicNonces = [publicNoncesOne, publicNoncesTwo]
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    const msg = 'test message'
    const signature = schnorrkelOne.multiSigSign(keyPairOne.privateKey, ethers.utils.hashMessage(msg), publicKeys, publicNonces)

    expect(signature).toBeDefined()
    expect(signature.publicNonce.buffer).toHaveLength(33)
    expect(signature.signature.buffer).toHaveLength(32)
    expect(signature.challenge.buffer).toHaveLength(32)
  })

  it('should requires two public keys or more', () => {
    const schnorrkel = new Schnorrkel()
    const keyPair = generateRandomKeys()
    const publicNonces = schnorrkel.generatePublicNonces()

    const msg = 'test message'
    const msgHash = ethers.utils.hashMessage(msg)
    const publicKeys = [keyPair.publicKey]

    expect(() => schnorrkel.multiSigSign(keyPair.privateKey, msgHash, publicKeys, [publicNonces])).toThrowError('At least 2 public keys should be provided')
  })

  it('should require nonces', () => {
    const schnorrkel = new Schnorrkel()
    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()

    const msg = 'test message'
    const msgHash = ethers.utils.hashMessage(msg)
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    expect(() => schnorrkel.multiSigSign(keyPairOne.privateKey, msgHash, publicKeys, [])).toThrowError('Nonces should be exchanged before signing')
  })

  it('should generate multi signature by hash', () => {
    const schnorrkelOne = new Schnorrkel()
    const schnorrkelTwo = new Schnorrkel()

    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicNoncesOne = schnorrkelOne.generatePublicNonces()
    const publicNoncesTwo = schnorrkelTwo.generatePublicNonces()

    const publicNonces = [publicNoncesOne, publicNoncesTwo]
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    const msg = 'test message'
    const hash = ethers.utils.solidityKeccak256(['string'], [msg])
    const signature = schnorrkelOne.multiSigSign(keyPairOne.privateKey, hash, publicKeys, publicNonces)

    expect(signature).toBeDefined()
    expect(signature.publicNonce.buffer).toHaveLength(33)
    expect(signature.signature.buffer).toHaveLength(32)
    expect(signature.challenge.buffer).toHaveLength(32)
  })
})