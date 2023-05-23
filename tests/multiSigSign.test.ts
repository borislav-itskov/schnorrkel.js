import { describe, expect, it } from 'vitest'

import Schnorrkel, { Key, PublicNonces } from '../src/index'
import { _hashPrivateKey } from '../src/core'


describe('testing multiSigSign', () => {
  it('should generate multi signature', () => {
    const schnorrkelOne = new Schnorrkel()
    const schnorrkelTwo = new Schnorrkel()

    const keyPairOne = Schnorrkel.generateRandomKeys()
    const keyPairTwo = Schnorrkel.generateRandomKeys()
    const publicNoncesOne = schnorrkelOne.generatePublicNonces(keyPairOne.privateKey)
    const publicNoncesTwo = schnorrkelTwo.generatePublicNonces(keyPairTwo.privateKey)

    const publicNonces = [publicNoncesOne, publicNoncesTwo]
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    const msg = 'test message'
    const signature = schnorrkelOne.multiSigSign(keyPairOne.privateKey, msg, publicKeys, publicNonces)

    expect(signature).toBeDefined()
    expect(signature.finalPublicNonce.buffer).toHaveLength(33)
    expect(signature.signature.buffer).toHaveLength(32)
    expect(signature.challenge.buffer).toHaveLength(32)
  })

  it('should requires two public keys or more', () => {
    const schnorrkel = new Schnorrkel()
    const keyPair = Schnorrkel.generateRandomKeys()
    const publicNonces = schnorrkel.generatePublicNonces(keyPair.privateKey)

    const msg = 'test message'
    const publicKeys = [keyPair.publicKey]

    expect(() => schnorrkel.multiSigSign(keyPair.privateKey, msg, publicKeys, [publicNonces])).toThrowError('At least 2 public keys should be provided')
  })

  it('should requires nonces', () => {
    const schnorrkel = new Schnorrkel()
    const keyPairOne = Schnorrkel.generateRandomKeys()
    const keyPairTwo = Schnorrkel.generateRandomKeys()

    const msg = 'test message'
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    expect(() => schnorrkel.multiSigSign(keyPairOne.privateKey, msg, publicKeys, [])).toThrowError('Nonces should be exchanged before signing')
  })

  it('should requires valid nonces', () => {
    const schnorrkel = new Schnorrkel()
    const keyPairOne = Schnorrkel.generateRandomKeys()
    const keyPairTwo = Schnorrkel.generateRandomKeys()
    const publicNoncesOne = schnorrkel.generatePublicNonces(keyPairOne.privateKey)

    const msg = 'test message'
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    const invalidNonce: PublicNonces = {
      kPublic: new Key(Buffer.from('invalid', 'hex')),
      kTwoPublic: new Key(Buffer.from('invalid', 'hex')),
    }

    expect(() => schnorrkel.multiSigSign(keyPairOne.privateKey, msg, publicKeys, [publicNoncesOne, invalidNonce])).toThrowError('Passed nonces are invalid')
  })


})