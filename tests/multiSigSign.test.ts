import { describe, expect, it } from 'vitest'

import Schnorrkel from '../src/index'
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
    expect(signature.finalPublicNonce).toHaveLength(33)
    expect(signature.signature).toHaveLength(32)
    expect(signature.challenge).toHaveLength(32)
  })
})