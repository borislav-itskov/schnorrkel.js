import { describe, expect, it } from 'vitest'

import Schnorrkel, { Key } from '../../src/index'
import { _hashPrivateKey, generateRandomKeys } from '../../src/core'
import { ethers } from 'ethers'

describe('testing verify', () => {
  it('should verify a normal schnorr signature and make sure sign does not overwrite the private key', () => {
    const privateKey = new Key(Buffer.from(ethers.utils.randomBytes(32)))

    const msg = 'test message'
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg])
    const signature = Schnorrkel.sign(privateKey, msgHash)

    const publicKey = ethers.utils.arrayify(
      ethers.utils.computePublicKey(ethers.utils.computePublicKey(privateKey.buffer, false), true)
    )

    expect(signature).toBeDefined()
    expect(signature.publicNonce.buffer).toHaveLength(33)
    expect(signature.signature.buffer).toHaveLength(32)
    expect(signature.challenge.buffer).toHaveLength(32)
    const result = Schnorrkel.verify(signature.signature, ethers.utils.solidityKeccak256(['string'], [msg]), signature.publicNonce, new Key(Buffer.from(publicKey)))
    expect(result).toEqual(true)

    const secondMsg = 'this is another msg'
    const secondMsgHash = ethers.utils.solidityKeccak256(['string'], [secondMsg])
    const secondSig = Schnorrkel.sign(privateKey, secondMsgHash)
    const secondRes = Schnorrkel.verify(secondSig.signature, ethers.utils.solidityKeccak256(['string'], [secondMsg]), secondSig.publicNonce, new Key(Buffer.from(publicKey)))
    expect(secondRes).toEqual(true)
  })
  it('should sum signatures and verify them', () => {
    const schnorrkelOne = new Schnorrkel()
    const schnorrkelTwo = new Schnorrkel()

    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicNoncesOne = schnorrkelOne.generatePublicNonces()
    const publicNoncesTwo = schnorrkelTwo.generatePublicNonces()

    const publicNonces = [publicNoncesOne, publicNoncesTwo]
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)

    const msg = 'test message'
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg])
    const signatureOne = schnorrkelOne.multiSigSign(keyPairOne.privateKey, msgHash, publicKeys, publicNonces)
    const signatureTwo = schnorrkelTwo.multiSigSign(keyPairTwo.privateKey, msgHash, publicKeys, publicNonces)

    const signatures = [signatureOne.signature, signatureTwo.signature]
    const signaturesSummed = Schnorrkel.sumSigs(signatures)
    const result = Schnorrkel.verify(signaturesSummed, ethers.utils.solidityKeccak256(['string'], [msg]), signatureTwo.publicNonce, combinedPublicKey)

    expect(result).toEqual(true)
  })
  it('should make sure private keys are not overwritten during signing', () => {
    const schnorrkelOne = new Schnorrkel()
    const schnorrkelTwo = new Schnorrkel()

    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()

    const publicNoncesOne = schnorrkelOne.generatePublicNonces()
    const publicNoncesTwo = schnorrkelTwo.generatePublicNonces()
    
    const publicNonces = [publicNoncesOne, publicNoncesTwo]
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)

    const msg = 'test message'
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg])
    const pkOneCache = new Key(Buffer.from(keyPairOne.privateKey.buffer))
    expect(pkOneCache.buffer).toEqual(keyPairOne.privateKey.buffer)
    const signatureOne = schnorrkelOne.multiSigSign(keyPairOne.privateKey, msgHash, publicKeys, publicNonces)
    expect(pkOneCache.buffer).toEqual(keyPairOne.privateKey.buffer)

    const pkTwoCache = new Key(Buffer.from(keyPairTwo.privateKey.buffer))
    expect(pkTwoCache.buffer).toEqual(keyPairTwo.privateKey.buffer)
    const signatureTwo = schnorrkelTwo.multiSigSign(keyPairTwo.privateKey, msgHash, publicKeys, publicNonces)
    expect(pkTwoCache.buffer).toEqual(keyPairTwo.privateKey.buffer)
    
    const signatures = [signatureOne.signature, signatureTwo.signature]
    const signaturesSummed = Schnorrkel.sumSigs(signatures)
    const result = Schnorrkel.verify(signaturesSummed, msgHash, signatureTwo.publicNonce, combinedPublicKey)

    expect(result).toEqual(true)
  })
  it('should verify a schnorr signature with sha256 hash function', () => {
    const privateKey = new Key(Buffer.from(ethers.utils.randomBytes(32)))

    const abiCoder = new ethers.utils.AbiCoder()
    const msg = abiCoder.encode(['string'], ['test message'])
    const msgHash = ethers.utils.sha256(ethers.utils.toUtf8Bytes(msg))
    const signature = Schnorrkel.sign(privateKey, msgHash)

    const publicKey = ethers.utils.arrayify(
      ethers.utils.computePublicKey(ethers.utils.computePublicKey(privateKey.buffer, false), true)
    )

    expect(signature).toBeDefined()
    expect(signature.publicNonce.buffer).toHaveLength(33)
    expect(signature.signature.buffer).toHaveLength(32)
    expect(signature.challenge.buffer).toHaveLength(32)
    const result = Schnorrkel.verify(
      signature.signature,
      msgHash,
      signature.publicNonce,
      new Key(Buffer.from(publicKey))
    )
    expect(result).toEqual(true)
  })
  it('should sum the signatures and verify them using a custom hash function for the message', () => {
    const schnorrkelOne = new Schnorrkel()
    const schnorrkelTwo = new Schnorrkel()

    const keyPairOne = generateRandomKeys()
    const keyPairTwo = generateRandomKeys()
    const publicNoncesOne = schnorrkelOne.generatePublicNonces()
    const publicNoncesTwo = schnorrkelTwo.generatePublicNonces()

    const publicNonces = [publicNoncesOne, publicNoncesTwo]
    const publicKeys = [keyPairOne.publicKey, keyPairTwo.publicKey]

    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)

    const abiCoder = new ethers.utils.AbiCoder()
    const msg = abiCoder.encode(['string'], ['test message'])
    const msgHash = ethers.utils.keccak256(msg)
    const signatureOne = schnorrkelOne.multiSigSign(keyPairOne.privateKey, msgHash, publicKeys, publicNonces)
    const signatureTwo = schnorrkelTwo.multiSigSign(keyPairTwo.privateKey, msgHash, publicKeys, publicNonces)

    const signatures = [signatureOne.signature, signatureTwo.signature]
    const signaturesSummed = Schnorrkel.sumSigs(signatures)
    const result = Schnorrkel.verify(signaturesSummed, ethers.utils.keccak256(msg), signatureTwo.publicNonce, combinedPublicKey)

    expect(result).toEqual(true)
  })
  it('should verify a signature for a msg hashed with solidityKeccak256', () => {
    const privateKey = new Key(Buffer.from(ethers.utils.randomBytes(32)))

    const msg = 'test message'
    const hash = ethers.utils.solidityKeccak256(['string'], [msg])
    const signature = Schnorrkel.sign(privateKey, hash)

    const publicKey = ethers.utils.arrayify(
      ethers.utils.computePublicKey(ethers.utils.computePublicKey(privateKey.buffer, false), true)
    )

    expect(signature).toBeDefined()
    expect(signature.publicNonce.buffer).toHaveLength(33)
    expect(signature.signature.buffer).toHaveLength(32)
    expect(signature.challenge.buffer).toHaveLength(32)
    const result = Schnorrkel.verify(signature.signature, hash, signature.publicNonce, new Key(Buffer.from(publicKey)))
    expect(result).toEqual(true)
  })

  it('should verify a multi signature for a msg hashed with solidityKeccak256', () => {
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
    const signatureTwo = schnorrkelTwo.multiSigSign(keyPairTwo.privateKey, hash, publicKeys, publicNonces)
    const signatures = [signature.signature, signatureTwo.signature]
    const signaturesSummed = Schnorrkel.sumSigs(signatures)

    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)
    const result = Schnorrkel.verify(signaturesSummed, hash, signature.publicNonce, combinedPublicKey)
    expect(result).toEqual(true)
  })
})