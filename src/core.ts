import { randomBytes } from 'crypto'
import { ethers } from 'ethers'
import secp256k1 from 'secp256k1'
import ecurve from 'ecurve'
import bigi from 'bigi'

import { Key, KeyPair } from './keys'
import type { NoncePairs, PublicNonces, Nonces } from './nonce'
import type { Signature } from './signature'

const curve = ecurve.getCurveByName('secp256k1')
const n = curve?.n


export const _generateL = (publicKeys: Array<Buffer>) => {
  return ethers.utils.keccak256(_concatTypedArrays(publicKeys.sort()))
}

export const _concatTypedArrays = (publicKeys: Buffer[]): Buffer => {
  const c: Buffer = Buffer.alloc(publicKeys.reduce((partialSum, publicKey) => partialSum + publicKey.length, 0))
  publicKeys.map((publicKey, index) => c.set(publicKey, (index * publicKey.length)))
  return c
}


export const _aCoefficient = (publicKey: Uint8Array, L: string): Uint8Array => {
  return ethers.utils.arrayify(ethers.utils.solidityKeccak256(
    ['bytes', 'bytes'],
    [L, publicKey]
  ))
}

const _bCoefficient = (combinedPublicKey: Buffer, msgHash: string, publicNonces: PublicNonces[]): Uint8Array => {
  type Key = keyof PublicNonces
  const arrayColumn = (arr: Array<PublicNonces>, n: Key) => arr.map(x => x[n].buffer)
  const kPublicNonces = secp256k1.publicKeyCombine(arrayColumn(publicNonces, 'kPublic'))
  const kTwoPublicNonces = secp256k1.publicKeyCombine(arrayColumn(publicNonces, 'kTwoPublic'))

  return ethers.utils.arrayify(ethers.utils.solidityKeccak256(
    ['bytes', 'bytes32', 'bytes', 'bytes'],
    [combinedPublicKey, msgHash, kPublicNonces, kTwoPublicNonces]
  ))
}


export const _generateRandomKeys = (): KeyPair => {
  let privKeyBytes: Buffer | undefined
  do {
    privKeyBytes = randomBytes(32)
  } while (!secp256k1.privateKeyVerify(privKeyBytes))

  const pubKey = Buffer.from(secp256k1.publicKeyCreate(privKeyBytes))

  return new KeyPair({
    publicKey: pubKey,
    privateKey: privKeyBytes,
  })
}

export const _hashPrivateKey = (privateKey: Buffer): string => {
  return ethers.utils.keccak256(privateKey)
}

export const _generatePublicNonces = (privateKey: Buffer): {
  privateNonceData: Pick<NoncePairs, 'k' | 'kTwo'>,
  publicNonceData: PublicNonces,
  hash: string,
} => {
  const hash = _hashPrivateKey(privateKey)
  const nonce = _generateNonce()

  return {
    hash,
    privateNonceData: {
      k: nonce.k,
      kTwo: nonce.kTwo,
    },
    publicNonceData: {
      kPublic: nonce.kPublic,
      kTwoPublic: nonce.kTwoPublic,
    }
  }
}

const _generateNonce = (): NoncePairs => {
  const k = ethers.utils.randomBytes(32)
  const kTwo = ethers.utils.randomBytes(32)
  const kPublic = secp256k1.publicKeyCreate(k)
  const kTwoPublic = secp256k1.publicKeyCreate(kTwo)

  return {
    k: new Key(Buffer.from(k)),
    kTwo: new Key(Buffer.from(kTwo)),
    kPublic: new Key(Buffer.from(kPublic)),
    kTwoPublic: new Key(Buffer.from(kTwoPublic)),
  }
}

export const _multiSigSign = (nonces: Nonces, combinedPublicKey: Key, privateKey: Buffer, msg: string, publicKeys: Buffer[], publicNonces: PublicNonces[]): Signature => {
  if (publicKeys.length < 2) {
    throw Error('At least 2 public keys should be provided')
  }

  const xHashed = _hashPrivateKey(privateKey)
  if (!(xHashed in nonces) || Object.keys(nonces[xHashed]).length === 0) {
    throw Error('Nonces should be exchanged before signing')
  }

  const publicKey = secp256k1.publicKeyCreate(privateKey)
  const L = _generateL(publicKeys)
  const msgHash = ethers.utils.solidityKeccak256(['string'], [msg])
  const a = _aCoefficient(publicKey, L)
  const b = _bCoefficient(combinedPublicKey.buffer, msgHash, publicNonces)

  const effectiveNonces = publicNonces.map((batch) => {
    return secp256k1.publicKeyCombine([batch.kPublic.buffer, secp256k1.publicKeyTweakMul(batch.kTwoPublic.buffer, b)])
  })
  const signerEffectiveNonce = secp256k1.publicKeyCombine([
    nonces[xHashed].kPublic.buffer,
    secp256k1.publicKeyTweakMul(nonces[xHashed].kTwoPublic.buffer, b)
  ])
  const inArray = effectiveNonces.filter(nonce => areBuffersSame(nonce, signerEffectiveNonce)).length != 0
  if (!inArray) {
    throw Error('Passed nonces are invalid')
  }

  const R = secp256k1.publicKeyCombine(effectiveNonces)
  const e = challenge(R, msgHash, combinedPublicKey.buffer)

  const { k, kTwo } = nonces[xHashed]

  // xe = x * e
  const xe = secp256k1.privateKeyTweakMul(privateKey, e)

  // xea = a * xe
  const xea = secp256k1.privateKeyTweakMul(xe, a)

  // k + xea
  const kPlusxea = secp256k1.privateKeyTweakAdd(xea, k.buffer)

  // kTwo * b
  const kTwoMulB = secp256k1.privateKeyTweakMul(kTwo.buffer, b)

  // k + kTwoMulB + xea
  const final = secp256k1.privateKeyTweakAdd(kPlusxea, kTwoMulB)


  return {
    // s = k + xea mod(n)
    signature: bigi.fromBuffer(final).mod(n).toBuffer(32),
    challenge: e,
    finalPublicNonce: R
  }
}

const areBuffersSame = (buf1: Uint8Array, buf2: Uint8Array): boolean => {
  if (buf1.byteLength != buf2.byteLength) return false;

  var dv1 = new Int8Array(buf1)
  var dv2 = new Int8Array(buf2)
  for (var i = 0; i != buf1.byteLength; i++) {
    if (dv1[i] != dv2[i]) return false
  }

  return true;
}

const challenge = (R: Uint8Array, msgHash: string, publicKey: Uint8Array): Uint8Array => {
  // convert R to address
  var R_uncomp = secp256k1.publicKeyConvert(R, false);
  var R_addr = ethers.utils.arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32)

  // e = keccak256(address(R) || compressed publicKey || msgHash)
  return ethers.utils.arrayify(
    ethers.utils.solidityKeccak256(
      ['address', 'uint8', 'bytes32', 'bytes32'],
      [R_addr, publicKey[0] + 27 - 2, publicKey.slice(1, 33), msgHash]
    )
  )
}