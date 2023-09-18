import { ethers } from 'ethers'
import secp256k1 from 'secp256k1'
import ecurve, { Point } from 'ecurve'
import bigi from 'bigi'
import { InternalNoncePairs, InternalNonces, InternalPublicNonces, InternalSignature } from './types'
import { KeyPair } from '../types'

const curve = ecurve.getCurveByName('secp256k1')
const n = curve.n

const _generateNonce = (): InternalNoncePairs => {
  const k = Buffer.from(ethers.utils.randomBytes(32))
  const kTwo = Buffer.from(ethers.utils.randomBytes(32))
  const kPublic = Buffer.from(secp256k1.publicKeyCreate(k))
  const kTwoPublic = Buffer.from(secp256k1.publicKeyCreate(kTwo))

  return {
    k,
    kTwo,
    kPublic,
    kTwoPublic,
  }
}

const _bCoefficient = (combinedPublicKey: Buffer, msgHash: string, publicNonces: InternalPublicNonces[]): Buffer => {
  type KeyOf = keyof InternalPublicNonces
  const arrayColumn = (arr: Array<InternalPublicNonces>, n: KeyOf) => arr.map(x => x[n])
  const kPublicNonces = secp256k1.publicKeyCombine(arrayColumn(publicNonces, 'kPublic'))
  const kTwoPublicNonces = secp256k1.publicKeyCombine(arrayColumn(publicNonces, 'kTwoPublic'))

  return Buffer.from(ethers.utils.arrayify(ethers.utils.solidityKeccak256(
    ['bytes', 'bytes32', 'bytes', 'bytes'],
    [combinedPublicKey, msgHash, kPublicNonces, kTwoPublicNonces]
  )))
}

const areBuffersSame = (buf1: Buffer, buf2: Buffer): boolean => {
  if (buf1.byteLength != buf2.byteLength) return false

  var dv1 = Buffer.from(buf1)
  var dv2 = Buffer.from(buf2)
  for (var i = 0; i != buf1.byteLength; i++) {
    if (dv1[i] != dv2[i]) return false
  }

  return true
}

const challenge = (R: Buffer, msgHash: string, publicKey: Buffer): Buffer => {
  // convert R to address
  var R_uncomp = secp256k1.publicKeyConvert(R, false)
  var R_addr = ethers.utils.arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32)

  // e = keccak256(address(R) || compressed publicKey || msgHash)
  return Buffer.from(ethers.utils.arrayify(
    ethers.utils.solidityKeccak256(
      ['address', 'uint8', 'bytes32', 'bytes32'],
      [R_addr, publicKey[0] + 27 - 2, publicKey.slice(1, 33), msgHash]
    )
  ))
}

export const _generateL = (publicKeys: Array<Buffer>) => {
  return ethers.utils.keccak256(_concatTypedArrays(publicKeys.sort(Buffer.compare)))
}

export const _concatTypedArrays = (publicKeys: Buffer[]): Buffer => {
  const c: Buffer = Buffer.alloc(publicKeys.reduce((partialSum, publicKey) => partialSum + publicKey.length, 0))
  publicKeys.map((publicKey, index) => c.set(publicKey, (index * publicKey.length)))
  return Buffer.from(c.buffer)
}


export const _aCoefficient = (publicKey: Buffer, L: string): Buffer => {
  return Buffer.from(ethers.utils.arrayify(ethers.utils.solidityKeccak256(
    ['bytes', 'bytes'],
    [L, publicKey]
  )))
}

export const generateRandomKeys = () => {
  let privKeyBytes: Buffer
  do {
    privKeyBytes = Buffer.from(ethers.utils.randomBytes(32))
  } while (!secp256k1.privateKeyVerify(privKeyBytes))

  const pubKey = Buffer.from(secp256k1.publicKeyCreate(privKeyBytes))

  const data = {
    publicKey: pubKey,
    privateKey: privKeyBytes,
  }

  return new KeyPair(data)
}

export const _hashPrivateKey = (privateKey: Buffer): string => {
  return ethers.utils.keccak256(privateKey)
}

export const _generatePublicNonces = (privateKey: Buffer): {
  privateNonceData: Pick<InternalNoncePairs, 'k' | 'kTwo'>,
  publicNonceData: InternalPublicNonces,
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

export const _multiSigSign = (nonces: InternalNonces, combinedPublicKey: Buffer, privateKey: Buffer, hash: string, publicKeys: Buffer[], publicNonces: InternalPublicNonces[]): InternalSignature => {
  if (publicKeys.length < 2) {
    throw Error('At least 2 public keys should be provided')
  }

  const localPk = Buffer.from(privateKey)
  const xHashed = _hashPrivateKey(localPk)
  if (!(xHashed in nonces) || Object.keys(nonces[xHashed]).length === 0) {
    throw Error('Nonces should be exchanged before signing')
  }

  const publicKey = Buffer.from(secp256k1.publicKeyCreate(localPk))
  const L = _generateL(publicKeys)
  const a = _aCoefficient(publicKey, L)
  const b = _bCoefficient(combinedPublicKey, hash, publicNonces)

  const effectiveNonces = publicNonces.map((batch) => {
    return Buffer.from(secp256k1.publicKeyCombine([batch.kPublic, secp256k1.publicKeyTweakMul(batch.kTwoPublic, b)]))
  })
  const signerEffectiveNonce = Buffer.from(secp256k1.publicKeyCombine([
    nonces[xHashed].kPublic,
    secp256k1.publicKeyTweakMul(nonces[xHashed].kTwoPublic, b)
  ]))
  const inArray = effectiveNonces.filter(nonce => areBuffersSame(nonce, signerEffectiveNonce)).length != 0
  if (!inArray) {
    throw Error('Passed nonces are invalid')
  }

  const R = Buffer.from(secp256k1.publicKeyCombine(effectiveNonces))
  const e = challenge(R, hash, combinedPublicKey)

  const { k, kTwo } = nonces[xHashed]

  // xe = x * e
  const xe = secp256k1.privateKeyTweakMul(localPk, e)

  // xea = a * xe
  const xea = secp256k1.privateKeyTweakMul(xe, a)

  // k + xea
  const kPlusxea = secp256k1.privateKeyTweakAdd(xea, k)

  // kTwo * b
  const kTwoMulB = secp256k1.privateKeyTweakMul(kTwo, b)

  // k + kTwoMulB + xea
  const final = secp256k1.privateKeyTweakAdd(kPlusxea, kTwoMulB)


  return {
    // s = k + xea mod(n)
    signature: bigi.fromBuffer(final).mod(n).toBuffer(32),
    challenge: e,
    finalPublicNonce: R
  }
}

export const _sumSigs = (signatures: Buffer[]): Buffer => {
  let combined = bigi.fromBuffer(signatures[0])
  signatures.shift()
  signatures.forEach(sig => {
    combined = combined.add(bigi.fromBuffer(sig))
  })
  return combined.mod(n).toBuffer(32)
}

export const _verify = (s: Buffer, hash: string, R: Buffer, publicKey: Buffer): boolean  => {
  const eC = challenge(R, hash, publicKey)

  const sG = curve.G.multiply(bigi.fromBuffer(s))
  const PasPoint = Point.decodeFrom(curve, publicKey)
  const Pe = PasPoint.multiply(bigi.fromBuffer(eC))
  const RasPoint = Point.decodeFrom(curve, R)
  const RplusPetest = RasPoint.add(Pe)
  return sG.equals(RplusPetest)
}

export const _generatePk = (combinedPublicKey: Buffer): string => {
  const px = ethers.utils.hexlify(combinedPublicKey.subarray(1,33))
  return '0x' + px.slice(px.length - 40, px.length)
}

export const _sign = (privateKey: Buffer, hash: string): InternalSignature  => {
  const localPk = Buffer.from(privateKey)
  const publicKey = Buffer.from(secp256k1.publicKeyCreate(localPk))

  // R = G * k
  var k = ethers.utils.randomBytes(32)
  var R = Buffer.from(secp256k1.publicKeyCreate(k))

  // e = h(address(R) || compressed pubkey || m)
  var e = challenge(R, hash, publicKey)

  // xe = x * e
  var xe = secp256k1.privateKeyTweakMul(localPk, e)

  // s = k + xe mod(n)
  var s = Buffer.from(secp256k1.privateKeyTweakAdd(k, xe))
  s = bigi.fromBuffer(s).mod(n).toBuffer(32)

  return {
    finalPublicNonce: R,
    challenge: e,
    signature: s
  }
}