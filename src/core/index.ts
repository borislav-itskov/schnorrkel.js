import { ethers } from 'ethers'
import secp256k1 from 'secp256k1'
import ecurve, { Point } from 'ecurve'
import bigi from 'bigi'
import { InternalNoncePairs, InternalNonces, InternalPublicNonces, InternalSignature } from './types'
import { KeyPair } from '../types'

const curve = ecurve.getCurveByName('secp256k1')

/**
 * Generate two random nonces in preparation for a multisignature.
 * We return along with them their public representations
 *
 * @returns InternalNoncePairs
 */
const generateNonce = (): InternalNoncePairs => {
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

/**
 * Compute the b coefficient needed for multisignature signing.
 * The b coefficient is needed to prevent the DL query attack
 * on the public nonces, in hand allowing us to skip the nonce
 * commitment round
 *
 * @param combinedPublicKey - the sum of the keys of the participants
 * @param msgHash - the hash that's going to be signed
 * @param publicNonces - the exchanged public nonces
 * @returns Buffer
 */
const bCoefficient = (combinedPublicKey: Buffer, msgHash: string, publicNonces: InternalPublicNonces[]): Buffer => {
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

  const dv1 = Buffer.from(buf1)
  const dv2 = Buffer.from(buf2)
  for (let i = 0; i != buf1.byteLength; i++) {
    if (dv1[i] != dv2[i]) return false
  }

  return true
}

/**
 * Compute the schnorr challenge.
 * The formula is: s = k + e*d. We're computing `e` here
 *
 * @param R
 * @param msgHash
 * @param publicKey
 * @returns Buffer hash(concat(public_nonce_addr, parity, x_coord, message))
 */
const challenge = (R: Buffer, msgHash: string, publicKey: Buffer): Buffer => {
  // convert R to address
  const R_uncomp = secp256k1.publicKeyConvert(R, false)
  const R_addr = ethers.utils.arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32)

  // e = keccak256(address(R) || compressed publicKey || msgHash)
  return Buffer.from(ethers.utils.arrayify(
    ethers.utils.solidityKeccak256(
      ['address', 'uint8', 'bytes32', 'bytes32'],
      [R_addr, publicKey[0] + 27 - 2, publicKey.slice(1, 33), msgHash]
    )
  ))
}

/**
 * A helper function that creates a key pair
 *
 * @returns KeyPair
 */
export const generateRandomKeys = (): KeyPair => {
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

/**
 * Generate a hash of all the public keys that are participating
 * in the signing process. We need this to craft the `a` coefficient,
 * which helps us prevent key cancelation attacks.
 *
 * @param publicKeys
 * @returns string
 */
export const _generateL = (publicKeys: Array<Buffer>): string => {
  return ethers.utils.keccak256(_concatTypedArrays(publicKeys.sort(Buffer.compare)))
}

export const _concatTypedArrays = (publicKeys: Buffer[]): Buffer => {
  const c: Buffer = Buffer.alloc(publicKeys.reduce((partialSum, publicKey) => partialSum + publicKey.length, 0))
  publicKeys.map((publicKey, index) => c.set(publicKey, (index * publicKey.length)))
  return Buffer.from(c.buffer)
}

/**
 * Generate `a` coefficient to prevent key cancelation attacks.
 * Hash commitment to all the public keys to prevent your key
 * not participating in the multisignature.
 *
 * @param publicKey - the signer's public key
 * @param L - review _generateL
 * @returns Buffer hash(concat(L, own_public_key))
 */
export const _aCoefficient = (publicKey: Buffer, L: string): Buffer => {
  return Buffer.from(ethers.utils.arrayify(ethers.utils.solidityKeccak256(
    ['bytes', 'bytes'],
    [L, publicKey]
  )))
}

/**
 * Hash the privateKey so it is not in plain text in arrays.
 * A separate method for easy reuse
 *
 * @param privateKey
 * @returns string
 */
export const _hashPrivateKey = (privateKey: Buffer): string => {
  return ethers.utils.keccak256(privateKey)
}

/**
 * Generate the nonces for the next signature.
 *
 * @returns
 */
export const _generateNonces = (): {
  privateNonceData: Pick<InternalNoncePairs, 'k' | 'kTwo'>,
  publicNonceData: InternalPublicNonces
} => {
  const nonce = generateNonce()

  return {
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

export const _multiSigSign = (nonceId: string, nonces: InternalNonces, combinedPublicKey: Buffer, privateKey: Buffer, hash: string, publicKeys: Buffer[], publicNonces: InternalPublicNonces[]): InternalSignature => {
  if (publicKeys.length < 2) {
    throw Error('At least 2 public keys should be provided')
  }

  const localPk = Buffer.from(privateKey)
  if (!(nonceId in nonces) || Object.keys(nonces[nonceId]).length === 0) {
    throw Error('Nonces should be exchanged before signing')
  }

  const publicKey = Buffer.from(secp256k1.publicKeyCreate(localPk))
  const L = _generateL(publicKeys)
  const a = _aCoefficient(publicKey, L)
  const b = bCoefficient(combinedPublicKey, hash, publicNonces)

  const effectiveNonces = publicNonces.map((batch) => {
    return Buffer.from(secp256k1.publicKeyCombine([batch.kPublic, secp256k1.publicKeyTweakMul(batch.kTwoPublic, b)]))
  })
  const signerEffectiveNonce = Buffer.from(secp256k1.publicKeyCombine([
    nonces[nonceId].kPublic,
    secp256k1.publicKeyTweakMul(nonces[nonceId].kTwoPublic, b)
  ]))
  const inArray = effectiveNonces.filter(nonce => areBuffersSame(nonce, signerEffectiveNonce)).length != 0
  if (!inArray) {
    throw Error('Passed nonces are invalid')
  }

  const R = Buffer.from(secp256k1.publicKeyCombine(effectiveNonces))
  const e = challenge(R, hash, combinedPublicKey)

  const { k, kTwo } = nonces[nonceId]

  // xe = x * e
  const xe = secp256k1.privateKeyTweakMul(localPk, e)

  // xea = a * xe
  const xea = secp256k1.privateKeyTweakMul(xe, a)

  // k + xea
  const kPlusxea = secp256k1.privateKeyTweakAdd(xea, k)

  // kTwo * b
  const kTwoMulB = secp256k1.privateKeyTweakMul(kTwo, b)

  // k + kTwoMulB + xea mod(n)
  const final = Buffer.from(secp256k1.privateKeyTweakAdd(kPlusxea, kTwoMulB))

  return {
    signature: final,
    challenge: e,
    publicNonce: R
  }
}

/**
 * Sum the passed signatures.
 * mod(n) is automatically applied in the privateKeyTweakAdd function
 *
 * @param signatures
 * @returns Buffer summed signature
 */
export const _sumSigs = (signatures: Buffer[]): Buffer => {
  if (signatures.length < 2) {
    throw Error('Expected at least 2 signatures for aggregation')
  }

  let combined = new Uint8Array()

  for (let i = 0; i < signatures.length - 1; i++) {
    combined = secp256k1.privateKeyTweakAdd(signatures[i], signatures[i+1])
  }

  return Buffer.from(combined)
}

/**
 * The verification formula is: s*G = R + H(m)*X
 * s is the signature
 * G is the generation point of the elliptic curve
 * R is the public nonce, or the ephemeral public nonce
 * H(m) is the hash of the message
 * X is the public key
 *
 * @param s the signature
 * @param hash the signed hash
 * @param R the public nonce used for this signature
 * @param publicKey the public key used for this signature
 * @returns bool
 */
export const _verify = (s: Buffer, hash: string, R: Buffer, publicKey: Buffer): boolean  => {
  const eC = challenge(R, hash, publicKey)

  const sG = curve.G.multiply(bigi.fromBuffer(s))
  const PasPoint = Point.decodeFrom(curve, publicKey)
  const Pe = PasPoint.multiply(bigi.fromBuffer(eC))
  const RasPoint = Point.decodeFrom(curve, R)
  const RplusPetest = RasPoint.add(Pe)
  return sG.equals(RplusPetest)
}

/**
 * Take the x-coordinate of the public key and transform it
 * into ethereum-like address.
 * This is the address returned by ecrecover on-chain schnorr verification
 *
 * @param combinedPublicKey
 * @returns address
 */
export const _generateSchnorrAddr = (combinedPublicKey: Buffer): string => {
  if (combinedPublicKey.length != 33) {
    throw Error('Public key should be 33 length, 1 byte parity and 32 bytes x-coordinate')
  }

  const px = ethers.utils.hexlify(combinedPublicKey.subarray(1,33))
  return '0x' + px.slice(px.length - 40, px.length)
}

export const _sign = (privateKey: Buffer, hash: string): InternalSignature  => {
  // if we use secp256k1 directly on the private key for operations
  // different than publicKeyCreate (privateKeyTweakMul, for example),
  // the private key gets modified. We do not want that and hence
  // do operations with a local copy
  const localPk = Buffer.from(privateKey)
  const publicKey = Buffer.from(secp256k1.publicKeyCreate(localPk))

  // R = G * k
  const k = ethers.utils.randomBytes(32)
  const R = Buffer.from(secp256k1.publicKeyCreate(k))

  // e = h(address(R) || compressed pubkey || m)
  const e = challenge(R, hash, publicKey)

  // xe = x * e
  const xe = secp256k1.privateKeyTweakMul(localPk, e)

  // s = k + xe mod(n)
  const s = Buffer.from(secp256k1.privateKeyTweakAdd(k, xe))

  return {
    publicNonce: R,
    challenge: e,
    signature: s
  }
}

/**
 * Provide a default hash function
 * It is not mandotory to use this one.
 *
 * @param message
 * @returns string
 */
export const _hashMessage = (message: string): string => {
  return ethers.utils.solidityKeccak256(['string'], [message])
}