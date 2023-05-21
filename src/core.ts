import { randomBytes } from 'crypto'
import { ethers } from 'ethers'
import secp256k1 from 'secp256k1'

import { Key, KeyPair } from './keys'
import { NoncePairs, PublicNonces } from './nonce'

export const _generateL = (publicKeys: Array<Buffer>) => {
  return ethers.utils.keccak256(_concatTypedArrays(publicKeys.sort()))
}

export const _concatTypedArrays = (publicKeys: Buffer[]): Buffer => {
  const c: Buffer = Buffer.alloc(publicKeys.reduce((partialSum, publicKey) => partialSum + publicKey.length, 0))
  publicKeys.map((publicKey, index) => c.set(publicKey, (index * publicKey.length)))
  return c as Buffer
}


export const _aCoefficient = (publicKey: Uint8Array, L: string): Uint8Array => {
  return ethers.utils.arrayify(ethers.utils.solidityKeccak256(
    ['bytes', 'bytes'],
    [L, publicKey]
  ));
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