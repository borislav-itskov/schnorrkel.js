import { randomBytes } from 'crypto'
import { ethers } from 'ethers'
import secp256k1 from 'secp256k1'

import { KeyPair } from './keys'

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