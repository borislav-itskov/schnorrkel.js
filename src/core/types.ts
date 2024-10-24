export interface InternalNoncePairs {
  readonly k: Buffer,
  readonly kTwo: Buffer,
  readonly kPublic: Buffer,
  readonly kTwoPublic: Buffer,
}

export interface InternalPublicNonces {
  readonly kPublic: Buffer,
  readonly kTwoPublic: Buffer,
}

export interface InternalSignature {
  publicNonce: Buffer, // the final public nonce
  challenge: Buffer, // the schnorr challenge
  signature: Buffer, // the signature
}

export interface InternalNoncePairs {
  readonly k: Buffer,
  readonly kTwo: Buffer,
  readonly kPublic: Buffer,
  readonly kTwoPublic: Buffer,
}

export type InternalNonces = {
  [nonceId: string]: InternalNoncePairs
}