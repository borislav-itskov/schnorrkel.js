
export interface SignatureOutput {
  publicNonce: PublicNonce, // the final public nonce
  challenge: Challenge, // the schnorr challenge
  signature: Signature, // the signature
}

export class PublicNonce {
  readonly buffer: Buffer

  constructor(buffer: Buffer) {
    this.buffer = buffer
  }

  toHex(): string {
    return this.buffer.toString('hex')
  }

  static fromHex(hex: string): PublicNonce {
    return new PublicNonce(Buffer.from(hex, 'hex'))
  }
}

export class Challenge {
  readonly buffer: Buffer

  constructor(buffer: Buffer) {
    this.buffer = buffer
  }

  toHex(): string {
    return this.buffer.toString('hex')
  }

  static fromHex(hex: string): Challenge {
    return new Challenge(Buffer.from(hex, 'hex'))
  }
}

export class Signature {
  readonly buffer: Buffer

  constructor(buffer: Buffer) {
    this.buffer = buffer
  }

  toHex(): string {
    return this.buffer.toString('hex')
  }

  static fromHex(hex: string): Signature {
    return new Signature(Buffer.from(hex, 'hex'))
  }
}

