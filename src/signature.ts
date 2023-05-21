export interface Signature {
    finalPublicNonce: Uint8Array, // the final public nonce
    challenge: Uint8Array, // the schnorr challenge
    signature: Uint8Array, // the signature
}